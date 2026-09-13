#!/usr/bin/env python3
"""mcp_oauth_gateway 的本地回归测试。

用 httpx 的 ASGITransport 直接打应用对象，不起服务器、不碰生产状态。
跑法:
    <venv>/Scripts/python.exe test_flow.py
"""
import asyncio
import base64
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path
from urllib.parse import parse_qs, urlparse

TMP = Path(tempfile.mkdtemp(prefix="oauth-test-"))
os.environ["MCP_OAUTH_STATE"] = str(TMP)
os.environ["MCP_OAUTH_PORT"] = "18099"
os.environ["MCP_UPSTREAM"] = "http://127.0.0.1:9/mcp"   # 故意不可达
os.environ["MCP_OAUTH_PASSWORD_HINT"] = str(TMP / "hint.txt")
os.environ["MCP_PUBLIC_BASE"] = "https://host.example.com"

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import mcp_oauth_gateway as gw          # noqa: E402
import httpx                            # noqa: E402

PASSWORD = "TestPassword-1234567890-xyz"
gw._set_password(PASSWORD)

BASE = "https://host.example.com"
CB = "https://client.example.com/cb"
results = []


def check(name, cond, extra=""):
    results.append((name, bool(cond)))
    print(("PASS  " if cond else "FAIL  ") + name
          + (("   | " + str(extra)[:160]) if extra else ""))


def new_verifier(tag="v"):
    return (tag * 64)[:64]


def challenge_of(verifier):
    d = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(d).rstrip(b"=").decode()


async def main():
    transport = httpx.ASGITransport(app=gw.app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url=BASE) as c:

        # ---------- 发现端点 ----------
        r = await c.get("/.well-known/oauth-protected-resource")
        check("metadata: resource 正确", r.json().get("resource") == f"{BASE}/mcp", r.text)
        r = await c.get("/.well-known/oauth-authorization-server")
        asm = r.json()
        check("metadata: issuer 被钉死", asm.get("issuer") == BASE)
        check("metadata: 有 revocation_endpoint",
              asm.get("revocation_endpoint") == f"{BASE}/oauth/revoke")
        check("响应头: no-store", r.headers.get("cache-control") == "no-store")
        check("响应头: nosniff", r.headers.get("x-content-type-options") == "nosniff")
        check("响应头: X-Frame-Options=DENY", r.headers.get("x-frame-options") == "DENY")
        check("响应头: CSP frame-ancestors",
              "frame-ancestors" in (r.headers.get("content-security-policy") or ""))

        # ---------- 无令牌访问 /mcp ----------
        r = await c.post("/mcp", json={})
        check("无令牌 → 401", r.status_code == 401)
        check("401 带 resource_metadata",
              "resource_metadata=" in (r.headers.get("www-authenticate") or ""))

        # ---------- 动态注册 ----------
        r = await c.post("/oauth/register", json={
            "client_name": "Bad", "redirect_uris": ["http://evil.example.com/cb"]})
        check("http 非 loopback 的 redirect_uri 被拒", r.status_code == 400, r.text)

        r = await c.post("/oauth/register", json={
            "client_name": "TestClient", "redirect_uris": [CB]})
        check("正常注册 → 201", r.status_code == 201, r.text)
        cid = r.json()["client_id"]

        # ---------- 授权 ----------
        verifier = new_verifier()
        q = {"client_id": cid, "redirect_uri": CB,
             "code_challenge": challenge_of(verifier),
             "code_challenge_method": "S256",
             "state": "st-123", "response_type": "code"}

        r = await c.get("/oauth/authorize", params=q)
        check("授权页 GET 出表单",
              r.status_code == 200 and 'name="password"' in r.text)

        r = await c.get("/oauth/authorize", params={**q, "client_id": "nope"})
        check("未知 client_id → 400", r.status_code == 400)

        r = await c.get("/oauth/authorize", params={**q, "redirect_uri": "https://other/cb"})
        check("未注册的 redirect_uri → 400", r.status_code == 400)

        r = await c.get("/oauth/authorize", params={**q, "code_challenge_method": "plain"})
        check("非 S256 的 PKCE → 400", r.status_code == 400)

        r = await c.post("/oauth/authorize", data={**q, "password": "wrong"})
        check("错密码 → 401", r.status_code == 401)

        r = await c.post("/oauth/authorize", data={**q, "password": PASSWORD},
                         follow_redirects=False)
        check("对密码 → 302 带 code", r.status_code == 302, r.headers.get("location"))
        loc = r.headers.get("location") or ""
        qs = parse_qs(urlparse(loc).query)
        code = qs.get("code", [""])[0]
        check("state 原样回传", qs.get("state", [""])[0] == "st-123")

        # ---------- 换令牌 ----------
        r = await c.post("/oauth/token", data={
            "grant_type": "authorization_code", "code": code, "client_id": cid,
            "redirect_uri": CB, "code_verifier": verifier})
        check("换令牌 → 200", r.status_code == 200, r.text)
        tok = r.json()
        check("令牌响应 no-store", r.headers.get("cache-control") == "no-store")
        access, refresh = tok["access_token"], tok["refresh_token"]

        r = await c.post("/oauth/token", data={
            "grant_type": "authorization_code", "code": code, "client_id": cid,
            "redirect_uri": CB, "code_verifier": verifier})
        check("授权码只能用一次", r.status_code == 400)

        # 错的 code_verifier
        r = await c.post("/oauth/authorize", data={**q, "password": PASSWORD},
                         follow_redirects=False)
        code2 = parse_qs(urlparse(r.headers.get("location") or "").query)["code"][0]
        r = await c.post("/oauth/token", data={
            "grant_type": "authorization_code", "code": code2, "client_id": cid,
            "redirect_uri": CB, "code_verifier": new_verifier("z")})
        check("PKCE verifier 不符 → 400", r.status_code == 400)

        # ---------- 磁盘上不留明文 ----------
        raw = (TMP / "tokens.json").read_text()
        check("tokens.json 无 access 明文", access not in raw)
        check("tokens.json 无 refresh 明文", refresh not in raw)
        check("tokens.json 存的是 sha256",
              hashlib.sha256(access.encode()).hexdigest() in raw)

        # ---------- 代理鉴权 ----------
        r = await c.post("/mcp", json={}, headers={"Authorization": "Bearer nope"})
        check("伪造令牌 → 401", r.status_code == 401)

        r = await c.post("/mcp", json={"jsonrpc": "2.0", "method": "initialize", "id": 1},
                         headers={"Authorization": f"Bearer {access}"})
        check("有效令牌能过鉴权（上游不通不算错）", r.status_code != 401, r.status_code)

        # ---------- 刷新 + 宽限窗口 ----------
        r = await c.post("/oauth/token", data={
            "grant_type": "refresh_token", "refresh_token": refresh, "client_id": cid})
        check("刷新 → 200", r.status_code == 200, r.text)
        tok2 = r.json()
        check("刷新后换了新 refresh", tok2["refresh_token"] != refresh)

        r = await c.post("/oauth/token", data={
            "grant_type": "refresh_token", "refresh_token": refresh, "client_id": cid})
        check("宽限窗口内重放旧 refresh → 200", r.status_code == 200, r.text)
        tok3 = r.json()
        check("宽限重放发的是又一对新令牌",
              tok3["refresh_token"] not in (refresh, tok2["refresh_token"]))
        access3 = tok3["access_token"]

        # 把宽限窗口拨到过去，旧 refresh 应该彻底作废
        store = json.loads((TMP / "tokens.json").read_text())
        key = hashlib.sha256(refresh.encode()).hexdigest()
        rec = store["refresh_tokens"].get(key)
        check("旧 refresh 记录还在", rec is not None)
        if rec:
            rec["rotated_at"] = gw._now() - (gw.REFRESH_GRACE + 10)
            rec["expires"] = gw._now() + 999
            (TMP / "tokens.json").write_text(json.dumps(store), "utf-8")
            r = await c.post("/oauth/token", data={
                "grant_type": "refresh_token", "refresh_token": refresh, "client_id": cid})
            check("宽限过期后旧 refresh → 400", r.status_code == 400, r.text)

        # ---------- 资源绑定 ----------
        store = json.loads((TMP / "tokens.json").read_text())
        k3 = hashlib.sha256(access3.encode()).hexdigest()
        if k3 in store["access_tokens"]:
            store["access_tokens"][k3]["resource"] = f"{BASE}/browser"
            (TMP / "tokens.json").write_text(json.dumps(store), "utf-8")
            r = await c.post("/mcp", json={}, headers={"Authorization": f"Bearer {access3}"})
            check("令牌绑定的 resource 不符 → 401", r.status_code == 401)
            store["access_tokens"][k3]["resource"] = f"{BASE}/mcp"
            (TMP / "tokens.json").write_text(json.dumps(store), "utf-8")
        else:
            check("找到宽限发出的 access 记录", False)

        # ---------- 撤销 ----------
        r = await c.post("/oauth/revoke", data={
            "token": access3, "token_type_hint": "access_token", "client_id": cid})
        check("撤销 → 200", r.status_code == 200)
        r = await c.post("/mcp", json={}, headers={"Authorization": f"Bearer {access3}"})
        check("撤销后 → 401", r.status_code == 401)

        r = await c.post("/oauth/revoke", data={"token": "no-such-token"})
        check("撤销不存在的令牌也是 200", r.status_code == 200)

        # ---------- 注册限流 ----------
        n429 = 0
        for i in range(12):
            rr = await c.post("/oauth/register", json={
                "client_name": f"spam{i}", "redirect_uris": ["https://x.example.com/cb"]})
            if rr.status_code == 429:
                n429 += 1
        check("注册被限流", n429 > 0, f"429 x{n429}")

        # ---------- 失败锁定：按 IP 分桶 ----------
        for _ in range(gw.MAX_AUTH_FAILURES):
            await c.post("/oauth/authorize", data={**q, "password": "wrong"})
        r = await c.post("/oauth/authorize", data={**q, "password": PASSWORD},
                         follow_redirects=False)
        check("连错后本 IP 被锁", r.status_code == 401 and "尝试过多" in r.text, r.status_code)

        async with httpx.AsyncClient(transport=transport, base_url=BASE,
                                     headers={"X-Forwarded-For": "203.0.113.9"}) as c2:
            r = await c2.post("/oauth/authorize", data={**q, "password": PASSWORD},
                              follow_redirects=False)
            check("别的 IP 不受影响（老代码会一起被锁）", r.status_code == 302, r.status_code)

        # ---------- 密码 ----------
        check("明文便利文件写出来了", (TMP / "hint.txt").read_text().strip() == PASSWORD)
        check("密码校验: 对", gw._verify_password(PASSWORD))
        check("密码校验: 错", not gw._verify_password("nope"))
        check("新密码记录带 scrypt 参数",
              json.loads((TMP / "password.json").read_text()).get("n") == gw.SCRYPT_N)

        # 老记录（没有 n/r/p）必须还能校验 —— 否则升级即锁死
        legacy_salt = base64.b64decode(json.loads((TMP / "password.json").read_text())["salt"])
        legacy = hashlib.scrypt(PASSWORD.encode(), salt=legacy_salt,
                                n=gw.SCRYPT_LEGACY_N, r=8, p=1, dklen=32)
        (TMP / "password.json").write_text(json.dumps({
            "salt": base64.b64encode(legacy_salt).decode(),
            "hash": base64.b64encode(legacy).decode()}), "utf-8")
        check("老格式（n=2**14 无参数字段）仍可校验", gw._verify_password(PASSWORD))

    failed = [n for n, ok in results if not ok]
    print()
    print(f"{len(results) - len(failed)}/{len(results)} passed")
    if failed:
        print("FAILED: " + "; ".join(failed))
        return 1
    return 0


sys.exit(asyncio.run(main()))
