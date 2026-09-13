#!/usr/bin/env python3
"""浏览器通道的端到端验收。

走真实公网 HTTPS，覆盖：发现 → 注册 → 授权 → 换令牌 → 调 MCP → 真的驱动浏览器，
最后验证两条通道的令牌互不通用。

跑法（密码默认从网关的明文便利文件读，也可以用环境变量覆盖）:
    E2E_BROWSER_URL=https://browser.example.com \\
    E2E_SHELL_URL=https://host.example.com \\
    E2E_PW_BROWSER=xxx E2E_PW_SHELL=yyy \\
    python3 tests/e2e_test.py
"""
import base64
import hashlib
import json
import os
import secrets
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx

BROWSER = os.environ.get("E2E_BROWSER_URL", "https://browser.example.com").rstrip("/")
SHELL = os.environ.get("E2E_SHELL_URL", "https://host.example.com").rstrip("/")
CB = os.environ.get("E2E_REDIRECT_URI", "https://client.example.com/cb")


def _pw(env_name: str, hint_path: str) -> str:
    if os.environ.get(env_name):
        return os.environ[env_name]
    p = Path(hint_path)
    if p.exists():
        return p.read_text("utf-8").strip()
    raise SystemExit(f"缺少 {env_name}，也读不到 {hint_path}")


PW_BROWSER = _pw("E2E_PW_BROWSER", "/root/.mcp-oauth-browser-password")
PW_SHELL = _pw("E2E_PW_SHELL", "/root/.mcp-oauth-password")

results = []


def check(name, cond, extra=""):
    results.append((name, bool(cond)))
    print(("PASS  " if cond else "FAIL  ") + name
          + (("   | " + str(extra)[:170]) if extra else ""))


def mcp_call(c, base, sid, payload, token=None):
    h = {"Content-Type": "application/json",
         "Accept": "application/json, text/event-stream"}
    if sid:
        h["mcp-session-id"] = sid
    if token:
        h["Authorization"] = f"Bearer {token}"
    return c.post(f"{base}/mcp", json=payload, headers=h, timeout=60)


def main():
    with httpx.Client(timeout=30, follow_redirects=False) as c:
        # ---------- 发现 ----------
        r = c.get(f"{BROWSER}/.well-known/oauth-protected-resource")
        check("发现：resource 指向 browser 域名",
              r.json().get("resource") == f"{BROWSER}/mcp", r.text[:120])
        r = c.get(f"{BROWSER}/.well-known/oauth-authorization-server")
        check("发现：issuer 是 browser 域名",
              r.json().get("issuer") == BROWSER, r.text[:120])

        # ---------- 注册 ----------
        r = c.post(f"{BROWSER}/oauth/register", json={
            "client_name": "E2E-Browser", "redirect_uris": [CB]})
        check("注册 -> 201", r.status_code == 201, r.text[:120])
        cid = r.json()["client_id"]

        # ---------- 授权：用 shell 的密码必须失败 ----------
        verifier = secrets.token_urlsafe(64)[:64]
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        form = {"client_id": cid, "redirect_uri": CB, "code_challenge": challenge,
                "code_challenge_method": "S256", "state": "e2e"}

        r = c.post(f"{BROWSER}/oauth/authorize",
                   data={**form, "password": PW_SHELL})
        check("拿 shell 的密码来授权 -> 401（密码确实是分开的）",
              r.status_code == 401, r.status_code)

        # ---------- 授权：用 browser 的密码 ----------
        r = c.post(f"{BROWSER}/oauth/authorize",
                   data={**form, "password": PW_BROWSER})
        check("用 browser 密码 -> 302", r.status_code == 302,
              r.headers.get("location", "")[:80])
        qs = parse_qs(urlparse(r.headers["location"]).query)
        code = qs["code"][0]

        # ---------- 换令牌 ----------
        r = c.post(f"{BROWSER}/oauth/token", data={
            "grant_type": "authorization_code", "code": code, "client_id": cid,
            "redirect_uri": CB, "code_verifier": verifier})
        check("换令牌 -> 200", r.status_code == 200, r.text[:150])
        tok = r.json()
        access = tok["access_token"]

        # ---------- 调 MCP ----------
        r = mcp_call(c, BROWSER, None, {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "e2e", "version": "1"}}},
            token=access)
        check("带令牌 initialize -> 200", r.status_code == 200, r.status_code)
        sid = r.headers.get("mcp-session-id")
        check("拿到 session id", bool(sid), sid)

        mcp_call(c, BROWSER, sid, {"jsonrpc": "2.0",
                                   "method": "notifications/initialized"},
                 token=access)

        r = mcp_call(c, BROWSER, sid, {"jsonrpc": "2.0", "id": 2,
                                       "method": "tools/list"}, token=access)
        tools = [m for m in r.text.split('"name":"')[1:]]
        names = [t.split('"')[0] for t in tools]
        check("拿到浏览器工具", "browser_navigate" in names,
              f"{len(names)} 个工具")

        # ---------- 真的驱动浏览器 ----------
        r = mcp_call(c, BROWSER, sid, {
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "browser_navigate",
                       "arguments": {"url": "https://example.com"}}}, token=access)
        check("真的驱动了浏览器（导航成功）",
              "Example Domain" in r.text, r.text[:160])

        # ---------- 隔离：browser 的令牌拿去打 shell ----------
        r = c.post(f"{SHELL}/mcp", json={}, headers={
            "Authorization": f"Bearer {access}",
            "Accept": "application/json, text/event-stream"}, timeout=30)
        check("browser 的令牌打 shell 通道 -> 401（隔离生效）",
              r.status_code == 401, r.status_code)

    failed = [n for n, ok in results if not ok]
    print()
    print(f"{len(results) - len(failed)}/{len(results)} passed")
    if failed:
        print("FAILED: " + "; ".join(failed))
        return 1
    return 0


sys.exit(main())
