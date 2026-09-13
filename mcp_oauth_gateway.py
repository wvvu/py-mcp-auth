#!/usr/bin/env python3
"""
mcp-oauth-gateway —— 给无鉴权的 MCP HTTP 端点套一层 OAuth 2.1。

    claude.ai / Claude Code
        ↓ OAuth 2.1 + PKCE
    本网关 (:18011)
        ↓ 裸 HTTP, 只听 127.0.0.1
    supergateway (:18010)
        ↓ stdio
    mcp-ssh-manager
        ↓ SSH
    目标机器

端点形状照抄 /opt/ombre-brain/src/web/oauth.py 的实测结果 —— 那份是被
claude.ai 真实握手验证过的，字段名和结构不要凭空改。

设计要点：
  * issuer / 各 endpoint 的 URL 默认从请求头推导（X-Forwarded-* 优先），
    所以同一份代码在局域网直连和过 Cloudflare 隧道时都不用改配置。
    但设了 MCP_PUBLIC_BASE 就以它为准 —— RFC 8414 要求 issuer 稳定，
    否则同一个网关在不同 Host 下会签发不同 resource 的令牌，客户端反复重新授权。
  * 公开客户端（token_endpoint_auth_method=none）+ 强制 PKCE S256，
    这是 MCP 客户端的通用形态：它们没有地方安全保存 client_secret。
  * 授权环节就一道密码。密码只比对 scrypt 哈希，明文不落盘
    （除了给 root 自己看的那份便利文件，见 _write_password_hint）。
  * 令牌是不透明随机串，**磁盘上只存 sha256**，JSON 文件泄露 ≠ 通道泄露。
  * 失败计数按来源 IP 分桶 —— 全局计数会被用来把管理员自己锁在门外。
  * 所有 JSON 状态都是「读-改-写」，必须串行化，否则并发换令牌会丢更新。
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import secrets
import time
import tomllib
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlencode, urlparse

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import (
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    Response,
    StreamingResponse,
)
from starlette.routing import Route

# ---------------------------------------------------------------- 配置

UPSTREAM = os.environ.get("MCP_UPSTREAM", "http://127.0.0.1:18010/mcp")
STATE_DIR = Path(os.environ.get("MCP_OAUTH_STATE", "/etc/mcp-ssh/oauth"))
LISTEN_PORT = int(os.environ.get("MCP_OAUTH_PORT", "18011"))

# 固定对外地址。留空则回落到从请求头推导（老行为）。
PUBLIC_BASE = os.environ.get("MCP_PUBLIC_BASE", "").rstrip("/")

# 明文密码便利文件。设成空字符串可以关掉（MCP_OAUTH_PASSWORD_HINT=""）。
_HINT_ENV = os.environ.get(
    "MCP_OAUTH_PASSWORD_HINT", "/root/.mcp-oauth-password"
).strip()
PASSWORD_HINT_FILE: Optional[Path] = Path(_HINT_ENV) if _HINT_ENV else None

ACCESS_TTL = 3600 * 12          # 访问令牌 12 小时
REFRESH_TTL = 3600 * 24 * 30    # 刷新令牌 30 天
CODE_TTL = 300                  # 授权码 5 分钟
MAX_AUTH_FAILURES = 8           # 单个 IP 密码错这么多次就锁一段时间
LOCKOUT_SECONDS = 900
REFRESH_GRACE = 60              # 刷新令牌轮换后的复用宽限窗口(秒)

# 动态注册闸门。MCP 客户端本来就该是一台设备注册一次，这个额度很宽松。
REGISTER_MAX_PER_WINDOW = 10    # 每个 IP 每窗口最多注册几个客户端
REGISTER_WINDOW = 3600
REGISTER_MAX_CLIENTS = 100      # clients.json 总量上限

# scrypt 参数。2**15 需要显式抬 maxmem，默认 32MB 会直接抛 ValueError。
SCRYPT_N = 2 ** 15
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_MAXMEM = 128 * 1024 * 1024
# 老记录没写 n/r/p 字段，那时用的是 2**14 —— 缺字段就按老参数校验，
# 否则升级这一版会把现有密码直接作废。
SCRYPT_LEGACY_N = 2 ** 14

STATE_DIR.mkdir(parents=True, exist_ok=True)
CLIENTS_FILE = STATE_DIR / "clients.json"
TOKENS_FILE = STATE_DIR / "tokens.json"
PASSWORD_FILE = STATE_DIR / "password.json"

_codes: Dict[str, Dict[str, Any]] = {}   # 授权码只放内存，反正 5 分钟就过期
_failures: Dict[str, Dict[str, Any]] = {}   # ip -> {"count": n, "until": ts}

# 所有 JSON 状态的读-改-写都要串在这把锁后面。
# _save() 的原子替换只保证「文件不会写坏」，不保证「不会丢更新」：
# 两个请求同时 load → 各自改 → 各自 save，后写的会把先写的整个覆盖掉。
_state_lock = asyncio.Lock()
_registrations: Dict[str, list] = {}     # ip -> [注册时间戳]


# ---------------------------------------------------------------- 小工具

def _load(path: Path) -> Dict[str, Any]:
    try:
        return json.loads(path.read_text("utf-8"))
    except Exception:
        return {}


def _save(path: Path, data: Dict[str, Any]) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), "utf-8")
    os.replace(tmp, path)          # 原子替换，别让断电写出半个文件
    os.chmod(path, 0o600)


def _now() -> int:
    return int(time.time())


def _purge_expired(store: Dict[str, Any]) -> None:
    now = _now()
    for bucket in ("access_tokens", "refresh_tokens"):
        section = store.get(bucket) or {}
        for key in [k for k, v in section.items() if v.get("expires", 0) <= now]:
            section.pop(key, None)


def _request_base(request: Request) -> str:
    """从请求头推导的自身地址。过隧道时 Host 头是公网域名，直连时是内网 IP。"""
    fwd_proto = request.headers.get("x-forwarded-proto")
    fwd_host = request.headers.get("x-forwarded-host")
    host = fwd_host or request.headers.get("host") or request.url.netloc
    if fwd_proto:
        scheme = fwd_proto.split(",")[0].strip()
    elif fwd_host:
        scheme = "https"           # 有 X-Forwarded-Host 基本就是过了反代
    else:
        scheme = request.url.scheme
    return f"{scheme}://{host}".rstrip("/")


def _base_url(request: Request) -> str:
    """对外声明的自身地址（issuer / resource / metadata 都用它）。

    设了 MCP_PUBLIC_BASE 就钉死 —— 令牌里的 resource 和 issuer 一旦随 Host 头漂移，
    客户端按 issuer 缓存元数据，换一次入口就是一轮莫名其妙的重新授权。
    """
    return PUBLIC_BASE or _request_base(request)


def _client_ip(request: Request) -> str:
    """真实来源 IP。只有 Caddy 能连到本端口，X-Forwarded-For 可信。"""
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _lock_remaining(ip: str) -> int:
    rec = _failures.get(ip)
    if not rec:
        return 0
    until = int(rec.get("until", 0))
    if until <= _now():
        # 只有「锁定已过期」才清记录。
        # until == 0 表示还在累积失败次数，这里必须留着 ——
        # 顺手 pop 掉会让计数永远凑不满 MAX_AUTH_FAILURES。
        if until:
            _failures.pop(ip, None)
        return 0
    return until - _now()


def _note_failure(ip: str) -> None:
    rec = _failures.setdefault(ip, {"count": 0, "until": 0})
    rec["count"] = int(rec.get("count", 0)) + 1
    if rec["count"] >= MAX_AUTH_FAILURES:
        # 递增锁定时长，封顶 1 小时，专治反复来撞的。
        rec["streak"] = int(rec.get("streak", 0)) + 1
        wait = min(LOCKOUT_SECONDS * rec["streak"], 3600)
        rec["until"] = _now() + wait
        rec["count"] = 0
    if len(_failures) > 4096:        # 防御性上限
        for key in [k for k, v in _failures.items() if v.get("until", 0) <= _now()]:
            _failures.pop(key, None)


def _clear_failures(ip: str) -> None:
    _failures.pop(ip, None)


def _token_key(token: str) -> str:
    """令牌在磁盘上的存储键。只存哈希：tokens.json 泄露 ≠ 通道泄露。"""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _verify_password(candidate: str) -> bool:
    rec = _load(PASSWORD_FILE)
    salt = rec.get("salt")
    expect = rec.get("hash")
    if not salt or not expect:
        return False
    # 参数从记录里读，这样以后抬 scrypt 强度不会把老密码作废。
    try:
        n = int(rec.get("n", SCRYPT_LEGACY_N))
        r = int(rec.get("r", SCRYPT_R))
        p = int(rec.get("p", SCRYPT_P))
        got = hashlib.scrypt(
            candidate.encode("utf-8"), salt=base64.b64decode(salt),
            n=n, r=r, p=p, dklen=32, maxmem=SCRYPT_MAXMEM,
        )
    except Exception:
        return False
    return hmac.compare_digest(base64.b64encode(got).decode(), expect)


_VERIFIER_OK = set(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)


def _pkce_ok(verifier: str, challenge: str) -> bool:
    # RFC 7636: code_verifier 是 43~128 个 unreserved ASCII 字符。
    # 不合规的一律判失败 —— 不能让非 ASCII 冒到 encode() 那里抛 500。
    if not (43 <= len(verifier) <= 128):
        return False
    if not set(verifier) <= _VERIFIER_OK:
        return False
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    calculated = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return hmac.compare_digest(calculated, challenge)


def _bearer(request: Request) -> Optional[str]:
    raw = request.headers.get("authorization", "")
    if raw.lower().startswith("bearer "):
        return raw[7:].strip()
    return None


def _loopback(host: str) -> bool:
    return host in ("127.0.0.1", "::1", "localhost")


def _redirect_uri_ok(uri: str) -> Tuple[bool, str]:
    """https 必收；http 只放行 loopback（原生客户端的本地回调）。"""
    if not uri or len(uri) > 512:
        return False, "redirect_uri 为空或过长"
    parsed = urlparse(uri)
    if not parsed.netloc:
        return False, f"不接受的 redirect_uri: {uri}"
    if parsed.scheme == "https":
        return True, ""
    if parsed.scheme == "http" and _loopback((parsed.hostname or "").lower()):
        return True, ""
    return False, f"不接受的 redirect_uri: {uri}"


def _register_allowed(ip: str) -> Tuple[bool, str]:
    """动态注册闸门：没人该在一小时内注册几十个 MCP 客户端。"""
    now = _now()
    hits = [t for t in _registrations.get(ip, []) if t > now - REGISTER_WINDOW]
    if len(hits) >= REGISTER_MAX_PER_WINDOW:
        _registrations[ip] = hits
        return False, "注册过于频繁，请稍后再试"
    hits.append(now)
    _registrations[ip] = hits
    if len(_registrations) > 4096:
        for key in [k for k, v in _registrations.items()
                    if not any(t > now - REGISTER_WINDOW for t in v)]:
            _registrations.pop(key, None)
    return True, ""


# ---------------------------------------------------------------- 安全响应头

class SecurityHeaders:
    """纯 ASGI 中间件 —— 不改缓冲、不碰流式响应，只往 response.start 里补头。

    用 BaseHTTPMiddleware 会把 SSE 流包坏，所以这里手动写一层。
    """

    def __init__(self, app, headers: Dict[str, str]):
        self.app = app
        self.headers = [(k.lower().encode("latin-1"), v.encode("latin-1"))
                        for k, v in headers.items()]

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                headers = message.setdefault("headers", [])
                present = {k for k, _ in headers}
                for key, value in self.headers:
                    if key not in present:
                        headers.append((key, value))
            await send(message)

        await self.app(scope, receive, send_wrapper)


_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    # 密码页没有 frame 保护的话可以被套进 iframe 做点击劫持 ——
    # 而那个密码框还是 autofocus，等于替攻击者聚焦好了。
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "frame-ancestors 'none'",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


# ---------------------------------------------------------------- 发现端点

async def protected_resource(request: Request) -> JSONResponse:
    base = _base_url(request)
    return JSONResponse({
        "resource": f"{base}/mcp",
        "authorization_servers": [base],
        "bearer_methods_supported": ["header"],
        "scopes_supported": ["mcp"],
    })


async def authorization_server(request: Request) -> JSONResponse:
    base = _base_url(request)
    return JSONResponse({
        "issuer": base,
        "authorization_endpoint": f"{base}/oauth/authorize",
        "token_endpoint": f"{base}/oauth/token",
        "registration_endpoint": f"{base}/oauth/register",
        "revocation_endpoint": f"{base}/oauth/revoke",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "revocation_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": ["mcp"],
    })


# ---------------------------------------------------------------- 动态注册

async def register(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid_client_metadata"}, status_code=400)

    if not isinstance(body, dict):
        return JSONResponse({"error": "invalid_client_metadata"}, status_code=400)

    redirect_uris = body.get("redirect_uris")
    if not isinstance(redirect_uris, list) or not redirect_uris:
        return JSONResponse(
            {"error": "invalid_redirect_uri",
             "error_description": "redirect_uris 必须是非空数组"},
            status_code=400,
        )
    if len(redirect_uris) > 10:
        return JSONResponse(
            {"error": "invalid_redirect_uri",
             "error_description": "redirect_uris 最多 10 个"},
            status_code=400,
        )
    for uri in redirect_uris:
        ok, why = _redirect_uri_ok(str(uri))
        if not ok:
            return JSONResponse(
                {"error": "invalid_redirect_uri", "error_description": why},
                status_code=400,
            )

    ip = _client_ip(request)
    allowed, why = _register_allowed(ip)
    if not allowed:
        return JSONResponse(
            {"error": "temporarily_unavailable", "error_description": why},
            status_code=429,
        )

    client_id = secrets.token_urlsafe(24)
    async with _state_lock:
        clients = _load(CLIENTS_FILE)
        if len(clients) >= REGISTER_MAX_CLIENTS:
            return JSONResponse(
                {"error": "temporarily_unavailable",
                 "error_description": f"客户端数量已达上限 {REGISTER_MAX_CLIENTS}，"
                                      "请先在管理页移除不用的设备"},
                status_code=429,
            )
        clients[client_id] = {
            "client_id": client_id,
            "client_name": str(body.get("client_name", "MCP Client"))[:120],
            "redirect_uris": [str(u) for u in redirect_uris],
            "created_at": _now(),
        }
        _save(CLIENTS_FILE, clients)

    return JSONResponse({
        "client_id": client_id,
        "client_name": clients[client_id]["client_name"],
        "redirect_uris": clients[client_id]["redirect_uris"],
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
    }, status_code=201)


# ---------------------------------------------------------------- 授权

_FORM = """<!doctype html><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>授权 MCP 访问</title>
<style>
 body{{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;background:#0f1115;
      color:#e6e6e6;display:flex;min-height:100vh;align-items:center;
      justify-content:center;margin:0;padding:1rem}}
 .card{{background:#171a21;border:1px solid #262b36;border-radius:14px;
        padding:1.75rem;max-width:26rem;width:100%}}
 h1{{font-size:1.1rem;margin:0 0 .35rem}}
 p{{color:#9aa4b2;font-size:.85rem;line-height:1.5;margin:0 0 1.1rem}}
 code{{color:#7cc4ff;word-break:break-all}}
 input{{width:100%;box-sizing:border-box;padding:.7rem;border-radius:8px;
        border:1px solid #2c3341;background:#0f1115;color:#e6e6e6;font-size:1rem}}
 button{{width:100%;margin-top:.9rem;padding:.7rem;border:0;border-radius:8px;
         background:#3b82f6;color:#fff;font-size:1rem;cursor:pointer}}
 .err{{color:#ff8a8a;font-size:.85rem;margin:.7rem 0 0}}
</style>
<div class="card">
  <h1>授权访问</h1>
  <p><code>{client}</code> 请求连接到你的 MCP 跳板机。<br>
     授权后它可以在配置的目标机器上执行命令。</p>
  <form method="post">
    {hidden}
    <input type="password" name="password" placeholder="访问密码"
           autofocus autocomplete="current-password">
    <button type="submit">授权</button>
    {error}
  </form>
</div>"""


def _render_form(params: Dict[str, str], client_name: str, error: str = "") -> HTMLResponse:
    hidden = "".join(
        f'<input type="hidden" name="{k}" value="{_esc(v)}">'
        for k, v in params.items()
    )
    err = f'<p class="err">{_esc(error)}</p>' if error else ""
    html = _FORM.format(client=_esc(client_name), hidden=hidden, error=err)
    return HTMLResponse(html, status_code=200 if not error else 401)


def _esc(text: str) -> str:
    return (str(text).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


async def authorize(request: Request) -> Response:
    if request.method == "GET":
        params = dict(request.query_params)
    else:
        form = await request.form()
        params = {k: str(v) for k, v in form.items()}

    client_id = params.get("client_id", "")
    redirect_uri = params.get("redirect_uri", "")
    challenge = params.get("code_challenge", "")
    method = params.get("code_challenge_method", "")
    state = params.get("state", "")

    clients = _load(CLIENTS_FILE)
    client = clients.get(client_id)
    if not client:
        return JSONResponse({"error": "invalid_client"}, status_code=400)
    if redirect_uri not in client["redirect_uris"]:
        return JSONResponse({"error": "invalid_redirect_uri"}, status_code=400)
    if method != "S256" or not challenge:
        return JSONResponse(
            {"error": "invalid_request",
             "error_description": "必须使用 PKCE S256"},
            status_code=400,
        )

    carry = {k: params.get(k, "") for k in
             ("client_id", "redirect_uri", "code_challenge",
              "code_challenge_method", "state", "scope")}

    if request.method == "GET":
        return _render_form(carry, client["client_name"])

    # POST：校验密码
    now = _now()
    ip = _client_ip(request)
    wait = _lock_remaining(ip)
    if wait:
        return _render_form(carry, client["client_name"],
                            f"尝试过多，请 {wait} 秒后再试")

    if not _verify_password(params.get("password", "")):
        _note_failure(ip)
        return _render_form(carry, client["client_name"], "密码不对")

    _clear_failures(ip)
    code = secrets.token_urlsafe(32)
    _codes[code] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": challenge,
        "expires": now + CODE_TTL,
    }
    query = {"code": code}
    if state:
        query["state"] = state
    sep = "&" if urlparse(redirect_uri).query else "?"
    return RedirectResponse(f"{redirect_uri}{sep}{urlencode(query)}", status_code=302)


# ---------------------------------------------------------------- 换令牌

def _token_response(payload: Dict[str, Any], status_code: int = 200) -> JSONResponse:
    # RFC 6749 §5.1：令牌响应必须不可缓存。
    return JSONResponse(payload, status_code=status_code,
                        headers={"Cache-Control": "no-store", "Pragma": "no-cache"})


async def _issue(client_id: str, resource: str) -> Dict[str, Any]:
    """签发一对新令牌。对 tokens.json 的读-改-写全在锁里，避免并发丢更新。"""
    access = secrets.token_urlsafe(32)
    refresh = secrets.token_urlsafe(32)
    now = _now()
    async with _state_lock:
        store = _load(TOKENS_FILE)
        _purge_expired(store)
        # 磁盘上只留哈希 —— 令牌原文只在响应里出现一次。
        store.setdefault("access_tokens", {})[_token_key(access)] = {
            "client_id": client_id, "expires": now + ACCESS_TTL, "resource": resource,
        }
        store.setdefault("refresh_tokens", {})[_token_key(refresh)] = {
            "client_id": client_id, "expires": now + REFRESH_TTL, "resource": resource,
        }
        _save(TOKENS_FILE, store)
    return {
        "access_token": access,
        "token_type": "Bearer",
        "expires_in": ACCESS_TTL,
        "refresh_token": refresh,
        "scope": "mcp",
    }


async def token(request: Request) -> JSONResponse:
    form = await request.form()
    grant = str(form.get("grant_type", ""))
    client_id = str(form.get("client_id", ""))
    base = _base_url(request)

    if grant == "authorization_code":
        code = str(form.get("code", ""))
        verifier = str(form.get("code_verifier", ""))
        record = _codes.pop(code, None)
        if not record or record["expires"] <= _now():
            return _token_response({"error": "invalid_grant"}, 400)
        if record["client_id"] != client_id:
            return _token_response({"error": "invalid_grant"}, 400)
        if str(form.get("redirect_uri", "")) != record["redirect_uri"]:
            return _token_response({"error": "invalid_grant"}, 400)
        if not verifier or not _pkce_ok(verifier, record["code_challenge"]):
            return _token_response(
                {"error": "invalid_grant",
                 "error_description": "PKCE 校验失败"}, 400)
        return _token_response(await _issue(client_id, f"{base}/mcp"))

    if grant == "refresh_token":
        presented = str(form.get("refresh_token", ""))
        key = _token_key(presented)
        now = _now()

        async with _state_lock:
            store = _load(TOKENS_FILE)
            _purge_expired(store)
            section = store.setdefault("refresh_tokens", {})
            record = section.get(key)

            if not record or record.get("expires", 0) <= now:
                _save(TOKENS_FILE, store)
                return _token_response({"error": "invalid_grant"}, 400)

            rotated_at = record.get("rotated_at")
            if rotated_at and now - rotated_at > REFRESH_GRACE:
                # 宽限窗口过了，这条旧令牌彻底作废
                section.pop(key, None)
                _save(TOKENS_FILE, store)
                return _token_response({"error": "invalid_grant"}, 400)

            # 一次性轮换 + 60 秒宽限：
            # 上一次轮换的响应要是在回程丢了，客户端手里只剩一条已消费的旧令牌，
            # 没有宽限就只能被逼回授权页。窗口内重放就再发一对新的。
            record["rotated_at"] = now
            record["expires"] = now + REFRESH_GRACE
            _save(TOKENS_FILE, store)
            client_id = record["client_id"]
            resource = record.get("resource") or f"{base}/mcp"

        return _token_response(await _issue(client_id, resource))

    return _token_response({"error": "unsupported_grant_type"}, 400)


# ---------------------------------------------------------------- 撤销 (RFC 7009)

async def revoke(request: Request) -> JSONResponse:
    """客户端侧断开连接时用来主动作废令牌。

    RFC 7009 要求：无论令牌存不存在、是否有效，都返回 200 ——
    不能让这个端点变成「这个令牌有效吗」的探测口。
    """
    form = await request.form()
    presented = str(form.get("token", ""))
    hint = str(form.get("token_type_hint", ""))
    client_id = str(form.get("client_id", ""))

    if not presented:
        return JSONResponse({}, status_code=200)

    key = _token_key(presented)
    buckets = ["refresh_tokens", "access_tokens"]
    if hint == "access_token":
        buckets.reverse()

    async with _state_lock:
        store = _load(TOKENS_FILE)
        changed = False
        for bucket in buckets:
            record = (store.get(bucket) or {}).get(key)
            if not record:
                continue
            # 传了 client_id 就必须对上，免得一个客户端撤掉别人的令牌。
            if client_id and record.get("client_id") != client_id:
                continue
            store[bucket].pop(key, None)
            changed = True
        if changed:
            _save(TOKENS_FILE, store)

    return JSONResponse({}, status_code=200)


# ---------------------------------------------------------------- 反代 /mcp

_HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "host", "content-length",
}


def _unauthorized(request: Request) -> JSONResponse:
    """401 必须带 WWW-Authenticate 指回资源元数据，客户端靠它发现授权服务器。"""
    base = _base_url(request)
    return JSONResponse(
        {"error": "unauthorized"},
        status_code=401,
        headers={
            "WWW-Authenticate":
                f'Bearer realm="mcp", '
                f'resource_metadata="{base}/.well-known/oauth-protected-resource"'
        },
    )


# ── 给模型的环境提示 ───────────────────────────────────────────────
# 上游 mcp-ssh-manager 不提供 instructions 字段, 所以在这里补。
# 走代理注入而不是改 npm 包 —— 包一更新补丁就没了, 这里不会。
# 克制原则: 只写"不写就一定会被误判"的事, 别当说明书。
# 每台机器的特殊性不同(手机版曾硬编码 MTK loadavg 虚高的提示),
# 所以改为环境变量 MCP_SERVER_INSTRUCTIONS 注入, 默认不注入。
_SERVER_INSTRUCTIONS = os.environ.get("MCP_SERVER_INSTRUCTIONS", "").strip()


def _inject_instructions(payload):
    """把提示合并进 initialize 的 result.instructions, 不覆盖上游已有内容。"""
    result = payload.get("result")
    if not isinstance(result, dict):
        return payload
    if not _SERVER_INSTRUCTIONS:
        return payload
    existing = result.get("instructions") or ""
    if _SERVER_INSTRUCTIONS not in existing:
        result["instructions"] = (existing + "\n\n" + _SERVER_INSTRUCTIONS).strip()
    return payload


def _rewrite_init_body(raw: str) -> str:
    """响应可能是纯 JSON, 也可能是 SSE(data: 开头)。两种都要认。"""
    stripped = raw.lstrip()
    if stripped.startswith("{"):
        try:
            return json.dumps(_inject_instructions(json.loads(raw)))
        except Exception:
            return raw
    out = []
    for line in raw.splitlines(keepends=True):
        if line.startswith("data: "):
            payload, nl = line[6:].rstrip("\r\n"), line[len(line.rstrip("\r\n")):]
            try:
                line = "data: " + json.dumps(_inject_instructions(json.loads(payload))) + nl
            except Exception:
                pass
        out.append(line)
    return "".join(out)


async def mcp_proxy(request: Request) -> Response:
    presented = _bearer(request)
    if not presented:
        return _unauthorized(request)
    store = _load(TOKENS_FILE)
    record = (store.get("access_tokens") or {}).get(_token_key(presented))
    if not record or record.get("expires", 0) <= _now():
        return _unauthorized(request)
    # 令牌绑定到具体资源：以后再加 /browser 之类的第二个上游时，
    # shell 的令牌不能拿去开浏览器。现在只有一个上游，这一步是恒等的。
    bound = record.get("resource")
    if bound and bound != f"{_base_url(request)}/mcp":
        return _unauthorized(request)

    upstream_headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in _HOP_BY_HOP and k.lower() != "authorization"
    }
    body = await request.body()

    client = httpx.AsyncClient(timeout=httpx.Timeout(None, connect=10.0))
    req = client.build_request(
        request.method, UPSTREAM, headers=upstream_headers,
        content=body, params=dict(request.query_params),
    )
    # initialize 要改写响应, 所以这一发不能流式 —— 它很小, 缓冲无所谓。
    is_init = False
    try:
        is_init = json.loads(body).get("method") == "initialize"
    except Exception:
        pass

    if is_init:
        upstream = await client.send(req)
        try:
            text = _rewrite_init_body(upstream.text)
        finally:
            await client.aclose()
        headers = {
            k: v for k, v in upstream.headers.items()
            if k.lower() not in _HOP_BY_HOP and k.lower() != "content-length"
        }
        return Response(
            text, status_code=upstream.status_code, headers=headers,
            media_type=upstream.headers.get("content-type"),
        )

    upstream = await client.send(req, stream=True)

    async def relay():
        try:
            async for chunk in upstream.aiter_raw():
                yield chunk
        finally:
            await upstream.aclose()
            await client.aclose()

    passthrough = {
        k: v for k, v in upstream.headers.items()
        if k.lower() not in _HOP_BY_HOP
    }
    return StreamingResponse(
        relay(), status_code=upstream.status_code,
        headers=passthrough,
        media_type=upstream.headers.get("content-type"),
    )


# ---------------------------------------------------------------- 管理页

# 管理会话只放内存: 重启即全部失效, 这正是想要的行为。
# 不用把密码塞进隐藏表单域 —— 那样它会明晃晃留在 DOM 和浏览器历史里。
_ADMIN_SESSIONS: Dict[str, int] = {}          # token -> 过期时间
_ADMIN_TTL = 1800                             # 30 分钟


def _admin_authed(request: Request) -> bool:
    tok = request.cookies.get("mcp_admin")
    if not tok:
        return False
    exp = _ADMIN_SESSIONS.get(tok, 0)
    if exp <= _now():
        _ADMIN_SESSIONS.pop(tok, None)
        return False
    return True


_ADMIN_LOGIN = """<!doctype html><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MCP 跳板机 · 管理</title>
<style>
 body{{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;background:#0f1115;
      color:#e6e6e6;display:flex;min-height:100vh;align-items:center;
      justify-content:center;margin:0;padding:1rem}}
 .card{{background:#171a21;border:1px solid #262b36;border-radius:14px;
        padding:1.75rem;max-width:24rem;width:100%}}
 h1{{font-size:1.1rem;margin:0 0 1.1rem}}
 input{{width:100%;box-sizing:border-box;padding:.7rem;border-radius:8px;
        border:1px solid #2c3341;background:#0f1115;color:#e6e6e6;font-size:1rem}}
 button{{width:100%;margin-top:.9rem;padding:.7rem;border:0;border-radius:8px;
         background:#3b82f6;color:#fff;font-size:1rem;cursor:pointer}}
 .err{{color:#ff8a8a;font-size:.85rem;margin:.7rem 0 0}}
</style>
<div class="card">
  <h1>管理已连接的设备</h1>
  <form method="post">
    <input type="hidden" name="action" value="login">
    <input type="password" name="password" placeholder="访问密码"
           autofocus autocomplete="current-password">
    <button type="submit">进入</button>
    {error}
  </form>
</div>"""

_ADMIN_PAGE = """<!doctype html><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MCP 跳板机 · 管理</title>
<style>
 body{{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;background:#0f1115;
      color:#e6e6e6;margin:0;padding:1.5rem;display:flex;justify-content:center}}
 .wrap{{width:100%;max-width:44rem}}
 h1{{font-size:1.15rem;margin:0 0 .3rem}}
 .sub{{color:#9aa4b2;font-size:.82rem;margin:0 0 1.4rem}}
 .card{{background:#171a21;border:1px solid #262b36;border-radius:14px;
        padding:1.25rem 1.4rem;margin-bottom:1rem}}
 table{{width:100%;border-collapse:collapse;font-size:.88rem}}
 th{{text-align:left;color:#9aa4b2;font-weight:500;font-size:.78rem;
     padding:0 .6rem .55rem 0;border-bottom:1px solid #262b36}}
 td{{padding:.65rem .6rem .65rem 0;border-bottom:1px solid #1e222b;
     vertical-align:middle}}
 tr:last-child td{{border-bottom:0}}
 .name{{font-weight:500}}
 .muted{{color:#6b7482;font-size:.78rem}}
 .live{{color:#4ade80}}
 .dead{{color:#6b7482}}
 button{{padding:.4rem .8rem;border:1px solid #3a2c30;border-radius:7px;
         background:#241a1d;color:#ff9b9b;font-size:.8rem;cursor:pointer}}
 button:hover{{background:#2e2023}}
 .danger{{width:100%;margin-top:.4rem;padding:.65rem;border:1px solid #3a2c30;
          background:#241a1d;color:#ff9b9b}}
 form.inline{{display:inline;margin:0}}
 .empty{{color:#6b7482;font-size:.85rem;padding:.6rem 0}}
 .note{{color:#6b7482;font-size:.78rem;line-height:1.6;margin:.5rem 0 0}}
 a{{color:#7cc4ff;font-size:.82rem;text-decoration:none}}
 .flash{{background:#132b1c;border:1px solid #1f4a30;color:#86efac;
         border-radius:9px;padding:.6rem .9rem;font-size:.85rem;margin-bottom:1rem}}
</style>
<div class="wrap">
  <h1>MCP 跳板机</h1>
  <p class="sub">{host}</p>
  {flash}
  <div class="card">
    <table>
      <tr><th>设备</th><th>授权于</th><th>令牌</th><th></th></tr>
      {rows}
    </table>
    {empty}
  </div>
  <div class="card">
    <h2 style="font-size:.82rem;color:#9aa4b2;font-weight:500;margin:0 0 .8rem">
      目标机器 <span style="color:#6b7482">· 只读, 改这里:
      <code style="color:#7cc4ff">/etc/mcp-ssh/ssh-config.toml</code></span>
    </h2>
    {targets}
    <p class="note">保存即生效, 不用重启 —— mcp-ssh-manager 每次调用都会
       比对文件签名, 变了自动重载。</p>
  </div>
  <div class="card">
    <form method="post" onsubmit="return confirm('所有设备都要重新授权, 确定?')">
      <input type="hidden" name="action" value="revoke_all">
      <button class="danger" type="submit">吊销全部令牌</button>
    </form>
    <p class="note">
      吊销后设备下次请求会收到 401, 走一遍授权页输密码即可恢复, 不用重新添加。<br>
      改密码要在手机上跑: <code>mcp_oauth_gateway.py --set-password</code>, 然后重启 18011。
    </p>
  </div>
  <form method="post" class="inline">
    <input type="hidden" name="action" value="logout">
    <a href="#" onclick="this.parentNode.submit();return false">退出管理</a>
  </form>
</div>"""


# 目标机器这张卡是只读的，故意的。能编辑它的人本来就能通过 MCP 拿到
# 一个 root shell（self 目标），再在网页上造一遍增删改，是把同一件事
# 实现两次。这里只解决唯一真的不方便的部分：看不见自己有哪些目标。
TARGETS_FILE = Path(os.environ.get("MCP_SSH_CONFIG", "/etc/mcp-ssh/ssh-config.toml"))


def _render_targets() -> str:
    try:
        data = tomllib.loads(TARGETS_FILE.read_text("utf-8"))
    except FileNotFoundError:
        return '<p class="empty">没有找到 %s。</p>' % _esc(str(TARGETS_FILE))
    except Exception as exc:
        # 配置写坏了要说出来 —— 这时候 MCP 那边多半也已经在报错了。
        return '<p class="empty" style="color:#ff9b9b">读不了 %s: %s</p>' % (
            _esc(str(TARGETS_FILE)), _esc(exc))

    servers = data.get("ssh_servers") or {}
    if not servers:
        return '<p class="empty">还没有配置任何目标机器。</p>'

    rows = []
    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        # 认密码的目标要标出来: 明文密码躺在配置文件里, 值得看一眼就知道。
        if cfg.get("password"):
            auth = '<span style="color:#fbbf24">密码</span>'
        elif cfg.get("key_path"):
            auth = "密钥"
        else:
            auth = '<span class="dead">未指定</span>'
        rows.append(
            '<tr><td class="name">{name}</td>'
            '<td class="muted">{user}@{host}:{port}</td>'
            '<td>{auth}</td><td class="muted">{desc}</td></tr>'.format(
                name=_esc(name),
                user=_esc(cfg.get("user") or "?"),
                host=_esc(cfg.get("host") or "?"),
                port=_esc(cfg.get("port") or 22),
                auth=auth,
                desc=_esc(cfg.get("description") or ""),
            )
        )
    return ('<table><tr><th>名称</th><th>地址</th><th>认证</th><th></th></tr>'
            + "".join(rows) + "</table>")


def _admin_render(request: Request, flash: str = "") -> HTMLResponse:
    store = _load(TOKENS_FILE)
    _purge_expired(store)
    access = store.get("access_tokens") or {}
    raw = _load(CLIENTS_FILE)
    clients = raw.get("clients", raw)

    rows = []
    for cid, meta in sorted(
        clients.items(), key=lambda kv: kv[1].get("created_at", 0), reverse=True
    ):
        n = sum(1 for r in access.values() if r.get("client_id") == cid)
        created = meta.get("created_at")
        when = (time.strftime("%m-%d %H:%M", time.localtime(created))
                if created else "—")
        state = ('<span class="live">%d 个有效</span>' % n if n
                 else '<span class="dead">无</span>')
        rows.append(
            '<tr><td class="name">{name}</td>'
            '<td class="muted">{when}</td><td>{state}</td>'
            '<td style="text-align:right"><form method="post" class="inline">'
            '<input type="hidden" name="action" value="revoke">'
            '<input type="hidden" name="client_id" value="{cid}">'
            '<button type="submit">移除</button></form></td></tr>'.format(
                name=_esc(meta.get("client_name") or "(未命名)"),
                when=when, state=state, cid=_esc(cid))
        )

    html = _ADMIN_PAGE.format(
        host=_esc(_base_url(request)),
        flash=('<div class="flash">%s</div>' % _esc(flash)) if flash else "",
        rows="".join(rows),
        empty='<p class="empty">还没有设备连进来。</p>' if not rows else "",
        targets=_render_targets(),
    )
    return HTMLResponse(html)


async def admin(request: Request) -> Response:
    if request.method == "GET":
        if _admin_authed(request):
            return _admin_render(request)
        return HTMLResponse(_ADMIN_LOGIN.format(error=""))

    form = await request.form()
    action = form.get("action") or ""

    if action == "login":
        # 和授权页共用一套按 IP 的失败计数, 免得管理页成了爆破密码的旁路。
        ip = _client_ip(request)
        wait = _lock_remaining(ip)
        if wait:
            return HTMLResponse(
                _ADMIN_LOGIN.format(
                    error='<p class="err">失败次数过多, 请稍后再试。</p>'),
                status_code=429)
        if not _verify_password(str(form.get("password") or "")):
            _note_failure(ip)
            return HTMLResponse(
                _ADMIN_LOGIN.format(error='<p class="err">密码不对。</p>'),
                status_code=401)
        _clear_failures(ip)
        tok = secrets.token_urlsafe(32)
        _ADMIN_SESSIONS[tok] = _now() + _ADMIN_TTL
        resp = RedirectResponse("/admin", status_code=303)
        resp.set_cookie("mcp_admin", tok, max_age=_ADMIN_TTL, httponly=True,
                        samesite="lax", secure=_base_url(request).startswith("https"))
        return resp

    if not _admin_authed(request):
        return RedirectResponse("/admin", status_code=303)

    if action == "logout":
        _ADMIN_SESSIONS.pop(request.cookies.get("mcp_admin", ""), None)
        resp = RedirectResponse("/admin", status_code=303)
        resp.delete_cookie("mcp_admin")
        return resp

    flash = ""

    if action == "revoke":
        cid = str(form.get("client_id") or "")
        async with _state_lock:
            store = _load(TOKENS_FILE)
            raw = _load(CLIENTS_FILE)
            clients = raw.get("clients", raw)
            name = (clients.get(cid) or {}).get("client_name") or cid[:12]
            removed = 0
            for bucket in ("access_tokens", "refresh_tokens"):
                section = store.get(bucket) or {}
                for key in [k for k, v in section.items() if v.get("client_id") == cid]:
                    section.pop(key, None)
                    removed += 1
            clients.pop(cid, None)
            _save(CLIENTS_FILE, raw)
            _save(TOKENS_FILE, store)
        flash = "已移除 %s, 连带清掉 %d 个令牌。" % (name, removed)

    elif action == "revoke_all":
        async with _state_lock:
            store = _load(TOKENS_FILE)
            n = (len(store.get("access_tokens") or {})
                 + len(store.get("refresh_tokens") or {}))
            store["access_tokens"] = {}
            store["refresh_tokens"] = {}
            _save(TOKENS_FILE, store)
        flash = "已吊销全部 %d 个令牌, 设备记录保留。" % n

    return _admin_render(request, flash)


async def healthz(_: Request) -> Response:
    return Response("ok", media_type="text/plain")


routes = [
    Route("/.well-known/oauth-protected-resource", protected_resource),
    Route("/.well-known/oauth-protected-resource/mcp", protected_resource),
    Route("/.well-known/oauth-authorization-server", authorization_server),
    Route("/.well-known/oauth-authorization-server/mcp", authorization_server),
    Route("/oauth/register", register, methods=["POST"]),
    Route("/oauth/authorize", authorize, methods=["GET", "POST"]),
    Route("/oauth/token", token, methods=["POST"]),
    Route("/oauth/revoke", revoke, methods=["POST"]),
    Route("/mcp", mcp_proxy, methods=["GET", "POST", "DELETE"]),
    Route("/admin", admin, methods=["GET", "POST"]),
    Route("/healthz", healthz),
]

app = SecurityHeaders(Starlette(routes=routes), _SECURITY_HEADERS)


def _set_password(plain: str, write_hint: bool = True) -> None:
    """存 scrypt 哈希。明文只写到 root 的便利文件里（可选）。"""
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(plain.encode("utf-8"), salt=salt,
                            n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=32,
                            maxmem=SCRYPT_MAXMEM)
    _save(PASSWORD_FILE, {
        "salt": base64.b64encode(salt).decode(),
        "hash": base64.b64encode(digest).decode(),
        # 参数一并存下来，以后抬强度不会把现有密码作废。
        "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P,
        "updated_at": _now(),
    })
    if write_hint and PASSWORD_HINT_FILE is not None:
        try:
            PASSWORD_HINT_FILE.write_text(plain + "\n", "utf-8")
            os.chmod(PASSWORD_HINT_FILE, 0o600)
        except Exception as exc:            # 便利文件写不了不该让设密码失败
            print(f"警告: 明文便利文件没写成 ({exc})")


if __name__ == "__main__":
    import sys

    def _hint_note() -> str:
        if PASSWORD_HINT_FILE is None:
            return "（明文便利文件已关闭）"
        return f"明文另存于 {PASSWORD_HINT_FILE}（0600，只有 root 能读）"

    if "--set-password" in sys.argv:
        idx = sys.argv.index("--set-password")
        if idx + 1 < len(sys.argv):          # 非交互：从参数取
            plain = sys.argv[idx + 1]
        else:                                 # 交互：不回显
            import getpass
            plain = getpass.getpass("新密码: ")
        _set_password(plain)
        print(f"密码已写入 {PASSWORD_FILE}（只存哈希）")
        print(_hint_note())
        raise SystemExit(0)

    if "--gen-password" in sys.argv:          # 生成一个强密码并设上
        generated = secrets.token_urlsafe(24)
        _set_password(generated)
        print(generated)
        print(_hint_note(), file=sys.stderr)
        raise SystemExit(0)

    if "--verify-password" in sys.argv:       # 自检：这个密码对不对
        idx = sys.argv.index("--verify-password")
        if idx + 1 < len(sys.argv):
            candidate = sys.argv[idx + 1]
        else:
            import getpass
            candidate = getpass.getpass("待校验的密码: ")
        print("匹配" if _verify_password(candidate) else "不匹配")
        raise SystemExit(0 if _verify_password(candidate) else 1)

    if "--show-hint" in sys.argv:             # 把便利文件里的明文读出来
        if PASSWORD_HINT_FILE is None or not PASSWORD_HINT_FILE.exists():
            raise SystemExit("没有明文便利文件。")
        print(PASSWORD_HINT_FILE.read_text("utf-8").strip())
        raise SystemExit(0)

    import uvicorn
    if not PASSWORD_FILE.exists():
        raise SystemExit(
            f"还没设密码。先跑: python3 {__file__} --set-password"
        )
    uvicorn.run(app, host="0.0.0.0", port=LISTEN_PORT, log_level="info")
