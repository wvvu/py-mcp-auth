#!/usr/bin/env python3
"""补测：SecurityHeaders 中间件不能破坏流式响应；迁移脚本必须幂等。"""
import asyncio
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

import httpx
from starlette.applications import Starlette
from starlette.responses import StreamingResponse
from starlette.routing import Route

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from mcp_oauth_gateway import SecurityHeaders, _SECURITY_HEADERS   # noqa: E402
import migrate_tokens                                              # noqa: E402

results = []


def check(name, cond, extra=""):
    results.append((name, bool(cond)))
    print(("PASS  " if cond else "FAIL  ") + name
          + (("   | " + str(extra)[:160]) if extra else ""))


async def stream_endpoint(request):
    async def gen():
        for i in range(5):
            yield f"data: chunk-{i}\n\n".encode()
            await asyncio.sleep(0)
    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache"})


async def main():
    # ---------- 中间件 + 流式 ----------
    inner = Starlette(routes=[Route("/s", stream_endpoint)])
    app = SecurityHeaders(inner, _SECURITY_HEADERS)
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.get("/s")
        body = r.text
        check("流式响应内容完整", body.count("data: chunk-") == 5, body)
        check("中间件补了 X-Frame-Options", r.headers.get("x-frame-options") == "DENY")
        check("中间件补了 nosniff", r.headers.get("x-content-type-options") == "nosniff")
        check("中间件不覆盖已有头（上游的 no-cache 保留）",
              r.headers.get("cache-control") == "no-cache", r.headers.get("cache-control"))

    # ---------- 迁移脚本 ----------
    tmp = Path(tempfile.mkdtemp(prefix="migrate-test-"))
    f = tmp / "tokens.json"
    plain_access = "PLAINTEXT-ACCESS-TOKEN-abc"
    plain_refresh = "PLAINTEXT-REFRESH-TOKEN-xyz"
    already = "a" * 64                      # 看起来已经是 sha256
    f.write_text(json.dumps({
        "access_tokens": {plain_access: {"client_id": "c1", "expires": 9999999999,
                                         "resource": "https://h/mcp"}},
        "refresh_tokens": {plain_refresh: {"client_id": "c1", "expires": 9999999999,
                                           "resource": "https://h/mcp"},
                           already: {"client_id": "c2", "expires": 9999999999}},
    }), "utf-8")

    n = migrate_tokens.migrate(str(f))
    data = json.loads(f.read_text("utf-8"))
    check("迁移了 2 个键", n == 2, n)
    check("明文 access 键没了", plain_access not in data["access_tokens"])
    check("明文 refresh 键没了", plain_refresh not in data["refresh_tokens"])
    check("access 换成了 sha256",
          hashlib.sha256(plain_access.encode()).hexdigest() in data["access_tokens"])
    check("refresh 换成了 sha256",
          hashlib.sha256(plain_refresh.encode()).hexdigest() in data["refresh_tokens"])
    check("已经是哈希的键原样保留", already in data["refresh_tokens"])
    check("元数据没丢",
          data["access_tokens"][hashlib.sha256(plain_access.encode()).hexdigest()]
          ["client_id"] == "c1")
    check("备份文件生成了", len(list(tmp.glob("*.bak"))) == 1,
          [p.name for p in tmp.glob("*.bak")])

    n2 = migrate_tokens.migrate(str(f))
    check("第二次跑是幂等的", n2 == 0, n2)

    failed = [x for x, ok in results if not ok]
    print()
    print(f"{len(results) - len(failed)}/{len(results)} passed")
    if failed:
        print("FAILED: " + "; ".join(failed))
        return 1
    return 0


sys.exit(asyncio.run(main()))
