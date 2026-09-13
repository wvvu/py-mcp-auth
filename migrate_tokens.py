#!/usr/bin/env python3
"""把 tokens.json 里的明文令牌键就地换成 sha256。

背景：老的 _issue() 直接拿 token_urlsafe(32) 的原文当字典键，于是
/etc/mcp-ssh/oauth/tokens.json 里躺着一堆可以直接用的 bearer 令牌。
这份文件一旦被顺手打进备份，等于把 root 通道一起备份了。

幂等：已经是 64 位十六进制的键原样保留，重复跑没有副作用。
改写前自动留一份 .bak。

用法:
    python3 migrate_tokens.py [/etc/mcp-ssh/oauth/tokens.json]
"""
import hashlib
import json
import os
import shutil
import sys
import time
from pathlib import Path

HEX = set("0123456789abcdef")


def is_hash(key: str) -> bool:
    return len(key) == 64 and set(key) <= HEX


def migrate(path: str) -> int:
    p = Path(path)
    data = json.loads(p.read_text("utf-8"))
    changed = 0

    for bucket in ("access_tokens", "refresh_tokens"):
        section = data.get(bucket) or {}
        out = {}
        for key, value in section.items():
            if is_hash(key):
                out[key] = value
            else:
                out[hashlib.sha256(key.encode("utf-8")).hexdigest()] = value
                changed += 1
        data[bucket] = out

    if not changed:
        return 0

    shutil.copy2(p, p.with_suffix(p.suffix + f".prehash.{int(time.time())}.bak"))
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), "utf-8")
    os.replace(tmp, p)                 # 原子替换
    os.chmod(p, 0o600)
    return changed


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "/etc/mcp-ssh/oauth/tokens.json"
    n = migrate(target)
    if n:
        print(f"{target}: {n} 个令牌键已换成 sha256（原文件已留 .bak）")
    else:
        print(f"{target}: 无需迁移（所有键都已经是哈希）")
