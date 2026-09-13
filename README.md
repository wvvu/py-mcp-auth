# py-mcp-auth

给**没有任何鉴权的 MCP HTTP 端点**套一层 OAuth 2.1。

解决的问题很具体：远端模型客户端（Claude、Grok、各类 MCP 客户端）想连你自建的 MCP
服务，但它只会走标准的 OAuth 发现流程。而你的服务要么裸奔，要么只有一道静态 token。
这个网关用「**一道密码换一对 OAuth 令牌**」把标准流程补齐，客户端那边完全无感。

典型用途：把一台机器的 shell 通道安全地开给远端模型。

## 架构

```
Claude / Grok / 任意 MCP 客户端
   │  HTTPS
   ▼
反代（Caddy / nginx，终结 TLS）
   │  127.0.0.1:18011
   ▼
mcp-oauth-gateway            ← 本项目
   │  127.0.0.1:18010（裸 HTTP，只监听本机）
   ▼
supergateway（stdio → streamableHttp）
   │  stdio
   ▼
你的 MCP 服务（例如 mcp-ssh-manager）
   │
   ▼
真正的目标
```

网关自己**不做 TLS**，也不该对公网监听。它的 systemd unit 里用
`IPAddressDeny=any` + `IPAddressAllow=localhost` 做 cgroup 级过滤 ——
因为上游 supergateway 只会绑 `0.0.0.0`，没有这层过滤，上游就等于裸奔。

## 实现要点

- **端点形状**照 RFC 9728（资源元数据）/ RFC 8414（授权服务器元数据）/
  RFC 7591（动态注册）/ RFC 7636（PKCE）/ RFC 7009（撤销）实现。
- **公开客户端**：`token_endpoint_auth_method=none`，不签发 `client_secret` ——
  MCP 客户端没有地方安全保存密钥，这是它们的通用形态。
- **强制 PKCE S256**，并严格按 RFC 7636 校验 `code_verifier` 的长度与字符集。
- **授权环节就一道密码**，只比对 scrypt 哈希，明文不落盘。
- **令牌是不透明随机串，磁盘上只存 `sha256`** —— 状态文件泄露 ≠ 通道泄露。
- **刷新令牌一次性轮换**，带 60 秒复用宽限（防「轮换成功但响应丢包」把用户逼回授权页）。
- **令牌绑定到具体 `resource`** —— 同一个网关挂多个上游时，A 的令牌开不了 B。
- **失败计数按来源 IP 分桶** —— 全局计数会被任何人用来把管理员自己锁在门外。
- **纯 ASGI 中间件**补安全响应头，不碰流式响应（`BaseHTTPMiddleware` 会把 SSE 包坏）。

## 快速开始

```bash
python3 -m venv /opt/mcp-oauth/venv
/opt/mcp-oauth/venv/bin/pip install starlette uvicorn httpx python-multipart

# 设密码（会打印一个强密码，并另存一份明文到便利文件供 root 查阅）
/opt/mcp-oauth/venv/bin/python mcp_oauth_gateway.py --gen-password

# 或者自己指定
/opt/mcp-oauth/venv/bin/python mcp_oauth_gateway.py --set-password 'your-password'

# 自检
/opt/mcp-oauth/venv/bin/python mcp_oauth_gateway.py --verify-password 'your-password'
/opt/mcp-oauth/venv/bin/python mcp_oauth_gateway.py --show-hint

# 跑起来
/opt/mcp-oauth/venv/bin/python mcp_oauth_gateway.py
```

**改密码不需要重启服务** —— 密码是每次请求现读文件的。

## 端点

| 路径 | 说明 |
|---|---|
| `/.well-known/oauth-protected-resource[/mcp]` | 资源元数据（RFC 9728） |
| `/.well-known/oauth-authorization-server[/mcp]` | 授权服务器元数据（RFC 8414） |
| `POST /oauth/register` | 动态客户端注册（RFC 7591），带每 IP 限速与总量上限 |
| `GET/POST /oauth/authorize` | 密码页 → 签发授权码（仅内存，5 分钟） |
| `POST /oauth/token` | `authorization_code` / `refresh_token` |
| `POST /oauth/revoke` | 撤销（RFC 7009，恒返回 200） |
| `ANY /mcp` | 受保护的代理，SSE 原样透传 |
| `GET/POST /admin` | 管理页：看设备、移除设备、吊销全部令牌 |
| `GET /healthz` | 健康检查 |

未授权访问 `/mcp` 会返回带 `WWW-Authenticate` 的 401，客户端靠它发现授权服务器。

## 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `MCP_UPSTREAM` | `http://127.0.0.1:18010/mcp` | 被保护的上游 |
| `MCP_OAUTH_STATE` | `/etc/mcp-ssh/oauth` | 状态目录（clients/tokens/password） |
| `MCP_OAUTH_PORT` | `18011` | 监听端口 |
| `MCP_PUBLIC_BASE` | 空（从请求头推导） | **建议显式设置**。issuer 和令牌的 `resource` 都取自它 |
| `MCP_OAUTH_PASSWORD_HINT` | `/root/.mcp-oauth-password` | 明文便利文件；设成空串关闭 |
| `MCP_SERVER_INSTRUCTIONS` | 空 | 注入到 `initialize` 响应的 `result.instructions` |
| `MCP_SSH_CONFIG` | `/etc/mcp-ssh/ssh-config.toml` | 管理页只读展示目标机器用 |

## 安全边界（说清楚它**不**做什么）

- 它只保护**网络入口**。上游服务本身如果还能从别处访问，那些路径不受保护。
- 一道密码 = 一份信任。如果密码等价于 root shell，**请务必加第二因素**
  （TOTP / Cloudflare Access / mTLS），并且不要和任何别处复用。
- `/oauth/register` 是开放的（动态注册的必然结果），靠限速和总量上限兜住。
  注册本身拿不到任何权限 —— 授权那一步过不了密码，注册的客户端就是废的。
- 路径/域名层面的「隐蔽」不是安全边界，只是降低噪音。见下文。

## 部署

`deploy/` 里有可直接用的模板：

- `mcp-oauth-gateway.service` — shell 通道的网关
- `mcp-oauth-browser.service` — 浏览器通道的网关（同一份代码的第二个实例）
- `mcp-ssh-supergateway.service` — 把 stdio MCP 服务转成 streamableHttp（含 `UMask=0027`）
- `playwright-mcp.service` — Playwright MCP over CDP
- `pwbrowser-watchdog.service` / `.timer` — 看门狗，浏览器被关掉自动拉回来
- `mcp-oauth-admin.fail2ban.conf` — 密码爆破封 IP
- `mcp-ssh-audit.logrotate` — 审计日志轮转
- `targets.toml.example` — 浏览器通道管理页里那张「目标」卡片的说明文件
- `Caddyfile.example` — 反代

`scripts/` 里的运行时脚本（装到 `/usr/local/bin`）：

- `pwbrowser` — 以桌面用户身份启动带 CDP 的浏览器
- `pwmcp` — 通道开关（`pwmcp-on` / `pwmcp-off` / `pwmcp-status` 软链接到它）
- `pw-mcp-serve` — systemd 调用的 Playwright MCP 启动器

装完记得 `systemctl daemon-reload`，否则 `systemctl status` 会一直报 "changed on disk"。

## 挂第二条通道：复制一份实例，别改代码

想再开一个入口（例如把浏览器自动化也暴露给模型），**最省事也最稳的做法是把这个
网关原样复制一份独立实例**，而不是改代码让它一个进程服务多个上游。

```
                    ┌─ host.example.com    ─→ 网关:18011 ─→ supergateway:18010 ─→ mcp-ssh-manager
   Caddy :443 ──────┤
                    └─ browser.example.com ─→ 网关:18013 ─→ Playwright MCP:18012 ─→ CDP:9222 ─→ 桌面浏览器
```

两个实例的差异**全部通过环境变量表达**，代码一个字都不用动：

| | shell 通道 | browser 通道 |
|---|---|---|
| `MCP_OAUTH_PORT` | 18011 | 18013 |
| `MCP_OAUTH_STATE` | `/etc/mcp-ssh/oauth` | `/etc/mcp-browser/oauth` |
| `MCP_PUBLIC_BASE` | `https://host.example.com` | `https://browser.example.com` |
| `MCP_OAUTH_PASSWORD_HINT` | `/root/.mcp-oauth-password` | `/root/.mcp-oauth-browser-password` |
| `MCP_UPSTREAM` | `:18010/mcp` | `:18012/mcp` |

收益：

- **零风险**：已经在跑的通道一行都不用改，不会因为"加个多域名支持"把现有连接搞挂。
- **真隔离**：独立状态目录 = 独立令牌库；独立密码；独立端口。哪一边的令牌泄露都跨不过去。
- **可分别演进**：两边权限面本来就不同（一边是 root shell，一边是你带登录态的浏览器），
  将来想让它们分叉（比如浏览器侧配更短的令牌 TTL）随时可以。

代价只是多占几十兆内存，以及升级时要重启两个服务。

> 令牌里的 `resource` 字段记录的是签发时的 `{base}/mcp`，代理时会校验是否与当前入口一致。
> 所以就算将来真的想合并成一个进程，只要给每个入口配一个稳定的 `MCP_PUBLIC_BASE`，
> 令牌也天然互不通用。

## 浏览器通道（Playwright MCP + CDP 接管桌面浏览器）

`scripts/` 和 `deploy/` 里带了一整套可直接用的东西。它的设计目标是：
**让模型操作你本人那个浏览器** —— 带着你的 cookie 和登录态，所以不容易撞上反爬验证码，
而且你在桌面上能实时看到模型在点什么。

```
browser.example.com
   → 网关 :18013（本项目，独立实例）
   → Playwright MCP :18012（--cdp-endpoint，不自己启动浏览器）
   → CDP :9222
   → 桌面用户自己那个 Chromium
```

### 三个脚本

| 脚本 | 作用 |
|---|---|
| `pwbrowser` | 以桌面用户身份、在他的 X 显示上启动带 CDP 端口的 Chromium，用他现有的 profile。**幂等**，可当看门狗反复调用 |
| `pwmcp` | 开关：`on` / `off` / `status` / `browser`（也有 `pwmcp-on` 等软链接） |
| `pw-mcp-serve` | 由 systemd 调用，把 Playwright MCP 转成 streamableHttp |

### 开和关的语义（重要）

```
pwmcp-on   起浏览器 + 起 MCP + 开看门狗
pwmcp-off  关看门狗 + 停 MCP + 关浏览器
```

**`off` 会把浏览器也关掉** —— 想彻底停就敲它，别只关浏览器窗口。

为什么需要看门狗（`pwbrowser-watchdog.timer`）：模型是靠 `--cdp-endpoint` 连
`127.0.0.1:9222` 的。只要浏览器不在（哪怕只是被手动关了窗口），模型就报
`connect ECONNREFUSED 127.0.0.1:9222`；而此时 supergateway 和网关都是好的，
从外面完全看不出问题出在哪。看门狗每分钟跑一次幂等的 `pwbrowser`，
浏览器被关掉会自动拉回来（实测 ~60 秒内恢复）。

看门狗由 `pwmcp-on` 启用、`pwmcp-off` 停用，**不要手动 enable** ——
否则你想彻底关掉的时候浏览器会被一直拉起来。

### 两个必须知道的坑

**1. snap 应用不能由 root 直接 fork。**
用 `runuser` 启动 snap 包会被 snap-confine 拒绝：

```
/user.slice/user-0.slice/session-907.scope is not a snap cgroup for tag snap.chromium.chromium
```

必须经由**用户自己的 systemd** 启动（也就是桌面应用正常走的那条路）：

```bash
runuser -u <user> -- env XDG_RUNTIME_DIR=/run/user/<uid> \
    DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/<uid>/bus \
    systemd-run --user --collect --unit=pwbrowser \
        --setenv=DISPLAY=:10 --setenv=XAUTHORITY=/home/<user>/.Xauthority \
        /snap/bin/chromium --remote-debugging-port=9222 \
        --user-data-dir=/home/<user>/snap/chromium/common/chromium
```

`pwbrowser` 已经把这套封好了。另外**必须用目标用户身份跑**，
否则 root 会在他的 profile 里写一堆 root 属主的文件。

**2. 别用 `PLAYWRIGHT_` 前缀的环境变量。**
`playwright-mcp` 自己会读 `PLAYWRIGHT_MCP_PORT`，一读到就**从 stdio 切换成 HTTP 监听模式**，
然后跟 supergateway 抢同一个端口，子进程直接 `EADDRINUSE` 崩掉。

症状很有迷惑性：supergateway 活着、端口也通、`initialize` 甚至返回 200 和一个 session id，
但**响应体是空的**，后续所有请求都报 `No valid session ID provided`。
所以本项目一律用 `PWMCP_` 前缀。

### 前提与限制

- 需要先有桌面（X 显示）。没有 X 就没地方画 headed 浏览器。
- Chromium 是**单实例**的：如果他本人已经开着一个（没带调试端口），
  再启一个同 profile 的只会把参数转发过去然后退出，端口不会开。
  `pwbrowser` 会检测并重启，**标签页会恢复，但没提交的表单会丢**。
- 模型拿到的是这个浏览器的**完整控制权，包括已登录的账号**。所以：
  单独一道密码、单独的令牌、`/oauth/revoke` 随时能撤，别和 shell 通道共用。
- 不需要 X 的场合（纯抓取）改用 `--headless` + `--isolated` 起独立 profile，
  别去动用户的浏览器。

## 测试

```bash
python -m venv .venv && .venv/bin/pip install starlette uvicorn httpx python-multipart
.venv/bin/python tests/test_flow.py                  # 完整 OAuth 流程 + 拒绝路径
.venv/bin/python tests/test_middleware_migration.py  # 中间件不破坏流式 + 迁移幂等
```

测试用 `httpx.ASGITransport` 直接打应用对象，不起服务器、不碰生产状态，秒级反馈。
**改认证逻辑请务必先在这两个测试上跑绿，再上远端** —— 认证层改错了会把人锁在门外。

## 从明文令牌版本升级

早期版本的 `tokens.json` 直接拿令牌原文当字典键。迁移：

```bash
systemctl stop mcp-oauth-gateway
python3 migrate_tokens.py /etc/mcp-ssh/oauth/tokens.json
systemctl start mcp-oauth-gateway
```

脚本幂等（已是 64 位 hex 的键原样保留），改写前自动留 `.bak`。

⚠️ 迁移完**记得删掉那个 `.bak`** —— 它里面就是明文令牌，留着等于白改。
另外旧版本的 `password.json` 没有 `n/r/p` 字段，本版本的 `_verify_password()`
会回落到 2¹⁴ 校验，所以升级不会把现有密码作废。

## 关于「路径/域名隐蔽」

有人会用 `example.com/random-path` 或高位端口来「藏」服务。这**不是安全边界**：

- 证书透明度日志（CT log）会公开所有签发的域名，子域名一览无余
- 全端口扫描对个人 VPS 来说成本极低，高位端口挡不住
- URL 会进浏览器历史、Referer、代理日志、以及模型自己的对话记录

它唯一真实的作用是**减少噪音**（少一堆自动化爬虫来敲门），这个价值可以有，
但别把它当成一道防线。真正的防线是：OAuth 密码 + 第二因素 + fail2ban + 只监听本机。

## License

未指定。自用项目，按需取用。
