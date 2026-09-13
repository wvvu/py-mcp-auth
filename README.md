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

- `mcp-oauth-gateway.service` — 网关本身
- `mcp-ssh-supergateway.service` — 把 stdio MCP 服务转成 streamableHttp（含 `UMask=0027`）
- `mcp-oauth-admin.fail2ban.conf` — 密码爆破封 IP
- `mcp-ssh-audit.logrotate` — 审计日志轮转
- `Caddyfile.example` — 反代

装完记得 `systemctl daemon-reload`，否则 `systemctl status` 会一直报 "changed on disk"。

## 多资源（一个网关，多个上游）

令牌里存了 `resource`，代理时会校验它和当前入口是否一致。要挂第二个上游：

1. 网关侧按入口 Host 分发到不同上游（改 `mcp_proxy` 里的 `UPSTREAM` 选择逻辑）
2. 把 `MCP_PUBLIC_BASE` 扩成域名白名单，按请求 Host 匹配，匹配不到直接拒
3. `scope` 拆开（例如 `shell` 和 `browser`），授权页上把「这次授予什么能力」显示出来

**不要**让一个令牌通吃两个上游。浏览器那侧往往带着已登录态，权限面和 shell 不是一回事。

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
