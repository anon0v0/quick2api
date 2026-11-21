# quick2api

面向 **Amazon Quick**（AIDP 双向 WebSocket + AWS `sso-oidc` 自动续期）的轻量级、单文件 **OpenAI 兼容 API 网关**。

使用纯 Go 编写，内置零外部依赖的极简 Web 管理控制台（`go:embed` 编译进单个静态二进制），支持多账号池轮询、单账号独立出口代理、差异化配额冷却、零停机热重载以及远程 OAuth 回调 URL 登录。

---

## 目录

- [核心特性](#核心特性)
- [支持的模型与推理控制](#支持的模型与推理控制)
- [编译与快速开始](#编译与快速开始)
- [配置说明](#配置说明)
- [账号接入与多账号池管理](#账号接入与多账号池管理)
- [内置 Web 管理控制台](#内置-web-管理控制台)
- [客户端调用示例](#客户端调用示例)
- [生产环境部署指南](#生产环境部署指南)
- [HTTP 接口速查](#http-接口速查)
- [注意事项与许可证](#注意事项与许可证)

---

## 核心特性

- **完整 OpenAI Chat Completions 兼容**
  - 支持非流式与 SSE 流式输出（`stream: true`、`stream_options.include_usage`、`reasoning_content` 思维链增量输出）。
  - 支持视觉多模态输入（`image_url`，兼容 Base64 Data URL 与远程图片）、`tools` / `tool_choice` 工具调用、`stop` 停止词、`response_format`（JSON Mode / JSON Schema）。
  - 自动统计输入、缓存命中（`prompt_tokens_details.cached_tokens`）与输出 Token。
- **高可靠多账号池与调度**
  - 多账号轮询分发，自动后台提前刷新 AWS `sso-oidc` `access_token` 并原子持久化（`0600` 权限）。
  - **差异化冷却策略**：区分瞬时限流 `rate_limited`（1m–15m 指数退避）与配额受限 `usage_blocked`（自动查询 `profile/usage` 接口，精准识别会话配额、月度配额耗尽或试用订阅过期并设置对应冷却时长）。
  - **单账号独立出口代理**：支持全局代理及单账号级 `proxy_url` 覆盖（`http` / `https` / `socks5` / `socks5h` / `direct` 强制直连），各账号的 OIDC 刷新、WebSocket 聊天、配额查询与出口探测均严格走各自代理通道。
  - **零停机热重载**：支持 `kill -HUP <pid>` 或 `POST /admin/reload`，平滑应用新增/禁用/删除及代理变更，同时保留运行中更鲜活的 Token 与配额状态。
- **多种账号接入方式**
  - **Web 控制台远程 OAuth 回调登录**：适配无浏览器 VPS 场景，生成 AWS `sso-oidc` PKCE 授权链接并在本地浏览器登录后，复制跳转的 `127.0.0.1` 回调 URL 粘贴提交即可完成入库与热重载。
  - **Web 控制台 JSON 导入**：支持粘贴单账号对象、账号数组或完整 `accounts.json` 一键导入。
  - **命令行工具**：内置 `quick2api login`（支持本地自动回调与 `-headless` 终端粘贴模式）与 Windows 专用的 `quick2api import-desktop`（直接读取已登录的 Amazon Quick 桌面端 Windows 凭据管理器并自动重组分片凭证）。
- **内置极简 Web 管理控制台（`/admin/`）**
  - 单文件静态内嵌，零外部 CDN 资源，支持浅色/深色主题切换。
  - 提供 **概览（24 小时流量/Token 趋势图 + KPI + 最近请求）**、**账号池（月度/会话配额进度条、实时冷却倒计时、出口代理修改与 IP 探测、OAuth 登录、启停与删除）**、**模型与账号用量统计**、**实时运行日志（自动脱敏 Token 与代理密码）**。
  - 独立管理员登录保护（固定用户名 `root` + 密码），支持 `HttpOnly; SameSite=Strict` 会话 Cookie、CSRF 校验与防暴力破解限流。

---

## 支持的模型与推理控制

通过 `GET /v1/models` 暴露以下 6 个标准模型：

| 模型 ID | 上游 `agent_mode` | 默认 `thinking_effort` | 上下文窗口 | 最大输出 | 图像 / 工具 / 思考 |
| :--- | :--- | :--- | :---: | :---: | :---: |
| `quick-haiku-5.5` | `fast` | `off` | 1,000,000 | 64,000 | 图像 / 工具 |
| `quick-sonnet-5.5` | `balanced` | `off` | 1,000,000 | 64,000 | 图像 / 工具 / 思考 |
| `quick-sonnet-5.5-thinking` | `balanced` | `high` | 1,000,000 | 64,000 | 图像 / 工具 / 思考 |
| `quick-opus-5.5` | `smart` | `off` | 1,000,000 | 64,000 | 图像 / 工具 / 思考 |
| `quick-opus-5.5-thinking` | `smart` | `high` | 1,000,000 | 64,000 | 图像 / 工具 / 思考 |
| `quick-opus-5.5-max` | `smart` | `max` | 1,000,000 | 64,000 | 图像 / 工具 / 思考 |

### 动态调整思考强度与模型别名

除了直接选择上述标准模型外，还可通过以下任意方式动态覆盖思考深度（优先级：显式请求参数 > 模型后缀 > 模型默认值）：

1. **请求体参数**：
   - OpenAI 风格：`reasoning_effort`（支持 `none`/`off`、`minimal`/`low`、`medium`、`high`、`max`/`xhigh`）或 `reasoning: { "effort": "high" }`。
   - Anthropic / 兼容风格：`thinking: { "type": "enabled", "budget_tokens": 16384 }`（自动按预算映射为 `low` / `medium` / `high` / `max`）。
2. **模型名后缀**：
   - 括号后缀：例如 `quick-opus-5.5(high)`、`quick-sonnet-5.5(medium)`、`quick-opus-5.5(max)`。
   - 连字符后缀：`-off` / `-none` / `-low` / `-medium` / `-high` / `-thinking` / `-max` / `-xhigh`。
3. **常见前缀自动剥离**：兼容 `quick/`、`amazon-quick/`、`[quick]-`、`[aws]-` 前缀以及 `fast` / `balanced` / `smart` / `haiku` / `sonnet` / `opus` 关键字匹配。

---

## 编译与快速开始

### 环境要求

- Go `1.22` 及以上（编译需要 Go 工具链；编译产物为纯静态单文件，运行时无需任何依赖）。

### 从源码编译

```bash
git clone https://github.com/anon0v0/quick2api.git
cd quick2api

# 运行单元测试
go test -count=1 ./...

# 编译当前平台二进制
go build -trimpath -ldflags="-s -w" -o quick2api ./cmd/quick2api
```

**交叉编译 Linux amd64 静态二进制**（适用于在 Windows / macOS 上打包后上传至 Linux 服务器）：

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o quick2api-linux-amd64 ./cmd/quick2api
```

### 快速启动

```bash
# 1. 复制示例配置文件
cp config.example.json config.json
cp accounts.example.json accounts.json

# 若希望先启动服务再通过 Web 控制台 OAuth 登录添加账号，可将 accounts.json 初始化为空池：
# echo '{"accounts":[]}' > accounts.json

# 2. 收紧敏感文件权限（Linux/macOS 强烈建议）
chmod 600 config.json accounts.json

# 3. 设置管理控制台密码（用户名固定为 root）并启动
export QUICK2API_ADMIN_PASSWORD="请替换为高强度管理密码"
./quick2api -config config.json
```

> **提示**：如果未在环境变量或 `config.json` 中设置管理密码，程序启动时会自动生成 20 位随机强密码，并**仅输出到标准错误 `stderr`**（不会进入 Web 日志缓冲区），可在终端或 `journalctl` 中查看。

启动后：
- OpenAI API 地址：`http://127.0.0.1:18082/v1`
- Web 管理控制台：`http://127.0.0.1:18082/admin/`（用户名 `root`）
- 健康检查：`http://127.0.0.1:18082/healthz`

---

## 配置说明

### `config.json` 配置项

```json
{
  "listen_addrs": ["127.0.0.1:18082"],
  "api_keys": ["sk-replace-with-your-key"],
  "admin_password": "",
  "accounts_file": "accounts.json",
  "proxy_url": "",
  "default_surface": "QUICK_WORK_DESKTOP_WINDOWS",
  "delete_session": true,
  "request_timeout_sec": 600,
  "stream_idle_timeout_sec": 120,
  "sse_keepalive_sec": 15,
  "max_body_mb": 64,
  "refresh_lead_sec": 600,
  "max_concurrent_turns": 8,
  "debug": false
}
```

| 字段 | 类型 | 默认值 | 说明 |
| :--- | :--- | :--- | :--- |
| `listen_addrs` | `string[]` | `["127.0.0.1:18082"]` | 监听地址列表，可同时监听多个网卡/端口（如本机回环 + Docker 网桥）。 |
| `api_keys` | `string[]` | `[]` | 访问 `/v1/*`（以及作为管理 API Bearer Key）的鉴权密钥列表；留空则 `/v1/*` 不校验 Key（生产环境务必配置）。 |
| `admin_password` | `string` | `""` | Web 控制台 `root` 管理员密码；更推荐通过环境变量 `QUICK2API_ADMIN_PASSWORD` 注入。 |
| `accounts_file` | `string` | `"accounts.json"` | 账号池凭证文件路径。 |
| `proxy_url` | `string` | `""` | 全局默认出口代理，支持 `http://`、`https://`、`socks5://`、`socks5h://`（必须显式指定端口）；留空直连。 |
| `default_surface` | `string` | `"QUICK_WORK_DESKTOP_WINDOWS"` | 上报给上游的客户端标识。 |
| `delete_session` | `bool` | `true` | 对话结束后是否异步清理上游临时会话。 |
| `request_timeout_sec` | `int` | `600` | 单次完整请求最大超时秒数。 |
| `stream_idle_timeout_sec` | `int` | `120` | 流式响应无新帧时的空闲超时秒数（设为 `< 0` 关闭）。 |
| `sse_keepalive_sec` | `int` | `15` | 流式等待上游思考期间发送 SSE 心跳注释的间隔秒数（设为 `< 0` 关闭）。 |
| `max_body_mb` | `int` | `64` | 单次 HTTP 请求体最大体积（MB，含 Base64 图片）。 |
| `refresh_lead_sec` | `int` | `600` | Token 过期前多少秒自动触发后台刷新。 |
| `max_concurrent_turns` | `int` | `8` | 全局最大并发上游对话数。 |
| `debug` | `bool` | `false` | 是否输出更详细的调试日志。 |

### 环境变量覆盖

环境变量优先级高于 `config.json` 中对应字段：

| 环境变量 | 对应配置 | 说明 |
| :--- | :--- | :--- |
| `QUICK2API_LISTEN` | `listen_addrs` | 逗号分隔的监听地址，如 `127.0.0.1:18082,172.17.0.1:18082` |
| `QUICK2API_API_KEYS` | `api_keys` | 逗号分隔的 API Key 列表 |
| `QUICK2API_ADMIN_PASSWORD` | `admin_password` | Web 控制台 `root` 登录密码（推荐使用 `EnvironmentFile` 注入） |
| `QUICK2API_ACCOUNTS_FILE` | `accounts_file` | `accounts.json` 路径 |
| `QUICK2API_PROXY_URL` | `proxy_url` | 全局默认出口代理 |
| `QUICK2API_DEBUG` | `debug` | 设为 `true` 或 `1` 开启调试日志 |

### `accounts.json` 结构

支持 `{"accounts": [...]}` 对象包装、账号数组 `[...]` 或单账号对象，允许显式空数组 `{"accounts": []}`：

```json
{
  "accounts": [
    {
      "id": "account-1",
      "disabled": false,
      "proxy_url": "socks5h://user:pass@127.0.0.1:1080",
      "tenant_url": "https://your-cell.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev",
      "region": "us-east-1",
      "client_id": "REPLACE_WITH_SSO_OIDC_CLIENT_ID",
      "client_secret": "REPLACE_WITH_SSO_OIDC_CLIENT_SECRET",
      "access_token": "REPLACE_WITH_ACCESS_TOKEN",
      "access_token_expiry": 1760000000,
      "refresh_token": "REPLACE_WITH_REFRESH_TOKEN"
    }
  ]
}
```

- **`proxy_url` 语义**：
  - `""`（留空或省略）：继承全局 `config.json` 中的 `proxy_url`。
  - `"direct"`：强制直连，绕过全局代理。
  - `"http://..."` / `"https://..."` / `"socks5://..."` / `"socks5h://..."`：该账号独占此出口代理（需包含显式端口）。

---

## 账号接入与多账号池管理

提供三种方式添加账号，可按部署环境自由组合：

### 方式一：Web 控制台远程 OAuth 回调登录（推荐，适配远程服务器）

由于 AWS `sso-oidc` 仅接受本机回环回调地址（`http://127.0.0.1:<port>/oauth/callback`），远程部署时无需开放额外端口，直接在 Web 控制台按两步完成：

1. 登录 Web 控制台（`/admin/`），进入 **账号池** 页面，点击右上角 **`+ OAuth 登录`**。
2. 填写 **租户地址（`tenant_url`）**（若账号池已有账号会自动预填）、可选自定义账号 ID 及独立出口代理（OIDC 注册与换取 Token 均会经该代理出站），点击 **`生成登录链接`**。
3. 点击 **`打开登录页`**（或复制链接）在**本地电脑浏览器**中完成 Amazon Quick 登录授权。
4. 授权完成后，浏览器会跳转到本地无法访问的 `http://127.0.0.1:18080/oauth/callback?code=...&state=...` 页面——直接复制浏览器地址栏的**完整 URL**，粘贴回控制台「步骤 2」输入框并点击 **`提交回调并完成登录`**。
5. 后端校验 `state` 并换取 Token 后，自动原子写入 `accounts.json`、触发热重载，并立即尝试拉取该账号的初始配额快照。

> 在同一弹窗内也可切换到 **「导入 JSON」** 标签页，直接粘贴单账号对象、数组或 `accounts.json` 内容导入，并支持导入时统一覆盖出口代理。

### 方式二：命令行 OAuth PKCE 登录（`quick2api login`）

适用于本机直接弹窗登录，或通过 SSH 在终端使用 `-headless` 模式粘贴回调 URL：

```bash
# 本机有浏览器：自动启动 127.0.0.1:18080 回调监听并打开浏览器
./quick2api login \
  -accounts accounts.json \
  -tenant-url https://your-cell.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev \
  -id my-account-1 \
  -proxy socks5h://127.0.0.1:1080

# 远程 SSH / 无图形界面服务器：打印授权链接并在终端粘贴回调 URL
./quick2api login \
  -headless \
  -accounts accounts.json \
  -tenant-url https://your-cell.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev
```

常用参数：`-config`、`-accounts`、`-id`、`-tenant-url`、`-proxy`、`-region`（默认 `us-east-1`）、`-port`（默认 `18080`）、`-headless`、`-issuer-url`、`-scopes`。

`login` 会优先使用 Amazon Quick 桌面端（`~/.quickwork/profiles.json`）为同一个 `tenant_url` 记录的 AWS Identity Center issuer。每个 Quick 账号对应独立的 issuer，旧版硬编码默认值只匹配其中一个实例，其他账号会被带到 AWS Builder ID 或提示会话过期。需要覆盖时显式传 `-issuer-url https://identitycenter.amazonaws.com/ssoins-<id>`；找不到匹配项时回退默认值并打印提示。

### 方式三：Windows 桌面端一键导入（`quick2api import-desktop`）

若你的 Windows 电脑已登录官方 Amazon Quick 桌面客户端，可直接从 Windows 凭据管理器读取并重组分片凭证，安全写入 `accounts.json`（不向终端输出任何明文 Token 或邮箱信息）：

```powershell
# 导入到本地 accounts.json（可选同时绑定单账号代理）
.\quick2api.exe import-desktop -accounts accounts.json -proxy socks5h://127.0.0.1:1080
```

导出后可将 `accounts.json` 上传至服务器，或直接复制其中的账号对象在 Web 控制台「导入 JSON」中粘贴导入。

### 零停机热重载

手动修改 `accounts.json` 后，无需重启进程，可通过任意一种方式立即热重载：

```bash
# 方式 A：向进程发送 SIGHUP（Unix/Linux）
kill -HUP $(pidof quick2api)
# 或配合 systemd：
systemctl reload quick2api

# 方式 B：调用管理接口或点击 Web 控制台「热重载账号」按钮
curl -X POST http://127.0.0.1:18082/admin/reload \
  -H "Authorization: Bearer sk-replace-with-your-key"
```

---

## 内置 Web 管理控制台

访问 `http://<host>:18082/admin/`（或反向代理后的 `https://quick.example.com/admin/`），使用用户名 `root` 与配置的管理密码登录：

- **概览**：实时展示可用账号数、活跃 WebSocket 连接、累计请求、成功率、Token 与缓存命中率、平均延迟、24 小时按小时柱状趋势图（请求量/Token 双视图）、模型分布及最近请求明细（仅记录元数据，不落盘也不展示对话正文）。
- **账号池**：
  - 直观呈现每个账号的**月度配额 / 会话配额**进度条与重置时间、订阅状态、出口代理、Token 剩余有效期及实时冷却倒计时。
  - 支持在线 **OAuth 回调登录 / JSON 导入**、**拉取实时配额**、**修改单账号代理**、**一键探测出口 IP 与延迟**、**清除冷却**、**启用/禁用**、**删除账号** 以及 **热重载账号**。
- **模型统计**：按模型汇总、按账号分摊及最新 50 条请求明细（支持按模型与状态筛选、支持重置内存统计）。
- **运行日志**：内存环形缓冲（最近 1000 条），支持按级别（`INFO`/`WARN`/`ERROR`）、模块标签与关键字实时过滤、暂停跟踪与一键复制；所有日志在入缓冲前自动对 `Bearer`、`aoa_`/`aor_` Token 及代理账密进行脱敏。

**安全机制**：
- 登录成功后下发 `HttpOnly; SameSite=Strict; Path=/admin/` 会话 Cookie（HTTPS 下自动启用 `Secure`），支持默认 24 小时或勾选 14 天保持登录。
- 同一 IP 连续 8 次登录失败触发 5 分钟 `429` 锁定；基于 Cookie 的写操作强制校验 `X-Requested-With: quick2api-ui` 请求头防范 CSRF；`/admin/*` 严禁通配 CORS 且固定返回 `Cache-Control: no-store`。
- 自动化脚本仍可通过 `Authorization: Bearer <api_key>` 直接调用所有 `/admin/*` 接口。

---

## 客户端调用示例

### `curl` 流式调用（含思考过程）

```bash
curl -N http://127.0.0.1:18082/v1/chat/completions \
  -H "Authorization: Bearer sk-replace-with-your-key" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "quick-opus-5.5-thinking",
    "stream": true,
    "stream_options": {"include_usage": true},
    "messages": [
      {"role": "user", "content": "简述 Go 中 channel 与 mutex 的选型原则"}
    ]
  }'
```

### Python（OpenAI SDK）

```python
from openai import OpenAI

client = OpenAI(
    base_url="https://quick.example.com/v1",
    api_key="sk-replace-with-your-key",
)

resp = client.chat.completions.create(
    model="quick-sonnet-5.5",
    reasoning_effort="medium",
    messages=[{"role": "user", "content": "Hello!"}],
)
print(resp.choices[0].message.content)
```

### 作为上游接入聚合网关（如 CLIProxyAPI / One API / New API）

- **渠道类型**：OpenAI Compatible
- **Base URL**：`http://127.0.0.1:18082/v1`（若聚合网关运行在 Docker 容器内，可在 `listen_addrs` 中增加 Docker 网桥地址如 `172.17.0.1:18082` 或直接填公网 HTTPS 地址）
- **API Key**：与 `config.json` 中 `api_keys` 保持一致
- **模型列表**：可直接拉取 `/v1/models`，或按需映射 `quick-haiku-5.5`、`quick-sonnet-5.5`、`quick-opus-5.5-thinking`、`quick-opus-5.5-max`

---

## 生产环境部署指南

推荐架构：**`quick2api` 仅监听本机回环 `127.0.0.1:18082` + `systemd` 守护进程 + `Nginx` TLS 反向代理**。

### 1. 准备目录与文件权限

```bash
sudo mkdir -p /opt/quick2api
sudo cp quick2api-linux-amd64 /opt/quick2api/quick2api
sudo chmod 0755 /opt/quick2api/quick2api

# 放置 config.json 与 accounts.json（可先用 '{"accounts":[]}' 初始化）
sudo cp config.example.json /opt/quick2api/config.json
echo '{"accounts":[]}' | sudo tee /opt/quick2api/accounts.json >/dev/null

# 使用独立环境文件存放管理密码，避免明文写入 systemd unit 或 config.json
cat <<'EOF' | sudo tee /opt/quick2api/quick2api.env >/dev/null
QUICK2API_ADMIN_PASSWORD=请替换为高强度随机密码
EOF

# 严格收紧凭证文件权限
sudo chown root:root /opt/quick2api/{config.json,accounts.json,quick2api.env}
sudo chmod 0600 /opt/quick2api/{config.json,accounts.json,quick2api.env}
```

### 2. 配置 `systemd` 服务

创建 `/etc/systemd/system/quick2api.service`：

```ini
[Unit]
Description=quick2api OpenAI-compatible gateway for Amazon Quick
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/quick2api
EnvironmentFile=/opt/quick2api/quick2api.env
ExecStart=/opt/quick2api/quick2api -config /opt/quick2api/config.json
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

启用并启动服务：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now quick2api
sudo systemctl status quick2api

# 验证本机健康检查
curl -fsS http://127.0.0.1:18082/healthz
```

### 3. 配置 Nginx + Let's Encrypt HTTPS 反向代理

创建 `/etc/nginx/sites-available/quick.example.com`（将域名替换为你的实际域名）：

```nginx
server {
    listen 80;
    listen [::]:80;
    server_name quick.example.com;

    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }

    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name quick.example.com;

    ssl_certificate     /etc/letsencrypt/live/quick.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/quick.example.com/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;

    # 允许上传较大的多模态图片请求（与 config.json max_body_mb 对应）
    client_max_body_size 64m;

    # 通用代理头（确保后端识别 HTTPS 以自动下发 Secure Cookie）
    proxy_http_version 1.1;
    proxy_set_header Host              $host;
    proxy_set_header X-Real-IP         $remote_addr;
    proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;

    # /v1/ 聊天补全接口：关闭缓冲以保证 SSE 流式输出零延迟
    location /v1/ {
        proxy_pass http://127.0.0.1:18082;
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 600s;
        proxy_send_timeout 600s;
        chunked_transfer_encoding on;
    }

    # 管理面板与健康检查
    location / {
        proxy_pass http://127.0.0.1:18082;
        proxy_read_timeout 120s;
    }
}
```

启用站点并签发证书：

```bash
sudo ln -s /etc/nginx/sites-available/quick.example.com /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx

# 若尚未签发证书，可使用 certbot 签发（推荐 ECDSA）：
sudo certbot certonly --webroot -w /var/www/html -d quick.example.com --key-type ecdsa
sudo systemctl reload nginx
```

> **反向代理注意点**：
> 1. `/v1/` 路由必须配置 `proxy_buffering off;` 和足够长的 `proxy_read_timeout`（如 `600s`），否则深度思考（`thinking` / `max`）长耗时流式响应容易被代理提前掐断或整块缓冲。
> 2. 务必透传 `X-Forwarded-Proto $scheme`，`quick2api` 在检测到本机反代透传 HTTPS 时会自动为管理员会话 Cookie 启用 `Secure` 标记。

---

## HTTP 接口速查

### 公开 / OpenAI 兼容接口

| 方法与路径 | 鉴权 | 说明 |
| :--- | :--- | :--- |
| `GET /healthz` | 无 | 返回服务状态、可用账号数与活跃 WebSocket 连接数 |
| `GET /v1/models` | `Bearer <api_key>` | 返回可用模型列表 |
| `GET /v1/models/{id}` | `Bearer <api_key>` | 查询单个模型信息 |
| `POST /v1/chat/completions` | `Bearer <api_key>` | OpenAI 兼容对话补全（流式/非流式、工具、视觉、思考） |

### Web 控制台与管理接口

以下 `/admin/*` 接口支持 **管理员会话 Cookie（非 GET 需附带 `X-Requested-With: quick2api-ui`）** 或 **`Authorization: Bearer <api_key>`**：

| 方法与路径 | 说明 |
| :--- | :--- |
| `GET /`、`GET /admin`、`GET /admin/` | Web 管理控制台入口 |
| `POST /admin/auth/login` | 管理员登录（`{"username":"root","password":"...","remember":false}`） |
| `POST /admin/auth/logout` | 退出登录并吊销当前会话 |
| `GET /admin/auth/me` | 查询当前登录状态 |
| `GET /admin/status` | 获取账号池实时状态与配额快照（附加 `?usage=1` 立即向远端拉取最新配额） |
| `GET /admin/metrics` / `POST /admin/metrics/reset` | 查询或重置内存中的 24h 趋势、模型与账号用量统计 |
| `GET /admin/logs` / `POST /admin/logs/clear` | 查询（支持 `since`/`level`/`tag`/`q`/`limit`）或清空脱敏运行日志 |
| `POST /admin/reload` | 零停机热重载 `accounts.json` |
| `POST /admin/oauth/start` | 发起远程 OAuth PKCE 登录，返回 `auth_url`、`state` 与 `redirect_uri` |
| `POST /admin/oauth/callback` | 提交浏览器跳转后的完整回调 URL（`{"state","redirect_url","tenant_url"}`）完成入库与热重载 |
| `POST /admin/accounts/import` | 批量或单条 JSON 导入账号（`{"payload": ..., "proxy_url": "..."}`） |
| `POST /admin/accounts/proxy` | 修改单账号出口代理（`{"id","proxy_url"}`）并立即断开旧连接 |
| `POST /admin/accounts/probe-proxy` | 经指定账号出口探测公网 IP 与延迟（`{"id"}`） |
| `POST /admin/accounts/toggle` | 启用或禁用指定账号（`{"id","disabled"}`） |
| `POST /admin/accounts/delete` | 永久删除指定账号（`{"id"}`）并原子持久化 |
| `POST /admin/accounts/reset-cooldown` | 清除单个账号（`{"id"}`）或全部账号（`{}`）的冷却状态 |

---

## 注意事项与许可证

- **凭证安全**：`config.json`、`accounts.json`、`quick2api.env` 均包含敏感密钥或账号令牌，请务必保持 `0600` 权限，切勿提交到公开代码仓库。
- **上游系统提示词说明**：Amazon Quick 服务端会在每次会话中由云端自动注入其内置系统指令与环境定义，因此上游返回的 `prompt_tokens` 基准会高于用户实际发送的消息长度，这是 Amazon Quick 服务端的固有行为，通常会被上游提示词缓存命中（可在控制台或响应 `cached_tokens` 中观察到较高缓存命中率）。
- **免责声明**：本项目仅供个人学习、协议研究与自用接口适配，请遵守相关服务条款与当地法律法规。

### 许可证

基于 [MIT License](LICENSE) 开源。
