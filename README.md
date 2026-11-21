# quick2api

OpenAI-compatible API gateway for Amazon Quick (AIDP WebSocket + AWS `sso-oidc` auto-refresh).

## Build

```bash
go test ./...
go build -trimpath -ldflags="-s -w" -o quick2api ./cmd/quick2api
```

## Quick Start

```bash
cp config.example.json config.json
cp accounts.example.json accounts.json
chmod 600 config.json accounts.json
./quick2api -config config.json
```

## Account Management

```bash
# Import logged-in Amazon Quick Desktop credentials (Windows)
./quick2api import-desktop -accounts accounts.json

# Standalone AWS sso-oidc PKCE login (add -headless for remote/SSH servers)
./quick2api login -accounts accounts.json -tenant-url https://<cell>.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev

# Zero-downtime hot reload after editing accounts.json
kill -HUP <pid>
```

Each account in `accounts.json` supports an optional `"proxy_url"` (`http://`, `https://`, `socks5://`, `socks5h://`, `"direct"` to bypass the global `proxy_url`, or `""` to inherit it). Transient `rate_limited` errors use short exponential backoff (`1m`–`15m`), while `usage_blocked` queries `profile/usage` to apply session, monthly, or trial-expiry cooldowns.

## Endpoints

- `GET /v1/models`
- `GET /v1/models/{id}`
- `POST /v1/chat/completions`
- `GET /healthz`
- `GET /admin/` (built-in minimalist web management dashboard, username `root` + password login)
- `GET /admin/status` (`?usage=1`)
- `GET /admin/metrics` & `POST /admin/metrics/reset`
- `GET /admin/logs` (`?since=&level=&tag=&q=&limit=`) & `POST /admin/logs/clear`
- `POST /admin/reload`
- `POST /admin/accounts/proxy` (`{"id","proxy_url"}`)
- `POST /admin/accounts/probe-proxy` (`{"id"}`)
- `POST /admin/accounts/reset-cooldown` (`{"id"}` or `{}`)

## Models

| Model ID | `agent_mode` | Default `thinking_effort` |
|---|---|---|
| `quick-haiku-5.5` | `fast` | `off` |
| `quick-sonnet-5.5` | `balanced` | `off` |
| `quick-sonnet-5.5-thinking` | `balanced` | `high` |
| `quick-opus-5.5` | `smart` | `off` |
| `quick-opus-5.5-thinking` | `smart` | `high` |
| `quick-opus-5.5-max` | `smart` | `max` |

Supports `reasoning_effort`, `reasoning`, `thinking`, model suffixes (e.g. `quick-opus-5.5(high)`), streaming SSE (`reasoning_content`, `stream_options.include_usage`), vision (`image_url`), `stop`, `response_format`, and OpenAI `tools` / `tool_choice`.

## Environment Variables

- `QUICK2API_LISTEN`
- `QUICK2API_API_KEYS`
- `QUICK2API_ADMIN_PASSWORD` (admin dashboard password for username `root`; if omitted, a strong random password is generated at startup and printed to `stderr`)
- `QUICK2API_ACCOUNTS_FILE`
- `QUICK2API_PROXY_URL`
- `QUICK2API_DEBUG`

## License
[MIT](LICENSE)
