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

## Endpoints

- `GET /v1/models`
- `GET /v1/models/{id}`
- `POST /v1/chat/completions`
- `GET /healthz`
- `GET /admin/status` (`?usage=1`)

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
- `QUICK2API_ACCOUNTS_FILE`
- `QUICK2API_PROXY_URL`
- `QUICK2API_DEBUG`

## License

[MIT](LICENSE)
