# Docker Incident Sentinel

Sidecar for an existing Docker Compose project. It watches one project, not every container on the host.

## Environment

| Variable | Default |
| --- | --- |
| `COMPOSE_PROJECT_NAME` | `my_app` |
| `OPENAI_API_KEY` | required |
| `OPENAI_BASE_URL` | `https://api.openai.com/v1` |
| `OPENAI_MODEL` | `gpt-4o-mini` |
| `TELEGRAM_BOT_TOKEN` | required |
| `TELEGRAM_CHAT_ID` | required |
| `LOG_LEVEL` | `INFO` |
| `BUFFER_SIZE_LINES` | `200` |
| `DEBOUNCE_WINDOW_SEC` | `5` |
| `COOLDOWN_PERIOD_SEC` | `300` |
