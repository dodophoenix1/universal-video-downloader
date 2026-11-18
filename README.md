# StreamVault — Universal Video Downloader

A security-hardened, ephemeral video & audio downloader built with **FastAPI**, **yt-dlp**, **FFmpeg**, and **Tailwind CSS**.

## Features

- Inspect video metadata & available quality tiers (`MP4`, `WebM`, `MP3`) before downloading
- Accurate quality detection for landscape, portrait (TikTok / Shorts), and ultrawide streams
- Zero-retention ephemeral streaming: temporary job directories are deleted immediately after download streaming completes (with periodic TTL cleanup for abandoned jobs)
- Hardened against SSRF, DNS rebinding, redirect-based SSRF, path traversal, header injection, XSS, and DoS

## Quick Start (Local)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --host 127.0.0.1 --port 8000 --no-server-header
```

> Requires `ffmpeg` installed on `PATH`.

## Deploy via Docker / Git Deploy

### Docker Compose

```bash
docker compose up -d --build
```

### Render / Railway / Fly.io

- **`Dockerfile`**: Non-root `appuser`, `ffmpeg` preinstalled, `/health` healthcheck
- **`render.yaml`**: Ready for Render Git Deploy
- **`Procfile`**: Ready for PaaS deployments

## Environment Variables

| Variable | Default | Description |
| --- | --- | --- |
| `PORT` | `8000` | HTTP server port |
| `MAX_DOWNLOAD_BYTES` | `2147483648` | Max download size (2 GiB) |
| `MAX_ACTIVE_JOBS` | `24` | Concurrent / active job cap |
| `JOB_TTL_SECONDS` | `900` | TTL for uncollected temp jobs |
| `RATE_LIMIT_INFO_PER_MIN` | `60` | `/api/info` requests/min/IP |
| `RATE_LIMIT_JOBS_PER_MIN` | `30` | `/api/jobs` requests/min/IP |
| `TRUST_PROXY_HEADERS` | `false` | Set `true` behind reverse proxy |
| `ENABLE_DOCS` | `false` | Enable `/docs` & `/openapi.json` |

## Testing & Security Audit

```bash
pytest -v
bandit -r main.py
ruff check .
pip-audit
```
