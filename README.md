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

### Render (One-Click Blueprint — Free Tier)

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/dodophoenix1/universal-video-downloader)

- **`Dockerfile`**: Non-root `appuser`, `ffmpeg` preinstalled, `/health` healthcheck
- **`render.yaml`**: Configured for Render Docker Web Service (`plan: free`, 512 MB RAM, ephemeral filesystem, spins down after 15 min idle, capped at `256 MiB`/file to help stay inside Render's 5 GB/month free outbound bandwidth allowance — keep no payment method attached on Render to prevent any overage charges)
- **`Procfile`**: Ready for PaaS deployments (Railway / Fly.io / Heroku)

### GitHub Actions CI/CD

Every push and pull request to `main` runs `.github/workflows/ci-cd.yml`:
1. `pytest`, `ruff`, `bandit`, and `pip-audit` security checks
2. Full Docker build + live `/health` container smoke test
3. On `main`: triggers a Render Deploy Hook automatically if the `RENDER_DEPLOY_HOOK_URL` GitHub Actions secret is set (Settings → Secrets and variables → Actions).

## Environment Variables

| Variable | Default | Description |
| --- | --- | --- |
| `PORT` | `8000` | HTTP server port |
| `MAX_DOWNLOAD_BYTES` | `2147483648` | Max download size (2 GiB; `256 MiB` in `render.yaml`) |
| `MAX_ACTIVE_JOBS` | `24` | Concurrent / active job cap (`6` in `render.yaml`) |
| `WORKER_POOL_SIZE` | `4` | Background download worker threads (`2` in `render.yaml`) |
| `JOB_TTL_SECONDS` | `900` | TTL for uncollected temp jobs (`300` in `render.yaml`) |
| `RATE_LIMIT_INFO_PER_MIN` | `60` | `/api/info` requests/min/IP (`30` in `render.yaml`) |
| `RATE_LIMIT_JOBS_PER_MIN` | `30` | `/api/jobs` requests/min/IP (`10` in `render.yaml`) |
| `TRUST_PROXY_HEADERS` | `false` | Set `true` behind reverse proxy |
| `ENABLE_DOCS` | `false` | Enable `/docs` & `/openapi.json` |

## Testing & Security Audit

```bash
pytest -v
bandit -r main.py
ruff check .
pip-audit
```
