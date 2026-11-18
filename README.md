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

> Requires Python 3.11+ and `ffmpeg` installed on `PATH`. (`requirements.txt` uses `yt-dlp[default,deno]`, which automatically bundles `deno` and `yt-dlp-ejs` for JavaScript challenges.)

## Deploy via Docker / Git Deploy

### Docker Compose (Recommended for Home Self-Hosting)

```bash
docker compose up -d --build
```

Runs at `http://localhost:8000` with hardened container settings (`read_only: true`, non-root `appuser`, `DENO_DIR=/tmp/deno_cache` on `tmpfs`, `cap_drop: ALL`, `ffmpeg` + `deno` + `yt-dlp-ejs` preinstalled).

### Render (Free Tier — \$0, No Billing Card Needed)

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/dodophoenix1/universal-video-downloader)

- **`Dockerfile`**: Non-root `appuser`, `ffmpeg` + `deno` + `yt-dlp-ejs`, `/health` healthcheck
- **`render.yaml`**: Configured for Render Docker Web Service (`plan: free`, 512 MB RAM, ephemeral filesystem, spins down after 15 min idle, capped at `256 MiB`/file to help stay inside Render's free outbound bandwidth allowance — keep no payment method attached on Render to prevent any charges)
- **Manual Public Git Repo Deploy Note**: If you created the Render Web Service manually via **Public Git Repository** (instead of Blueprint / Connect GitHub), `render.yaml` is not auto-synced on push. Set the `render.yaml` environment variables manually in **Render Dashboard → Environment** (`MAX_DOWNLOAD_BYTES=268435456`, `MAX_ACTIVE_JOBS=6`, `WORKER_POOL_SIZE=2`, `JOB_TTL_SECONDS=300`, `RATE_LIMIT_INFO_PER_MIN=30`, `RATE_LIMIT_JOBS_PER_MIN=10`, `TRUST_PROXY_HEADERS=true`, `ENABLE_DOCS=false`) and click **Manual Deploy → Deploy latest commit** after merging PRs to `main`.

### GitHub Actions CI/CD

Every push and pull request to `main` runs `.github/workflows/ci-cd.yml`:
1. `pytest`, `ruff`, `bandit`, and `pip-audit` security checks
2. Full Docker build + hardened read-only `/health`, `ffmpeg`, `deno`, and `yt-dlp-ejs` container smoke test
3. On `main`: triggers a Render Deploy Hook automatically if the `RENDER_DEPLOY_HOOK_URL` GitHub Actions secret is set (Settings → Secrets and variables → Actions).

## Cloud (Render Free) vs. Home PC Self-Hosting

| Aspect | Cloud Free Tier (Render Free) | Home PC Self-Hosting (`docker compose` / Local) |
| --- | --- | --- |
| **IP Reputation** | Shared datacenter IP — YouTube, TikTok, IG, and Reddit frequently trigger anti-bot checks, HTTP 403, or login walls even with `deno` + `yt-dlp-ejs` | Residential ISP IP — dramatically fewer anti-bot blocks on public YouTube/social URLs |
| **Compute & Disk** | 512 MB RAM, shared CPU, `256 MiB` default cap in `render.yaml`, sleeps after 15 min idle | Full host RAM/CPU/disk speed, `2 GiB` default cap, always instant (`0s` cold start) |
| **Bandwidth Limit** | Limited free monthly egress (Render Free Tier) | Full home internet bandwidth with zero PaaS egress bill |
| **Best Use Case** | SoundCloud, direct `.mp4`/`.webm` links, low-restriction sites | Daily personal use across stricter platforms & large/HD 1080p–4K remuxes |

### What Can Still Be Blocked Even When Self-Hosted at Home?

1. **Login-gated / Age-restricted / Private media**: `main.py` intentionally disables `cookiefile`, `cookiesfrombrowser`, and `.netrc` so a web service never leaks or burns your personal account sessions.
2. **DRM-protected streams** (Widevine / FairPlay): Cannot be decrypted or downloaded.
3. **Geo-restricted streams**: Content blocked outside your home ISP's country.
4. **Heavy burst rate-limiting (`429`) or anti-bot TLS WAFs**: Firing dozens of requests rapidly can temporarily cooldown your IP, and certain strict sites rely on browser TLS impersonation (`curl-cffi` is intentionally stripped alongside WebSockets by `_attach_ytdlp_ssrf_guard` to enforce per-hop SSRF validation).

### Safe Remote Access from Home

If you want to access your home instance outside your home network:
- **Prefer a private VPN (Recommended)**: Use **Tailscale** (`tailscale serve` or private Tailnet IP) so only your own devices can reach it.
- **If using Cloudflare Tunnel**: Do **not** leave a public tunnel open without authentication (Cloudflare Access / Zero Trust), otherwise anyone who finds the URL can spend your home bandwidth and trigger blocks on your residential IP.

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
