# Security Audit Report — StreamVault (`universal-video-downloader`)

**Audit Date:** 2026-11-18  
**Scope:** Backend (`main.py`), Frontend (`static/`), Container & Deployment Config (`Dockerfile`, `docker-compose.yml`, `render.yaml`, `Procfile`), Dependencies (`requirements.txt`), Automated Dynamic & Static Tests.

---

## 1. Automated Tools & Test Results

| Check | Tool / Suite | Outcome | Notes |
| --- | --- | --- | --- |
| Dependency CVE Audit | `pip-audit` | **PASS (0 CVEs)** | Verified `fastapi 0.163.2`, `starlette 1.10.0`, `uvicorn 0.54.0`, `pydantic 2.14.3`, `yt-dlp 2026.10.26`, `setuptools >=84.1.0` |
| Static Security Analysis | `bandit -r main.py` | **PASS (0 issues)** | 1,196 LOC scanned; 0 High, 0 Medium, 0 Low, 0 `#nosec` bypasses |
| Linter & Code Quality | `ruff check .` | **PASS (0 issues)** | All checks passed across `main.py` and `tests/` |
| Real HTTP Integration Tests | `test_uvd.py` | **PASS** | Verified `/`, `/health`, `/api/info`, `/api/jobs`, streaming, immediate temp cleanup & 404 post-stream |
| Security Test Suite | `pytest -v tests/` | **PASS (12/12)** | Verified SSRF (incl. live 302 redirect attack), path traversal, header injection, CSP, symlink rejection, rate limit, anti-spoofing |

---

## 2. Vulnerabilities Identified & Fixed During Audit

1. **yt-dlp Multi-Backend Redirect SSRF (`RequestsRH` vs `UrllibRH`) — CRITICAL FINDING FIXED**
   - *Finding:* When `requests` is installed in the runtime environment, `yt-dlp` defaults to `RequestsRH` instead of `UrllibRH`, meaning a hook on `UrllibRH` alone could be bypassed by an HTTP `302` redirect to `http://169.254.169.254/latest/meta-data/`.
   - *Fix:* Guarded `RequestDirector.send`, removed unguarded handlers (`Websockets`), rebuilt `UrllibRH`'s `OpenerDirector` without `FTPHandler`/`DataHandler`/`FileHandler` and with `_SafeRedirectHandler`, and wrapped `RequestsRH`'s `session.send` to validate every outbound URL and redirect hop. Verified via live local HTTP `302` exploit test against both backends.

2. **`OpenerDirector` Handler Cache Bypass — HIGH FINDING FIXED**
   - *Finding:* Filtering `opener.handlers` after `OpenerDirector.add_handler()` leaves cached method references in `opener.handle_open` / `opener.handle_error`.
   - *Fix:* Constructed a fresh `urllib.request.OpenerDirector()` containing only safe HTTP/HTTPS handlers and `_SafeRedirectHandler`.

3. **Rate-Limiter Bypass via Leftmost `X-Forwarded-For` Spoofing — MEDIUM FINDING FIXED**
   - *Finding:* Reading `X-Forwarded-For.split(",")[0]` allows clients to spoof arbitrary IPs per request.
   - *Fix:* When `TRUST_PROXY_HEADERS=true`, extracted the rightmost `TRUSTED_PROXY_HOPS` entry appended by the reverse proxy and validated IP syntax with `ipaddress.ip_address()`.

4. **Legacy `setuptools` CVEs in Base Python `venv` — MEDIUM FINDING FIXED**
   - *Finding:* `pip-audit` detected 7 known CVEs on `setuptools 66.1.1`.
   - *Fix:* Pinned `setuptools>=84.1.0` upgrade in `Dockerfile` and verified 0 CVEs via `pip-audit`.

5. **XSS & Inline Script Hardening — MEDIUM FINDING FIXED**
   - *Fix:* Externalized Tailwind config & application JS (`/static/tailwind-config.js`, `/static/app.js`), removed `'unsafe-inline'` from `script-src` CSP, used `textContent` / `createElement` exclusively (zero `innerHTML`).

---

## 3. Security Control Matrix

- **SSRF / DNS Rebinding / Protocol Confusion:** Strict `http`/`https` allowlist; port allowlist (`80, 443, 8080, 8443`); blocks embedded credentials, Unicode/IDNA homoglyphs (`NFKC` + `idna`), decimal/hex/octal/shorthand IPv4, IPv4-mapped/6to4/Teredo IPv6, loopback/private/link-local/CGNAT/reserved ranges, internal TLDs, single-label hostnames, DNS private resolutions, HTTP 30x redirects, and extracted stream/thumbnail URLs.
- **Path Traversal & Filesystem Safety:** 128-bit CSPRNG `job_id` (`secrets.token_hex(16)`), strict `^[a-f0-9]{32}$` validation, fixed on-disk template `media.%(ext)s`, `os.path.realpath` containment checks, explicit symlink refusal, `0o700` job directories, immediate deletion after streaming, and startup/periodic TTL cleanup.
- **HTTP Header Injection & Clickjacking:** RFC 6266 `Content-Disposition` sanitization (CR/LF/control/quote/separator stripping + RFC 5987 UTF-8 encoding), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, strict CSP, `Cache-Control: no-store` on `/api/*`, no wildcard CORS.
- **DoS / Resource Exhaustion:** 16 KiB JSON body cap (`413`), memory-bounded per-IP sliding-window rate limiter (`429`), bounded `ThreadPoolExecutor`, `MAX_ACTIVE_JOBS` cap (`503`), `MAX_DOWNLOAD_BYTES` cap, `noplaylist: True`, `socket_timeout: 15`, `cachedir: False`.
- **Container Hardening:** Non-root `appuser` (`uid 10001`), `--no-server-header`, read-only rootfs & `noexec,nosuid,nodev` tmpfs & `cap_drop: [ALL]` in `docker-compose.yml`.
