"""StreamVault - Hardened Universal Video Downloader (FastAPI + yt-dlp).

Security controls implemented:
- Strict SSRF validation (scheme allowlist, credential blocking, Unicode/IDNA
  normalization, obfuscated IP detection, private/loopback/link-local/CGNAT
  blocking, DNS IP validation, clean yt-dlp OpenerDirector without FTP/Data/File
  handlers, redirect SSRF hooking, and extracted stream URL verification).
- Path traversal prevention (CSPRNG 128-bit job IDs, fixed on-disk template
  `media.%(ext)s`, realpath containment verification, symlink rejection).
- Header injection & XSS prevention (RFC 6266 Content-Disposition sanitizer,
  strict CSP without `unsafe-inline` in `script-src`, zero `innerHTML` usage).
- DoS / resource-exhaustion controls (body size cap, spoof-resistant proxy IP
  resolution, memory-bounded per-IP sliding-window rate limiter, bounded worker
  pool, max active jobs cap, max filesize cap, `noplaylist`, immediate temp
  deletion + TTL janitor).
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import re
import secrets
import shutil
import socket
import tempfile
import threading
import time
import unicodedata
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Literal

import yt_dlp
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Configuration & Constants
# ---------------------------------------------------------------------------

APP_NAME = "StreamVault"
BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

TEMP_ROOT = os.path.realpath(
    os.environ.get("TEMP_ROOT")
    or os.path.join(tempfile.gettempdir(), "streamvault_jobs")
)

MAX_URL_LENGTH = 2048
MAX_BODY_BYTES = int(os.environ.get("MAX_BODY_BYTES", str(16 * 1024)))
MAX_DOWNLOAD_BYTES = int(
    os.environ.get("MAX_DOWNLOAD_BYTES", str(2 * 1024 * 1024 * 1024))
)
MAX_ACTIVE_JOBS = int(os.environ.get("MAX_ACTIVE_JOBS", "24"))
JOB_TTL_SECONDS = int(os.environ.get("JOB_TTL_SECONDS", "900"))
WORKER_POOL_SIZE = int(os.environ.get("WORKER_POOL_SIZE", "4"))
RATE_LIMIT_INFO_PER_MIN = int(os.environ.get("RATE_LIMIT_INFO_PER_MIN", "60"))
RATE_LIMIT_JOBS_PER_MIN = int(os.environ.get("RATE_LIMIT_JOBS_PER_MIN", "30"))
TRUST_PROXY_HEADERS = os.environ.get("TRUST_PROXY_HEADERS", "false").lower() == "true"
TRUSTED_PROXY_HOPS = max(1, int(os.environ.get("TRUSTED_PROXY_HOPS", "1")))
ENABLE_DOCS = os.environ.get("ENABLE_DOCS", "false").lower() == "true"

ALLOWED_PORTS = frozenset({80, 443, 8080, 8443})
ALLOWED_FORMATS = frozenset({"mp4", "webm", "mp3"})
ALLOWED_QUALITIES = frozenset(
    {
        "best",
        "2160",
        "1440",
        "1080",
        "720",
        "480",
        "360",
        "240",
        "144",
        "320",
        "192",
        "128",
    }
)
VIDEO_QUALITY_TIERS = (
    (3840, 2160, 2160),
    (2560, 1440, 1440),
    (1920, 1080, 1080),
    (1280, 720, 720),
    (854, 480, 480),
    (640, 360, 360),
    (426, 240, 240),
    (256, 144, 144),
)
MEDIA_MIME_TYPES = {
    "mp4": "video/mp4",
    "webm": "video/webm",
    "mp3": "audio/mpeg",
}
VIDEO_CONTAINER_EXTS = frozenset({"mp4", "webm", "m4v", "mov", "mkv"})
AUDIO_ONLY_EXTS = frozenset(
    {"mp3", "m4a", "aac", "opus", "ogg", "oga", "wav", "flac", "weba"}
)

BLOCKED_HOSTNAMES = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "ip6-localhost",
        "ip6-loopback",
        "metadata",
        "metadata.google.internal",
        "metadata.aws.internal",
        "instance-data",
    }
)
BLOCKED_SUFFIXES = (
    ".localhost",
    ".local",
    ".internal",
    ".localdomain",
    ".arpa",
    ".home",
    ".lan",
    ".corp",
)
EXTRA_RESTRICTED_NETWORKS = (
    ipaddress.ip_network("100.64.0.0/10"),  # CGNAT (RFC 6598)
    ipaddress.ip_network("192.0.0.0/24"),   # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),   # TEST-NET-1
    ipaddress.ip_network("198.18.0.0/15"),  # Benchmarking
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),  # Documentation IPv6
)

JOB_ID_RE = re.compile(r"^[a-f0-9]{32}$")
FORMAT_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
ASCII_HOSTNAME_RE = re.compile(r"^[a-z0-9.-]+$")
CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")
UNSAFE_FILENAME_CHARS_RE = re.compile(r'[/\\:*?"<>|;]+')

PLATFORM_DISPLAY_NAMES = {
    "youtube": "YouTube",
    "tiktok": "TikTok",
    "instagram": "Instagram",
    "facebook": "Facebook",
    "twitter": "X (Twitter)",
    "x": "X (Twitter)",
    "vimeo": "Vimeo",
    "twitch": "Twitch",
    "bilibili": "Bilibili",
    "dailymotion": "Dailymotion",
    "reddit": "Reddit",
    "soundcloud": "SoundCloud",
}

logger = logging.getLogger("streamvault")
if not logger.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

# ---------------------------------------------------------------------------
# Runtime State & Concurrency
# ---------------------------------------------------------------------------

JOBS_LOCK = threading.Lock()
JOBS: dict[str, dict[str, Any]] = {}
EXECUTOR = ThreadPoolExecutor(
    max_workers=WORKER_POOL_SIZE, thread_name_prefix="sv-worker"
)


class SlidingWindowRateLimiter:
    """Thread-safe, memory-bounded sliding-window rate limiter per client IP."""

    def __init__(self, max_tracked_ips: int = 10_000) -> None:
        self._lock = threading.Lock()
        self._hits: dict[str, list[float]] = {}
        self._max_tracked_ips = max_tracked_ips

    def allow(self, key: str, limit: int, window_seconds: float = 60.0) -> bool:
        if limit <= 0:
            return True
        now = time.monotonic()
        cutoff = now - window_seconds
        with self._lock:
            if len(self._hits) >= self._max_tracked_ips and key not in self._hits:
                self._prune_expired(cutoff)
                if len(self._hits) >= self._max_tracked_ips:
                    oldest_key = next(iter(self._hits))
                    del self._hits[oldest_key]
            timestamps = [t for t in self._hits.get(key, []) if t > cutoff]
            if len(timestamps) >= limit:
                self._hits[key] = timestamps
                return False
            timestamps.append(now)
            self._hits[key] = timestamps
            return True

    def _prune_expired(self, cutoff: float) -> None:
        stale = [
            k for k, ts in self._hits.items() if not any(t > cutoff for t in ts)
        ]
        for k in stale:
            del self._hits[k]

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


RATE_LIMITER = SlidingWindowRateLimiter()


# ---------------------------------------------------------------------------
# Security Helpers: SSRF, Path Safety, Header Sanitization
# ---------------------------------------------------------------------------


def _is_public_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return True strictly when `ip` is a globally routable public IP."""
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return _is_public_ip(ip.ipv4_mapped)
        if ip.sixtofour is not None:
            return _is_public_ip(ip.sixtofour)
        if ip.teredo is not None:
            return False

    if (
        not ip.is_global
        or ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return False

    return all(ip not in net for net in EXTRA_RESTRICTED_NETWORKS)


def _normalize_hostname(raw_host: str) -> str:
    """Normalize Unicode/IDNA hostname to canonical lowercase ASCII."""
    nfkc = unicodedata.normalize("NFKC", raw_host).rstrip(".").lower()
    if not nfkc:
        raise HTTPException(status_code=400, detail="Missing URL hostname.")

    # Direct IPv6 literal (without brackets as returned by urlsplit.hostname).
    if ":" in nfkc:
        return nfkc

    try:
        ascii_host = nfkc.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise HTTPException(
            status_code=400, detail="Invalid hostname encoding."
        ) from exc

    if not ASCII_HOSTNAME_RE.fullmatch(ascii_host):
        raise HTTPException(
            status_code=400, detail="Hostname contains invalid characters."
        )
    return ascii_host


def _check_url_safety(url: str, *, resolve_dns: bool = True) -> str:
    """Validate an external HTTP(S) URL and reject SSRF / parser-confusion targets."""
    if not isinstance(url, str):
        raise HTTPException(status_code=400, detail="Invalid URL type.")

    raw = url.strip()
    if not raw or len(raw) > MAX_URL_LENGTH:
        raise HTTPException(
            status_code=400,
            detail="URL must be non-empty and at most 2048 characters.",
        )

    if (
        any(ch.isspace() for ch in raw)
        or CONTROL_CHARS_RE.search(raw)
        or "\\" in raw
    ):
        raise HTTPException(
            status_code=400, detail="URL contains illegal characters."
        )

    try:
        parsed = urllib.parse.urlsplit(raw)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Malformed URL.") from exc

    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise HTTPException(
            status_code=400,
            detail="Only http and https URLs are supported.",
        )

    if parsed.username is not None or parsed.password is not None:
        raise HTTPException(
            status_code=400,
            detail="URLs containing embedded credentials are not allowed.",
        )

    if not parsed.netloc or "%" in parsed.netloc:
        raise HTTPException(
            status_code=400, detail="URL host is missing or invalid."
        )

    try:
        port = parsed.port
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid URL port.") from exc

    if port is not None and port not in ALLOWED_PORTS:
        raise HTTPException(
            status_code=400,
            detail="URL port is not in the allowed web ports list.",
        )

    if not parsed.hostname:
        raise HTTPException(status_code=400, detail="Missing URL hostname.")

    hostname = _normalize_hostname(parsed.hostname)

    if hostname in BLOCKED_HOSTNAMES or hostname.endswith(BLOCKED_SUFFIXES):
        raise HTTPException(
            status_code=400,
            detail="Access to local or internal hostnames is prohibited.",
        )

    # Check standard IPv4/IPv6 literal first.
    parsed_ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
    try:
        parsed_ip = ipaddress.ip_address(hostname)
    except ValueError:
        # Catch obfuscated IPv4 forms accepted by C/OS resolvers (decimal, hex, octal, short).
        try:
            packed = socket.inet_aton(hostname)
            parsed_ip = ipaddress.IPv4Address(packed)
        except OSError:
            parsed_ip = None

    if parsed_ip is not None:
        if not _is_public_ip(parsed_ip):
            raise HTTPException(
                status_code=400,
                detail="Access to private, loopback, or reserved IP addresses is prohibited.",
            )
        return raw

    # Reject single-label hostnames (e.g., internal service names like `redis`, `metadata`).
    if "." not in hostname:
        raise HTTPException(
            status_code=400,
            detail="Single-label internal hostnames are not allowed.",
        )

    if resolve_dns:
        target_port = port or (443 if scheme == "https" else 80)
        try:
            addr_infos = socket.getaddrinfo(
                hostname, target_port, type=socket.SOCK_STREAM
            )
        except socket.gaierror:
            addr_infos = []

        for info in addr_infos:
            sockaddr = info[4]
            if not sockaddr:
                continue
            ip_str = str(sockaddr[0]).split("%", 1)[0]
            try:
                resolved_ip = ipaddress.ip_address(ip_str)
            except ValueError as exc:
                raise HTTPException(
                    status_code=400, detail="Invalid resolved IP address."
                ) from exc
            if not _is_public_ip(resolved_ip):
                raise HTTPException(
                    status_code=400,
                    detail="URL resolves to a restricted network address.",
                )

    return raw


def validate_video_url(url: str) -> str:
    """Public validator entrypoint for user-supplied video URLs."""
    return _check_url_safety(url, resolve_dns=True)


def _validate_extracted_info_urls(info: dict[str, Any]) -> None:
    """Verify URLs returned by an extractor before passing them to downloaders/ffmpeg."""
    if not isinstance(info, dict):
        return
    for key in ("webpage_url", "url", "manifest_url"):
        val = info.get(key)
        if isinstance(val, str) and val:
            _check_url_safety(val, resolve_dns=True)
    for fmt in info.get("formats") or []:
        if not isinstance(fmt, dict):
            continue
        for key in ("url", "manifest_url"):
            val = fmt.get(key)
            if isinstance(val, str) and val:
                _check_url_safety(val, resolve_dns=False)
        for frag in fmt.get("fragments") or []:
            if isinstance(frag, dict):
                furl = frag.get("url")
                if isinstance(furl, str) and ("://" in furl or furl.startswith("//")):
                    _check_url_safety(furl, resolve_dns=False)


def _sanitize_text(value: Any, max_len: int = 200, default: str = "") -> str:
    if not isinstance(value, str):
        return default
    cleaned = CONTROL_CHARS_RE.sub(" ", value).strip()
    cleaned = re.sub(r"\s+", " ", cleaned)
    if not cleaned:
        return default
    return cleaned[:max_len]


def _sanitize_thumbnail_url(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        safe = _check_url_safety(value, resolve_dns=False)
    except HTTPException:
        return None
    if not safe.lower().startswith(("https://", "http://")):
        return None
    return safe


def _build_content_disposition(title: str, ext: str) -> str:
    """Build an RFC 6266 Content-Disposition header strictly encodable in latin-1."""
    clean_ext = re.sub(r"[^a-z0-9]", "", (ext or "").lower())
    if clean_ext not in ALLOWED_FORMATS:
        clean_ext = "bin"

    stem = _sanitize_text(title, max_len=120, default="streamvault_media")
    stem = UNSAFE_FILENAME_CHARS_RE.sub("_", stem)
    stem = stem.strip(" ._-")
    if not stem or stem in {".", ".."}:
        stem = "streamvault_media"
    stem = stem[:120]

    ascii_stem = re.sub(r"[^A-Za-z0-9._-]+", "_", stem).strip("._-")
    if not ascii_stem:
        ascii_stem = "video"
    ascii_stem = ascii_stem[:80]

    utf8_name = urllib.parse.quote(f"{stem}.{clean_ext}", safe="")
    return (
        f'attachment; filename="{ascii_stem}.{clean_ext}"; '
        f"filename*=UTF-8''{utf8_name}"
    )


def _ensure_temp_root() -> None:
    os.makedirs(TEMP_ROOT, mode=0o700, exist_ok=True)
    try:
        os.chmod(TEMP_ROOT, 0o700)
    except OSError:
        pass


def _safe_job_dir(job_id: str) -> str:
    if not JOB_ID_RE.fullmatch(job_id):
        raise HTTPException(status_code=404, detail="Job not found.")
    _ensure_temp_root()
    candidate = os.path.realpath(os.path.join(TEMP_ROOT, job_id))
    root_real = os.path.realpath(TEMP_ROOT)
    if os.path.commonpath([root_real, candidate]) != root_real or candidate == root_real:
        raise HTTPException(status_code=404, detail="Job not found.")
    return candidate


# ---------------------------------------------------------------------------
# yt-dlp Hardening & Redirect Guard
# ---------------------------------------------------------------------------


def _attach_ytdlp_ssrf_guard(ydl: Any) -> None:
    """Hook real yt-dlp RequestDirector, UrllibRH, and RequestsRH to block SSRF redirects."""
    director = getattr(ydl, "_request_director", None)
    if director is None or not hasattr(director, "send"):
        return

    try:
        from yt_dlp.networking.exceptions import RequestError as YtRequestError
    except ImportError:
        YtRequestError = None

    def _assert_safe_or_raise_yt(url: str) -> None:
        try:
            _check_url_safety(url, resolve_dns=True)
        except HTTPException as exc:
            if YtRequestError is not None:
                raise YtRequestError(f"SSRF blocked: {exc.detail}") from exc
            raise

    original_send = director.send

    def guarded_send(req: Any, *args: Any, **kwargs: Any) -> Any:
        url = getattr(req, "url", None)
        if isinstance(url, str):
            _check_url_safety(url, resolve_dns=True)
        return original_send(req, *args, **kwargs)

    director.send = guarded_send

    handlers = getattr(director, "handlers", None)
    if not isinstance(handlers, dict):
        return

    # Only keep guarded HTTP/HTTPS handlers (remove Websockets / CurlCffi / etc.).
    for key in list(handlers.keys()):
        if key not in {"Urllib", "Requests"}:
            handlers.pop(key, None)

    urllib_rh = handlers.get("Urllib")
    if urllib_rh is not None and hasattr(urllib_rh, "_create_instance"):
        try:
            from yt_dlp.networking import _urllib as ytdlp_urllib

            class _SafeRedirectHandler(ytdlp_urllib.RedirectHandler):
                def redirect_request(
                    self,
                    req: Any,
                    fp: Any,
                    code: Any,
                    msg: Any,
                    headers: Any,
                    newurl: Any,
                ) -> Any:
                    target = urllib.parse.urljoin(req.full_url, str(newurl))
                    _assert_safe_or_raise_yt(target)
                    return super().redirect_request(
                        req, fp, code, msg, headers, target
                    )

            def safe_urllib_create_instance(
                proxies: Any, cookiejar: Any, legacy_ssl_support: Any = None
            ) -> urllib.request.OpenerDirector:
                opener = urllib.request.OpenerDirector()
                safe_handlers = [
                    ytdlp_urllib.ProxyHandler(proxies),
                    ytdlp_urllib.HTTPHandler(
                        debuglevel=int(bool(urllib_rh.verbose)),
                        context=urllib_rh._make_sslcontext(
                            legacy_ssl_support=legacy_ssl_support
                        ),
                        source_address=urllib_rh.source_address,
                    ),
                    ytdlp_urllib.HTTPCookieProcessor(cookiejar),
                    ytdlp_urllib.UnknownHandler(),
                    ytdlp_urllib.HTTPDefaultErrorHandler(),
                    ytdlp_urllib.HTTPErrorProcessor(),
                    _SafeRedirectHandler(),
                ]
                for handler in safe_handlers:
                    opener.add_handler(handler)
                opener.addheaders = []
                return opener

            urllib_rh._create_instance = safe_urllib_create_instance
        except (ImportError, AttributeError):
            handlers.pop("Urllib", None)

    requests_rh = handlers.get("Requests")
    if requests_rh is not None and hasattr(requests_rh, "_create_instance"):
        orig_req_create = requests_rh._create_instance

        def safe_requests_create_instance(
            cookiejar: Any, legacy_ssl_support: Any = None
        ) -> Any:
            session = orig_req_create(cookiejar, legacy_ssl_support)
            orig_session_send = session.send

            def guarded_session_send(prep: Any, *args: Any, **kwargs: Any) -> Any:
                target_url = getattr(prep, "url", None)
                if isinstance(target_url, str):
                    _assert_safe_or_raise_yt(target_url)
                return orig_session_send(prep, *args, **kwargs)

            session.send = guarded_session_send
            return session

        requests_rh._create_instance = safe_requests_create_instance


def _build_ydl_opts(extra: dict[str, Any] | None = None) -> dict[str, Any]:
    opts: dict[str, Any] = {
        "quiet": True,
        "no_warnings": True,
        "noprogress": True,
        "noplaylist": True,
        "playlist_items": "1",
        "allow_playlist_files": False,
        "cachedir": False,
        "enable_file_urls": False,
        "restrictfilenames": True,
        "windowsfilenames": True,
        "socket_timeout": 15,
        "retries": 2,
        "extractor_retries": 2,
        "max_filesize": MAX_DOWNLOAD_BYTES,
        "netrc_location": None,
        "cookiefile": None,
        "cookiesfrombrowser": None,
        "writedescription": False,
        "writeinfojson": False,
        "writethumbnail": False,
        "writesubtitles": False,
        "writeautomaticsub": False,
    }
    if extra:
        opts.update(extra)
    return opts


def _open_ydl(opts: dict[str, Any]) -> Any:
    ydl = yt_dlp.YoutubeDL(opts)
    _attach_ytdlp_ssrf_guard(ydl)
    return ydl


# ---------------------------------------------------------------------------
# Format & Metadata Analysis
# ---------------------------------------------------------------------------


def format_duration(seconds: float | None) -> str:
    if seconds is None:
        return "--:--"
    try:
        total = int(seconds)
    except (TypeError, ValueError):
        return "--:--"
    if total < 0:
        return "--:--"
    hours, rem = divmod(total, 3600)
    minutes, secs = divmod(rem, 60)
    if hours > 0:
        return f"{hours}:{minutes:02d}:{secs:02d}"
    return f"{minutes:02d}:{secs:02d}"


def format_filesize(num_bytes: float | None) -> str | None:
    if not num_bytes or num_bytes <= 0:
        return None
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024.0 or unit == "GB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024.0
    return None


def effective_resolution(
    width: float | None, height: float | None
) -> int:
    w = int(width) if isinstance(width, (int, float)) and width > 0 else 0
    h = int(height) if isinstance(height, (int, float)) and height > 0 else 0
    if w == 0 and h == 0:
        return 0
    if w == 0:
        return h
    if h == 0:
        return w
    long_edge = max(w, h)
    short_edge = min(w, h)
    for min_long, min_short, tier in VIDEO_QUALITY_TIERS:
        if long_edge >= min_long or short_edge >= min_short:
            return tier
    return short_edge


def _normalize_platform(info: dict[str, Any]) -> str:
    raw = str(info.get("extractor_key") or info.get("extractor") or "Web").strip()
    key = raw.lower()
    if key in PLATFORM_DISPLAY_NAMES:
        return PLATFORM_DISPLAY_NAMES[key]
    return _sanitize_text(raw, max_len=40, default="Web")


def _quality_label(res: int) -> str:
    labels = {
        2160: "2160p (4K UHD)",
        1440: "1440p (2K QHD)",
        1080: "1080p (Full HD)",
        720: "720p (HD)",
        480: "480p (SD)",
        360: "360p",
        240: "240p",
        144: "144p",
    }
    return labels.get(res, f"{res}p")


def _is_video_stream(fmt: dict[str, Any]) -> bool:
    vcodec = fmt.get("vcodec")
    if vcodec is not None:
        return str(vcodec).lower() != "none"
    if fmt.get("width") or fmt.get("height"):
        return True
    ext = str(fmt.get("ext") or "").lower()
    return ext in VIDEO_CONTAINER_EXTS


def _is_audio_stream(fmt: dict[str, Any]) -> bool:
    acodec = fmt.get("acodec")
    return acodec is not None and str(acodec).lower() != "none"


def _unwrap_single_entry(info: dict[str, Any]) -> dict[str, Any]:
    """Unwrap single-video playlist/carousel wrappers safely when entries exist."""
    entries = info.get("entries")
    if isinstance(entries, list):
        for entry in entries:
            if isinstance(entry, dict):
                return entry
        raise HTTPException(
            status_code=422, detail="No downloadable media found at this URL."
        )
    return info


def _classify_ytdlp_error(
    exc: Exception, *, operation: str = "inspect"
) -> tuple[str, int, str]:
    """Map raw extractor/downloader errors into safe, non-leaking user messages."""
    raw = str(exc).lower().replace("\u2019", "'")

    if "ssrf blocked" in raw:
        return (
            "ssrf_blocked",
            400,
            "Target or redirect URL is prohibited by SSRF security policy.",
        )
    if (
        "exceeds maximum" in raw
        or "max-filesize" in raw
        or "file is larger than" in raw
    ):
        return (
            "file_too_large",
            413,
            "Requested media exceeds the maximum allowed file size.",
        )
    if (
        "not a bot" in raw
        or "ip is likely being blocked" in raw
        or "ip address is blocked" in raw
        or "all player responses are invalid" in raw
    ):
        return (
            "bot_or_ip_blocked",
            422,
            "Blocked by source platform anti-bot protection (cloud/server IP is blocked; self-hosting on a home connection usually works).",
        )
    if (
        "drm" in raw
        or "widevine" in raw
        or "fairplay" in raw
    ):
        return (
            "drm_protected",
            422,
            "This media is DRM-protected and cannot be downloaded.",
        )
    if (
        "geo restricted" in raw
        or "geo-restricted" in raw
        or "not available in your country" in raw
        or "blocked it in your country" in raw
        or "blocked in your country" in raw
        or "not made this video available in your country" in raw
    ):
        return (
            "geo_restricted",
            422,
            "This media is geo-restricted and unavailable from the server region.",
        )
    if (
        "login required" in raw
        or "requiring login" in raw
        or "behind the login page" in raw
        or "sign in to confirm" in raw
        or "confirm your age" in raw
        or "age-restricted" in raw
        or "use --cookies" in raw
        or "cookiesfrombrowser" in raw
        or "authentication" in raw
    ):
        return (
            "auth_required",
            422,
            "Source platform requires account login, cookies, or age verification.",
        )
    if (
        "http error 429" in raw
        or "too many requests" in raw
        or "rate limit exceeded" in raw
    ):
        return (
            "upstream_rate_limit",
            429,
            "Upstream platform rate-limited requests from this server IP (HTTP 429). Please try again later.",
        )
    if "http error 403" in raw or "403: forbidden" in raw:
        return (
            "upstream_forbidden",
            422,
            "Upstream platform rejected download access (HTTP 403; often caused by server IP blocks or expired stream signatures).",
        )
    if (
        "private video" in raw
        or "this video is private" in raw
        or "members-only" in raw
        or "join this channel" in raw
        or "video unavailable" in raw
        or "video is unavailable" in raw
        or "has been removed" in raw
        or "does not exist" in raw
        or "has been terminated" in raw
        or "http error 404" in raw
    ):
        return (
            "unavailable",
            422,
            "This media is private, removed, or no longer available.",
        )
    if (
        "javascript runtime" in raw
        or "n challenge" in raw
        or "signature extraction" in raw
        or "js challenge" in raw
        or "challenge solver" in raw
        or "error running deno" in raw
    ):
        return (
            "js_challenge_failed",
            422,
            "Failed to solve source platform JavaScript challenge.",
        )
    if (
        "requested format is not available" in raw
        or "no video formats found" in raw
    ):
        return (
            "format_unavailable",
            422,
            "Requested format or quality is not available for this media.",
        )
    if (
        "does not contain any audio" in raw
        or "unable to obtain file audio codec" in raw
    ):
        return (
            "no_audio_stream",
            422,
            "This video does not contain an audio track to extract as MP3.",
        )
    if "ffprobe" in raw or "ffmpeg" in raw or "postprocessing" in raw:
        return (
            "postprocess_error",
            422,
            "Media post-processing with FFmpeg failed.",
        )
    if "unsupported url" in raw or "no suitable extractor" in raw:
        return (
            "unsupported_url",
            422,
            "Unsupported URL or no downloadable video was found on this page.",
        )
    if (
        "timed out" in raw
        or "timeout" in raw
        or "connection reset" in raw
        or "unable to download webpage" in raw
        or "unable to download api page" in raw
        or "name resolution" in raw
        or "tlsv1" in raw
        or "ssl:" in raw
    ):
        return (
            "upstream_network",
            502,
            "Network timeout or connection error while reaching the source platform.",
        )

    if operation == "inspect":
        return (
            "extract_failed",
            422,
            "Unable to inspect this video URL. Ensure it is public and supported.",
        )
    return (
        "download_failed",
        422,
        "Failed to download media. Please verify the URL is public and supported.",
    )


def analyze_formats(info: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Analyze yt-dlp info dict into available MP4, WebM, and MP3 quality options."""
    formats = [f for f in (info.get("formats") or []) if isinstance(f, dict)]

    if not formats and info.get("ext"):
        formats = [info]

    video_tiers: dict[str, set[int]] = {"mp4": set(), "webm": set()}
    video_available: dict[str, bool] = {"mp4": False, "webm": False}
    has_audio = False
    has_unprobed_audio = False
    max_abr = 0.0

    for fmt in formats:
        ext = str(fmt.get("ext") or "").lower()
        acodec = fmt.get("acodec")
        if _is_audio_stream(fmt):
            has_audio = True
            abr = fmt.get("abr") or fmt.get("tbr") or 0
            if isinstance(abr, (int, float)) and abr > max_abr:
                max_abr = float(abr)
        elif acodec is None and (
            ext in AUDIO_ONLY_EXTS or ext in VIDEO_CONTAINER_EXTS
        ):
            has_unprobed_audio = True

        if ext in video_tiers and _is_video_stream(fmt):
            video_available[ext] = True
            res = effective_resolution(fmt.get("width"), fmt.get("height"))
            if res > 0:
                video_tiers[ext].add(res)

    result: dict[str, dict[str, Any]] = {}
    for container in ("mp4", "webm"):
        sorted_res = sorted(video_tiers[container], reverse=True)
        if video_available[container]:
            qualities = [{"id": "best", "label": "Best Available"}]
            qualities.extend(
                {"id": str(r), "label": _quality_label(r)} for r in sorted_res
            )
            result[container] = {"available": True, "qualities": qualities}
        else:
            result[container] = {"available": False, "qualities": []}

    if has_audio or has_unprobed_audio:
        mp3_qualities = [{"id": "best", "label": "Best Audio"}]
        if max_abr >= 256:
            mp3_qualities.append({"id": "320", "label": "320 kbps"})
        mp3_qualities.extend(
            [
                {"id": "192", "label": "192 kbps"},
                {"id": "128", "label": "128 kbps"},
            ]
        )
        result["mp3"] = {"available": True, "qualities": mp3_qualities}
    else:
        result["mp3"] = {"available": False, "qualities": []}

    return result


def _safe_format_id(fmt: dict[str, Any]) -> str | None:
    raw = str(fmt.get("format_id") or "").strip()
    if raw and FORMAT_ID_RE.fullmatch(raw):
        return raw
    return None


def _pick_format_selector(info: dict[str, Any], fmt: str, quality: str) -> str:
    """Choose an explicit, injection-safe yt-dlp format selector."""
    fmt_clean = (fmt or "").lower().strip()
    quality_clean = (quality or "best").lower().strip()
    if fmt_clean not in ALLOWED_FORMATS:
        raise HTTPException(status_code=400, detail="Unsupported format.")
    if quality_clean not in ALLOWED_QUALITIES:
        raise HTTPException(status_code=400, detail="Unsupported quality.")

    if fmt_clean == "mp3":
        return "bestaudio/best"

    formats = [f for f in (info.get("formats") or []) if isinstance(f, dict)]
    video_candidates = [
        f
        for f in formats
        if str(f.get("ext") or "").lower() == fmt_clean
        and _is_video_stream(f)
        and _safe_format_id(f) is not None
    ]

    if quality_clean != "best" and quality_clean.isdigit():
        target = int(quality_clean)
        exact = [
            f
            for f in video_candidates
            if effective_resolution(f.get("width"), f.get("height")) == target
        ]
        if exact:
            video_candidates = exact
        else:
            video_candidates = [
                f
                for f in video_candidates
                if 0
                < effective_resolution(f.get("width"), f.get("height"))
                <= target
            ]

    video_candidates.sort(
        key=lambda f: (
            effective_resolution(f.get("width"), f.get("height")),
            1 if _is_audio_stream(f) else 0,
            float(f.get("tbr") or 0),
            float(f.get("filesize") or f.get("filesize_approx") or 0),
        ),
        reverse=True,
    )

    if video_candidates:
        best_v = video_candidates[0]
        vid = _safe_format_id(best_v)
        if vid:
            if _is_audio_stream(best_v):
                return vid

            audio_candidates = [
                f
                for f in formats
                if not _is_video_stream(f)
                and _is_audio_stream(f)
                and _safe_format_id(f) is not None
            ]

            def _audio_rank(af: dict[str, Any]) -> tuple[int, float]:
                aext = str(af.get("ext") or "").lower()
                acodec = str(af.get("acodec") or "").lower()
                if fmt_clean == "mp4":
                    pref = (
                        2
                        if (aext == "m4a" or "mp4a" in acodec or "aac" in acodec)
                        else 1
                    )
                else:
                    pref = (
                        2
                        if (aext == "webm" or "opus" in acodec or "vorbis" in acodec)
                        else 1
                    )
                return (pref, float(af.get("abr") or af.get("tbr") or 0))

            audio_candidates.sort(key=_audio_rank, reverse=True)
            if audio_candidates:
                aid = _safe_format_id(audio_candidates[0])
                if aid:
                    return f"{vid}+{aid}/{vid}/best[ext={fmt_clean}]/best"
            if best_v.get("vcodec") is None and best_v.get("acodec") is None:
                return f"{vid}/best[ext={fmt_clean}]/best"
            return f"{vid}+bestaudio/{vid}/best[ext={fmt_clean}]/best"

    if quality_clean != "best" and quality_clean.isdigit():
        return (
            f"bestvideo[ext={fmt_clean}][height<={quality_clean}]+bestaudio/"
            f"best[ext={fmt_clean}][height<={quality_clean}]/best[ext={fmt_clean}]/best"
        )
    return f"bestvideo[ext={fmt_clean}]+bestaudio/best[ext={fmt_clean}]/best"


# ---------------------------------------------------------------------------
# Background Job Processing & Janitor
# ---------------------------------------------------------------------------


def _cleanup_job_dir(job_dir: str) -> None:
    try:
        root_real = os.path.realpath(TEMP_ROOT)
        dir_real = os.path.realpath(job_dir)
        if os.path.commonpath([root_real, dir_real]) == root_real and dir_real != root_real:
            shutil.rmtree(dir_real, ignore_errors=True)
    except OSError:
        pass


def _purge_stale_jobs() -> None:
    now = time.time()
    to_delete: list[tuple[str, str]] = []
    with JOBS_LOCK:
        for job_id, job in list(JOBS.items()):
            if job.get("status") == "streaming":
                continue
            updated_at = float(job.get("updated_at") or job.get("created_at") or now)
            if now - updated_at > JOB_TTL_SECONDS:
                to_delete.append((job_id, str(job.get("job_dir") or "")))
                del JOBS[job_id]
    for _, job_dir in to_delete:
        if job_dir:
            _cleanup_job_dir(job_dir)


def _sweep_orphaned_dirs_on_startup() -> None:
    _ensure_temp_root()
    try:
        for entry in os.scandir(TEMP_ROOT):
            if entry.is_dir(follow_symlinks=False):
                _cleanup_job_dir(entry.path)
            elif entry.is_symlink() or entry.is_file(follow_symlinks=False):
                try:
                    os.unlink(entry.path)
                except OSError:
                    pass
    except OSError:
        pass


def _run_download_job(job_id: str, url: str, fmt: str, quality: str) -> None:
    job_dir = _safe_job_dir(job_id)
    try:
        with JOBS_LOCK:
            if job_id not in JOBS:
                return
            JOBS[job_id]["status"] = "downloading"
            JOBS[job_id]["progress"] = 10
            JOBS[job_id]["updated_at"] = time.time()

        validate_video_url(url)

        info_opts = _build_ydl_opts()
        with _open_ydl(info_opts) as ydl:
            info = ydl.extract_info(url, download=False)

        if not isinstance(info, dict):
            raise TypeError("Unable to extract video metadata.")

        info = _unwrap_single_entry(info)
        _validate_extracted_info_urls(info)
        selector = _pick_format_selector(info, fmt, quality)
        title = _sanitize_text(info.get("title"), max_len=120, default="streamvault_media")

        with JOBS_LOCK:
            if job_id not in JOBS:
                return
            JOBS[job_id]["progress"] = 35
            JOBS[job_id]["title"] = title
            JOBS[job_id]["updated_at"] = time.time()

        def _progress_hook(data: dict[str, Any]) -> None:
            if data.get("status") != "downloading":
                return
            total = data.get("total_bytes") or data.get("total_bytes_estimate")
            downloaded = data.get("downloaded_bytes") or 0
            if isinstance(total, (int, float)) and total > 0:
                if total > MAX_DOWNLOAD_BYTES:
                    raise ValueError("File exceeds maximum permitted download size.")
                pct = min(90, 35 + int((downloaded / total) * 55))
                with JOBS_LOCK:
                    if job_id in JOBS:
                        JOBS[job_id]["progress"] = pct
                        JOBS[job_id]["updated_at"] = time.time()

        dl_extra: dict[str, Any] = {
            "format": selector,
            "outtmpl": os.path.join(job_dir, "media.%(ext)s"),
            "progress_hooks": [_progress_hook],
        }

        if fmt == "mp3":
            pref_q = quality if quality in {"320", "192", "128"} else "192"
            dl_extra["postprocessors"] = [
                {
                    "key": "FFmpegExtractAudio",
                    "preferredcodec": "mp3",
                    "preferredquality": pref_q,
                }
            ]
        else:
            dl_extra["merge_output_format"] = fmt

        dl_opts = _build_ydl_opts(dl_extra)
        with _open_ydl(dl_opts) as ydl:
            ydl.download([url])

        candidates: list[Path] = []
        for entry in os.scandir(job_dir):
            if entry.is_symlink():
                raise RuntimeError("Unexpected symlink in download workspace.")
            if entry.is_file(follow_symlinks=False):
                p = Path(os.path.realpath(entry.path))
                if (
                    os.path.commonpath([os.path.realpath(job_dir), str(p)])
                    != os.path.realpath(job_dir)
                ):
                    raise RuntimeError("Invalid output path.")
                if p.suffix.lower() not in {".part", ".ytdl"}:
                    candidates.append(p)

        if not candidates:
            raise RuntimeError("Download completed without producing a media file.")

        target_file = max(candidates, key=lambda p: p.stat().st_size)
        file_size = target_file.stat().st_size
        if file_size <= 0:
            raise RuntimeError("Downloaded file is empty.")
        if file_size > MAX_DOWNLOAD_BYTES:
            raise RuntimeError("Downloaded file exceeds maximum allowed size.")

        ext = target_file.suffix.lstrip(".").lower()
        if ext not in ALLOWED_FORMATS:
            ext = fmt

        with JOBS_LOCK:
            if job_id not in JOBS:
                _cleanup_job_dir(job_dir)
                return
            JOBS[job_id].update(
                {
                    "status": "ready",
                    "progress": 100,
                    "file_path": str(target_file),
                    "ext": ext,
                    "title": title,
                    "filesize": file_size,
                    "filesize_text": format_filesize(file_size),
                    "download_url": f"/api/jobs/{job_id}/download",
                    "updated_at": time.time(),
                }
            )
    except HTTPException as exc:
        _cleanup_job_dir(job_dir)
        with JOBS_LOCK:
            if job_id in JOBS:
                JOBS[job_id].update(
                    {
                        "status": "error",
                        "error": str(exc.detail),
                        "updated_at": time.time(),
                    }
                )
    except Exception as exc:  # noqa: BLE001 - top-level background worker boundary must clean temp dir
        category, _status_code, safe_msg = _classify_ytdlp_error(
            exc, operation="download"
        )
        logger.warning(
            "Download job %s failed (%s: %s)", job_id, category, type(exc).__name__
        )
        _cleanup_job_dir(job_dir)
        with JOBS_LOCK:
            if job_id in JOBS:
                JOBS[job_id].update(
                    {
                        "status": "error",
                        "error": safe_msg,
                        "updated_at": time.time(),
                    }
                )


# ---------------------------------------------------------------------------
# FastAPI Lifespan, Middleware & App
# ---------------------------------------------------------------------------


async def _janitor_loop(stop_event: asyncio.Event) -> None:
    while not stop_event.is_set():
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=60.0)
        except TimeoutError:
            _purge_stale_jobs()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    _sweep_orphaned_dirs_on_startup()
    stop_event = asyncio.Event()
    janitor_task = asyncio.create_task(_janitor_loop(stop_event))
    try:
        yield
    finally:
        stop_event.set()
        janitor_task.cancel()
        try:
            await janitor_task
        except asyncio.CancelledError:
            pass


app = FastAPI(
    title=APP_NAME,
    version="1.0.0",
    docs_url="/docs" if ENABLE_DOCS else None,
    redoc_url="/redoc" if ENABLE_DOCS else None,
    openapi_url="/openapi.json" if ENABLE_DOCS else None,
    lifespan=lifespan,
)

allowed_origins = [
    o.strip()
    for o in os.environ.get("ALLOWED_ORIGINS", "").split(",")
    if o.strip()
]
if allowed_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
    )


@app.middleware("http")
async def security_middleware(request: Request, call_next: Any):
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > MAX_BODY_BYTES:
                return JSONResponse(
                    status_code=413,
                    content={"detail": "Request payload too large."},
                )
        except ValueError:
            return JSONResponse(
                status_code=400,
                content={"detail": "Invalid Content-Length header."},
            )

    if request.method in {"POST", "PUT", "PATCH"}:
        body = await request.body()
        if len(body) > MAX_BODY_BYTES:
            return JSONResponse(
                status_code=413,
                content={"detail": "Request payload too large."},
            )

    response = await call_next(request)

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=(), payment=()"
    )
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.tailwindcss.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com data:; "
        "img-src 'self' https: data:; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'; "
        "form-action 'self'"
    )
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        response.headers["Pragma"] = "no-cache"
    return response


def _client_ip(request: Request) -> str:
    peer_ip = request.client.host if request.client else "unknown"
    if TRUST_PROXY_HEADERS:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            parts = [p.strip() for p in forwarded.split(",") if p.strip()]
            if parts:
                idx = max(0, len(parts) - TRUSTED_PROXY_HOPS)
                candidate = parts[idx]
                try:
                    ipaddress.ip_address(candidate)
                    return candidate
                except ValueError:
                    pass
    return peer_ip


# ---------------------------------------------------------------------------
# Request Models
# ---------------------------------------------------------------------------


class InfoRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=MAX_URL_LENGTH)


class JobCreateRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=MAX_URL_LENGTH)
    format: Literal["mp4", "webm", "mp3"] = "mp4"
    quality: str = Field(default="best", min_length=1, max_length=16)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.get("/", include_in_schema=False)
async def serve_index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html", media_type="text/html; charset=utf-8")


@app.get("/static/tailwind-config.js", include_in_schema=False)
async def serve_tailwind_config() -> FileResponse:
    return FileResponse(
        STATIC_DIR / "tailwind-config.js",
        media_type="application/javascript; charset=utf-8",
    )


@app.get("/static/app.js", include_in_schema=False)
async def serve_app_js() -> FileResponse:
    return FileResponse(
        STATIC_DIR / "app.js",
        media_type="application/javascript; charset=utf-8",
    )


@app.get("/health")
async def health_check() -> dict[str, Any]:
    return {
        "status": "ok",
        "ffmpeg": shutil.which("ffmpeg") is not None,
    }


@app.post("/api/info")
async def extract_info_endpoint(
    payload: InfoRequest, request: Request
) -> dict[str, Any]:
    ip = _client_ip(request)
    if not RATE_LIMITER.allow(f"info:{ip}", RATE_LIMIT_INFO_PER_MIN):
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded. Please try again in a minute.",
        )

    safe_url = validate_video_url(payload.url)

    def _fetch() -> dict[str, Any]:
        opts = _build_ydl_opts()
        with _open_ydl(opts) as ydl:
            info = ydl.extract_info(safe_url, download=False)
        if not isinstance(info, dict):
            raise HTTPException(
                status_code=422, detail="Could not extract metadata for this URL."
            )
        info = _unwrap_single_entry(info)
        _validate_extracted_info_urls(info)
        return info

    loop = asyncio.get_running_loop()
    try:
        info = await loop.run_in_executor(EXECUTOR, _fetch)
    except HTTPException:
        raise
    except Exception as exc:
        category, status_code, safe_msg = _classify_ytdlp_error(
            exc, operation="inspect"
        )
        logger.warning(
            "Metadata extraction failed (%s: %s)", category, type(exc).__name__
        )
        raise HTTPException(status_code=status_code, detail=safe_msg) from exc

    return {
        "id": _sanitize_text(info.get("id"), max_len=64, default=""),
        "title": _sanitize_text(info.get("title"), max_len=180, default="Untitled Media"),
        "uploader": _sanitize_text(
            info.get("uploader") or info.get("channel"), max_len=100, default=""
        ),
        "platform": _normalize_platform(info),
        "duration": info.get("duration"),
        "duration_text": format_duration(info.get("duration")),
        "thumbnail": _sanitize_thumbnail_url(info.get("thumbnail")),
        "formats": analyze_formats(info),
    }


@app.post("/api/jobs")
async def create_job_endpoint(
    payload: JobCreateRequest, request: Request
) -> dict[str, Any]:
    ip = _client_ip(request)
    if not RATE_LIMITER.allow(f"jobs:{ip}", RATE_LIMIT_JOBS_PER_MIN):
        raise HTTPException(
            status_code=429,
            detail="Too many download jobs requested. Please wait a minute.",
        )

    _purge_stale_jobs()

    safe_url = validate_video_url(payload.url)
    fmt = payload.format.lower().strip()
    quality = payload.quality.lower().strip()
    if quality not in ALLOWED_QUALITIES:
        raise HTTPException(status_code=400, detail="Unsupported quality option.")

    job_id = secrets.token_hex(16)
    job_dir = _safe_job_dir(job_id)

    with JOBS_LOCK:
        active_count = sum(
            1
            for j in JOBS.values()
            if j.get("status") in {"queued", "downloading", "ready", "streaming"}
        )
        if active_count >= MAX_ACTIVE_JOBS:
            raise HTTPException(
                status_code=503,
                detail="Server is busy processing other downloads. Please try again shortly.",
            )

        os.makedirs(job_dir, mode=0o700, exist_ok=False)
        now = time.time()
        JOBS[job_id] = {
            "job_id": job_id,
            "status": "queued",
            "progress": 0,
            "format": fmt,
            "quality": quality,
            "job_dir": job_dir,
            "file_path": None,
            "ext": fmt,
            "title": "streamvault_media",
            "filesize": None,
            "filesize_text": None,
            "download_url": None,
            "error": None,
            "created_at": now,
            "updated_at": now,
        }

    loop = asyncio.get_running_loop()
    loop.run_in_executor(EXECUTOR, _run_download_job, job_id, safe_url, fmt, quality)

    return {
        "job_id": job_id,
        "status": "queued",
        "progress": 0,
    }


@app.get("/api/jobs/{job_id}")
async def get_job_status(job_id: str) -> dict[str, Any]:
    if not JOB_ID_RE.fullmatch(job_id):
        raise HTTPException(status_code=404, detail="Job not found.")
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found.")
        return {
            "job_id": job["job_id"],
            "status": job["status"],
            "progress": job["progress"],
            "download_url": job["download_url"],
            "filesize": job["filesize"],
            "filesize_text": job["filesize_text"],
            "error": job["error"],
        }


@app.get("/api/jobs/{job_id}/download")
async def download_job_file(job_id: str) -> StreamingResponse:
    job_dir = _safe_job_dir(job_id)

    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Download not found or expired.")
        status = job.get("status")
        if status == "streaming":
            raise HTTPException(status_code=409, detail="Download already in progress.")
        if status != "ready":
            raise HTTPException(status_code=409, detail="Download is not ready yet.")

        file_path = str(job.get("file_path") or "")
        ext = str(job.get("ext") or "mp4")
        title = str(job.get("title") or "streamvault_media")
        job["status"] = "streaming"
        job["updated_at"] = time.time()

    real_file = os.path.realpath(file_path)
    if (
        not file_path
        or os.path.islink(file_path)
        or os.path.commonpath([job_dir, real_file]) != job_dir
        or not os.path.isfile(real_file)
    ):
        _cleanup_job_dir(job_dir)
        with JOBS_LOCK:
            JOBS.pop(job_id, None)
        raise HTTPException(status_code=404, detail="Media file not found.")

    file_size = os.path.getsize(real_file)
    content_disposition = _build_content_disposition(title, ext)
    media_type = MEDIA_MIME_TYPES.get(ext, "application/octet-stream")

    def _stream_and_delete():
        try:
            with open(real_file, "rb") as fh:
                while True:
                    chunk = fh.read(65536)
                    if not chunk:
                        break
                    yield chunk
        finally:
            _cleanup_job_dir(job_dir)
            with JOBS_LOCK:
                JOBS.pop(job_id, None)

    return StreamingResponse(
        _stream_and_delete(),
        media_type=media_type,
        headers={
            "Content-Length": str(file_size),
            "Content-Disposition": content_disposition,
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store, no-cache, must-revalidate",
        },
    )


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", "8000"))
    host = os.environ.get("HOST", "127.0.0.1")
    uvicorn.run(
        "main:app",
        host=host,
        port=port,
        server_header=False,
    )
