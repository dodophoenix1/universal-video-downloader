"""Comprehensive security & functional test suite for StreamVault."""

from __future__ import annotations

import http.server
import os
import sys
import threading
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import main


@pytest.fixture(autouse=True)
def reset_state():
    main.RATE_LIMITER.reset()
    with main.JOBS_LOCK:
        main.JOBS.clear()
    yield
    main.RATE_LIMITER.reset()


def test_ssrf_blocks_all_dangerous_urls():
    malicious_urls = [
        "",
        "   ",
        "ftp://example.com/video.mp4",
        "file:///etc/passwd",
        "gopher://127.0.0.1:6379/_INFO",
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "http://localhost/video",
        "http://localhost:8000/admin",
        "http://sub.localhost/video",
        "http://127.0.0.1/video",
        "http://127.0.0.1:8000/a",
        "http://127.1/a",
        "http://2130706433/a",
        "http://0x7f000001/a",
        "http://0177.0.0.1/a",
        "http://[::1]/a",
        "http://[::ffff:127.0.0.1]/a",
        "http://[::ffff:169.254.169.254]/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.1/internal",
        "http://172.16.0.1/internal",
        "http://192.168.1.1/router",
        "http://100.64.0.1/cgnat",
        "http://0.0.0.0/zero",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://backend.internal/secret",
        "http://printer.local/status",
        "http://redis:6379/",
        "http://redis/",
        "https://user:pass@www.youtube.com/watch?v=dQw4w9WgXcQ",
        "https://www.youtube.com:22/watch?v=dQw4w9WgXcQ",
        "https://www.youtube.com/watch?v=1\r\nHost: evil.com",
        "https://www.youtube.com/watch\\test",
        "http://ⓛⓞⓒⓐⓛⓗⓞⓢⓣ/admin",
        "http://１２７.０.０.１/admin",
        "http://%31%32%37%2e%30%2e%30%2e%31/",
        "https://www.youtube.com/" + ("a" * 2100),
    ]
    for url in malicious_urls:
        with pytest.raises(main.HTTPException) as exc_info:
            main.validate_video_url(url)
        assert exc_info.value.status_code == 400, f"Expected 400 for {url!r}"


def test_ssrf_allows_legitimate_public_urls(monkeypatch):
    monkeypatch.setattr(
        main.socket,
        "getaddrinfo",
        lambda host, port, type=0: [
            (main.socket.AF_INET, main.socket.SOCK_STREAM, 6, "", ("142.250.190.46", 443))
        ],
    )
    valid = main.validate_video_url("https://www.youtube.com/watch?v=dQw4w9WgXcQ")
    assert valid == "https://www.youtube.com/watch?v=dQw4w9WgXcQ"


def test_ssrf_blocks_dns_resolving_to_private_ip(monkeypatch):
    monkeypatch.setattr(
        main.socket,
        "getaddrinfo",
        lambda host, port, type=0: [
            (main.socket.AF_INET, main.socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))
        ],
    )
    with pytest.raises(main.HTTPException) as exc_info:
        main.validate_video_url("https://rebind.example.com/video")
    assert exc_info.value.status_code == 400


def test_ytdlp_redirect_ssrf_guard_blocks_302_to_metadata(monkeypatch):
    """Spin up a real HTTP server returning 302 -> 169.254.169.254 and verify real yt-dlp blocks it."""
    import yt_dlp as real_yt_dlp

    for var in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        monkeypatch.delenv(var, raising=False)

    class RedirectHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
            self.end_headers()

        def log_message(self, format, *args):
            return

    server = http.server.HTTPServer(("127.0.0.1", 0), RedirectHandler)
    port = server.server_port
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        monkeypatch.setattr(main, "yt_dlp", real_yt_dlp)
        orig_check = main._check_url_safety

        def allow_only_test_server(u, *, resolve_dns=True):
            if u.startswith(f"http://127.0.0.1:{port}"):
                return u
            return orig_check(u, resolve_dns=resolve_dns)

        monkeypatch.setattr(main, "_check_url_safety", allow_only_test_server)

        from yt_dlp.networking.exceptions import RequestError as YtRequestError

        # Verify default (RequestsRH) blocks 302 redirect to metadata IP
        with main._open_ydl(main._build_ydl_opts()) as ydl:
            assert "Websockets" not in ydl._request_director.handlers
            with pytest.raises(YtRequestError) as exc_info:
                ydl.urlopen(f"http://127.0.0.1:{port}/video")
            assert "SSRF blocked" in str(exc_info.value)

        # Verify UrllibRH fallback also blocks 302 redirect to metadata IP
        with main._open_ydl(main._build_ydl_opts()) as ydl:
            ydl._request_director.handlers.pop("Requests", None)
            with pytest.raises(YtRequestError) as exc_info:
                ydl.urlopen(f"http://127.0.0.1:{port}/video")
            assert "SSRF blocked" in str(exc_info.value)
    finally:
        server.shutdown()
        server.server_close()


def test_content_disposition_prevents_header_injection():
    evil_title = 'video"\r\nSet-Cookie: session=evil\r\nX-Injected: true / ../etc/passwd 🎬'
    disp = main._build_content_disposition(evil_title, "mp4")
    assert "\r" not in disp
    assert "\n" not in disp
    assert disp.startswith('attachment; filename="')
    assert "; filename*=UTF-8''" in disp
    assert disp.count('"') == 2
    assert "../" not in disp
    disp.encode("latin-1")


def test_security_headers_and_csp_and_no_inline_scripts():
    client = TestClient(main.app)
    resp = client.get("/")
    assert resp.status_code == 200
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert resp.headers.get("X-Frame-Options") == "DENY"
    assert resp.headers.get("Referrer-Policy") == "no-referrer"
    csp = resp.headers.get("Content-Security-Policy", "")
    assert "object-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "script-src 'self' https://cdn.tailwindcss.com" in csp
    assert "'unsafe-inline'" not in csp.split("script-src")[1].split(";")[0]
    assert "Access-Control-Allow-Origin" not in resp.headers

    # Ensure frontend JS never uses innerHTML
    app_js = (Path(__file__).resolve().parent.parent / "static" / "app.js").read_text("utf-8")
    assert "innerHTML" not in app_js


def test_oversized_body_rejected_with_413():
    client = TestClient(main.app)
    huge_payload = '{"url": "https://example.com/' + ("x" * 20000) + '"}'
    resp = client.post(
        "/api/info",
        content=huge_payload,
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 413


def test_path_traversal_on_job_endpoints():
    client = TestClient(main.app)
    for bad_id in ["../etc/passwd", "..%2F..%2Fetc", "invalid-id", "a" * 31, "g" * 32]:
        assert client.get(f"/api/jobs/{bad_id}").status_code == 404
        assert client.get(f"/api/jobs/{bad_id}/download").status_code == 404


def test_symlink_in_job_dir_rejected(monkeypatch):
    fake_yt = MagicMock()

    class SymlinkYDL:
        def __init__(self, opts):
            self.opts = opts

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def extract_info(self, url, download=False):
            return {
                "id": "x",
                "title": "<script>alert(1)</script>",
                "duration": 10,
                "extractor_key": "Youtube",
                "formats": [
                    {"format_id": "18", "ext": "mp4", "vcodec": "avc1", "acodec": "aac", "width": 640, "height": 360}
                ],
            }

        def download(self, urls):
            out_path = self.opts["outtmpl"].replace("%(ext)s", "mp4")
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            os.symlink("/etc/passwd", out_path)

    monkeypatch.setattr(main, "yt_dlp", fake_yt)
    fake_yt.YoutubeDL = SymlinkYDL
    monkeypatch.setattr(
        main.socket,
        "getaddrinfo",
        lambda host, port, type=0: [
            (main.socket.AF_INET, main.socket.SOCK_STREAM, 6, "", ("142.250.190.46", 443))
        ],
    )

    with TestClient(main.app) as client:
        res = client.post(
            "/api/jobs",
            json={"url": "https://www.youtube.com/watch?v=dQw4w9WgXcQ", "format": "mp4", "quality": "360"},
        )
        assert res.status_code == 200
        job_id = res.json()["job_id"]
        import time

        status_body = None
        for _ in range(30):
            status_body = client.get(f"/api/jobs/{job_id}").json()
            if status_body["status"] in {"ready", "error"}:
                break
            time.sleep(0.05)

        assert status_body is not None
        assert status_body["status"] == "error"
        assert not os.path.exists(os.path.join(main.TEMP_ROOT, job_id))


def test_rate_limiter_enforces_429(monkeypatch):
    monkeypatch.setattr(main, "RATE_LIMIT_INFO_PER_MIN", 3)
    monkeypatch.setattr(
        main.socket,
        "getaddrinfo",
        lambda host, port, type=0: [
            (main.socket.AF_INET, main.socket.SOCK_STREAM, 6, "", ("142.250.190.46", 443))
        ],
    )

    fake_yt = MagicMock()

    class QuickYDL:
        def __init__(self, opts):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def extract_info(self, url, download=False):
            return {
                "id": "ok",
                "title": "OK",
                "duration": 5,
                "extractor_key": "Youtube",
                "formats": [{"format_id": "18", "ext": "mp4", "vcodec": "h264", "acodec": "aac", "width": 640, "height": 360}],
            }

    fake_yt.YoutubeDL = QuickYDL
    monkeypatch.setattr(main, "yt_dlp", fake_yt)

    client = TestClient(main.app)
    for _ in range(3):
        r = client.post("/api/info", json={"url": "https://www.youtube.com/watch?v=dQw4w9WgXcQ"})
        assert r.status_code == 200

    blocked = client.post("/api/info", json={"url": "https://www.youtube.com/watch?v=dQw4w9WgXcQ"})
    assert blocked.status_code == 429


def test_trusted_proxy_ip_takes_rightmost_unspoofable_hop(monkeypatch):
    monkeypatch.setattr(main, "TRUST_PROXY_HEADERS", True)
    monkeypatch.setattr(main, "TRUSTED_PROXY_HOPS", 1)
    fake_req = MagicMock()
    fake_req.client.host = "10.0.0.5"
    # Attacker tries to spoof leftmost IP on every request; proxy appends real IP at end.
    fake_req.headers = {"x-forwarded-for": "1.2.3.4, 198.51.100.42"}
    assert main._client_ip(fake_req) == "198.51.100.42"

    # Malformed header falls back to peer socket IP.
    fake_req.headers = {"x-forwarded-for": "not-an-ip"}
    assert main._client_ip(fake_req) == "10.0.0.5"


def test_thumbnail_ssrf_sanitized_in_info_response(monkeypatch):
    monkeypatch.setattr(
        main.socket,
        "getaddrinfo",
        lambda host, port, type=0: [
            (main.socket.AF_INET, main.socket.SOCK_STREAM, 6, "", ("142.250.190.46", 443))
        ],
    )
    fake_yt = MagicMock()

    class EvilMetaYDL:
        def __init__(self, opts):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def extract_info(self, url, download=False):
            return {
                "id": "v1",
                "title": "Test\r\nTitle",
                "thumbnail": "http://169.254.169.254/latest/meta-data/",
                "duration": 30,
                "extractor_key": "Youtube",
                "formats": [
                    {"format_id": "18", "ext": "mp4", "vcodec": "h264", "acodec": "aac", "width": 640, "height": 360}
                ],
            }

    fake_yt.YoutubeDL = EvilMetaYDL
    monkeypatch.setattr(main, "yt_dlp", fake_yt)
    client = TestClient(main.app)
    resp = client.post("/api/info", json={"url": "https://www.youtube.com/watch?v=dQw4w9WgXcQ"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["thumbnail"] is None
    assert "\r" not in body["title"]
    assert "\n" not in body["title"]


def test_analyze_formats_direct_unprobed_mp4_and_selector():
    info = {
        "id": "mov",
        "ext": "mp4",
        "formats": [
            {
                "format_id": "0",
                "ext": "mp4",
                "url": "https://example.com/mov_bbb.mp4",
                "vcodec": None,
                "acodec": None,
                "width": None,
                "height": None,
            }
        ],
    }
    analyzed = main.analyze_formats(info)
    assert analyzed["mp4"]["available"] is True
    assert analyzed["mp4"]["qualities"] == [{"id": "best", "label": "Best Available"}]
    assert analyzed["webm"]["available"] is False
    assert analyzed["mp3"]["available"] is True
    assert main._pick_format_selector(info, "mp4", "best") == "0/best[ext=mp4]/best"


def test_analyze_formats_respects_explicit_audio_or_video_none():
    video_only_no_dims = {
        "formats": [
            {
                "format_id": "v0",
                "ext": "mp4",
                "vcodec": "avc1",
                "acodec": "none",
                "width": None,
                "height": None,
            }
        ]
    }
    res1 = main.analyze_formats(video_only_no_dims)
    assert res1["mp4"]["available"] is True
    assert res1["mp3"]["available"] is False

    audio_in_mp4_container = {
        "formats": [
            {
                "format_id": "a0",
                "ext": "mp4",
                "vcodec": "none",
                "acodec": "mp4a.40.2",
                "abr": 128,
            }
        ]
    }
    res2 = main.analyze_formats(audio_in_mp4_container)
    assert res2["mp4"]["available"] is False
    assert res2["mp3"]["available"] is True


def test_error_classification_and_non_leakage(monkeypatch):
    monkeypatch.setattr(
        main.socket,
        "getaddrinfo",
        lambda host, port, type=0: [
            (main.socket.AF_INET, main.socket.SOCK_STREAM, 6, "", ("142.250.190.46", 443))
        ],
    )
    fake_yt = MagicMock()
    raised_error = RuntimeError("default")

    class FailingYDL:
        def __init__(self, opts):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def extract_info(self, url, download=False):
            raise raised_error

    fake_yt.YoutubeDL = FailingYDL
    monkeypatch.setattr(main, "yt_dlp", fake_yt)
    client = TestClient(main.app)

    cases = [
        (
            "ERROR: [youtube] x: Sign in to confirm you\u2019re not a bot (/tmp/secret 10.0.0.1)",
            422,
            "anti-bot",
            "/tmp/secret",
        ),
        (
            "ERROR: [instagram] Main webpage is locked behind the login page token=secret",
            422,
            "login",
            "token=secret",
        ),
        (
            "ERROR: This video is DRM protected",
            422,
            "DRM-protected",
            None,
        ),
        (
            "ERROR: Unsupported URL: https://example.com/?secret=123",
            422,
            "Unsupported URL",
            "secret=123",
        ),
        (
            "SSRF blocked: private IP 169.254.169.254",
            400,
            "SSRF security policy",
            "169.254.169.254",
        ),
    ]
    for msg, expected_code, expected_substr, forbidden in cases:
        raised_error = RuntimeError(msg)
        resp = client.post("/api/info", json={"url": "https://www.youtube.com/watch?v=dQw4w9WgXcQ"})
        assert resp.status_code == expected_code
        detail = resp.json()["detail"]
        assert expected_substr in detail
        if forbidden:
            assert forbidden not in detail


def test_playlist_entry_unwrapping_enforces_ssrf(monkeypatch):
    monkeypatch.setattr(
        main.socket,
        "getaddrinfo",
        lambda host, port, type=0: [
            (main.socket.AF_INET, main.socket.SOCK_STREAM, 6, "", ("142.250.190.46", 443))
        ],
    )
    fake_yt = MagicMock()
    payload_to_return: dict = {}

    class PlaylistYDL:
        def __init__(self, opts):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def extract_info(self, url, download=False):
            return payload_to_return

    fake_yt.YoutubeDL = PlaylistYDL
    monkeypatch.setattr(main, "yt_dlp", fake_yt)
    client = TestClient(main.app)

    payload_to_return = {
        "_type": "playlist",
        "entries": [
            {"id": "evil", "url": "http://169.254.169.254/latest/meta-data/", "formats": []}
        ],
    }
    resp_evil = client.post("/api/info", json={"url": "https://www.instagram.com/p/test/"})
    assert resp_evil.status_code == 400

    payload_to_return = {
        "_type": "playlist",
        "entries": [
            {
                "id": "ok1",
                "title": "Carousel Clip",
                "ext": "mp4",
                "extractor_key": "Instagram",
                "formats": [{"format_id": "0", "ext": "mp4", "vcodec": None, "acodec": None}],
            }
        ],
    }
    resp_ok = client.post("/api/info", json={"url": "https://www.instagram.com/p/test/"})
    assert resp_ok.status_code == 200
    assert resp_ok.json()["formats"]["mp4"]["available"] is True


def test_ytdlp_has_deno_and_ejs_available():
    import yt_dlp as real_yt_dlp
    import yt_dlp_ejs

    assert yt_dlp_ejs.version
    assert real_yt_dlp.__name__ == "yt_dlp"
    with main._open_ydl(main._build_ydl_opts()) as ydl:
        deno_rt = ydl._js_runtimes.get("deno")
        assert deno_rt is not None
        assert deno_rt.info is not None
        assert deno_rt.info.supported is True
