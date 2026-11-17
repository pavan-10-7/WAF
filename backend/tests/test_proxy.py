"""Comprehensive Integration and Unit Tests for WAF Reverse Proxy."""

import json
from pathlib import Path
from typing import Dict, List
import pytest
from fastapi.testclient import TestClient
import httpx

from app.main import create_app
from app.event_logger import EventLogger, EXPECTED_SCHEMA_KEYS
from app.proxy import WAFReverseProxy
from app.detection_adapter import DetectionAdapter


@pytest.fixture
def temp_event_log(tmp_path: Path):
    """Provides a fresh temporary events.jsonl path for each test."""
    log_file = tmp_path / "events.jsonl"
    return log_file


@pytest.fixture
def mock_upstream():
    """Mock upstream helper tracking received requests and controlling responses."""
    class MockUpstreamState:
        def __init__(self):
            self.calls: List[httpx.Request] = []
            self.response_status = 200
            self.response_body = b"Upstream OK: DVWA Response"
            self.response_headers = {"content-type": "text/html; charset=utf-8", "server": "Apache"}
            self.exception_to_raise = None

        def handle_request(self, request: httpx.Request) -> httpx.Response:
            self.calls.append(request)
            if self.exception_to_raise:
                raise self.exception_to_raise
            return httpx.Response(
                status_code=self.response_status,
                content=self.response_body,
                headers=self.response_headers,
                request=request,
            )

    return MockUpstreamState()


@pytest.fixture
def test_app_and_client(temp_event_log: Path, mock_upstream):
    """Creates a configured TestClient with mocked upstream and isolated logger."""
    app = create_app()

    mock_transport = httpx.MockTransport(mock_upstream.handle_request)
    mock_http_client = httpx.AsyncClient(transport=mock_transport)

    test_logger = EventLogger(log_path=str(temp_event_log))
    test_adapter = DetectionAdapter()

    proxy = WAFReverseProxy(
        upstream_url="http://127.0.0.1:8081",
        timeout=5.0,
        adapter=test_adapter,
        event_logger=test_logger,
        http_client=mock_http_client,
    )
    app.state.proxy = proxy

    client = TestClient(app, base_url="http://127.0.0.1:8080")
    return client, mock_upstream, temp_event_log


def test_health_check(test_app_and_client):
    """1. Health endpoint returns 200 with service status."""
    client, upstream, _ = test_app_and_client
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["service"] == "waf-proxy"
    # Health checks must not reach upstream
    assert len(upstream.calls) == 0


def test_legitimate_request_forwarded_get(test_app_and_client):
    """2. Legitimate GET request forwards to upstream and returns response."""
    client, upstream, log_file = test_app_and_client
    upstream.response_body = b"<h1>Welcome to DVWA</h1>"

    resp = client.get("/vulnerabilities/sqli/?id=1&Submit=Submit", headers={"User-Agent": "Mozilla/5.0"})

    assert resp.status_code == 200
    assert resp.text == "<h1>Welcome to DVWA</h1>"
    assert len(upstream.calls) == 1

    # Verify upstream request attributes
    fwd_req = upstream.calls[0]
    assert fwd_req.method == "GET"
    assert fwd_req.url.path == "/vulnerabilities/sqli/"
    assert fwd_req.url.query.decode() == "id=1&Submit=Submit"
    assert fwd_req.headers.get("x-forwarded-for") is not None


def test_legitimate_request_forwarded_post(test_app_and_client):
    """Preserve request body and headers across POST/PUT forwarding."""
    client, upstream, _ = test_app_and_client
    upstream.response_body = b'{"status":"created"}'
    upstream.response_headers = {"content-type": "application/json"}

    resp = client.post("/api/data", content=b"user=alice&action=login", headers={"Content-Type": "application/x-www-form-urlencoded"})

    assert resp.status_code == 200
    assert len(upstream.calls) == 1
    fwd_req = upstream.calls[0]
    assert fwd_req.method == "POST"
    assert fwd_req.content == b"user=alice&action=login"


def test_blocked_request_returns_403(test_app_and_client):
    """3 & 4. Malicious request blocked with HTTP 403 and NEVER reaches upstream."""
    client, upstream, log_file = test_app_and_client

    # Send SQL injection in query string
    resp = client.get("/vulnerabilities/sqli/?id=1%27%20OR%20%271%27=%271&Submit=Submit")

    assert resp.status_code == 403
    data = resp.json()
    assert "Forbidden" in data["detail"]
    assert data["attack_type"] == "sqli"

    # Upstream must NEVER be contacted
    assert len(upstream.calls) == 0


def test_upstream_connection_failure_returns_502(test_app_and_client):
    """6. Upstream connection failure returns HTTP 502 Bad Gateway."""
    client, upstream, _ = test_app_and_client
    upstream.exception_to_raise = httpx.ConnectError("Failed to connect to 127.0.0.1:8081")

    resp = client.get("/legitimate/path")
    assert resp.status_code == 502
    assert "502 Bad Gateway" in resp.json()["detail"]


def test_upstream_timeout_returns_504(test_app_and_client):
    """7. Upstream timeout returns HTTP 504 Gateway Timeout."""
    client, upstream, _ = test_app_and_client
    upstream.exception_to_raise = httpx.ReadTimeout("Upstream read timed out")

    resp = client.get("/slow/endpoint")
    assert resp.status_code == 504
    assert "504 Gateway Timeout" in resp.json()["detail"]


def test_events_written_with_exact_schema(test_app_and_client):
    """8 & 9. Both allowed and blocked events are logged matching exact contract."""
    client, _, log_file = test_app_and_client

    # 1. Allowed request
    client.get("/index.php?page=home")

    # 2. Blocked SQLi request
    client.post("/login.php", content=b"user=admin'--&pass=secret")

    # 3. Blocked XSS request
    client.get("/search?q=<script>alert(1)</script>")

    lines = log_file.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == 3

    for line in lines:
        record = json.loads(line)
        assert tuple(record.keys()) == EXPECTED_SCHEMA_KEYS
        assert isinstance(record["score"], float)
        assert record["verdict"] in {"allow", "block"}

    rec1, rec2, rec3 = [json.loads(l) for l in lines]
    assert rec1["verdict"] == "allow"
    assert rec1["attack_type"] == "none"

    assert rec2["verdict"] == "block"
    assert rec2["attack_type"] == "sqli"

    assert rec3["verdict"] == "block"
    assert rec3["attack_type"] == "xss"


def test_payload_logging_policy(test_app_and_client):
    """10. Test payload priority: body > query > empty string."""
    client, _, log_file = test_app_and_client

    # Case A: Body present (should log body, ignoring query)
    client.post("/submit?query_param=123", content=b"body_param=456")

    # Case B: Query only (should log query)
    client.get("/search?q=testing_query")

    # Case C: Neither body nor query (should log empty string)
    client.get("/about")

    lines = log_file.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == 3

    rec_a = json.loads(lines[0])
    assert rec_a["payload"] == "body_param=456"

    rec_b = json.loads(lines[1])
    assert rec_b["payload"] == "q=testing_query"

    rec_c = json.loads(lines[2])
    assert rec_c["payload"] == ""


def test_supported_http_methods(test_app_and_client):
    """Verify proxy supports PUT, PATCH, DELETE, OPTIONS, and HEAD methods."""
    client, upstream, _ = test_app_and_client

    methods = ["PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]
    for m in methods:
        upstream.calls.clear()
        upstream.response_body = b"method ok" if m != "HEAD" else b""
        req_fn = getattr(client, m.lower())
        resp = req_fn("/api/resource")
        assert resp.status_code == 200, f"Method {m} failed with {resp.status_code}"
        assert len(upstream.calls) == 1
        assert upstream.calls[0].method == m


def test_root_path_forwarding(test_app_and_client):
    """Verify root path / is forwarded correctly without redirect loops."""
    client, upstream, _ = test_app_and_client
    upstream.response_body = b"Root Index"

    resp = client.get("/")
    assert resp.status_code == 200
    assert resp.text == "Root Index"
    assert len(upstream.calls) == 1
    assert upstream.calls[0].url.path == "/"


def test_hop_by_hop_and_host_headers(test_app_and_client):
    """Verify hop-by-hop headers are removed and Host header handled."""
    client, upstream, _ = test_app_and_client

    resp = client.get(
        "/headers-test",
        headers={
            "Connection": "close",
            "Upgrade": "websocket",
            "Proxy-Authorization": "Basic dGVzdDp0ZXN0",
            "Custom-App-Header": "WAF-Test",
            "Host": "waf-proxy:8080",
        },
    )
    assert resp.status_code == 200
    assert len(upstream.calls) == 1
    sent_headers = upstream.calls[0].headers

    # Client-supplied hop-by-hop headers must be stripped from forwarding
    assert "upgrade" not in sent_headers
    assert "proxy-authorization" not in sent_headers
    assert sent_headers["custom-app-header"] == "WAF-Test"
    assert sent_headers["x-forwarded-host"] == "waf-proxy:8080"
