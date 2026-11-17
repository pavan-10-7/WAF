"""Tests for Detection Stub and Detection Adapter."""

import asyncio
import pytest
from app.detection_stub import detect as detect_stub
from app.detection_adapter import DetectionAdapter


def test_detection_stub_legitimate_request():
    """Verify legitimate requests are permitted with zero score."""
    req = {
        "method": "GET",
        "path": "/products/list",
        "query": "category=books&page=2",
        "body": "",
        "headers": {"user-agent": "test-browser"},
    }
    result = detect_stub(req)
    assert result["verdict"] == "allow"
    assert result["attack_type"] == "none"
    assert result["score"] == 0.0
    assert "No attack pattern" in result["reason"]


def test_detection_stub_sqli_patterns():
    """Verify common SQL injection patterns in query and body are blocked."""
    sqli_cases = [
        {"path": "/login", "query": "id=1' OR '1'='1", "body": ""},
        {"path": "/users", "query": "", "body": "username=admin'--&password=x"},
        {"path": "/search", "query": "q=UNION SELECT 1,2,3", "body": ""},
        {"path": "/items", "query": "id=1; DROP TABLE users;", "body": ""},
        {"path": "/test", "query": "param=%27%20OR%201%3D1--", "body": ""},
    ]
    for case in sqli_cases:
        req = {
            "method": "POST" if case["body"] else "GET",
            "path": case["path"],
            "query": case["query"],
            "body": case["body"],
            "headers": {},
        }
        res = detect_stub(req)
        assert res["verdict"] == "block", f"Failed to block SQLi: {case}"
        assert res["attack_type"] == "sqli"
        assert res["score"] > 0.8


def test_detection_stub_xss_patterns():
    """Verify cross-site scripting signatures are blocked."""
    xss_cases = [
        {"path": "/comment", "query": "", "body": "<script>alert(1)</script>"},
        {"path": "/view", "query": "input=<img src=x onerror=alert(1)>", "body": ""},
        {"path": "/redirect", "query": "url=javascript:alert(document.cookie)", "body": ""},
    ]
    for case in xss_cases:
        req = {
            "method": "GET",
            "path": case["path"],
            "query": case["query"],
            "body": case["body"],
            "headers": {},
        }
        res = detect_stub(req)
        assert res["verdict"] == "block", f"Failed to block XSS: {case}"
        assert res["attack_type"] == "xss"
        assert res["score"] > 0.8


def test_detection_stub_traversal_patterns():
    """Verify directory traversal signatures are blocked."""
    traversal_cases = [
        {"path": "/download", "query": "file=../../../../etc/passwd", "body": ""},
        {"path": "/read", "query": "path=..\\..\\win.ini", "body": ""},
        {"path": "/view", "query": "f=%2e%2e%2f%2e%2e%2fetc%2fpasswd", "body": ""},
    ]
    for case in traversal_cases:
        req = {
            "method": "GET",
            "path": case["path"],
            "query": case["query"],
            "body": case["body"],
            "headers": {},
        }
        res = detect_stub(req)
        assert res["verdict"] == "block", f"Failed to block Traversal: {case}"
        assert res["attack_type"] == "traversal"
        assert res["score"] > 0.8


def test_adapter_validates_and_passes_compliant_detector():
    """Adapter passes through conformant detector output."""
    async def _run():
        adapter = DetectionAdapter()
        req = {"method": "GET", "path": "/safe", "query": "", "body": "", "headers": {}}
        res = await adapter.detect(req)
        assert res["verdict"] in {"allow", "block"}
        assert res["attack_type"] in {"none", "sqli", "xss", "traversal"}
        assert 0.0 <= res["score"] <= 1.0

    asyncio.run(_run())


def test_adapter_fails_safely_on_exception():
    """If detector throws an error, adapter must fail-safe (block, not allow)."""
    async def _run():
        def faulty_detector(req):
            raise RuntimeError("Crash inside detection module")

        adapter = DetectionAdapter(detector_fn=faulty_detector)
        res = await adapter.detect({"method": "GET", "path": "/test", "query": "", "body": "", "headers": {}})

        assert res["verdict"] == "block"
        assert res["score"] == 1.0
        assert "safe block" in res["reason"].lower()

    asyncio.run(_run())


def test_adapter_fails_safely_on_invalid_verdict():
    """If detector returns unknown verdict or missing fields, adapter enforces safe block."""
    async def _run():
        def invalid_verdict_detector(req):
            return {"verdict": "maybe", "attack_type": "none", "score": 0.5, "reason": "Unsure"}

        adapter = DetectionAdapter(detector_fn=invalid_verdict_detector)
        res = await adapter.detect({"method": "GET", "path": "/test", "query": "", "body": "", "headers": {}})

        assert res["verdict"] == "block"
        assert res["score"] == 1.0
        assert "detector execution failed" in res["reason"]

    asyncio.run(_run())


def test_adapter_fails_safely_on_invalid_score():
    """If detector returns invalid score (out of bounds or wrong type), adapter enforces safe block."""
    async def _run():
        def invalid_score_detector(req):
            return {"verdict": "allow", "attack_type": "none", "score": 99.9, "reason": "Allow"}

        adapter = DetectionAdapter(detector_fn=invalid_score_detector)
        res = await adapter.detect({"method": "GET", "path": "/test", "query": "", "body": "", "headers": {}})

        assert res["verdict"] == "block"
        assert res["score"] == 1.0

    asyncio.run(_run())


def test_adapter_supports_swapping_detector():
    """Verify Member 2 can plug in an ML detector function cleanly."""
    async def _run():
        def custom_member2_detector(req):
            return {
                "verdict": "block",
                "attack_type": "sqli",
                "score": 0.99,
                "reason": "Member 2 ML classifier detected SQLi",
            }

        adapter = DetectionAdapter()
        adapter.set_detector(custom_member2_detector)
        res = await adapter.detect({"method": "GET", "path": "/test", "query": "", "body": "", "headers": {}})

        assert res["verdict"] == "block"
        assert res["attack_type"] == "sqli"
        assert res["score"] == 0.99
        assert "Member 2" in res["reason"]

    asyncio.run(_run())
