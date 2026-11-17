"""Tests for Member 2 Detector Integration and Detection Adapter."""

import asyncio
import pytest

from detector import detect as real_detect
from app.detection_adapter import DetectionAdapter, DetectionContractError


def test_detector_import_from_root():
    """Verify Member 2's detector imports and returns expected contract."""
    req = {"method": "GET", "path": "/test", "query": "id=1", "body": "", "headers": {}}
    res = real_detect(req)
    assert isinstance(res, dict)
    assert "verdict" in res
    assert "attack_type" in res
    assert "score" in res
    assert "reason" in res


def test_real_detector_known_sqli():
    """Verify Member 2 detector blocks SQL injection attacks."""
    cases = [
        {"method": "GET", "path": "/search", "query": "id=1 OR 1=1", "body": ""},
        {"method": "POST", "path": "/login", "query": "", "body": "user=admin'-- &pass=x"},
        {"method": "GET", "path": "/api", "query": "q=UNION SELECT 1,2,3", "body": ""},
    ]
    for case in cases:
        res = real_detect(case)
        assert res["verdict"] == "block", f"Failed for SQLi: {case}"
        assert res["attack_type"] == "sqli"
        assert res["score"] >= 0.8


def test_real_detector_known_xss():
    """Verify Member 2 detector blocks Cross-site Scripting attacks."""
    cases = [
        {"method": "POST", "path": "/comment", "query": "", "body": "<script>alert(1)</script>"},
        {"method": "GET", "path": "/view", "query": "input=<img src=x onerror=alert(1)>", "body": ""},
        {"method": "GET", "path": "/redirect", "query": "url=javascript:alert(1)", "body": ""},
    ]
    for case in cases:
        res = real_detect(case)
        assert res["verdict"] == "block", f"Failed for XSS: {case}"
        assert res["attack_type"] == "xss"
        assert res["score"] >= 0.8


def test_real_detector_known_traversal():
    """Verify Member 2 detector blocks Path Traversal attacks."""
    cases = [
        {"method": "GET", "path": "/files", "query": "file=../../etc/passwd", "body": ""},
        {"method": "GET", "path": "/file", "query": "name=%2e%2e%2fetc/passwd", "body": ""},
        {"method": "GET", "path": "/win", "query": "path=..\\..\\windows\\win.ini", "body": ""},
    ]
    for case in cases:
        res = real_detect(case)
        assert res["verdict"] == "block", f"Failed for Traversal: {case}"
        assert res["attack_type"] == "traversal"
        assert res["score"] >= 0.8


def test_real_detector_benign_request():
    """Verify Member 2 detector permits benign requests."""
    benign_cases = [
        {"method": "GET", "path": "/products", "query": "sort=price&order=asc", "body": ""},
        {"method": "POST", "path": "/api/users", "query": "", "body": '{"name": "Alice", "age": 30}'},
        {"method": "GET", "path": "/", "query": "", "body": ""},
    ]
    for case in benign_cases:
        res = real_detect(case)
        assert res["verdict"] == "allow", f"False positive for benign request: {case}"
        assert res["attack_type"] == "none"
        assert res["score"] == 0.0


def test_adapter_validates_and_passes_real_detector():
    """Adapter passes through conformant detector output."""
    async def _run():
        adapter = DetectionAdapter()  # Defaults to real detector
        req = {"method": "GET", "path": "/safe", "query": "", "body": "", "headers": {}}
        res = await adapter.detect(req)
        assert res["verdict"] == "allow"
        assert res["attack_type"] == "none"
        assert res["score"] == 0.0

    asyncio.run(_run())


def test_adapter_raises_on_detector_exception():
    """If detector throws an unhandled error, adapter raises DetectionContractError."""
    async def _run():
        def faulty_detector(req):
            raise RuntimeError("Crash inside detection module")

        adapter = DetectionAdapter(detector_fn=faulty_detector)
        with pytest.raises(DetectionContractError) as exc_info:
            await adapter.detect({"method": "GET", "path": "/test", "query": "", "body": "", "headers": {}})
        assert "Detector execution failed" in str(exc_info.value)

    asyncio.run(_run())


def test_adapter_raises_on_invalid_verdict():
    """If detector returns unknown verdict, adapter raises DetectionContractError."""
    async def _run():
        def invalid_verdict_detector(req):
            return {"verdict": "unknown", "attack_type": "none", "score": 0.5, "reason": "Unsure"}

        adapter = DetectionAdapter(detector_fn=invalid_verdict_detector)
        with pytest.raises(DetectionContractError) as exc_info:
            await adapter.detect({"method": "GET", "path": "/test", "query": "", "body": "", "headers": {}})
        assert "Invalid verdict" in str(exc_info.value)

    asyncio.run(_run())


def test_adapter_raises_on_invalid_score():
    """If detector returns invalid score, adapter raises DetectionContractError."""
    async def _run():
        def invalid_score_detector(req):
            return {"verdict": "allow", "attack_type": "none", "score": 105.0, "reason": "Allow"}

        adapter = DetectionAdapter(detector_fn=invalid_score_detector)
        with pytest.raises(DetectionContractError) as exc_info:
            await adapter.detect({"method": "GET", "path": "/test", "query": "", "body": "", "headers": {}})
        assert "Score must be a float between 0.0 and 1.0" in str(exc_info.value)

    asyncio.run(_run())


def test_adapter_raises_on_non_dict_or_missing_reason():
    """If detector returns non-dict or non-string reason, adapter raises DetectionContractError."""
    async def _run():
        adapter = DetectionAdapter(detector_fn=lambda r: "not a dict")
        with pytest.raises(DetectionContractError) as exc_info:
            await adapter.detect({"method": "GET", "path": "/test", "query": "", "body": "", "headers": {}})
        assert "must return a dict" in str(exc_info.value)

        adapter2 = DetectionAdapter(detector_fn=lambda r: {"verdict": "allow", "attack_type": "none", "score": 0.0, "reason": ""})
        with pytest.raises(DetectionContractError) as exc_info2:
            await adapter2.detect({"method": "GET", "path": "/test", "query": "", "body": "", "headers": {}})
        assert "Reason must be a non-empty string" in str(exc_info2.value)

    asyncio.run(_run())
