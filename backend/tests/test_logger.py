"""Tests for Event Logger and Schema Contract."""

import asyncio
import json
from pathlib import Path
import pytest

from app.event_logger import EventLogger, EXPECTED_SCHEMA_KEYS


def test_payload_extraction_policy():
    """Verify strict payload extraction hierarchy: body > query > ''."""
    # 1. Body non-empty -> use body
    assert EventLogger.extract_payload(body="param=val", query="q=search") == "param=val"
    
    # 2. Body empty, query non-empty -> use query
    assert EventLogger.extract_payload(body="", query="q=search") == "q=search"
    assert EventLogger.extract_payload(body=None, query="id=42") == "id=42"

    # 3. Both empty -> empty string
    assert EventLogger.extract_payload(body="", query="") == ""
    assert EventLogger.extract_payload(body=None, query=None) == ""


def test_create_event_record_schema():
    """Verify event record matches exact required schema keys."""
    record = EventLogger.create_event_record(
        ip="192.168.1.100",
        method="POST",
        path="/api/login",
        payload="user=admin",
        verdict="block",
        attack_type="sqli",
        score=0.98765,
    )
    # Check exact keys present
    assert tuple(record.keys()) == EXPECTED_SCHEMA_KEYS
    assert record["ip"] == "192.168.1.100"
    assert record["method"] == "POST"
    assert record["path"] == "/api/login"
    assert record["payload"] == "user=admin"
    assert record["verdict"] == "block"
    assert record["attack_type"] == "sqli"
    assert record["score"] == 0.9877  # rounded


def test_logger_writes_valid_jsonl(tmp_path: Path):
    """Verify events are written as valid append-only JSON lines with exact keys."""
    async def _run():
        log_file = tmp_path / "test_events.jsonl"
        logger = EventLogger(log_path=str(log_file))

        # Log an allowed request
        rec_allow = logger.create_event_record(
            ip="127.0.0.1",
            method="GET",
            path="/home",
            payload="view=grid",
            verdict="allow",
            attack_type="none",
            score=0.0,
        )
        await logger.log_event(rec_allow)

        # Log a blocked request
        rec_block = logger.create_event_record(
            ip="10.0.0.5",
            method="GET",
            path="/search",
            payload="id=1' OR '1'='1",
            verdict="block",
            attack_type="sqli",
            score=0.95,
        )
        await logger.log_event(rec_block)

        # Read back and validate lines
        lines = log_file.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 2

        parsed_1 = json.loads(lines[0])
        parsed_2 = json.loads(lines[1])

        assert tuple(parsed_1.keys()) == EXPECTED_SCHEMA_KEYS
        assert parsed_1["verdict"] == "allow"
        assert parsed_1["payload"] == "view=grid"

        assert tuple(parsed_2.keys()) == EXPECTED_SCHEMA_KEYS
        assert parsed_2["verdict"] == "block"
        assert parsed_2["attack_type"] == "sqli"

    asyncio.run(_run())


def test_logger_concurrent_writes(tmp_path: Path):
    """Verify concurrent write safety without corrupted lines."""
    async def _run():
        log_file = tmp_path / "concurrent_events.jsonl"
        logger = EventLogger(log_path=str(log_file))

        async def write_task(idx: int):
            rec = logger.create_event_record(
                ip=f"10.0.0.{idx}",
                method="POST",
                path=f"/test/{idx}",
                payload=f"data_{idx}",
                verdict="allow",
                attack_type="none",
                score=0.0,
            )
            await logger.log_event(rec)

        # Dispatch 25 concurrent tasks
        await asyncio.gather(*(write_task(i) for i in range(25)))

        lines = log_file.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 25
        for line in lines:
            data = json.loads(line)
            assert tuple(data.keys()) == EXPECTED_SCHEMA_KEYS

    asyncio.run(_run())
