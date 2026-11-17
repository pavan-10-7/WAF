"""Event Logger for WAF reverse proxy.

Writes structured event records to an append-only JSON Lines file.
Strict contract schema:
- ts: ISO-8601 formatted timestamp string
- ip: Client IP address string
- method: HTTP method string
- path: Request URI path string
- payload: Extracted payload according to policy (body > query > "")
- verdict: 'block' | 'allow'
- attack_type: 'sqli' | 'xss' | 'traversal' | 'none'
- score: float in [0.0, 1.0]

Concurrency safety:
Uses an asynchronous lock to serialize file writes under high concurrent load.
Does NOT record credentials, auth tokens, or sensitive headers.
"""

import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Dict, Optional

from app.config import EVENTS_LOG_PATH

EXPECTED_SCHEMA_KEYS = ("ts", "ip", "method", "path", "payload", "verdict", "attack_type", "score")


class EventLogger:
    """Thread/coroutine safe append-only JSON Lines event logger."""

    def __init__(self, log_path: Optional[str] = None):
        self.log_path = Path(log_path or EVENTS_LOG_PATH)
        self._lock = asyncio.Lock()
        self._ensure_log_file()

    def _ensure_log_file(self) -> None:
        """Ensures the parent directory and log file exist."""
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.log_path.exists():
            self.log_path.touch()

    @staticmethod
    def extract_payload(body: Optional[str], query: Optional[str]) -> str:
        """Applies the strict payload selection policy:

        1. Use request body when non-empty.
        2. Otherwise use raw query string when non-empty.
        3. Otherwise use an empty string.
        """
        if body and str(body).strip():
            return str(body)
        if query and str(query).strip():
            return str(query)
        return ""

    @staticmethod
    def create_event_record(
        ip: str,
        method: str,
        path: str,
        payload: str,
        verdict: str,
        attack_type: str,
        score: float,
        ts: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Constructs an event record conforming strictly to the 8 required fields."""
        timestamp = ts or datetime.now(timezone.utc).isoformat()
        return {
            "ts": timestamp,
            "ip": ip or "127.0.0.1",
            "method": method.upper(),
            "path": path if path.startswith("/") else f"/{path}",
            "payload": payload,
            "verdict": verdict,
            "attack_type": attack_type,
            "score": round(float(score), 4),
        }

    async def log_event(self, record: Dict[str, Any]) -> None:
        """Validates and appends a single event record to events.jsonl."""
        # Enforce exact field contract in deterministic key order
        filtered_record = {k: record[k] for k in EXPECTED_SCHEMA_KEYS}

        line = json.dumps(filtered_record, ensure_ascii=False) + "\n"

        async with self._lock:
            # Append write to file
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(line)
                f.flush()


# Global event logger instance
default_event_logger = EventLogger()
