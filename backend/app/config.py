
"""Application configuration for the Hybrid AI WAF reverse proxy."""

import os
from pathlib import Path

# Base directories
BASE_DIR = Path(__file__).resolve().parent.parent
LOGS_DIR = BASE_DIR / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)

# Server configuration
WAF_HOST: str = os.getenv("WAF_HOST", "0.0.0.0")
WAF_PORT: int = int(os.getenv("WAF_PORT", "8080"))

# Upstream application configuration
UPSTREAM_URL: str = os.getenv(
    "UPSTREAM_URL",
    "http://127.0.0.1:8081"
).rstrip("/")

UPSTREAM_TIMEOUT: float = float(
    os.getenv("UPSTREAM_TIMEOUT", "10.0")
)

# Event logging configuration
EVENTS_LOG_PATH = Path(
    os.getenv("EVENTS_LOG_PATH", str(LOGS_DIR / "events.jsonl"))
)

# System health status configuration.
# By default, this is stored beside events.jsonl.
SYSTEM_STATUS_PATH = Path(
    os.getenv(
        "SYSTEM_STATUS_PATH",
        str(EVENTS_LOG_PATH.parent / "system_status.json")
    )
)

# Ensure output directories exist
EVENTS_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
SYSTEM_STATUS_PATH.parent.mkdir(parents=True, exist_ok=True)
