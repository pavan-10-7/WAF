"""TEMPORARY Detection Stub for WAF development.

NOTE: This is a placeholder development stub for Member 1's reverse proxy testing.
It uses simple pattern matching to simulate attack detection.
IT IS NOT A MACHINE LEARNING MODEL.
This module will be replaced or supplemented by Member 2's actual detection model.
"""

from typing import Any, Dict
import urllib.parse
import re

# Obvious test attack signatures (case-insensitive)
SQLI_PATTERNS = [
    re.compile(r"(\bor\b|\band\b)\s+['\"0-9a-zA-Z]+\s*=\s*['\"0-9a-zA-Z]+", re.IGNORECASE),
    re.compile(r"['\"];?\s*(--|#|\/\*)", re.IGNORECASE),
    re.compile(r"\bunion\s+(all\s+)?select\b", re.IGNORECASE),
    re.compile(r"\bexec(\s|\+)+(s|x)p\w+", re.IGNORECASE),
    re.compile(r"\bdrop\s+table\b", re.IGNORECASE),
    re.compile(r"' OR '1'='1", re.IGNORECASE),
    re.compile(r"' OR 1=1", re.IGNORECASE),
    re.compile(r"1' OR '1' = '1", re.IGNORECASE),
]

XSS_PATTERNS = [
    re.compile(r"<\s*script[^>]*>", re.IGNORECASE),
    re.compile(r"javascript\s*:", re.IGNORECASE),
    re.compile(r"<\s*img[^>]+onerror\s*=", re.IGNORECASE),
    re.compile(r"<\s*svg[^>]+onload\s*=", re.IGNORECASE),
    re.compile(r"alert\s*\(", re.IGNORECASE),
]

TRAVERSAL_PATTERNS = [
    re.compile(r"\.\./|\.\.\\", re.IGNORECASE),
    re.compile(r"/etc/passwd", re.IGNORECASE),
    re.compile(r"boot\.ini", re.IGNORECASE),
    re.compile(r"win\.ini", re.IGNORECASE),
    re.compile(r"c:\\windows", re.IGNORECASE),
]


def detect(req: Dict[str, Any]) -> Dict[str, Any]:
    """Shared detection contract: detect(req: dict) -> dict.

    Analyzes request components (path, query, body) against signature patterns.
    Returns verdict, attack_type, score, and reason.
    """
    path = req.get("path", "")
    query = req.get("query", "")
    body = req.get("body", "")
    
    # URL-decode components to detect encoded attacks
    try:
        decoded_path = urllib.parse.unquote(path)
        decoded_query = urllib.parse.unquote(query)
        decoded_body = urllib.parse.unquote(body) if isinstance(body, str) else str(body)
    except Exception:
        decoded_path = path
        decoded_query = query
        decoded_body = str(body)

    combined_targets = [
        path, query, body if isinstance(body, str) else "",
        decoded_path, decoded_query, decoded_body
    ]
    target_text = " ".join(combined_targets)

    # 1. SQL Injection check
    for pattern in SQLI_PATTERNS:
        if pattern.search(target_text):
            return {
                "verdict": "block",
                "attack_type": "sqli",
                "score": 0.95,
                "reason": "SQL injection signature detected by development stub",
            }

    # 2. XSS check
    for pattern in XSS_PATTERNS:
        if pattern.search(target_text):
            return {
                "verdict": "block",
                "attack_type": "xss",
                "score": 0.95,
                "reason": "Cross-site scripting (XSS) signature detected by development stub",
            }

    # 3. Path Traversal check
    for pattern in TRAVERSAL_PATTERNS:
        if pattern.search(target_text):
            return {
                "verdict": "block",
                "attack_type": "traversal",
                "score": 0.95,
                "reason": "Directory traversal signature detected by development stub",
            }

    # Legitimate traffic
    return {
        "verdict": "allow",
        "attack_type": "none",
        "score": 0.0,
        "reason": "No attack pattern detected by development stub",
    }
