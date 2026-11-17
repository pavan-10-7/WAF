"""Small, explainable rules for the three project-approved attack classes."""

from __future__ import annotations

import base64
import html
import re
import urllib.parse

RULES: dict[str, tuple[re.Pattern[str], ...]] = {
    "sqli": (
        re.compile(r"\b(?:union\s+(?:all\s+)?select|select\b.{0,80}\bfrom\b)", re.I),
        re.compile(r"(?:'|%27|\b)\s*(?:or|and)\s+(?:'[^']*'\s*=\s*'[^']*'|\d+\s*=\s*\d+)", re.I),
        re.compile(r"""['"]\s*(?:or|and)\s+['"]?\d+['"]?\s*=\s*['"]?\d+['"]?""", re.I),
        re.compile(r"\b(?:sleep|benchmark)\s*\(", re.I),
        re.compile(r"(?:--|#)\s*(?:$|\s)|/\*.*?\*/", re.I),
    ),
    "xss": (
        re.compile(r"<\s*script\b", re.I),
        re.compile(r"\bon\w+\s*=", re.I),
        re.compile(r"\bjavascript\s*:", re.I),
        re.compile(r"<\s*(?:iframe|svg|img|object|embed)\b", re.I),
    ),
    "traversal": (
        re.compile(r"(?:\.\.[/\\]|%2e%2e(?:%2f|%5c|[/\\]))", re.I),
        re.compile(r"(?:^|[/\\])\.\.(?:[/\\]|$)"),
        re.compile(r"\b(?:etc/passwd|windows/win\.ini)\b", re.I),
    ),
}


def normalize(value: str) -> str:
    """Decode common URL/HTML encodings repeatedly, without executing content."""
    current = value
    for _ in range(3):
        decoded = html.unescape(urllib.parse.unquote_plus(current))
        if decoded == current:
            break
        current = decoded
    # Decode base64 only when a value is clearly a base64 token and yields text.
    tokens = re.findall(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/])", current)
    for token in tokens:
        try:
            raw = base64.b64decode(token + "=" * (-len(token) % 4), validate=True)
            candidate = raw.decode("utf-8")
            if candidate.isprintable():
                current += " " + candidate
        except (ValueError, UnicodeDecodeError):
            pass
    return current


def detect_rule(text: str) -> tuple[str | None, str | None]:
    """Return the first matching attack type and a short explanation."""
    cleaned = normalize(text)
    for attack_type in ("sqli", "xss", "traversal"):
        if any(pattern.search(cleaned) for pattern in RULES[attack_type]):
            names = {"sqli": "SQL injection", "xss": "Cross-site scripting", "traversal": "Path traversal"}
            return attack_type, f"{names[attack_type]} pattern detected"
    return None, None
