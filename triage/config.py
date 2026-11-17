"""Configuration constants, weights, and virtual-patch templates for the Triage Engine."""

WEIGHT_CVSS: float = 0.40
WEIGHT_EXPLOITABILITY: float = 0.20
WEIGHT_CRITICALITY: float = 0.20
WEIGHT_FREQUENCY: float = 0.20

FREQUENCY_SATURATION_CAP: int = 50

CRITICALITY_MAP: dict[str, float] = {
    "critical": 1.00,
    "high": 0.85,
    "medium": 0.55,
    "low": 0.25,
}
DEFAULT_CRITICALITY: float = 0.55

EXPLOITABILITY_BY_TYPE: dict[str, float] = {
    "sqli": 0.95,
    "traversal": 0.85,
    "xss": 0.80,
}
DEFAULT_EXPLOITABILITY: float = 0.75

PRIORITY_THRESHOLDS: list[tuple[float, str]] = [
    (8.5, "CRITICAL"),
    (6.5, "HIGH"),
    (4.0, "MEDIUM"),
    (0.0, "LOW"),
]

VIRTUAL_PATCH_TEMPLATES: dict[str, str] = {
    "sqli": (
        "Enforce strict WAF regex/ML blocking on '{endpoint}' for SQL meta-characters "
        "(', \", --, ;, UNION, SELECT, OR 1=1) across query and body parameters; "
        "apply parameterised queries in application code."
    ),
    "xss": (
        "Enable WAF payload inspection on '{endpoint}' to block HTML/JS injection vectors "
        "(<script>, onerror=, onload=, javascript:) and enforce Content-Security-Policy "
        "and output HTML encoding."
    ),
    "traversal": (
        "Block path traversal sequences (../, ..\\, %2e%2e%2f, /etc/passwd, win.ini) on "
        "'{endpoint}' at the WAF proxy and restrict file access to an allowlisted base directory."
    ),
}

DEFAULT_VIRTUAL_PATCH: str = (
    "Enable strict WAF input validation and anomaly blocking on '{endpoint}' "
    "for suspicious payloads targeting attack type '{attack_type}'."
)
