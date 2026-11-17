"""Detection Adapter for WAF.

Provides a decoupled integration layer between the reverse proxy and the detection engine.
Uses Member 2's hybrid detection engine directly:
    from detector import detect

Validates detection outputs against the project contract:
- result is a dictionary
- verdict is 'block' or 'allow'
- attack_type is 'sqli', 'xss', 'traversal', or 'none'
- score is numeric and between 0.0 and 1.0
- reason is a string

Fail-closed policy:
Detector exceptions or invalid outputs raise DetectionContractError so the proxy
can return an appropriate HTTP 503 response and prevent uninspected traffic from passing.
"""

import inspect
import logging
from pathlib import Path
import sys
from typing import Any, Callable, Dict, Optional

# Ensure repository root is in sys.path so 'from detector import detect' always succeeds
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from detector import detect

logger = logging.getLogger("waf.detection_adapter")

VALID_VERDICTS = {"block", "allow"}
VALID_ATTACK_TYPES = {"sqli", "xss", "traversal", "none"}


class DetectionContractError(Exception):
    """Raised when detection engine returns non-compliant results or fails execution."""
    pass


class DetectionAdapter:
    """Manages detection function execution, output validation, and safe failure handling."""

    def __init__(self, detector_fn: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None):
        self._detector: Callable[[Dict[str, Any]], Dict[str, Any]] = detector_fn or detect

    def set_detector(self, detector_fn: Callable[[Dict[str, Any]], Dict[str, Any]]) -> None:
        """Allows switching or mocking detection function for testing."""
        self._detector = detector_fn

    def get_detector(self) -> Callable[[Dict[str, Any]], Dict[str, Any]]:
        return self._detector

    def _validate_response(self, result: Any) -> Dict[str, Any]:
        """Validates that detector response strictly matches the contract."""
        if not isinstance(result, dict):
            raise DetectionContractError(f"Detector must return a dict, got {type(result).__name__}")

        verdict = result.get("verdict")
        if verdict not in VALID_VERDICTS:
            raise DetectionContractError(f"Invalid verdict: {verdict!r}, must be one of {VALID_VERDICTS}")

        attack_type = result.get("attack_type")
        if attack_type not in VALID_ATTACK_TYPES:
            raise DetectionContractError(f"Invalid attack_type: {attack_type!r}, must be one of {VALID_ATTACK_TYPES}")

        score = result.get("score")
        if not isinstance(score, (int, float)) or not (0.0 <= float(score) <= 1.0):
            raise DetectionContractError(f"Score must be a float between 0.0 and 1.0, got {score!r}")

        reason = result.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            raise DetectionContractError(f"Reason must be a non-empty string, got {reason!r}")

        return {
            "verdict": verdict,
            "attack_type": attack_type,
            "score": float(score),
            "reason": reason.strip(),
        }

    async def detect(self, req: Dict[str, Any]) -> Dict[str, Any]:
        """Executes the detector function (synchronous or async) and enforces validation."""
        try:
            detector = self._detector
            if inspect.iscoroutinefunction(detector):
                raw_result = await detector(req)
            else:
                raw_result = detector(req)
        except Exception as exc:
            logger.error("Detector raised an exception during execution: %s", exc)
            raise DetectionContractError(f"Detector execution failed: {exc}") from exc

        return self._validate_response(raw_result)


# Global adapter instance for the application using Member 2's detector
default_adapter = DetectionAdapter()
