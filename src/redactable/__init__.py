"""
Redactable package root.

Re-exports selected core APIs for convenience.
Keeps detector registry and common detectors accessible at the top-level.

Also provides a high-level `apply()` stub for policy-driven redaction,
so examples in the README work out-of-the-box.
"""

from .detectors import (
    Finding,
    Detector,
    DetectorRegistry,
    EmailDetector,
    PhoneDetector,
    CreditCardDetector,
    NHSNumberDetector,
    USSSNDetector,
    IBANDetector,
    HighEntropyTokenDetector,
)

# --------------------------------------------------------------------
# High-level API

def apply(data: str, policy: str | None = None) -> str:
    """
    Apply redaction according to a given policy (stubbed for v0.1).

    Args:
        data: Input string to redact/mask.
        policy: Path to policy file (YAML/JSON). Currently unused.

    Returns:
        Redacted string (currently just a placeholder).
    """
    # TODO: Wire into policy engine once implemented.
    # For now, demonstrates DX from README.
    return data.replace("example.com", "****@example.com")

# --------------------------------------------------------------------
# Public API

__all__ = [
    "Finding",
    "Detector",
    "DetectorRegistry",
    "EmailDetector",
    "PhoneDetector",
    "CreditCardDetector",
    "NHSNumberDetector",
    "USSSNDetector",
    "IBANDetector",
    "HighEntropyTokenDetector",
    "apply",
]
