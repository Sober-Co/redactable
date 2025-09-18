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
from pathlib import Path

from .policy import Policy, PolicyBuilder, PolicyFactory
from .policy.loader import load_policy
from .policy.engine import apply_policy


# --------------------------------------------------------------------
# High-level API


def apply(data: str, policy: str | Policy | Path | None = None, *, region: str = "GB") -> str:
    """
    Detect sensitive data in `data` and apply a redaction policy.


    Args:
        data: Input text to process.
        policy: Either a :class:`Policy` instance or a path to a YAML/JSON policy file.
        region: Default region for phone parsing (e.g., "GB", "US").


    Returns:
        The transformed text after applying the policy. If no policy is
        provided, detection runs but the original text is returned unchanged.
    """
    registry = DetectorRegistry.default(region=region)
    findings = list(registry.scan(data))
    if policy:
        if isinstance(policy, Policy):
            pol = policy
        else:
            pol = load_policy(Path(policy))
        return apply_policy(pol, findings, data)
    return data


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
"Policy",
"PolicyBuilder",
"PolicyFactory",
]