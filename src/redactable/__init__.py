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


def apply(
    data: str,
    policy: str | Policy | Path | None = None,
    *,
    region: str = "GB",
    return_findings: bool = False,
) -> str | tuple[str, list[Finding]]:
    """
    Detect sensitive data in `data` and apply a redaction policy.


    Args:
        data: Input text to process.
        policy: Either a :class:`Policy` instance or a path to a YAML/JSON policy file.
        region: Default region for phone parsing (e.g., "GB", "US").
        return_findings: If ``True``, return a tuple of ``(text, findings)``
            so callers can inspect detection output. Defaults to ``False`` for
            backwards compatibility.


    Returns:
        The transformed text after applying the policy. If ``return_findings``
        is ``True`` a tuple of ``(text, findings)`` is returned instead. When
        no policy is provided the text is left unchanged, but detections are
        still included in the returned findings when requested.
    """
    registry = DetectorRegistry.default(region=region)
    findings = list(registry.scan(data))
    if policy:
        if isinstance(policy, Policy):
            pol = policy
        else:
            pol = load_policy(Path(policy))
        result = apply_policy(pol, findings, data)
    else:
        result = data

    if return_findings:
        return result, findings
    return result


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