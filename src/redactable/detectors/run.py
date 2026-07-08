# Force registration even if package __init__ is bypassed
# (pytest imports run_all directly in tests)
from . import (  # noqa: F401
    credit_card,
    email,
    entropy,
    iban,
    nhs,
    phone,
    schema_hints,
    ssn,
)
from .base import Finding, all_detectors


def run_all(text: str) -> list[Finding]:
    matches: list[Finding] = []
    for det in all_detectors():
        for m in det.detect(text):
            if m is not None:
                matches.append(m)
    matches.sort(key=lambda m: (m.span[0], m.span[1]))
    return matches
