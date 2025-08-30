from typing import Optional
from .base import Match, all_detectors

# Force registration even if package __init__ is bypassed
# (pytest imports run_all directly in tests)
from . import email, credit_card, iban, nhs, ssn, phone, entropy, schema_hints  # noqa: F401

def run_all(text: str, *, context: Optional[dict] = None) -> list[Match]:
    matches: list[Match] = []
    for det in all_detectors():
        for m in det.detect(text, context=context):
            if m is not None:
                matches.append(m)
    matches.sort(key=lambda m: (m.start, m.end))
    return matches