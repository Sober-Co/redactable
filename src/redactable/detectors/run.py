from typing import Optional
from .base import Finding, all_detectors

# Ensure side-effect registration
from . import email, credit_card, iban, nhs, ssn, phone, entropy, schema_hints  # noqa: F401

def run_all(text: str, *, context: Optional[dict] = None) -> list[Finding]:
    findings: list[Finding] = []
    for det in all_detectors():
        for f in det.detect(text, context=context):
            if f is not None:
                findings.append(f)
    findings.sort(key=lambda f: (f.span[0], f.span[1]))
    return findings
