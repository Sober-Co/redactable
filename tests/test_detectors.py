import pytest
from redactable.detectors import (
    DetectorRegistry,
    EmailDetector,
    PhoneDetector,
    CreditCardDetector,
    NHSNumberDetector,
    USSSNDetector,
    IBANDetector,
    HighEntropyTokenDetector,
)

@pytest.fixture
def registry():
    return DetectorRegistry.default()

def test_registry_scans_email(registry):
    text = "Contact me at alice@example.com"
    findings = registry.scan(text)
    assert any(f.kind == "email" for f in findings)

def test_registry_scans_credit_card(registry):
    text = "Card: 4111 1111 1111 1111"
    findings = registry.scan(text)
    assert any(f.kind == "credit_card" for f in findings)

def test_registry_scans_entropy_token(registry):
    text = "Here is a secret: AAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBB"
    findings = registry.scan(text)
    assert any(f.kind == "high_entropy_token" for f in findings)
