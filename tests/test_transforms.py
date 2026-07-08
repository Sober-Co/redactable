"""Tests for transformation operations (redact, mask, tokenize)."""

from redactable.detectors import Finding
from redactable.policy.engine import _mask, _MaskCfg, _redact, _tokenize


def test_redact_single_finding():
    """Test redaction of a single finding."""
    text = "My email is alice@example.com"
    findings = [Finding(kind="email", value="alice@example.com", span=(12, 30), confidence=0.95)]
    result = _redact(text, findings, "[REDACTED:{kind}]")
    assert result == "My email is [REDACTED:EMAIL]"


def test_redact_multiple_findings():
    """Test redaction of multiple findings."""
    text = "alice@example.com and bob@example.com"
    findings = [
        Finding(kind="email", value="alice@example.com", span=(0, 16), confidence=0.95),
        Finding(kind="email", value="bob@example.com", span=(21, 36), confidence=0.95),
    ]
    result = _redact(text, findings)
    assert "[REDACTED:EMAIL]" in result
    assert "@example.com" not in result


def test_redact_preserves_spans_right_to_left():
    """Test that redaction preserves spans by processing right-to-left."""
    text = "emails: alice@example.com and bob@corp.com"
    findings = [
        Finding(kind="email", value="alice@example.com", span=(8, 25), confidence=0.95),
        Finding(kind="email", value="bob@corp.com", span=(30, 42), confidence=0.95),
    ]
    result = _redact(text, findings)
    # Both should be redacted
    assert result.count("[REDACTED:EMAIL]") == 2


def test_mask_single_finding():
    """Test masking of a single finding."""
    text = "Card: 4111111111111111"
    findings = [
        Finding(kind="credit_card", value="4111111111111111", span=(6, 22), confidence=0.99)
    ]
    cfg = _MaskCfg(keep_head=0, keep_tail=4, glyph="•")
    result = _mask(text, findings, cfg)
    assert "••••1111" in result
    assert "4111111111111111" not in result


def test_mask_with_keep_head():
    """Test masking with head retention."""
    text = "SSN: 078-05-1120"
    findings = [Finding(kind="ssn", value="078-05-1120", span=(5, 16), confidence=0.99)]
    cfg = _MaskCfg(keep_head=3, keep_tail=0, glyph="*")
    result = _mask(text, findings, cfg)
    assert "078" in result
    assert "*" in result


def test_mask_custom_glyph():
    """Test masking with custom glyph."""
    text = "Phone: +447911123456"
    findings = [Finding(kind="phone", value="+447911123456", span=(7, 20), confidence=0.95)]
    cfg = _MaskCfg(keep_head=0, keep_tail=4, glyph="X")
    result = _mask(text, findings, cfg)
    assert "XXXXXX3456" in result


def test_tokenize_single_finding():
    """Test tokenization (SHA256 hashing) of a finding."""
    text = "Email: alice@example.com"
    findings = [Finding(kind="email", value="alice@example.com", span=(7, 25), confidence=0.95)]
    result = _tokenize(text, findings, salt="")
    # Should be a 64-character hex string (SHA256)
    token = result.split(": ")[1]
    assert len(token) == 64
    assert all(c in "0123456789abcdef" for c in token)


def test_tokenize_deterministic():
    """Test that tokenization is deterministic with same salt."""
    text = "Email: alice@example.com"
    findings = [Finding(kind="email", value="alice@example.com", span=(7, 25), confidence=0.95)]
    result1 = _tokenize(text, findings, salt="test_salt")
    result2 = _tokenize(text, findings, salt="test_salt")
    assert result1 == result2


def test_tokenize_with_salt():
    """Test that different salts produce different tokens."""
    text = "Email: alice@example.com"
    findings = [Finding(kind="email", value="alice@example.com", span=(7, 25), confidence=0.95)]
    result1 = _tokenize(text, findings, salt="salt1")
    result2 = _tokenize(text, findings, salt="salt2")
    assert result1 != result2
