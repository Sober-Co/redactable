"""Tests for the transforms package."""

from redactable.detectors.base import Finding
from redactable.transforms.redact import redact
from redactable.transforms.mask import mask_in_place, _mask
from redactable.transforms.tokenise import tokenise


def _finding(kind, value, start, end, confidence=0.9):
    return Finding(kind=kind, value=value, span=(start, end), confidence=confidence)


class TestRedact:
    def test_basic_redaction(self):
        text = "Email: alice@example.com"
        findings = [_finding("email", "alice@example.com", 7, 24)]
        result = redact(text, findings)
        assert result == "Email: [REDACTED:EMAIL]"

    def test_custom_placeholder(self):
        text = "Card: 4111111111111111"
        findings = [_finding("credit_card", "4111111111111111", 6, 22)]
        result = redact(text, findings, placeholder_fmt="***")
        assert result == "Card: ***"

    def test_multiple_findings(self):
        text = "a@b.com and c@d.com"
        findings = [
            _finding("email", "a@b.com", 0, 7),
            _finding("email", "c@d.com", 12, 19),
        ]
        result = redact(text, findings)
        assert "a@b.com" not in result
        assert "c@d.com" not in result


class TestMask:
    def test_mask_value(self):
        assert _mask("hello world", keep_head=0, keep_tail=4, glyph="*") == "*******orld"

    def test_mask_short_value(self):
        assert _mask("hi", keep_head=0, keep_tail=4, glyph="*") == "**"

    def test_mask_with_head_and_tail(self):
        result = _mask("1234567890", keep_head=2, keep_tail=3, glyph="X")
        assert result == "12XXXXX890"

    def test_mask_in_place_basic(self):
        text = "Email: alice@example.com"
        findings = [_finding("email", "alice@example.com", 7, 24)]
        result = mask_in_place(text, findings, keep_head=0, keep_tail=4, glyph="*")
        assert result == "Email: *************.com"


class TestTokenise:
    def test_basic_tokenisation(self):
        text = "Email: alice@example.com"
        findings = [_finding("email", "alice@example.com", 7, 24)]
        result = tokenise(text, findings, salt="test-salt")
        assert "alice@example.com" not in result
        # SHA-256 hex digest is 64 chars
        token = result[7:]
        assert len(token) == 64

    def test_tokenisation_is_deterministic(self):
        text = "Email: alice@example.com"
        findings = [_finding("email", "alice@example.com", 7, 24)]
        r1 = tokenise(text, findings, salt="s")
        r2 = tokenise(text, findings, salt="s")
        assert r1 == r2

    def test_different_salt_different_output(self):
        text = "Email: alice@example.com"
        findings = [_finding("email", "alice@example.com", 7, 24)]
        r1 = tokenise(text, findings, salt="salt1")
        r2 = tokenise(text, findings, salt="salt2")
        assert r1 != r2
