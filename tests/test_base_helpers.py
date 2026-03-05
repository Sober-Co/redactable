"""Tests for base.py helper functions to verify the regex fix."""

from redactable.detectors.base import digits_only, luhn_ok, guess_card_brand, Finding, Match


class TestDigitsOnly:
    def test_strips_non_digits(self):
        assert digits_only("4111 1111 1111 1111") == "4111111111111111"

    def test_strips_dashes(self):
        assert digits_only("4111-1111-1111-1111") == "4111111111111111"

    def test_pure_digits(self):
        assert digits_only("1234567890") == "1234567890"

    def test_empty_string(self):
        assert digits_only("") == ""

    def test_no_digits(self):
        assert digits_only("abcdef") == ""


class TestLuhnOk:
    def test_valid_visa(self):
        assert luhn_ok("4111111111111111") is True

    def test_valid_with_spaces(self):
        assert luhn_ok("4111 1111 1111 1111") is True

    def test_invalid(self):
        assert luhn_ok("4111111111111112") is False

    def test_too_short(self):
        assert luhn_ok("411111") is False


class TestGuessCardBrand:
    def test_visa(self):
        assert guess_card_brand("4111111111111111") == "visa"

    def test_mastercard(self):
        assert guess_card_brand("5500000000000004") == "mastercard"

    def test_amex(self):
        assert guess_card_brand("340000000000009") == "amex"

    def test_unknown(self):
        assert guess_card_brand("9999999999999999") is None

    def test_empty(self):
        assert guess_card_brand("") is None


class TestFinding:
    def test_valid_finding(self):
        f = Finding(kind="email", value="test@example.com", span=(0, 16), confidence=0.9)
        assert f.extras == {}

    def test_invalid_confidence(self):
        import pytest
        with pytest.raises(ValueError, match="confidence"):
            Finding(kind="email", value="test", span=(0, 4), confidence=1.5)


class TestMatch:
    def test_default_meta(self):
        m = Match(label="EMAIL", start=0, end=5, value="hello")
        assert m.meta == {}
