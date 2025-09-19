import pytest
from types import SimpleNamespace

from redactable.detectors.run import run_all
from redactable.detectors.utils import nhs_check, luhn_check, iban_check
from redactable.detectors import regexes

def test_email():
    text = "Contact: alice.smith+test@sub.example.co.uk and bad@mail"
    m = [x for x in run_all(text) if x.label == "EMAIL"]
    assert any("alice.smith+test@sub.example.co.uk" in x.value for x in m)
    assert all("bad@mail" not in x.value for x in m)

def test_credit_card_luhn():
    # Visa test PAN: 4111 1111 1111 1111
    text = "Card: 4111 1111 1111 1111"
    m = [x for x in run_all(text) if x.label == "CREDIT_CARD"]
    assert len(m) == 1 and luhn_check('4111111111111111')


def test_phone_fallback_does_not_truncate_card_numbers():
    # Ensure fallback phone regex doesn't partially consume card numbers
    text = "Card: 4111 1111 1111 1111"
    phone_matches = [x for x in run_all(text) if x.label == "PHONE"]
    assert phone_matches == []


def test_phone_libphonenumber_span_trimming(monkeypatch):
    text = " phone (+07123…"
    plus_index = text.index("+")
    ellipsis_index = text.index("…")
    fake_number = object()

    class FakePhoneNumberMatcher:
        def __init__(self, text_arg, region):
            assert text_arg == text
            assert region == "GB"
            self._match = SimpleNamespace(
                start=plus_index - 1,  # include leading "("
                end=ellipsis_index,
                number=fake_number,
            )

        def __iter__(self):
            yield self._match

    fake_phonenumbers = SimpleNamespace(
        PhoneNumberMatcher=FakePhoneNumberMatcher,
        PhoneNumberFormat=SimpleNamespace(E164="E164"),
        format_number=lambda num, fmt: "+07123",
        is_valid_number=lambda num: True,
        region_code_for_number=lambda num: "GB",
        number_type=lambda num: "MOBILE",
    )

    monkeypatch.setattr(regexes, "phonenumbers", fake_phonenumbers)

    detector = regexes.PhoneDetector()
    findings = list(detector.detect(text))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.value == "+07123"
    assert finding.span == (plus_index, ellipsis_index)
    assert finding.normalized.endswith("07123")


def test_credit_card_confidence_branding():
    branded_text = "Card: 4111 1111 1111 1111"
    branded = [x for x in run_all(branded_text) if x.label == "CREDIT_CARD"]
    assert len(branded) == 1
    branded_match = branded[0]
    assert branded_match.meta["brand"] == "VISA"

    unbranded_text = "Other: 6011 1111 1111 1117"
    unbranded = [x for x in run_all(unbranded_text) if x.label == "CREDIT_CARD"]
    assert len(unbranded) == 1
    unbranded_match = unbranded[0]
    assert unbranded_match.meta["brand"] is None

    assert branded_match.confidence > unbranded_match.confidence

def test_iban():
    # Example GB: GB82 WEST 1234 5698 7654 32
    text = "Payout to IBAN GB82WEST12345698765432 today."
    m = [x for x in run_all(text) if x.label == "IBAN"]
    assert len(m) == 1 and iban_check(m[0].value)

def test_nhs():
    # Valid NHS example: 943 476 5919 (common example)
    text = "NHS No: 943 476 5919"
    m = [x for x in run_all(text) if x.label == "NHS_NUMBER"]
    assert len(m) == 1

def test_ssn():
    text = "Employee SSN 078-05-1120 and invalid 000-00-0000"
    m = [x for x in run_all(text) if x.label == "SSN"]
    assert any("078-05-1120" in x.value for x in m)
    assert all("000-00-0000" not in x.value for x in m)

def test_phone():
    text = "Call me at +447911123456 or 07123456789."
    m = [x for x in run_all(text) if x.label == "PHONE"]
    vals = [x.value for x in m]
    assert "+447911123456" in vals or "07123456789" in vals

def test_entropy():
    likely = "sk_live_9aGQ2d1ZbQk81Y2U5YjRjY2QxY2E5ZWFm"  # base64-ish
    text = f"api key: {likely}"
    m = [x for x in run_all(text) if x.label == "SECRET"]
    assert len(m) >= 1


def test_entropy_long_random_string():
    long_secret = (
        "1972308aa69828cadf41f9ca7bf252715521bb76b1762fa3da47c41076d422a0"
        "856177c1a70fbd759c8c4a820748a21c07abab0989749afaf391b279a5c67aae"
    )
    text = f"token={long_secret}"
    matches = [x for x in run_all(text) if x.label == "SECRET"]
    assert any(long_secret in x.value for x in matches)


def test_schema_hints_from_context_schema_mapping():
    context = {
        "schema": {
            "Email": {"type": "string"},
            "user_id": {"type": "uuid"},
            "cardNumber": {"type": "string"},
            "notes": {"type": "text"},
        }
    }

    matches = [m for m in run_all("", context=context) if m.label in {"EMAIL", "CREDIT_CARD"}]
    assert {m.value for m in matches} == {"Email", "cardNumber"}
    for match in matches:
        assert match.start == 0 and match.end == 0
        assert match.meta["source"] == "schema"
        assert match.meta["field"] in {"Email", "cardNumber"}
        assert match.confidence == pytest.approx(0.6)


def test_schema_hints_handles_nested_iterables():
    context = {
        "schema": {
            "fields": [
                {"name": "customerDOB"},
                {"name": "PHONE_NUMBER"},
                {"name": "address"},
            ]
        }
    }

    matches = [m for m in run_all("", context=context) if m.label in {"DATE_DOB", "PHONE"}]
    assert len(matches) == 2

    dob_match = next(m for m in matches if m.label == "DATE_DOB")
    phone_match = next(m for m in matches if m.label == "PHONE")

    assert dob_match.value == "customerDOB"
    assert dob_match.meta["schema_meta"] == {"name": "customerDOB"}

    assert phone_match.value == "PHONE_NUMBER"
    assert phone_match.meta["schema_meta"] == {"name": "PHONE_NUMBER"}


def test_schema_hints_recurses_into_named_mappings():
    context = {
        "schema": {
            "fields": [
                {
                    "name": "customer",
                    "fields": [
                        {"name": "customerEmail"},
                        {"name": "customer_ssn"},
                    ],
                }
            ]
        }
    }

    matches = [m for m in run_all("", context=context) if m.label in {"EMAIL", "SSN"}]
    assert {m.value for m in matches} == {"customerEmail", "customer_ssn"}


def test_schema_hints_recurses_into_nested_mappings():
    context = {
        "schema": {
            "schema": {
                "customer": {
                    "Email": {"type": "string"},
                    "phone": {"type": "string"},
                }
            }
        }
    }

    matches = [m for m in run_all("", context=context) if m.label in {"EMAIL", "PHONE"}]
    assert {m.value for m in matches} == {"Email", "phone"}
