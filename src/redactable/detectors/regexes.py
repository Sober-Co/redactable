"""
Regex-based detectors.

Detectors included:
- EmailDetector
- PhoneDetector
- CreditCardDetector
- NHSNumberDetector
- USSSNDetector
- IBANDetector

Design:
- Each detector uses a regex prefilter to identify candidate matches.
- Optional external libraries (e.g. email-validator, phonenumbers, python-stdnum)
  can be used to raise confidence and normalize values.
- All detectors implement the Detector protocol defined in base.py.
"""

from __future__ import annotations
import re
from typing import Iterable, Dict, Any

from .base import Finding, Detector, digits_only, luhn_ok, guess_card_brand

# --------------------------------------------------------------------
# Optional external dependencies (gracefully degrade if missing)

try:
    from email_validator import validate_email, EmailNotValidError  # type: ignore
except Exception:  # pragma: no cover
    validate_email = None
    class EmailNotValidError(Exception): ...
try:
    import phonenumbers  # type: ignore
except Exception:  # pragma: no cover
    phonenumbers = None
try:
    from stdnum import iban as std_iban  # type: ignore
    from stdnum.gb import nhs as std_nhs  # type: ignore
    from stdnum.us import ssn as std_us_ssn  # type: ignore
except Exception:  # pragma: no cover
    std_iban = std_nhs = std_us_ssn = None

# --------------------------------------------------------------------
# Regex patterns (baseline filters)

RE_EMAIL = re.compile(r"...")   # TODO: implement full RFC-ish regex
RE_PHONE = re.compile(r"...")   # TODO: phone number pattern
RE_CARD  = re.compile(r"...")   # TODO: credit card pattern
RE_NHS   = re.compile(r"...")   # TODO: UK NHS number pattern
RE_SSN   = re.compile(r"...")   # TODO: US SSN pattern
RE_IBAN  = re.compile(r"...")   # TODO: IBAN pattern

# --------------------------------------------------------------------
# Detector stubs

class EmailDetector:
    """Detect email addresses via regex + optional email-validator."""
    name = "email"
    def detect(self, text: str) -> Iterable[Finding]:
        # TODO: implement regex scan + validation
        return []

class PhoneDetector:
    """Detect phone numbers via regex + optional libphonenumber."""
    name = "phone"
    def __init__(self, default_region: str = "GB") -> None:
        self.default_region = default_region
    def detect(self, text: str) -> Iterable[Finding]:
        # TODO: implement regex scan + validation
        return []

class CreditCardDetector:
    """Detect payment card PANs via regex + Luhn check."""
    name = "credit_card"
    def detect(self, text: str) -> Iterable[Finding]:
        # TODO: implement regex scan + Luhn + brand guess
        return []

class NHSNumberDetector:
    """Detect UK NHS numbers via regex + mod-11 check."""
    name = "nhs_number"
    def detect(self, text: str) -> Iterable[Finding]:
        # TODO: implement regex scan + checksum validation
        return []

class USSSNDetector:
    """Detect US Social Security Numbers via regex + range validation."""
    name = "ssn_us"
    def detect(self, text: str) -> Iterable[Finding]:
        # TODO: implement regex scan + validation
        return []

class IBANDetector:
    """Detect IBANs via regex + mod-97 validation."""
    name = "iban"
    def detect(self, text: str) -> Iterable[Finding]:
        # TODO: implement regex scan + validation
        return []
