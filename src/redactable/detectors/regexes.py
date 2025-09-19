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

import re
from typing import Iterable, Dict, Any

from .base import Finding, Detector, digits_only, luhn_ok, guess_card_brand

# --------------------------------------------------------------------
# Optional external dependencies (gracefully degrade if missing)


try:
    from email_validator import validate_email, EmailNotValidError  # type: ignore
except Exception:  # pragma: no cover
    validate_email = None
    class EmailNotValidError(Exception):
        pass
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

# Regex pattern: not fully RFC 5322 (too heavy) but good 95% case
RE_EMAIL = re.compile(
    r"""
    (?P<email>
      [a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+
      @
      [a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?
      (?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+
    )
    """,
    re.VERBOSE)

# PAN: 13–19 digits, spaces/dashes optional
RE_CARD = re.compile(r"(?:\b(?:\d[ -]?){13,19}\b)")

class CreditCardDetector:
    """Detect payment card PANs via regex + Luhn + brand guess."""
    name = "credit_card"

    def detect(self, text: str) -> Iterable[Finding]:
        for m in RE_CARD.finditer(text):
            raw = m.group(0)
            digits = digits_only(raw)

            # Quick reject obvious bad lengths
            if not (13 <= len(digits) <= 19):
                continue

            ok = luhn_ok(digits)
            brand = guess_card_brand(digits)
            conf = 0.9 if ok else 0.4

            yield Finding(
                kind=self.name,
                value=raw,
                span=m.span(),
                confidence=conf,
                normalized=digits,
                extras={"luhn_valid": ok, "brand": brand},
            )

# --------------------------------------------------------------------
# Simple phone regex fallback
RE_PHONE = re.compile(
    r"""
    (?<!\d)                    # do not start in the middle of a digit run
    (?:\+\d{1,3}[\s-]?)?      # optional country code
    (?:\(?\d{2,4}\)?[\s-]?)?  # optional area code
    \d{3,4}[\s-]?\d{3,4}      # subscriber number
    (?![\s-]?\d)              # ensure the number does not continue
    """,
    re.VERBOSE,
)

# Helpers to detect digit runs neighbouring phone candidates
RE_PHONE_PREFIX_RUN = re.compile(r"(?:\d[\s-]?)+$")
RE_PHONE_SUFFIX_RUN = re.compile(r"^(?:[\s-]?\d)+")


def _looks_like_pan(candidate: str) -> bool:
    """Heuristic guard for card-like numbers in the phone fallback."""

    compact = candidate.replace(" ", "").replace("-", "")
    if not compact.isdigit():
        return False

    digits = digits_only(candidate)
    if not (13 <= len(digits) <= 19):
        return False

    groups = [g for g in re.split(r"[\s-]", candidate) if g]
    if len(groups) <= 1:
        # Continuous 13-19 digits – highly card-like.
        return True

    if all(len(g) == 4 for g in groups):
        return True

    fourish = sum(len(g) == 4 for g in groups)
    return len(groups) >= 3 and fourish >= len(groups) - 1

class PhoneDetector:
    """Detect phone numbers via regex + optional libphonenumber."""
    name = "phone"

    def __init__(self, default_region: str = "GB") -> None:
        self.default_region = default_region

    def detect(self, text: str):
        if phonenumbers is not None:
            # Preferred: use Google's libphonenumber
            for m in phonenumbers.PhoneNumberMatcher(text, self.default_region):
                num = m.number
                start, end = m.start, m.end

                # Trim leading punctuation (e.g. "(") and trailing noise so the
                # span/value cover just the phone number starting at the first
                # plus or digit and ending on the final digit.
                trim_start = start
                while trim_start < end and not (
                    text[trim_start] == "+" or text[trim_start].isdigit()
                ):
                    trim_start += 1

                trim_end = end
                while trim_end > trim_start and not text[trim_end - 1].isdigit():
                    trim_end -= 1

                if trim_start >= trim_end:
                    continue

                value = text[trim_start:trim_end]
                digits = digits_only(value)
                if not digits:
                    continue

                normalized = ("+" if value.startswith("+") else "") + digits
                try:
                    formatted = phonenumbers.format_number(
                        num, phonenumbers.PhoneNumberFormat.E164
                    )
                except Exception:
                    formatted = None
                else:
                    if formatted and digits_only(formatted) == digits:
                        normalized = formatted

                conf = 0.95 if phonenumbers.is_valid_number(num) else 0.6
                extras = {
                    "region": phonenumbers.region_code_for_number(num),
                    "type": str(phonenumbers.number_type(num)),
                }
                yield Finding(
                    kind=self.name,
                    value=value,
                    span=(trim_start, trim_end),
                    confidence=conf,
                    normalized=normalized,
                    extras=extras,
                )
            return

        # Fallback regex-only detection
        for m in RE_PHONE.finditer(text):
            start, end = m.span()
            raw = text[start:end]

            # Skip obvious credit card numbers that happen to match
            if RE_CARD.fullmatch(raw):
                continue

            # Expand the credit-card guard by checking neighbouring 4-digit groups.
            expanded_start = start
            expanded_end = end
            left_group = re.search(r"(\d{4}[\s-])$", text[:start])
            if left_group:
                expanded_start = left_group.start()
            right_group = re.match(r"([\s-]?\d{4})", text[end:])
            if right_group:
                expanded_end = end + right_group.end()

            if expanded_start != start or expanded_end != end:
                expanded = text[expanded_start:expanded_end]
                if RE_CARD.fullmatch(expanded):
                    continue

            if _looks_like_pan(raw):
                continue

            prefix_match = RE_PHONE_PREFIX_RUN.search(text, 0, start)
            suffix_match = RE_PHONE_SUFFIX_RUN.match(text, end)

            prefix_digits = (
                sum(ch.isdigit() for ch in prefix_match.group())
                if prefix_match
                else 0
            )
            suffix_digits = (
                sum(ch.isdigit() for ch in suffix_match.group())
                if suffix_match
                else 0
            )

            # Guard against slicing into digit runs (e.g. credit card groups)
            if prefix_digits >= 4 or suffix_digits >= 4:
                continue

            yield Finding(
                kind=self.name,
                value=raw,
                span=m.span(),
                confidence=0.5,
                normalized=digits_only(raw),
            )


# --------------------------------------------------------------------
# Detector stubs

class EmailDetector:
    """Detect email addresses via regex + optional email-validator."""
    name = "email"

    def detect(self, text: str) -> Iterable[Finding]:
        for m in RE_EMAIL.finditer(text):
            raw = m.group("email")
            start, end = m.span()
            conf = 0.6
            norm = raw
            extras: Dict[str, Any] = {}
            # If email-validator is available, upgrade confidence
            if validate_email is not None:
                try:
                    result = validate_email(raw, allow_smtputf8=True)
                    norm = result.normalized
                    conf = 0.95
                    extras["domain"] = result.domain
                except EmailNotValidError as e:
                    extras["invalid_reason"] = str(e)
            yield Finding(
                kind=self.name,
                value=raw,
                span=(start, end),
                confidence=conf,
                normalized=norm,
                extras=extras,
            )

# --------------------------------------------------------------------
# Regex patterns
RE_NHS = re.compile(r"\b(\d{3})[\s-]?(\d{3})[\s-]?(\d{4})\b")
RE_SSN = re.compile(r"\b(\d{3})[\s-]?(\d{2})[\s-]?(\d{4})\b")
RE_IBAN = re.compile(r"\b([A-Z]{2}\d{2}[A-Z0-9]{11,30})\b", re.IGNORECASE)

# --------------------------------------------------------------------
# NHS Number
class NHSNumberDetector:
    """Detect UK NHS numbers via regex + mod-11 check."""
    name = "nhs_number"

    def detect(self, text: str):
        for m in RE_NHS.finditer(text):
            raw = m.group(0)
            d = digits_only(raw)
            if len(d) != 10:
                continue
            valid = False
            reason = None
            if std_nhs is not None:
                try:
                    valid = std_nhs.is_valid(d)
                except Exception as e:
                    reason = str(e)
            else:
                # Mod 11 algorithm
                weights = [10, 9, 8, 7, 6, 5, 4, 3, 2]
                total = sum(int(d[i]) * weights[i] for i in range(9))
                remainder = total % 11
                check = 11 - remainder
                if check == 11:
                    check = 0
                valid = (check != 10) and (check == int(d[9]))
            conf = 0.92 if valid else 0.4
            yield Finding(
                kind=self.name,
                value=raw,
                span=m.span(),
                confidence=conf,
                normalized=d,
                extras={"valid": valid, "reason": reason},
            )

# --------------------------------------------------------------------
# US Social Security Number
class USSSNDetector:
    """Detect US Social Security Numbers via regex + range validation."""
    name = "ssn_us"

    def detect(self, text: str):
        for m in RE_SSN.finditer(text):
            raw = m.group(0)
            d = digits_only(raw)
            if len(d) != 9:
                continue
            valid = None
            reason = None
            if std_us_ssn is not None:
                try:
                    valid = std_us_ssn.is_valid(d)
                except Exception as e:
                    valid = False
                    reason = str(e)
            else:
                # Basic exclusions
                area, group, serial = d[:3], d[3:5], d[5:]
                if area == "000" or area == "666" or "900" <= area <= "999":
                    valid = False
                elif group == "00" or serial == "0000":
                    valid = False
                else:
                    valid = True
            conf = 0.9 if valid else 0.4
            yield Finding(
                kind=self.name,
                value=raw,
                span=m.span(),
                confidence=conf,
                normalized=d,
                extras={"valid": valid, "reason": reason},
            )

# --------------------------------------------------------------------
# IBAN
class IBANDetector:
    """Detect IBANs via regex + mod-97 validation."""
    name = "iban"

    def detect(self, text: str):
        for m in RE_IBAN.finditer(text):
            raw = m.group(1)
            canon = re.sub(r"\s+", "", raw).upper()
            valid = None
            reason = None
            country = canon[:2]
            if std_iban is not None:
                try:
                    valid = std_iban.is_valid(canon)
                except Exception as e:
                    valid = False
                    reason = str(e)
            else:
                # Minimal IBAN check: mod-97
                def _mod97(s: str) -> int:
                    rearr = s[4:] + s[:4]
                    num = "".join(str(ord(c) - 55) if c.isalpha() else c for c in rearr)
                    rem = 0
                    for i in range(0, len(num), 9):
                        rem = int(str(rem) + num[i:i+9]) % 97
                    return rem
                valid = country.isalpha() and canon[2:4].isdigit() and _mod97(canon) == 1
            conf = 0.95 if valid else 0.5
            yield Finding(
                kind=self.name,
                value=raw,
                span=m.span(),
                confidence=conf,
                normalized=canon,
                extras={"valid": valid, "country": country, "reason": reason},
            )