"""
Core types and helpers for detectors.

Contents:
- Finding: dataclass representing a detected entity.
- Detector: Protocol interface that all detectors must implement.
- Shared helper functions: digits_only, luhn_ok, guess_card_brand.
"""

from dataclasses import dataclass
from typing import Iterable, Optional, Protocol, Tuple, Dict, Any
import re

# --------------------------------------------------------------------
# Shared type aliases
Span = Tuple[int, int]
Extras = Dict[str, Any]


@dataclass(slots=True)
class Finding:
    """
    Represents a detected entity in text.

    Attributes:
        kind: Type of entity (e.g. "email", "phone", "iban").
        value: Raw text that was matched.
        span: (start, end) indices of the match in the original text.
        confidence: Detection confidence score in [0, 1].
        normalized: Canonicalized form (e.g. digits-only phone number).
        extras: Additional metadata (brand, region, reasons, etc.).
    """
    kind: str
    value: str
    span: Span
    confidence: float
    normalized: Optional[str] = None
    extras: Extras | None = None

    def __post_init__(self) -> None:
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError("confidence must be between 0 and 1")
        if self.extras is None:
            self.extras = {}

    def __str__(self) -> str:
        return f"<Finding {self.kind} value='{self.value}' conf={self.confidence:.2f}>"


class Detector(Protocol):
    """
    Protocol that all detectors must follow.
    Each detector must expose a `name` and a `detect` method.
    """
    name: str

    def detect(self, text: str) -> Iterable[Finding]: ...

# --------------------------------------------------------------------
# Shared helpers

_DIGITS = re.compile(r"\\D+")

def digits_only(s: str) -> str:
    """Strip all non-digit characters from a string."""
    return _DIGITS.sub("", s)

def luhn_ok(num: str) -> bool:
    """
    Check if a string of digits passes the Luhn algorithm.
    Useful for validating credit card numbers.
    """
    d = digits_only(num)
    if len(d) < 12:
        return False
    total = 0
    alt = False
    for ch in reversed(d):
        x = ord(ch) - 48
        if alt:
            x *= 2
            if x > 9:
                x -= 9
        total += x
        alt = not alt
    return total % 10 == 0

def guess_card_brand(pan: str) -> str | None:
    """
    Make a naive guess of card brand from PAN digits.
    Not exhaustive — just common prefixes and lengths.
    """
    d = digits_only(pan)

    if d.startswith("4") and len(d) in (13, 16, 19):
        return "visa"

    if d[:2].isdigit() and 51 <= int(d[:2]) <= 55 and len(d) == 16:
        return "mastercard"
    if d[:4].isdigit() and 2221 <= int(d[:4]) <= 2720 and len(d) == 16:
        return "mastercard"

    if d.startswith(("34", "37")) and len(d) == 15:
        return "amex"

    if d.startswith("35") and len(d) == 16:
        return "jcb"

    if d.startswith("6011") or d.startswith(("64", "65")):
        return "discover"

    if d[:4] in {"3000", "3050", "3095"} or d[:2] in {"36", "38"}:
        return "diners_club"

    if d.startswith(("50", "56", "57", "58", "63", "67")):
        return "maestro"

    if d.startswith("62"):
        return "unionpay"

    return None


