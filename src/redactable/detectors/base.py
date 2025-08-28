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
    span: Tuple[int, int]
    confidence: float
    normalized: Optional[str] = None
    extras: Dict[str, Any] | None = None

    def __post_init__(self) -> None:
        if self.extras is None:
            self.extras = {}

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
    Returns one of: visa, mastercard, amex, jcb, discover, or None.
    """
    d = digits_only(pan)
    if d.startswith("4") and len(d) in (13, 16, 19):
        return "visa"
    if d[:2].isdigit() and 51 <= int(d[:2]) <= 55 and len(d) == 16:
        return "mastercard"
    if d.startswith(("34", "37")) and len(d) == 15:
        return "amex"
    if d.startswith("35") and len(d) == 16:
        return "jcb"
    if d.startswith("6011") or d.startswith(("64", "65")):
        return "discover"
    return None
