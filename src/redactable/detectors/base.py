"""
Core types and helpers for detectors.

Contents:
- Finding: dataclass representing a detected entity (used by DetectorRegistry / regexes.py).
- Match: dataclass representing a detected entity (used by modular detectors / run_all).
- Detector: Protocol interface that all detectors must implement.
- Shared helper functions: digits_only, luhn_ok, guess_card_brand.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Protocol, Tuple

# --------------------------------------------------------------------
# Shared type aliases
Span = Tuple[int, int]
Extras = Dict[str, Any]


# --------------------------------------------------------------------
# Match: used by modular detectors (email.py, credit_card.py, etc.)

@dataclass(slots=True)
class Match:
    label: str               # e.g. "EMAIL", "CREDIT_CARD"
    start: int               # char index in the input text
    end: int
    value: str               # matched text (pre-transform)
    confidence: float = 1.0  # 0..1
    meta: dict[str, Any] = field(default_factory=dict)


# --------------------------------------------------------------------
# Finding: used by DetectorRegistry / regexes.py

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
    extras: Extras = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError("confidence must be between 0 and 1")

    def __str__(self) -> str:
        return f"<Finding {self.kind} value='{self.value}' conf={self.confidence:.2f}>"


# --------------------------------------------------------------------
# Detector protocol
#
# Detectors in regexes.py return Finding; modular detectors return Match.
# Both share a common shape: .name attribute and .detect() method.

class Detector(Protocol):
    """
    Protocol that all detectors must follow.
    Each detector must expose a `name` and a `detect` method.
    """
    name: str

    def detect(self, text: str, **kwargs: Any) -> Iterable[Finding] | Iterable[Match]: ...


# --------------------------------------------------------------------
# Global detector registry (used by modular detectors)

_REGISTRY: Dict[str, Any] = {}
_LABEL_TO_DETECTORS: Dict[str, List[str]] = {}


def register(detector: Any) -> None:
    """Register a modular detector in the global registry."""
    _REGISTRY[detector.name] = detector
    for label in getattr(detector, "labels", ()):
        _LABEL_TO_DETECTORS.setdefault(label, []).append(detector.name)


def get(name: str) -> Any:
    """Get a registered detector by name."""
    return _REGISTRY[name]


def detectors_for(label: str) -> list[Any]:
    """Get all registered detectors that emit a given label."""
    return [_REGISTRY[n] for n in _LABEL_TO_DETECTORS.get(label, [])]


def all_detectors() -> list[Any]:
    """Get all registered detectors."""
    return list(_REGISTRY.values())


# --------------------------------------------------------------------
# Shared helpers

_DIGITS = re.compile(r"\D+")


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
    Not exhaustive -- just common prefixes and lengths.
    """
    d = digits_only(pan)
    if not d:
        return None

    if d.startswith("4") and len(d) in (13, 16, 19):
        return "visa"

    if len(d) >= 2 and d[:2].isdigit() and 51 <= int(d[:2]) <= 55 and len(d) == 16:
        return "mastercard"
    if len(d) >= 4 and d[:4].isdigit() and 2221 <= int(d[:4]) <= 2720 and len(d) == 16:
        return "mastercard"

    if d.startswith(("34", "37")) and len(d) == 15:
        return "amex"

    if d.startswith("35") and len(d) == 16:
        return "jcb"

    if d.startswith("6011") or d.startswith(("64", "65")):
        return "discover"

    if len(d) >= 4 and d[:4] in {"3000", "3050", "3095"} or d[:2] in {"36", "38"}:
        return "diners_club"

    if d.startswith(("50", "56", "57", "58", "63", "67")):
        return "maestro"

    if d.startswith("62"):
        return "unionpay"

    return None
