"""
Core types and helpers for detectors.

Contents:

- Finding: dataclass representing a detected entity.
- Detector: Protocol interface that all detectors must implement.
- Registry helpers: register/get/detectors_for/all_detectors
- Shared helpers: digits_only, luhn_ok, guess_card_brand
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional, Protocol, Tuple, Dict, Any, List
import re

# --------------------------------------------------------------------
# Shared type aliases
Span = Tuple[int, int]
Extras = Dict[str, Any]

# --------------------------------------------------------------------
# Public result type

@dataclass(slots=True)
class Finding:
    """
    Represents a detected entity in text.

    Attributes:
        kind: Type of entity (e.g., "CREDIT_CARD", "EMAIL", "PHONE").
        value: Raw text that was matched.
        span: (start, end) indices in the original text.
        confidence: Detection confidence score in [0, 1].
        normalized: Canonicalized form (e.g., digits-only phone number).
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

# --------------------------------------------------------------------
# Detector protocol (single, canonical)

class Detector(Protocol):
    """
    All detectors must expose:
      - `name`: unique identifier for the detector
      - `labels`: tuple of labels this detector can produce (e.g., ("CREDIT_CARD",))
      - `detect(text, *, context=None) -> Iterable[Finding]`
    """
    name: str
    labels: tuple[str, ...]
    def detect(self, text: str, *, context: Optional[dict[str, Any]] = None) -> Iterable[Finding]: ...

# --------------------------------------------------------------------
# Simple registry

_REGISTRY: Dict[str, Detector] = {}
_LABEL_TO_DETECTORS: Dict[str, List[str]] = {}

def register(detector: Detector) -> None:
    _REGISTRY[detector.name] = detector
    for label in detector.labels:
        _LABEL_TO_DETECTORS.setdefault(label, []).append(detector.name)

def get(name: str) -> Detector:
    return _REGISTRY[name]

def detectors_for(label: str) -> list[Detector]:
    return [_REGISTRY[n] for n in _LABEL_TO_DETECTORS.get(label, [])]

def all_detectors() -> list[Detector]:
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
    Naive guess of card brand from PAN digits.
    Not exhaustive — just common prefixes and lengths.
    """
    d = digits_only(pan)

    if d.startswith("4") and len(d) in (13, 16, 19):
        return "VISA"

    if d[:2].isdigit() and 51 <= int(d[:2]) <= 55 and len(d) == 16:
        return "MASTERCARD"
    if d[:4].isdigit() and 2221 <= int(d[:4]) <= 2720 and len(d) == 16:
        return "MASTERCARD"

    if d.startswith(("34", "37")) and len(d) == 15:
        return "AMEX"

    if d.startswith("35") and len(d) == 16:
        return "JCB"

    if d.startswith("6011") or d.startswith(("64", "65")):
        return "DISCOVER"

    if d[:4] in {"3000", "3050", "3095"} or d[:2] in {"36", "38"}:
        return "DINERS_CLUB"

    if d.startswith(("50", "56", "57", "58", "63", "67")):
        return "MAESTRO"

    if d.startswith("62"):
        return "UNIONPAY"

    return None
