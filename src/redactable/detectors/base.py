"""Core types and helpers for detectors.

This module defines the public API surface that detectors consume:

* :class:`Match` – lightweight results used by the built-in registry.
* :class:`Finding` – richer results used by the legacy registry layer.
* :class:`Detector` – the protocol detectors must implement.
* Helper utilities shared by multiple detectors.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable, Optional, Protocol

@dataclass(slots=True)
class Match:
    """A lightweight finding produced by detectors registered in this module."""

    label: str               # e.g. "EMAIL", "CREDIT_CARD"
    start: int               # byte/char index in the input text
    end: int
    value: str               # matched text (pre-transform)
    confidence: float = 1.0  # 0..1
    meta: dict[str, Any] | None = None


class Detector(Protocol):
    """Protocol that built-in detectors adhere to.

    Detectors expose a :pydata:`name`, a collection of :pydata:`labels`, and a
    :py:meth:`detect` method that yields :class:`Match` instances.  The optional
    ``context`` keyword argument allows callers to pass detector-specific
    configuration without breaking the common interface.
    """

    name: str
    labels: tuple[str, ...]

    def detect(
        self,
        text: str,
        *,
        context: Optional[dict[str, Any]] = None,
    ) -> Iterable[Match]:
        ...


# Simple registry
_REGISTRY: dict[str, Detector] = {}
_LABEL_TO_DETECTORS: dict[str, list[str]] = {}


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
    span: tuple[int, int]
    confidence: float
    normalized: Optional[str] = None
    extras: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError("confidence must be between 0 and 1")
        if self.extras is None:
            self.extras = {}

    def __str__(self) -> str:
        return f"<Finding {self.kind} value='{self.value}' conf={self.confidence:.2f}>"

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


