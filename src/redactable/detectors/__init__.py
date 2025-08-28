"""
Detectors subpackage.

Exports:
- Core types: Finding, Detector
- Registry: DetectorRegistry
- Built-in detectors: Email, Phone, Credit Card, NHS, SSN, IBAN, High-Entropy Token
"""

from .base import Finding, Detector
from .registry import DetectorRegistry
from .regexes import (
    EmailDetector,
    PhoneDetector,
    CreditCardDetector,
    NHSNumberDetector,
    USSSNDetector,
    IBANDetector,
)
from .entropy import HighEntropyTokenDetector

__all__ = [
    "Finding",
    "Detector",
    "DetectorRegistry",
    "EmailDetector",
    "PhoneDetector",
    "CreditCardDetector",
    "NHSNumberDetector",
    "USSSNDetector",
    "IBANDetector",
    "HighEntropyTokenDetector",
]
