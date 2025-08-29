"""
Detectors subpackage.

Exports:
- Core types: Finding, Detector
- Registry: DetectorRegistry
- Built-in detectors: Email, Phone, Credit Card, NHS, SSN, IBAN, High-Entropy Token
"""

from .base import Finding, Detector, Match, all_detectors, detectors_for, get
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
from . import email, credit_card, iban, nhs, ssn, phone, entropy, schema_hints  # noqa: F401
from .run import run_all
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
