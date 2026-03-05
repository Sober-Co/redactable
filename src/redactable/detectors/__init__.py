"""
Detectors subpackage.

Exports:
- Core types: Finding, Match, Detector
- Registry: DetectorRegistry
- Built-in detectors: Email, Phone, Credit Card, NHS, SSN, IBAN, High-Entropy Token
- Modular detector API: run_all, register, get, all_detectors, detectors_for
"""

from .base import Finding, Detector, Match, all_detectors, detectors_for, get, register
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

# Force registration of modular detectors
from . import email, credit_card, iban, nhs, ssn, phone, entropy, schema_hints  # noqa: F401
from .run import run_all

__all__ = [
    "Finding",
    "Match",
    "Detector",
    "DetectorRegistry",
    "EmailDetector",
    "PhoneDetector",
    "CreditCardDetector",
    "NHSNumberDetector",
    "USSSNDetector",
    "IBANDetector",
    "HighEntropyTokenDetector",
    "run_all",
    "register",
    "get",
    "all_detectors",
    "detectors_for",
]
