"""
Detectors subpackage.

Exports:
- Core types: Finding, Detector
- Registry: DetectorRegistry
- Built-in detectors: Email, Phone, Credit Card, NHS, SSN, IBAN, High-Entropy Token
"""

from . import (  # noqa: F401
    credit_card,
    email,
    entropy,
    iban,
    nhs,
    phone,
    schema_hints,
    ssn,
)
from .base import Detector, Finding, all_detectors, get, register
from .entropy import HighEntropyTokenDetector
from .regexes import (
    CreditCardDetector,
    EmailDetector,
    IBANDetector,
    NHSNumberDetector,
    PhoneDetector,
    USSSNDetector,
)
from .registry import DetectorRegistry
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
    "all_detectors",
    "get",
    "register",
    "run_all",
]
