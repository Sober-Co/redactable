"""Detector registry and unified scanning interface."""

from __future__ import annotations

import logging
from typing import List, Optional

from .base import Detector, Finding
from .regexes import (
    EmailDetector,
    PhoneDetector,
    CreditCardDetector,
    NHSNumberDetector,
    USSSNDetector,
    IBANDetector,
)
from .entropy import HighEntropyTokenDetector

logger = logging.getLogger(__name__)


class DetectorRegistry:
    """
    Registry of detectors. Provides a unified scan() method
    that runs all registered detectors over input text.
    """

    def __init__(self, detectors: Optional[List[Detector]] = None) -> None:
        self.detectors: List[Detector] = detectors or []

    @classmethod
    def default(cls, region: str = "GB") -> DetectorRegistry:
        """
        Return a registry preloaded with all built-in detectors.
        Region argument affects phone detection.
        """
        return cls([
            EmailDetector(),
            PhoneDetector(default_region=region),
            CreditCardDetector(),
            NHSNumberDetector(),
            USSSNDetector(),
            IBANDetector(),
            HighEntropyTokenDetector(),
        ])

    def register(self, detector: Detector) -> None:
        """Add a detector to the registry."""
        self.detectors.append(detector)

    def unregister(self, name: str) -> None:
        """Remove detectors by name."""
        self.detectors = [d for d in self.detectors if getattr(d, "name", "") != name]

    def scan(self, text: str) -> List[Finding]:
        """
        Run all detectors against a text string.
        Returns a list of Finding objects, sorted by start offset.
        """
        findings: List[Finding] = []
        for d in self.detectors:
            try:
                findings.extend(d.detect(text))
            except Exception:  # fail-safe
                logger.exception(
                    "Detector %s raised an exception during scan", getattr(d, "name", "unknown")
                )
        return sorted(findings, key=lambda f: (f.span[0], f.span[1]))
