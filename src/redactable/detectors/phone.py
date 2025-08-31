from __future__ import annotations
import re
from typing import Optional
from .base import Finding, register

_E164 = re.compile(r'(?<!\w)(\+\d{9,15})(?!\w)')
_UK   = re.compile(r'(?<!\d)(0(?:7\d{9}|1\d{8,9}|2\d{8,9}))(?!\d)')

class PhoneDetector:
    name = "phone"
    labels = ("PHONE",)

    def detect(self, text: str, *, context: Optional[dict] = None):
        for m in _E164.finditer(text):
            yield Finding(
                kind="PHONE",
                value=m.group(1),
                span=(m.start(1), m.end(1)),
                confidence=0.90,
                extras={"format": "E164"},
            )
        for m in _UK.finditer(text):
            yield Finding(
                kind="PHONE",
                value=m.group(1),
                span=(m.start(1), m.end(1)),
                confidence=0.85,
                extras={"format": "UK"},
            )

register(PhoneDetector())
