from __future__ import annotations
import re
from .base import Match, register

# E.164 (+441234567890), simple UK patterns (07..., 01/02... with spaces)
_E164 = re.compile(r'(?<!\w)(\+\d{9,15})(?!\w)')
_UK   = re.compile(r'(?<!\d)(0(?:7\d{9}|1\d{8,9}|2\d{8,9}))(?!\d)')

class PhoneDetector:
    name = "phone"
    labels = ("PHONE",)

    def detect(self, text: str, *, context=None):
        for m in _E164.finditer(text):
            yield Match("PHONE", m.start(1), m.end(1), m.group(1), 0.9, {"format": "E164"})
        for m in _UK.finditer(text):
            yield Match("PHONE", m.start(1), m.end(1), m.group(1), 0.85, {"format": "UK"})

register(PhoneDetector())
