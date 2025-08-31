import re
from typing import Optional
from .base import Finding, register
from .utils import nhs_check

_NHS = re.compile(r'\b((?:\d\s*){10})\b')

class NHSDetector:
    name = "nhs"
    labels = ("NHS_NUMBER",)

    def detect(self, text: str, *, context: Optional[dict] = None):
        for m in _NHS.finditer(text):
            raw = m.group(1)
            digits = ''.join(ch for ch in raw if ch.isdigit())
            if nhs_check(digits):
                yield Finding(
                    kind="NHS_NUMBER",
                    value=raw,
                    span=(m.start(1), m.end(1)),
                    confidence=0.99,
                    normalized=digits,
                )

register(NHSDetector())
