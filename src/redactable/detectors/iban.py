import re
from typing import Optional
from .base import Finding, register
from .utils import iban_check

_IBAN = re.compile(r'\b([A-Z]{2}\d{2}[A-Z0-9]{11,30})\b', re.I)

class IBANDetector:
    name = "iban"
    labels = ("IBAN",)

    def detect(self, text: str, *, context: Optional[dict] = None):
        for m in _IBAN.finditer(text):
            token = m.group(1).upper()
            if iban_check(token):
                yield Finding(
                    kind="IBAN",
                    value=token,
                    span=(m.start(1), m.end(1)),
                    confidence=0.98,
                    normalized=token,
                    extras={"country": token[:2]},
                )

register(IBANDetector())
