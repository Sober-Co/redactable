import re
from .base import Match, register
from .utils import iban_check

_IBAN = re.compile(r'\b([A-Z]{2}\d{2}[A-Z0-9]{11,30})\b', re.I)

class IBANDetector:
    name = "iban"
    labels = ("IBAN",)

    def detect(self, text: str, *, context=None):
        for m in _IBAN.finditer(text):
            token = m.group(1).upper()
            if iban_check(token):
                yield Match("IBAN", m.start(1), m.end(1), token, 0.98, {"country": token[:2]})

register(IBANDetector())
