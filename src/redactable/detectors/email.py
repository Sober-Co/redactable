import re
from typing import Optional
from .base import Finding, register

_EMAIL = re.compile(
    r'(?<![A-Za-z0-9._%+-])'     # left boundary
    r'([A-Za-z0-9._%+-]+@'       # local
    r'(?:[A-Za-z0-9-]+\.)+'      # subdomains
    r'[A-Za-z]{2,63})'           # TLD
    r'(?![A-Za-z0-9._%+-])'      # right boundary
)

class EmailDetector:
    name = "email"
    labels = ("EMAIL",)

    def detect(self, text: str, *, context: Optional[dict] = None):
        for m in _EMAIL.finditer(text):
            yield Finding(
                kind="EMAIL",
                value=m.group(1),
                span=(m.start(1), m.end(1)),
                confidence=0.95,
            )

register(EmailDetector())
