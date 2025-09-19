import re
from typing import Any, Iterable, Optional

from .base import Match, register

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

    def detect(
        self,
        text: str,
        *,
        context: Optional[dict[str, Any]] = None,
    ) -> Iterable[Match]:
        for m in _EMAIL.finditer(text):
            yield Match(label="EMAIL", start=m.start(1), end=m.end(1), value=m.group(1), confidence=0.95)

register(EmailDetector())
