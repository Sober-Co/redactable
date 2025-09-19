import re
from typing import Any, Iterable, Optional

from .base import Match, register
from .utils import nhs_check

# Accept formats: 10 digits with optional spaces
_NHS = re.compile(r'\b((?:\d\s*){10})\b')

class NHSDetector:
    name = "nhs"
    labels = ("NHS_NUMBER",)

    def detect(
        self,
        text: str,
        *,
        context: Optional[dict[str, Any]] = None,
    ) -> Iterable[Match]:
        for m in _NHS.finditer(text):
            raw = m.group(1)
            digits = ''.join(ch for ch in raw if ch.isdigit())
            if nhs_check(digits):
                yield Match("NHS_NUMBER", m.start(1), m.end(1), raw, 0.99, {"digits": digits})

register(NHSDetector())
