import re
from typing import Any, Iterable, Optional

from .base import Match, register
from .utils import luhn_check

# Match 13–19 digits allowing optional single space/hyphen separators.
# Capture the whole thing; we'll strip non-digits before Luhn.
_PAN = re.compile(r'(?<!\d)((?:\d[ -]?){13,19})(?!\d)')

def _brand(digits: str) -> str | None:
    if digits.startswith('4') and len(digits) in (13, 16, 19):
        return "VISA"
    if digits[:2] in {str(i) for i in range(51, 56)} or (len(digits) >= 4 and 2221 <= int(digits[:4]) <= 2720):
        if len(digits) == 16:
            return "MASTERCARD"
    if digits.startswith(('34', '37')) and len(digits) == 15:
        return "AMEX"
    return None

class CreditCardDetector:
    name = "credit_card"
    labels = ("CREDIT_CARD",)

    def detect(
        self,
        text: str,
        *,
        context: Optional[dict[str, Any]] = None,
    ) -> Iterable[Match]:
        for m in _PAN.finditer(text):
            raw = m.group(1)
            digits = ''.join(ch for ch in raw if ch.isdigit())
            brand = _brand(digits)
            if 13 <= len(digits) <= 19 and luhn_check(digits):
                confidence = 0.95
                if brand:
                    confidence = min(1.0, confidence + 0.03)
                else:
                    confidence = max(0.0, confidence - 0.03)
                yield Match(
                    label="CREDIT_CARD",
                    start=m.start(1), end=m.end(1),
                    value=raw,
                    confidence=confidence,
                    meta={"digits": digits, "brand": brand}
                )

register(CreditCardDetector())
