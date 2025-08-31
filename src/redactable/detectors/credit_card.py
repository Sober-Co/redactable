import re
from typing import Optional

from .base import register, luhn_ok, guess_card_brand, digits_only, Finding

# Match 13–19 digits allowing optional single space/hyphen separators.
# Capture the whole thing; we'll strip non-digits before Luhn.
_PAN = re.compile(r'(?<!\d)((?:\d[ -]?){13,19})(?!\d)')

class CreditCardDetector:
    name = "credit_card"
    labels = ("CREDIT_CARD",)

    def detect(self, text: str, *, context: Optional[dict] = None):
        for m in _PAN.finditer(text):
            raw = m.group(1)
            digits = digits_only(raw)
            if 13 <= len(digits) <= 19 and luhn_ok(digits):
                yield Finding(
                    kind="CREDIT_CARD",
                    value=raw,
                    span=(m.start(1), m.end(1)),
                    confidence=0.9,
                    normalized=digits,
                    extras={"brand": guess_card_brand(digits)}
                )


register(CreditCardDetector())
