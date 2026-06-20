import re

from .base import Finding, register
from .utils import luhn_check

_PAN = re.compile(r"(?<!\d)((?:\d[ -]?){13,19})(?!\d)")


def _brand(digits: str) -> str | None:
    if digits.startswith("4") and len(digits) in (13, 16, 19):
        return "VISA"
    if (
        (digits[:2] in {str(i) for i in range(51, 56)}
         or (len(digits) >= 4 and 2221 <= int(digits[:4]) <= 2720))
        and len(digits) == 16
    ):
        return "MASTERCARD"
    if digits.startswith(("34", "37")) and len(digits) == 15:
        return "AMEX"
    return None


class CreditCardDetector:
    name = "credit_card"

    def detect(self, text: str):
        for m in _PAN.finditer(text):
            raw = m.group(1)
            digits = "".join(ch for ch in raw if ch.isdigit())
            if 13 <= len(digits) <= 19 and luhn_check(digits):
                yield Finding(
                    kind="credit_card",
                    value=raw,
                    span=(m.start(1), m.end(1)),
                    confidence=0.98,
                    extras={"digits": digits, "brand": _brand(digits)},
                )


register(CreditCardDetector())
