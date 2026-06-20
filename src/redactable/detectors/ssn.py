from __future__ import annotations

import re

from .base import Finding, register

_SSN = re.compile(r"(?<!\d)(\d{3}-?\d{2}-?\d{4})(?!\d)")


def _valid_ssn(d: str) -> bool:
    d = d.replace("-", "")
    if len(d) != 9:
        return False
    if d[:3] in {"000", "666"} or d[0] == "9":
        return False
    if d[3:5] == "00":
        return False
    return d[5:] != "0000"


class SSNDetector:
    name = "ssn"

    def detect(self, text: str):
        for m in _SSN.finditer(text):
            raw = m.group(1)
            if _valid_ssn(raw):
                yield Finding(
                    kind="ssn",
                    value=raw,
                    span=(m.start(1), m.end(1)),
                    confidence=0.95,
                )


register(SSNDetector())
