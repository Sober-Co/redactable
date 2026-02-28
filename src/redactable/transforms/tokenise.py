import hashlib
from typing import Iterable

from redactable.detectors import Finding


def _sha256(value: str, salt: str = "") -> str:
    return hashlib.sha256((salt + value).encode("utf-8")).hexdigest()


def tokenise_in_place(text: str, findings: Iterable[Finding], salt: str = "") -> str:
    out = text
    for f in sorted(findings, key=lambda x: x.span[0], reverse=True):
        s, e = f.span
        token = _sha256(f.normalized or f.value, salt)
        out = out[:s] + token + out[e:]
    return out
