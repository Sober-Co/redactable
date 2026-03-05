"""Tokenization (hashing) transform for redactable."""

import hashlib
from typing import Iterable

from redactable.detectors.base import Finding


def _sha256(value: str, salt: str = "") -> str:
    """Compute a SHA-256 hash of value with optional salt."""
    return hashlib.sha256((salt + value).encode("utf-8")).hexdigest()


def tokenise(
    text: str,
    findings: Iterable[Finding],
    salt: str = "",
) -> str:
    """Replace matched spans with SHA-256 hash tokens (right-to-left)."""
    out = text
    for f in sorted(findings, key=lambda x: x.span[0], reverse=True):
        s, e = f.span
        token = _sha256(f.normalized or f.value, salt)
        out = out[:s] + token + out[e:]
    return out
