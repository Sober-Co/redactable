"""Masking transform for redactable."""

from typing import Iterable

from redactable.detectors.base import Finding


def _mask(value: str, keep_head: int = 0, keep_tail: int = 4, glyph: str = "\u2022") -> str:
    """Mask a single value, preserving optional head/tail characters."""
    if len(value) <= keep_head + keep_tail:
        return glyph * len(value)
    return value[:keep_head] + glyph * (len(value) - keep_head - keep_tail) + value[-keep_tail:]


def mask_in_place(
    text: str,
    findings: Iterable[Finding],
    keep_head: int = 0,
    keep_tail: int = 4,
    glyph: str = "\u2022",
) -> str:
    """Replace matched spans with masked versions (right-to-left)."""
    out = text
    for f in sorted(findings, key=lambda x: x.span[0], reverse=True):
        s, e = f.span
        out = out[:s] + _mask(out[s:e], keep_head, keep_tail, glyph) + out[e:]
    return out
