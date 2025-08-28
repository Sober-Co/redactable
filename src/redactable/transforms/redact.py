from typing import Iterable
from redactable.detectors import Finding

def redact(text: str, findings: Iterable[Finding], placeholder_fmt: str = "[REDACTED:{kind}]") -> str:
    """
    Replace spans with a placeholder; assumes findings' spans are in original coordinates.
    Applies from right-to-left to preserve offsets.
    """
    out = text
    for f in sorted(findings, key=lambda x: x.span[0], reverse=True):
        start, end = f.span
        out = out[:start] + placeholder_fmt.format(kind=f.kind.upper()) + out[end:]
    return out
