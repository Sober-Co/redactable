# ruff: noqa: E402
from dataclasses import dataclass
import hashlib
from typing import Iterable

from redactable.detectors import Finding
from redactable.policy import Policy


@dataclass(slots=True)
class _MaskCfg:
    keep_head: int = 0
    keep_tail: int = 4
    glyph: str = "•"

# --- local transforms (minimal v0.1; no external deps) ---------------------

def _redact(text: str, findings: Iterable[Finding], placeholder: str = "[REDACTED:{kind}]") -> str:
    out = text
    for f in sorted(findings, key=lambda x: x.span[0], reverse=True):
        s, e = f.span
        out = out[:s] + placeholder.format(kind=f.kind.upper()) + out[e:]
    return out


def _mask_segment(s: str, cfg: _MaskCfg) -> str:
    if len(s) <= cfg.keep_head + cfg.keep_tail:
        return cfg.glyph * len(s)
    mid = cfg.glyph * (len(s) - cfg.keep_head - cfg.keep_tail)
    return s[:cfg.keep_head] + mid + s[-cfg.keep_tail:]


def _mask(text: str, findings: Iterable[Finding], cfg: _MaskCfg) -> str:
    out = text
    for f in sorted(findings, key=lambda x: x.span[0], reverse=True):
        s, e = f.span
        out = out[:s] + _mask_segment(out[s:e], cfg) + out[e:]
    return out


def _sha256(value: str, salt: str = "") -> str:
    return hashlib.sha256((salt + value).encode("utf-8")).hexdigest()


def _tokenize(text: str, findings: Iterable[Finding], salt: str = "") -> str:
    out = text
    for f in sorted(findings, key=lambda x: x.span[0], reverse=True):
        s, e = f.span
        token = _sha256(f.normalized or f.value, salt)
        out = out[:s] + token + out[e:]
    return out


# --- public API -------------------------------------------------------------

def apply_policy(policy: Policy, findings: list[Finding], text: str) -> str:
    """
    Apply a Policy to text using previously-detected Findings.

    Strategy (v0.1):
    - Treat `rule.field` as the detector kind (e.g. "email", "credit_card").
    - Apply actions independently; rules are idempotent by design.
    - Apply replacements right-to-left to preserve spans.
    """
    out = text

    # Group findings by kind for quick lookup
    by_kind: dict[str, list[Finding]] = {}
    for f in findings:
        by_kind.setdefault(f.kind, []).append(f)

    for rule in policy.rules:
        targets = by_kind.get(rule.field, [])
        if not targets:
            continue
        if rule.action == "redact":
            placeholder = rule.replacement or "[REDACTED:{kind}]"
            out = _redact(out, targets, placeholder)
        elif rule.action == "mask":
            cfg = _MaskCfg(keep_head=rule.keep_head, keep_tail=rule.keep_tail, glyph=rule.mask_glyph)
            out = _mask(out, targets, cfg)
        elif rule.action == "tokenize":
            out = _tokenize(out, targets, salt=rule.salt)

    return out
