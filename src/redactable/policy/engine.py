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

def _cumulative_offset(offsets: list[tuple[int, int]], position: int) -> int:
    """Compute total offset to apply before ``position``.

    Offsets are recorded against the original finding start indices, so any
    replacement that happened earlier in the text (strictly before the
    position) should contribute to the adjustment. The returned value is the
    shift that needs to be applied to map the original coordinate to the
    current text.
    """

    total = 0
    for start, delta in offsets:
        if start < position:
            total += delta
    return total


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

    offsets: list[tuple[int, int]] = []

    for rule in policy.rules:
        targets = by_kind.get(rule.field, [])
        if rule.where is not None:
            targets = [f for f in targets if rule.applies_to(f)]
        if not targets:
            continue

        adjusted_targets: list[tuple[Finding, int, int]] = []
        for f in targets:
            start, end = f.span
            adj_start = start + _cumulative_offset(offsets, start)
            adj_end = end + _cumulative_offset(offsets, end)
            adjusted_targets.append((f, adj_start, adj_end))

        replacements: list[tuple[int, int, str, int]] = []
        # tuple -> (adjusted_start, adjusted_end, replacement_text, original_start)
        if rule.action == "redact":
            placeholder = rule.replacement or "[REDACTED:{kind}]"
            for f, adj_start, adj_end in adjusted_targets:
                replacement = placeholder.format(kind=f.kind.upper())
                replacements.append((adj_start, adj_end, replacement, f.span[0]))
        elif rule.action == "mask":
            cfg = _MaskCfg(keep_head=rule.keep_head, keep_tail=rule.keep_tail, glyph=rule.mask_glyph)
            for f, adj_start, adj_end in adjusted_targets:
                replacement = _mask_segment(out[adj_start:adj_end], cfg)
                replacements.append((adj_start, adj_end, replacement, f.span[0]))
        elif rule.action == "tokenize":
            for f, adj_start, adj_end in adjusted_targets:
                token = _sha256(f.normalized or f.value, salt=rule.salt)
                replacements.append((adj_start, adj_end, token, f.span[0]))

        if not replacements:
            continue

        for adj_start, adj_end, replacement, orig_start in sorted(replacements, key=lambda r: r[0], reverse=True):
            out = out[:adj_start] + replacement + out[adj_end:]
            delta = len(replacement) - (adj_end - adj_start)
            if delta:
                offsets.append((orig_start, delta))

    return out
