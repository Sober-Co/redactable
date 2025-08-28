from __future__ import annotations
from redactable.detectors import Finding
from .model import Policy
from ..transforms import redact as redact_mod, mask as mask_mod, tokenize as tok_mod

def apply_policy(policy: Policy, findings: list[Finding], text: str) -> str:
    out = text
    # Naive v0.1: apply rules by kind (“field” aligns with detector kind)
    for rule in policy.rules:
        targets = [f for f in findings if f.kind == rule.field]
        if not targets:
            continue
        if rule.action == "redact":
            out = redact_mod.redact(out, targets, placeholder_fmt=rule.replacement or "[REDACTED:{kind}]")
        elif rule.action == "mask":
            # simple heuristic: keep last 4
            out = mask_mod.mask_in_place(out, targets, keep_head=0, keep_tail=4)
        elif rule.action == "tokenize":
            out = tok_mod.tokenize(out, targets, salt="")
    return out
