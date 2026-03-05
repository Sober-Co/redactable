"""
Composite detection + policy application engine.

Provides a high-level RedactionEngine that wires together
detection, policy loading, transformation, and audit logging.
"""

from __future__ import annotations

from typing import Any

from .detectors.registry import DetectorRegistry
from .detectors.base import Finding
from .policy.loader import load_policy
from .policy.engine import apply_policy
from .policy.model import Policy
from .audit import AuditLogger


class RedactionEngine:
    """
    High-level engine that combines detection, policy, and audit.

    Usage:
        engine = RedactionEngine(policy="gdpr.yaml")
        result = engine.redact("Customer email: test@example.com")
    """

    def __init__(
        self,
        policy: str | Policy | None = None,
        *,
        region: str = "GB",
        audit_path: str | None = None,
    ):
        self._registry = DetectorRegistry.default(region=region)
        self._policy: Policy | None = None
        if isinstance(policy, Policy):
            self._policy = policy
        elif isinstance(policy, str):
            self._policy = load_policy(policy)
        self._audit = AuditLogger(path=audit_path)

    def detect(self, text: str) -> list[Finding]:
        """Run all detectors on text and return findings."""
        return list(self._registry.scan(text))

    def redact(self, text: str) -> str:
        """Detect and apply policy transformations to text."""
        findings = self.detect(text)
        if not self._policy:
            return text

        result = apply_policy(self._policy, findings, text)

        for f in findings:
            matched_rules = self._policy.by_field(f.kind)
            for rule in matched_rules:
                self._audit.log(
                    field=f.kind,
                    action=rule.action,
                    rule_id=rule.id,
                    detector=f.kind,
                    confidence=f.confidence,
                )

        return result

    @property
    def audit_log(self) -> AuditLogger:
        """Access the audit logger."""
        return self._audit
