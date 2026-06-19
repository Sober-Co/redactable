"""Audit trail generation for redaction operations."""

from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Any, TYPE_CHECKING

from redactable.detectors import Finding

if TYPE_CHECKING:
    from redactable.policy import Rule


@dataclass(slots=True)
class AuditEvent:
    """Record of a single redaction/masking operation."""

    timestamp: str
    field: str
    action: str
    value_original: str
    value_transformed: str
    span: tuple[int, int]
    confidence: float
    rule_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


def generate_audit_event(
    finding: Finding,
    rule: "Rule",
    original_text: str,
    transformed_text: str,
) -> AuditEvent:
    """
    Generate an audit event for a finding that was transformed.

    Args:
        finding: The detected sensitive data.
        rule: The policy rule that was applied.
        original_text: The original full text.
        transformed_text: The transformed full text.

    Returns:
        AuditEvent record.
    """
    s, e = finding.span
    original_segment = original_text[s:e]
    transformed_segment = transformed_text[s:e]

    return AuditEvent(
        timestamp=datetime.utcnow().isoformat() + "Z",
        field=rule.field,
        action=rule.action,
        value_original=original_segment,
        value_transformed=transformed_segment,
        span=finding.span,
        confidence=finding.confidence,
        rule_reason=rule.reason,
    )
