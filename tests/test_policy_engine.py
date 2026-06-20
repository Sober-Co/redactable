"""Tests for policy engine and audit logging."""

from redactable.audit import AuditEvent
from redactable.detectors import Finding
from redactable.policy.engine import apply_policy
from redactable.policy.model import Policy, Rule


def test_apply_policy_single_rule():
    """Test applying a policy with a single rule."""
    text = "Contact: alice@example.com"
    findings = [Finding(kind="email", value="alice@example.com", span=(9, 27), confidence=0.95)]
    policy = Policy(
        version=1,
        name="test",
        rules=[
            Rule(
                id="email_redact",
                field="email",
                action="redact",
                replacement="[REDACTED:EMAIL]",
            )
        ],
    )
    result = apply_policy(policy, findings, text)
    assert result == "Contact: [REDACTED:EMAIL]"
    assert "@example.com" not in result


def test_apply_policy_multiple_rules():
    """Test applying a policy with multiple rules."""
    text = "Email: alice@example.com and Card: 4111111111111111"
    findings = [
        Finding(kind="email", value="alice@example.com", span=(7, 25), confidence=0.95),
        Finding(kind="credit_card", value="4111111111111111", span=(37, 53), confidence=0.99),
    ]
    policy = Policy(
        version=1,
        name="test",
        rules=[
            Rule(id="r1", field="email", action="redact"),
            Rule(id="r2", field="credit_card", action="mask", keep_tail=4),
        ],
    )
    result = apply_policy(policy, findings, text)
    assert "[REDACTED:EMAIL]" in result
    assert "••••1111" in result
    assert "alice@example.com" not in result
    assert "4111111111111111" not in result


def test_apply_policy_with_mask_rule():
    """Test applying a mask rule."""
    text = "Card: 4111111111111111"
    findings = [
        Finding(kind="credit_card", value="4111111111111111", span=(6, 22), confidence=0.99)
    ]
    policy = Policy(
        version=1,
        name="test",
        rules=[Rule(id="r1", field="credit_card", action="mask", keep_tail=4)],
    )
    result = apply_policy(policy, findings, text)
    assert "••••1111" in result
    assert "4111111111111111" not in result


def test_apply_policy_with_tokenize_rule():
    """Test applying a tokenize rule."""
    text = "Email: alice@example.com"
    findings = [Finding(kind="email", value="alice@example.com", span=(7, 25), confidence=0.95)]
    policy = Policy(
        version=1,
        name="test",
        rules=[Rule(id="r1", field="email", action="tokenize")],
    )
    result = apply_policy(policy, findings, text)
    # Result should be a hex string (64 chars for SHA256)
    token_part = result.split(": ")[1]
    assert len(token_part) == 64
    assert all(c in "0123456789abcdef" for c in token_part)


def test_apply_policy_no_matching_findings():
    """Test that policy with no matching findings returns unchanged text."""
    text = "No sensitive data here"
    findings = []
    policy = Policy(
        version=1,
        name="test",
        rules=[Rule(id="r1", field="email", action="redact")],
    )
    result = apply_policy(policy, findings, text)
    assert result == text


def test_apply_policy_with_audit_events():
    """Test that audit events are generated when with_audit=True."""
    text = "Contact: alice@example.com"
    findings = [Finding(kind="email", value="alice@example.com", span=(9, 27), confidence=0.95)]
    policy = Policy(
        version=1,
        name="test",
        rules=[Rule(id="email_rule", field="email", action="redact")],
    )
    result, audit_events = apply_policy(policy, findings, text, with_audit=True)

    assert isinstance(result, str)
    assert isinstance(audit_events, list)
    assert len(audit_events) == 1

    event = audit_events[0]
    assert isinstance(event, AuditEvent)
    assert event.field == "email"
    assert event.action == "redact"
    assert event.value_original == "alice@example.com"
    assert "[REDACTED" in event.value_transformed


def test_apply_policy_audit_events_multiple():
    """Test audit events for multiple transformations."""
    text = "Email: alice@example.com and card: 4111111111111111"
    findings = [
        Finding(kind="email", value="alice@example.com", span=(7, 25), confidence=0.95),
        Finding(kind="credit_card", value="4111111111111111", span=(38, 54), confidence=0.99),
    ]
    policy = Policy(
        version=1,
        name="test",
        rules=[
            Rule(id="r1", field="email", action="redact"),
            Rule(id="r2", field="credit_card", action="mask", keep_tail=4),
        ],
    )
    result, audit_events = apply_policy(policy, findings, text, with_audit=True)

    assert len(audit_events) == 2
    assert audit_events[0].field == "email"
    assert audit_events[1].field == "credit_card"


def test_apply_policy_audit_events_no_changes():
    """Test that no audit events are generated when no transformations occur."""
    text = "No sensitive data"
    findings = []
    policy = Policy(
        version=1,
        name="test",
        rules=[Rule(id="r1", field="email", action="redact")],
    )
    result, audit_events = apply_policy(policy, findings, text, with_audit=True)

    assert result == text
    assert audit_events == []


def test_apply_policy_backward_compatibility():
    """Test that apply_policy without with_audit returns only the string."""
    text = "Contact: alice@example.com"
    findings = [Finding(kind="email", value="alice@example.com", span=(9, 27), confidence=0.95)]
    policy = Policy(
        version=1,
        name="test",
        rules=[Rule(id="r1", field="email", action="redact")],
    )
    result = apply_policy(policy, findings, text)

    # Should return only a string, not a tuple
    assert isinstance(result, str)
    assert "[REDACTED" in result
