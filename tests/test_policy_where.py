import pytest

from redactable.detectors import Finding
from redactable.policy import Policy, Rule
from redactable.policy.engine import apply_policy


def test_rule_where_filters_by_confidence():
    text = "a@b.com z@x.com"
    findings = [
        Finding(kind="email", value="a@b.com", span=(0, 7), confidence=0.95),
        Finding(kind="email", value="z@x.com", span=(8, 15), confidence=0.5),
    ]
    policy = Policy(
        version=1,
        name="conf",
        rules=[
            Rule(
                id="redact-high-confidence",
                field="email",
                action="redact",
                where={"min_confidence": 0.9},
            )
        ],
    )

    out = apply_policy(policy, findings, text)

    assert "[REDACTED:EMAIL]" in out
    assert "z@x.com" in out


def test_rule_where_filters_by_value_regex():
    text = "Contact: a@example.com or z@test.dev"
    findings = [
        Finding(kind="email", value="a@example.com", span=(9, 22), confidence=0.9),
        Finding(kind="email", value="z@test.dev", span=(26, 36), confidence=0.9),
    ]
    policy = Policy(
        version=1,
        name="regex",
        rules=[
            Rule(
                id="mask-example-domain",
                field="email",
                action="mask",
                keep_tail=4,
                mask_glyph="*",
                where={"value_matches": r"@example\.com$"},
            )
        ],
    )

    out = apply_policy(policy, findings, text)

    assert "z@test.dev" in out
    assert "@example.com" not in out
    assert "*********.com" in out


def test_rule_where_filters_on_metadata():
    text = "4111 1111 1111 1111 and 5555 5555 5555 4444"
    findings = [
        Finding(
            kind="credit_card",
            value="4111 1111 1111 1111",
            span=(0, 19),
            confidence=0.85,
            normalized="4111111111111111",
            extras={"brand": "visa"},
        ),
        Finding(
            kind="credit_card",
            value="5555 5555 5555 4444",
            span=(24, 43),
            confidence=0.85,
            normalized="5555555555554444",
            extras={"brand": "mastercard"},
        ),
    ]
    policy = Policy(
        version=1,
        name="metadata",
        rules=[
            Rule(
                id="tokenize-visa",
                field="credit_card",
                action="tokenize",
                salt="pepper",
                where={"metadata": {"brand": "visa"}},
            )
        ],
    )

    out = apply_policy(policy, findings, text)

    assert "5555 5555 5555 4444" in out
    assert "visa" not in out


def test_rule_where_invalid_regex_raises_validation_error():
    with pytest.raises(ValueError):
        Rule(id="bad", field="email", action="redact", where={"value_matches": "["})
