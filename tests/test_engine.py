"""Tests for the RedactionEngine and audit logging."""

from redactable.engine import RedactionEngine
from redactable.audit import AuditLogger


class TestRedactionEngine:
    def test_engine_with_policy(self):
        engine = RedactionEngine(policy="gdpr.yaml")
        result = engine.redact("Email: test@example.com")
        assert "test@example.com" not in result or result != "Email: test@example.com"

    def test_engine_without_policy(self):
        engine = RedactionEngine()
        text = "Email: test@example.com"
        result = engine.redact(text)
        assert result == text

    def test_engine_detect(self):
        engine = RedactionEngine()
        findings = engine.detect("Email: test@example.com")
        assert len(findings) > 0
        assert any(f.kind == "email" for f in findings)


class TestAuditLogger:
    def test_log_and_summary(self):
        logger = AuditLogger()
        logger.log(field="email", action="mask")
        logger.log(field="phone", action="redact")
        logger.log(field="ssn", action="redact")
        assert len(logger.events) == 3
        summary = logger.summary()
        assert summary["mask"] == 1
        assert summary["redact"] == 2

    def test_log_with_metadata(self):
        logger = AuditLogger()
        logger.log(
            field="email",
            action="mask",
            rule_id="email_mask",
            reason="GDPR",
            detector="email",
            confidence=0.95,
        )
        event = logger.events[0]
        assert event["field"] == "email"
        assert event["rule_id"] == "email_mask"
        assert event["confidence"] == 0.95
        assert "timestamp" in event
