from redactable import apply


def test_apply_with_gdpr_policy():
    text = "Customer email: test@example.com"
    out = apply(text, policy="gdpr.yaml")
    # The GDPR policy masks email - original should not appear unchanged
    assert "test@example.com" not in out or out != text


def test_apply_without_policy_returns_unchanged():
    text = "Customer email: test@example.com"
    out = apply(text)
    assert out == text


def test_apply_with_region():
    text = "Call +447911123456"
    out = apply(text, region="GB")
    assert isinstance(out, str)
