from redactable import apply
from redactable.policy import PolicyBuilder


def test_apply_stub_masks_example_com():
    text = "Customer email: test@example.com"
    policy = PolicyBuilder(name="stub").mask("email", keep_tail=12, mask_glyph="*").build()
    out = apply(text, policy=policy)
    assert "****@example.com" in out


def test_apply_can_return_findings():
    text = "Customer email: test@example.com"
    policy = (
        PolicyBuilder(name="stub")
        .mask("email", keep_tail=12, mask_glyph="*")
        .build()
    )
    out, findings = apply(text, policy=policy, return_findings=True)
    assert "****@example.com" in out
    assert any(f.kind == "email" for f in findings)


def test_apply_return_findings_without_policy():
    text = "Customer email: test@example.com"
    out, findings = apply(text, policy=None, return_findings=True)
    assert out == text
    assert any(f.kind == "email" for f in findings)


def test_apply_mixed_policy_handles_length_shifts():
    text = "Email test@example.com and phone 07123456789."
    policy = (
        PolicyBuilder(name="mixed")
        .redact("email")
        .mask("phone", keep_head=2, keep_tail=2, mask_glyph="*")
        .build()
    )

    out = apply(text, policy=policy)

    assert "[REDACTED:EMAIL]" in out
    assert "07*******89" in out
