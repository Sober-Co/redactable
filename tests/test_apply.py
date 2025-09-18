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
