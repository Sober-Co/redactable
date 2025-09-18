from redactable import apply
from redactable.policy import PolicyBuilder


def test_apply_stub_masks_example_com():
    text = "Customer email: test@example.com"
    policy = PolicyBuilder(name="stub").mask("email", keep_tail=12, mask_glyph="*").build()
    out = apply(text, policy=policy)
    assert "****@example.com" in out
