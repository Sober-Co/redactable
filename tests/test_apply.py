from redactable import apply

def test_apply_stub_masks_example_com():
    text = "Customer email: test@example.com"
    out = apply(text, policy="gdpr.yaml")
    # Since apply is stubbed, we only check the placeholder behavior
    assert "****@example.com" in out
