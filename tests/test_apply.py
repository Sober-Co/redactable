from redactable import apply


def test_apply_builtin_gdpr_masks_example_com():
    text = "Customer email: test@example.com"
    out = apply(text, policy="gdpr")
    assert "****@example.com" in out


def test_apply_builtin_alias_extension_still_works():
    text = "Customer email: test@example.com"
    out = apply(text, policy="gdpr.yaml")
    assert "****@example.com" in out


def test_apply_pci_redacts_pan():
    text = "Card: 4111 1111 1111 1111"
    out = apply(text, policy="pci")
    assert "[PCI-PAN]" in out
