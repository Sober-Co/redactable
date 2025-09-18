import pytest

from redactable.policy.defaults import (
    builtin_policy_names,
    describe_builtin_policies,
    get_builtin_policy,
    is_builtin_policy,
)
from redactable.policy.loader import load_policy


def test_builtin_catalog_lists_expected_templates():
    names = set(builtin_policy_names())
    assert {"gdpr", "pci", "hipaa"}.issubset(names)

    descriptions = describe_builtin_policies()
    assert all(descriptions.get(name) for name in names)


def test_get_builtin_policy_returns_deep_copies():
    first = get_builtin_policy("gdpr")
    second = get_builtin_policy("gdpr")
    assert first is not second
    assert first.model_dump() == second.model_dump()


def test_loader_accepts_aliases_and_suffixes():
    hipaa = load_policy("hipaa")
    assert hipaa.name == "hipaa"

    pci_alias = load_policy("pci-dss")
    assert pci_alias.name == "pci-dss"

    gdpr_suffix = load_policy("gdpr.yaml")
    assert gdpr_suffix.name == "gdpr"

    assert is_builtin_policy("hipaa")


def test_loader_does_not_fallback_for_missing_paths_with_directories(tmp_path):
    missing_in_tmp = tmp_path / "policies" / "gdpr.yaml"
    with pytest.raises(FileNotFoundError):
        load_policy(missing_in_tmp)

    with pytest.raises(FileNotFoundError):
        load_policy("missing/gdpr.yaml")
