import json
from pathlib import Path

import pytest

from redactable.policy.loader import load_policy


def test_load_policy_expands_user_path(tmp_path, monkeypatch):
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    monkeypatch.setenv("HOME", str(home_dir))

    policy_content = {
        "version": 1,
        "name": "test",
        "description": "Test policy",
        "rules": [
            {
                "id": "rule-email",
                "field": "email",
                "action": "redact",
            }
        ],
    }
    policy_path = home_dir / "policy.json"
    policy_path.write_text(json.dumps(policy_content), encoding="utf-8")

    policy = load_policy(Path("~/policy.json"))

    assert policy.name == "test"


@pytest.mark.parametrize(
    "policy_path",
    [
        Path("policies/gdpr.yaml"),
        Path("policies/pci.yaml"),
    ],
)
def test_load_policy_extended_examples(policy_path: Path) -> None:
    policy = load_policy(policy_path)

    assert policy.name
    assert policy.rules, "expected rules to be inferred from extended policy"

    # Ensure key rules were converted with inferred actions/fields
    first = policy.rules[0]
    assert first.field
    assert first.action in {"redact", "mask", "tokenize"}


def test_load_policy_preserves_basic_schema() -> None:
    policy = load_policy(Path("src/examples/policies/gdpr.yaml"))

    assert policy.name == "GDPR Default (GB)"
    assert policy.rules[0].action == "mask"
