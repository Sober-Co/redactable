from pathlib import Path
import json

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
