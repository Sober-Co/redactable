# ruff: noqa: E402
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Mapping

from .model import Policy

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None


_RULE_ALLOWED_KEYS = {
    "id",
    "field",
    "action",
    "replacement",
    "keep_head",
    "keep_tail",
    "mask_glyph",
    "salt",
}


def _extract_field(rule: Mapping[str, Any]) -> str | None:
    """Infer the rule field from extended policy formats."""

    value = rule.get("field")
    if isinstance(value, str) and value.strip():
        return value.strip().lower()

    when = rule.get("when")
    if isinstance(when, Mapping):
        for key in ("detector", "field", "kind"):
            candidate = when.get(key)
            if isinstance(candidate, str) and candidate.strip():
                return candidate.strip().lower()

    return None


def _guess_action_from_type(t: str | None) -> str | None:
    if not t:
        return None
    key = t.strip().lower()
    mapping = {
        "mask": "mask",
        "mask_pan": "mask",
        "tokenise": "tokenize",
        "tokenize": "tokenize",
        "pseudonymise": "tokenize",
        "pseudonymize": "tokenize",
        "hash": "tokenize",
        "redact": "redact",
        "scrub": "redact",
        "generalise": "mask",
        "generalize": "mask",
    }
    return mapping.get(key)


def _guess_action_from_name(name: str | None) -> str | None:
    if not name:
        return None
    key = name.strip().lower()
    prefixes = (
        ("mask", "mask"),
        ("tokenise", "tokenize"),
        ("tokenize", "tokenize"),
        ("pseudonymise", "tokenize"),
        ("pseudonymize", "tokenize"),
        ("hash", "tokenize"),
        ("redact", "redact"),
        ("scrub", "redact"),
        ("generalise", "mask"),
        ("generalize", "mask"),
    )
    for prefix, action in prefixes:
        if key.startswith(prefix):
            return action
    return None


def _infer_action(
    rule: Mapping[str, Any],
    transform_types: Mapping[str, Any],
    default_action: str | None,
) -> str | None:
    value = rule.get("action")
    if isinstance(value, str) and value.strip():
        return value

    transform_name = rule.get("transform")
    transform_key: str | None = None
    if isinstance(transform_name, str) and transform_name.strip():
        transform_key = transform_name.strip()
    has_transform = transform_key is not None
    if has_transform:
        cfg = transform_types.get(transform_key)
        if isinstance(cfg, Mapping):
            action = _guess_action_from_type(cfg.get("type"))
        else:
            action = _guess_action_from_type(cfg)
        if action:
            return action
        action = _guess_action_from_name(transform_key)
        if action:
            return action
        return None

    if not has_transform and isinstance(default_action, str) and default_action.strip():
        return default_action

    return None


def _merge_transform_settings(
    rule: dict[str, Any],
    transform: Mapping[str, Any] | None,
    action: str,
) -> None:
    if not isinstance(transform, Mapping):
        return

    if action == "mask":
        for source_key, target_key in (
            ("show_first", "keep_head"),
            ("show_last", "keep_tail"),
            ("keep_first", "keep_head"),
            ("keep_last", "keep_tail"),
            ("keep_head", "keep_head"),
            ("keep_tail", "keep_tail"),
        ):
            value = transform.get(source_key)
            if isinstance(value, int) and target_key not in rule:
                rule[target_key] = value
        glyph = transform.get("mask_glyph") or transform.get("glyph") or transform.get("replacement")
        if isinstance(glyph, str) and glyph.strip() and "mask_glyph" not in rule:
            rule["mask_glyph"] = glyph
    elif action == "redact":
        replacement = transform.get("replacement")
        if isinstance(replacement, str) and replacement.strip() and "replacement" not in rule:
            rule["replacement"] = replacement
    elif action == "tokenize":
        salt = transform.get("salt")
        if isinstance(salt, str) and salt.strip() and "salt" not in rule:
            rule["salt"] = salt


def _prepare_rules(
    data: Mapping[str, Any],
    *,
    transform_types: Mapping[str, Any],
    default_action: str | None,
) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    for raw_rule in data.get("rules", []) or []:
        if not isinstance(raw_rule, Mapping):
            continue

        field = _extract_field(raw_rule)
        if not field:
            continue

        action = _infer_action(raw_rule, transform_types, default_action)
        if not action:
            continue

        rule: dict[str, Any] = {}
        for key in _RULE_ALLOWED_KEYS:
            if key in raw_rule:
                rule[key] = raw_rule[key]

        rule.setdefault("id", str(raw_rule.get("id", f"rule_{len(rules)}")))
        rule["field"] = field
        rule["action"] = action

        transform_name = raw_rule.get("transform")
        transform_cfg: Mapping[str, Any] | None = None
        if isinstance(transform_name, str) and transform_name.strip():
            transform_cfg = transform_types.get(transform_name.strip())
        _merge_transform_settings(rule, transform_cfg, action)

        rules.append(rule)

    return rules


def _normalize_policy_payload(data: Any, source: Path) -> dict[str, Any]:
    if not isinstance(data, Mapping):
        raise ValueError("Policy documents must define a mapping at the top level")

    metadata = data.get("metadata")
    name: str | None = None
    description: str | None = None
    if isinstance(metadata, Mapping):
        for key in ("name", "id", "title"):
            value = metadata.get(key)
            if isinstance(value, str) and value.strip():
                name = value.strip()
                break
        meta_desc = metadata.get("description")
        if isinstance(meta_desc, str) and meta_desc.strip():
            description = meta_desc.strip()

    if isinstance(data.get("name"), str) and data.get("name").strip():
        name = data["name"].strip()

    if name is None:
        name = source.stem

    if isinstance(data.get("description"), str) and data.get("description").strip():
        description = data["description"].strip()

    defaults = data.get("defaults")
    default_action: str | None = None
    if isinstance(defaults, Mapping):
        default_value = defaults.get("action")
        if isinstance(default_value, str) and default_value.strip():
            default_action = default_value.strip()

    raw_transforms = data.get("transforms")
    transform_types: dict[str, Any] = {}
    if isinstance(raw_transforms, Mapping):
        for key, value in raw_transforms.items():
            if isinstance(value, Mapping):
                transform_types[key] = dict(value)
            else:
                transform_types[key] = {"type": value}

    rules = _prepare_rules(
        data,
        transform_types=transform_types,
        default_action=default_action,
    )

    payload: dict[str, Any] = {
        "version": data.get("version"),
        "name": name,
        "description": description,
        "rules": rules,
    }
    return payload


def _candidate_paths(path: Path) -> Iterable[Path]:
    seen: set[Path] = set()

    def emit(candidate: Path) -> Iterable[Path]:
        resolved = candidate.resolve(strict=False)
        if resolved in seen:
            return
        seen.add(resolved)
        yield candidate

    yield from emit(path)

    if path.is_absolute():
        return

    package_root = Path(__file__).resolve().parents[3]
    roots = [Path.cwd(), package_root, package_root / "src"]
    relative_names = [path]
    if path.parent in {Path("."), Path()}:  # simple filename
        relative_names.extend(
            [
                Path("src") / "examples" / "policies" / path.name,
                Path("examples") / "policies" / path.name,
                Path("policies") / path.name,
            ]
        )

    for root in roots:
        for rel in relative_names:
            yield from emit(root / rel)


def _resolve_policy_path(raw: str | Path) -> Path:
    requested = Path(raw)
    for candidate in _candidate_paths(requested):
        if candidate.exists():
            return candidate
    return requested


def load_policy(path: str | Path) -> Policy:
    """Load a YAML or JSON policy file into a Policy object."""

    p = _resolve_policy_path(path)
    if not p.exists():
        raise FileNotFoundError(f"Policy file not found: {p}")

    text = p.read_text(encoding="utf-8")
    suffix = p.suffix.lower()

    data: Any
    if suffix in {".yaml", ".yml"}:
        if yaml is None:
            raise RuntimeError(
                "PyYAML is required to load YAML policies. Install with `pip install pyyaml`."
            )
        data = yaml.safe_load(text)
    elif suffix == ".json":
        data = json.loads(text)
    else:
        raise ValueError(f"Unsupported policy format: {suffix}")

    payload = _normalize_policy_payload(data, p)
    return Policy(**payload)
