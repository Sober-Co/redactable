# ruff: noqa: E402
from pathlib import Path
import json
from .model import Policy

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None

from typing import Any

def load_policy(path: str | Path) -> Policy:
    """
    Load a YAML or JSON policy file into a Policy object.

    Raises:
        FileNotFoundError: if the path does not exist
        ValueError: if the file extension is unsupported
        pydantic.ValidationError: if the content does not match the schema
    """
    p = Path(path)
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

    return Policy(**data)