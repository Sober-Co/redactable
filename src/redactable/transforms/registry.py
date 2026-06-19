"""Transform Registry for redaction operations.

Note: In v0.1, transforms are applied directly via policy engine.
This registry provides extensibility for v0.2+ plugin system.
"""

from __future__ import annotations
from typing import Callable, Dict, Optional


class TransformRegistry:
    """
    Registry of transforms. Provides extensibility for custom transformations.

    In v0.1, this is a placeholder for the plugin system coming in v0.2.
    Actual transforms (redact, mask, tokenize) are applied via policy/engine.py.
    """

    def __init__(self, transforms: Optional[Dict[str, Callable]] = None) -> None:
        self.transforms: Dict[str, Callable] = transforms or {}

    @classmethod
    def default(cls) -> TransformRegistry:
        """Return a registry preloaded with built-in transforms (v0.2)."""
        return cls({
            "redact": None,
            "mask": None,
            "tokenize": None,
        })

    def register(self, name: str, transform: Callable) -> None:
        """Register a custom transformation function."""
        self.transforms[name] = transform

    def get(self, name: str) -> Optional[Callable]:
        """Get a transformation function by name."""
        return self.transforms.get(name.lower())

    def list(self) -> list[str]:
        """List all available transforms."""
        return list(self.transforms.keys())
