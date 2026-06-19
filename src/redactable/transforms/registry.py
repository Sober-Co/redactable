"""Transform Registry for redaction operations."""

from __future__ import annotations
from typing import Callable, Dict, Optional

from redactable.detectors import Finding


class TransformRegistry:
    """
    Registry of transforms. Provides access to registered transformation functions.
    """

    def __init__(self, transforms: Optional[Dict[str, Callable]] = None) -> None:
        self.transforms: Dict[str, Callable] = transforms or {}

    @classmethod
    def default(cls) -> TransformRegistry:
        """Return a registry preloaded with built-in transforms."""
        from . import redact, mask, tokenise

        return cls({
            "redact": redact.redact,
            "mask": mask.mask,
            "tokenize": tokenise.tokenize,
            "tokenise": tokenise.tokenize,  # Alias
        })

    def register(self, name: str, transform: Callable) -> None:
        """Register a transformation function."""
        self.transforms[name] = transform

    def get(self, name: str) -> Optional[Callable]:
        """Get a transformation function by name."""
        return self.transforms.get(name.lower())

    def list(self) -> list[str]:
        """List all available transforms."""
        return list(self.transforms.keys())
