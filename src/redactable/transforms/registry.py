"""Transform registry -- maps action names to transform functions."""

from __future__ import annotations

from typing import Any, Callable

# Action name -> callable(text, findings, **kwargs) -> str
_TRANSFORMS: dict[str, Callable[..., str]] = {}


def register_transform(name: str, fn: Callable[..., str]) -> None:
    """Register a transform function under a given action name."""
    _TRANSFORMS[name] = fn


def get_transform(name: str) -> Callable[..., str]:
    """Look up a registered transform by action name."""
    if name not in _TRANSFORMS:
        raise KeyError(f"Unknown transform: {name!r}")
    return _TRANSFORMS[name]


def _register_builtins() -> None:
    from .redact import redact
    from .mask import mask_in_place
    from .tokenise import tokenise

    register_transform("redact", redact)
    register_transform("mask", mask_in_place)
    register_transform("tokenize", tokenise)
    register_transform("tokenise", tokenise)


_register_builtins()
