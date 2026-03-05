"""Decorators for inline redaction of function I/O."""

from __future__ import annotations

import functools
from typing import Any, Callable

from .policy.loader import load_policy
from .policy.engine import apply_policy
from .detectors.registry import DetectorRegistry


def redactable_io(policy: str, *, region: str = "GB") -> Callable:
    """
    Decorator that redacts the return value of a function.

    Usage:
        @redactable_io("gdpr.yaml")
        def get_user_data():
            return "Email: test@example.com"
    """
    pol = load_policy(policy)
    registry = DetectorRegistry.default(region=region)

    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> str:
            result = fn(*args, **kwargs)
            if not isinstance(result, str):
                return result
            findings = list(registry.scan(result))
            return apply_policy(pol, findings, result)
        return wrapper
    return decorator
