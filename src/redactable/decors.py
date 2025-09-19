"""Decorator helpers for applying redactable policies to callables."""

from __future__ import annotations

from functools import wraps
from typing import Any, Callable, ParamSpec, TypeVar


P = ParamSpec("P")
R = TypeVar("R")


def redactable_io(
    policy: Any,
    *,
    region: str = "GB",
    return_findings: bool = False,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Wrap a callable so its string output is processed by :func:`apply`.

    The decorator executes the wrapped callable first and, when the returned
    value is a string, runs :func:`redactable.apply` with the provided policy
    and region. Non-string return values are passed through unchanged. This
    keeps the decorator flexible for functions that sometimes return metadata
    objects or ``None``.

    Args:
        policy: Policy specification accepted by :func:`redactable.apply`.
        region: Region hint forwarded to the detector registry.
        return_findings: When ``True`` the decorated callable will return the
            tuple ``(text, findings)`` produced by :func:`apply`.
    """

    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        @wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            result = func(*args, **kwargs)

            if not isinstance(result, str):
                return result

            from redactable import apply as _apply  # Local import to avoid cycle.

            return _apply(
                result,
                policy=policy,
                region=region,
                return_findings=return_findings,
            )

        return wrapper  # type: ignore[return-value]

    return decorator


__all__ = ["redactable_io"]
