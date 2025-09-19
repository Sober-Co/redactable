"""Utilities for constructing :class:`Policy` objects in code."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Iterator, TYPE_CHECKING

from .model import Policy, Rule


if TYPE_CHECKING:  # pragma: no cover - for typing only
    from .model import RuleWhere


class PolicyBuilder:
    """Fluent helper for building :class:`Policy` objects in Python code.

    The builder hides the JSON/YAML layout required by :func:`load_policy`
    and exposes convenience helpers for the common actions (``redact``,
    ``mask`` and ``tokenize``). The resulting :class:`Policy` is fully
    compatible with the policy engine.
    """

    def __init__(
        self,
        *,
        name: str,
        version: int = 1,
        description: str | None = None,
    ) -> None:
        self._name = name
        self._version = version
        self._description = description
        self._counter = 0
        self._rules: list[Rule] = []

    # ------------------------------------------------------------------
    # public API

    def rule(self, *, id: str | None = None, **kwargs) -> "PolicyBuilder":
        """Append an arbitrary rule to the policy.

        Args:
            id: Optional identifier. If omitted a stable identifier is
                generated from the detector ``field`` and ``action``.
            **kwargs: Keyword arguments forwarded to :class:`Rule`.
        """

        data = dict(kwargs)
        if "field" not in data:
            raise TypeError("rule() missing required keyword argument: 'field'")
        if "action" not in data:
            raise TypeError("rule() missing required keyword argument: 'action'")

        data.setdefault("id", id or self._next_id(data["field"], data["action"]))
        rule = Rule(**data)
        self._rules.append(rule)
        return self

    def redact(
        self,
        field: str,
        *,
        id: str | None = None,
        replacement: str | None = None,
        where: dict[str, object] | "RuleWhere" | None = None,
    ) -> "PolicyBuilder":
        """Append a redact rule."""

        data: dict[str, object] = {
            "field": field,
            "action": "redact",
        }
        if replacement is not None:
            data["replacement"] = replacement
        if where is not None:
            data["where"] = where
        return self.rule(id=id, **data)

    def mask(
        self,
        field: str,
        *,
        id: str | None = None,
        keep_head: int | None = None,
        keep_tail: int | None = None,
        mask_glyph: str | None = None,
        where: dict[str, object] | "RuleWhere" | None = None,
    ) -> "PolicyBuilder":
        """Append a mask rule."""

        data: dict[str, object] = {
            "field": field,
            "action": "mask",
        }
        if keep_head is not None:
            data["keep_head"] = keep_head
        if keep_tail is not None:
            data["keep_tail"] = keep_tail
        if mask_glyph is not None:
            data["mask_glyph"] = mask_glyph
        if where is not None:
            data["where"] = where
        return self.rule(id=id, **data)

    def tokenize(
        self,
        field: str,
        *,
        id: str | None = None,
        salt: str | None = None,
        where: dict[str, object] | "RuleWhere" | None = None,
    ) -> "PolicyBuilder":
        """Append a tokenize rule."""

        data: dict[str, object] = {
            "field": field,
            "action": "tokenize",
        }
        if salt is not None:
            data["salt"] = salt
        if where is not None:
            data["where"] = where
        return self.rule(id=id, **data)

    def extend(self, rules: Iterable[Rule]) -> "PolicyBuilder":
        """Append an iterable of existing :class:`Rule` instances."""

        for rule in rules:
            self._rules.append(rule)
        return self

    def build(self) -> Policy:
        """Create the :class:`Policy` described by the builder."""

        return Policy(
            version=self._version,
            name=self._name,
            description=self._description,
            rules=list(self._rules),
        )

    # ------------------------------------------------------------------
    # helpers

    def _next_id(self, field: str, action: str) -> str:
        self._counter += 1
        norm_field = field.strip().lower().replace(" ", "_")
        return f"rule_{norm_field}_{action}_{self._counter:02d}"


@dataclass(frozen=True)
class PolicyFactory:
    """Convenience wrapper to generate common policies.

    Instances are callable and yield :class:`Policy` objects when invoked.
    The factory stores the configuration used to populate a
    :class:`PolicyBuilder`, making it easy to create consistent policies in
    multiple places (e.g. for tests and production).
    """

    name: str
    version: int = 1
    description: str | None = None
    rules: tuple[dict[str, object], ...] = field(default_factory=tuple)

    def __call__(self) -> Policy:
        builder = PolicyBuilder(name=self.name, version=self.version, description=self.description)
        for data in self.rules:
            builder.rule(**data)
        return builder.build()

    def iter_rules(self) -> Iterator[dict[str, object]]:
        """Return an iterator over the stored rule dictionaries."""

        return iter(self.rules)
