# ruff: noqa: E402
from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, Literal, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

if TYPE_CHECKING:  # pragma: no cover - typing helpers
    from redactable.detectors import Finding

Action = Literal["redact", "mask", "tokenize"]
_ACTION_ALIASES = {
    "tokenise": "tokenize",
    "tokenize": "tokenize",
    "pseudonymise": "tokenize",  # treat as tokenize for now
    "pseudonymize": "tokenize",
    "redact": "redact",
    "mask": "mask",
    "scrub": "redact",  # scrub ≈ redact pass over text
    "generalise": "mask",  # placeholder until a real generalise op exists
    "generalize": "mask",
}

class MetadataPredicate(BaseModel):
    """Constraint applied to a metadata value in :class:`Finding` extras."""

    equals: Any | None = Field(default=None, description="Value must equal this literal")
    matches: str | None = Field(
        default=None,
        description="Value must match this regular expression (string values only)",
    )

    @field_validator("matches")
    @classmethod
    def _validate_regex(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        try:
            re.compile(v)
        except re.error as exc:  # pragma: no cover - defensive
            raise ValueError(f"Invalid regex pattern: {exc}") from exc
        return v

    @model_validator(mode="after")
    def _check_any(self) -> "MetadataPredicate":
        if self.equals is None and self.matches is None:
            raise ValueError("metadata predicate requires 'equals' and/or 'matches'")
        return self

    def applies(self, value: Any) -> bool:
        if self.equals is not None and value != self.equals:
            return False
        if self.matches is not None:
            if not isinstance(value, str):
                return False
            if re.search(self.matches, value) is None:
                return False
        return True


class RuleWhere(BaseModel):
    """Optional filters applied before executing a :class:`Rule`."""

    min_confidence: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Lower confidence bound for matched findings",
    )
    max_confidence: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Upper confidence bound for matched findings",
    )
    value_matches: str | None = Field(
        default=None,
        description="Regex that the finding value must match",
    )
    normalized_matches: str | None = Field(
        default=None,
        description="Regex that the normalized value must match",
    )
    metadata: dict[str, MetadataPredicate] | None = Field(
        default=None,
        description="Mapping of metadata keys to predicates that must pass",
    )

    @field_validator("value_matches", "normalized_matches")
    @classmethod
    def _validate_regex(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        try:
            re.compile(v)
        except re.error as exc:  # pragma: no cover - defensive
            raise ValueError(f"Invalid regex pattern: {exc}") from exc
        return v

    @field_validator("metadata", mode="before")
    @classmethod
    def _coerce_metadata(
        cls, value: Optional[dict[str, Any | MetadataPredicate]]
    ) -> Optional[dict[str, MetadataPredicate]]:
        if value is None:
            return None
        result: dict[str, MetadataPredicate] = {}
        for key, predicate in value.items():
            if isinstance(predicate, MetadataPredicate):
                result[key] = predicate
            elif isinstance(predicate, dict):
                result[key] = MetadataPredicate(**predicate)
            else:
                result[key] = MetadataPredicate(equals=predicate)
        return result

    @model_validator(mode="after")
    def _ensure_any(self) -> "RuleWhere":
        if (
            self.min_confidence is None
            and self.max_confidence is None
            and self.value_matches is None
            and self.normalized_matches is None
            and not self.metadata
        ):
            raise ValueError("where clause must define at least one predicate")
        if (
            self.min_confidence is not None
            and self.max_confidence is not None
            and self.min_confidence > self.max_confidence
        ):
            raise ValueError("min_confidence cannot be greater than max_confidence")
        return self

    def applies(self, finding: "Finding") -> bool:
        if self.min_confidence is not None and finding.confidence < self.min_confidence:
            return False
        if self.max_confidence is not None and finding.confidence > self.max_confidence:
            return False
        if self.value_matches is not None and re.search(self.value_matches, finding.value) is None:
            return False
        if self.normalized_matches is not None:
            norm = finding.normalized or ""
            if not norm or re.search(self.normalized_matches, norm) is None:
                return False
        if self.metadata:
            extras = finding.extras or {}
            for key, predicate in self.metadata.items():
                if key not in extras:
                    return False
                if not predicate.applies(extras[key]):
                    return False
        return True


class Rule(BaseModel):
    """One transformation applied to all Findings whose ``kind`` matches ``field``."""
    id: str = Field(..., description="Rule identifier (unique within policy)")
    field: str = Field(..., description="Detector kind (e.g. email, credit_card, phone)")
    action: Action = Field(..., description="Transformation to apply")
    where: RuleWhere | None = Field(
        default=None,
        description="Optional predicates limiting which findings are transformed",
    )

    # Redact options
    replacement: Optional[str] = Field(
        default=None,
        description="Placeholder for redact action, e.g. '[REDACTED:{kind}]'",
    )

    # Mask options
    keep_head: int = Field(0, ge=0, description="Leading chars to keep when masking")
    keep_tail: int = Field(4, ge=0, description="Trailing chars to keep when masking")
    mask_glyph: str = Field("•", min_length=1, description="Glyph used for masking")

    # Tokenize options
    salt: str = Field("", description="Optional salt used for tokenization hashing")

    @field_validator("action", mode="before")
    @classmethod
    def _normalize_action(cls, v: str) -> str:
        if isinstance(v, str):
            key = v.strip().lower()
            if key in _ACTION_ALIASES:
                return _ACTION_ALIASES[key]
        return v

    @field_validator("field")
    @classmethod
    def _normalize_field(cls, v: str) -> str:
        return v.strip().lower()

    @field_validator("replacement")
    @classmethod
    def _validate_replacement(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v.strip() == "":
            raise ValueError("replacement cannot be empty; use None to default")
        return v

    def applies_to(self, finding: "Finding") -> bool:
        if self.where is None:
            return True
        return self.where.applies(finding)

class Policy(BaseModel):
    """
    A named collection of Rules.

    version: integer schema version for migration control.
    name: a short policy name (e.g., 'gdpr').
    description: optional human-friendly explanation.
    rules: ordered list; earlier rules do not block later ones (idempotent ops).
    """
    version: int = Field(..., ge=1, description="Policy schema version (>=1)")
    name: str = Field(..., min_length=1, description="Short policy name")
    description: Optional[str] = Field(default=None, description="Optional description")
    rules: list[Rule] = Field(default_factory=list)

    @field_validator("name")
    @classmethod
    def _normalize_name(cls, v: str) -> str:
        return v.strip()

    def by_field(self, field: str) -> list[Rule]:
        """Return all rules targeting a given detector kind."""
        f = field.strip().lower()
        return [r for r in self.rules if r.field == f]
