# ruff: noqa: E402
from __future__ import annotations
from typing import Literal, Optional
from pydantic import BaseModel, Field, field_validator

Action = Literal["redact", "mask", "tokenize"]

class Rule(BaseModel):
    """
    One transformation applied to all Findings whose kind == field.
    Future: add 'where' filters (regex, confidence threshold, etc.).
    """
    id: str = Field(..., description="Rule identifier (unique within policy)")
    field: str = Field(..., description="Detector kind (e.g. email, credit_card, phone)")
    action: Action = Field(..., description="Transformation to apply")

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
