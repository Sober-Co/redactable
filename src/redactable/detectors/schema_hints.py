from __future__ import annotations

import re
from collections.abc import Iterable, Mapping

from .base import Match, register

# This detector relies on context = {"schema": {"field_name": "value", ...}}
# It emits matches for fields whose names are known sensitive hints.
_HINTS = {
    "email": "EMAIL",
    "e_mail": "EMAIL",
    "mail": "EMAIL",
    "cc": "CREDIT_CARD",
    "credit_card": "CREDIT_CARD",
    "card_number": "CREDIT_CARD",
    "ssn": "SSN",
    "national_insurance": "NINO",  # placeholder label if/when added
    "phone": "PHONE",
    "phone_number": "PHONE",
    "dob": "DATE_DOB",
    "date_of_birth": "DATE_DOB",
}

class SchemaHintDetector:
    name = "schema_hints"
    labels = tuple(set(_HINTS.values()))
    confidence = 0.6

    def detect(self, text: str, *, context=None):
        schema = (context or {}).get("schema")
        if not schema:
            return []

        matches: list[Match] = []
        seen_fields: set[str] = set()

        for field_name, raw in _iter_schema_fields(schema):
            canonical = _canonical_name(field_name)
            if not canonical or canonical in seen_fields:
                continue
            label = _label_for_field(canonical)
            if not label:
                continue
            seen_fields.add(canonical)
            meta = {"source": "schema", "field": field_name}
            if raw is not None:
                meta["schema_meta"] = raw
            matches.append(
                Match(
                    label=label,
                    start=0,
                    end=0,
                    value=str(field_name),
                    confidence=self.confidence,
                    meta=meta,
                )
            )
        return matches

register(SchemaHintDetector())


_CONTAINER_KEYS = {"fields", "columns", "schema", "properties"}


def _iter_schema_fields(schema) -> Iterable[tuple[str, object]]:
    if schema is None:
        return []

    if isinstance(schema, Mapping):
        results: list[tuple[str, object]] = []
        for key in _CONTAINER_KEYS:
            if key in schema and key not in _HINTS:
                results.extend(_iter_schema_fields(schema[key]))
        for key, value in schema.items():
            if key in _CONTAINER_KEYS:
                continue
            results.append((str(key), value))
            if isinstance(value, Mapping):
                results.extend(_iter_schema_fields(value))
            elif isinstance(value, Iterable) and not isinstance(value, (bytes, bytearray, str)):
                results.extend(_iter_schema_fields(value))
        return results

    if isinstance(schema, str):
        return [(schema, None)]

    if isinstance(schema, Iterable) and not isinstance(schema, (bytes, bytearray)):
        results = []
        for item in schema:
            if isinstance(item, Mapping):
                name = (
                    item.get("name")
                    or item.get("field")
                    or item.get("column")
                    or item.get("key")
                )
                if name:
                    results.append((str(name), item))
                    results.extend(_iter_schema_fields(item))
                else:
                    results.extend(_iter_schema_fields(item))
            elif isinstance(item, str):
                results.append((item, None))
            elif isinstance(item, Iterable) and not isinstance(item, (bytes, bytearray)):
                sequence = list(item)
                if sequence:
                    results.append((str(sequence[0]), item))
            else:
                name = getattr(item, "name", None)
                if name:
                    results.append((str(name), item))
        return results

    return [(str(schema), None)]


_CAMEL_RE = re.compile(r"([a-z0-9])([A-Z])")


def _canonical_name(field_name: str) -> str:
    field = str(field_name)
    field = _CAMEL_RE.sub(r"\1_\2", field)
    field = re.sub(r"[^a-zA-Z0-9]+", "_", field)
    field = field.strip("_")
    field = re.sub(r"_+", "_", field)
    return field.lower()


def _label_for_field(canonical: str) -> str | None:
    if not canonical:
        return None
    if canonical in _HINTS:
        return _HINTS[canonical]

    parts = [p for p in canonical.split("_") if p]
    for i in range(len(parts)):
        for j in range(i + 1, len(parts) + 1):
            candidate = "_".join(parts[i:j])
            if candidate in _HINTS:
                return _HINTS[candidate]
    return None
