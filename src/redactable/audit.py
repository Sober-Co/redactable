"""
JSONL audit logging for redaction operations.

Records what was detected, what action was taken, and why,
without logging the original sensitive values.
"""

from __future__ import annotations

import json
import datetime
from pathlib import Path
from typing import Any


class AuditLogger:
    """Append-only JSONL audit logger for redaction events."""

    def __init__(self, path: str | Path | None = None):
        self._path = Path(path) if path else None
        self._events: list[dict[str, Any]] = []

    def log(
        self,
        *,
        field: str,
        action: str,
        rule_id: str | None = None,
        reason: str | None = None,
        detector: str | None = None,
        confidence: float | None = None,
    ) -> None:
        """Record a single redaction event."""
        event: dict[str, Any] = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "field": field,
            "action": action,
        }
        if rule_id:
            event["rule_id"] = rule_id
        if reason:
            event["reason"] = reason
        if detector:
            event["detector"] = detector
        if confidence is not None:
            event["confidence"] = confidence

        self._events.append(event)

        if self._path:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._path, "a", encoding="utf-8") as f:
                f.write(json.dumps(event, ensure_ascii=False) + "\n")

    @property
    def events(self) -> list[dict[str, Any]]:
        """Return all logged events from this session."""
        return list(self._events)

    def summary(self) -> dict[str, int]:
        """Return a count of events grouped by action."""
        counts: dict[str, int] = {}
        for e in self._events:
            action = e.get("action", "unknown")
            counts[action] = counts.get(action, 0) + 1
        return counts
