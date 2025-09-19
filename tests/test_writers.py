import json
from pathlib import Path

from redactable.in_out.base import Record
from redactable.in_out.writers import AuditJSONLWriter


def test_audit_jsonl_writer_writes_records(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    writer = AuditJSONLWriter(str(path))
    record = Record("redacted text", meta={"id": "123", "tags": ["a", "b"]})

    writer.write_record(record)
    writer.close()

    contents = path.read_text(encoding="utf-8").strip().splitlines()
    assert len(contents) == 1
    event = json.loads(contents[0])
    assert event["id"] == "123"
    assert event["tags"] == ["a", "b"]
    assert event["content"] == "redacted text"


def test_audit_jsonl_writer_can_write_raw_events(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    writer = AuditJSONLWriter(str(path))

    writer.write_event({"custom": True})
    writer.close()

    contents = path.read_text(encoding="utf-8").strip()
    assert json.loads(contents) == {"custom": True}
