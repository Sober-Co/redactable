import json
import sys

from .base import Writer, Record, _open


class TextFileWriter(Writer):
    def __init__(self, path: str):
        self.path = path; self._f = _open(self.path, "wt")
    def write_record(self, record: Record) -> None:
        self._f.write(record.content + "\n")
    def close(self): self._f.close()

class StdoutWriter(Writer):
    def write_record(self, record: Record) -> None:
        sys.stdout.write(record.content + "\n")
    def close(self): pass

class AuditJSONLWriter(Writer):
    def __init__(self, path: str):
        self._f = open(path, "w", encoding="utf-8")
    def write_event(self, event: dict) -> None:
        self._f.write(json.dumps(event, ensure_ascii=False) + "\n")
    def close(self): self._f.close()