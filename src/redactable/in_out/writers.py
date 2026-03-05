import json
import sys

from .base import Writer, Record, _open


class TextFileWriter:
    def __init__(self, path: str):
        self.path = path
        self._f = _open(self.path, "wt")

    def write_record(self, record: Record) -> None:
        self._f.write(record.content + "\n")

    def close(self) -> None:
        self._f.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


class StdoutWriter:
    def write_record(self, record: Record) -> None:
        sys.stdout.write(record.content + "\n")

    def close(self) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class AuditJSONLWriter:
    def __init__(self, path: str):
        self._f = open(path, "a", encoding="utf-8")

    def write_record(self, record: Record) -> None:
        self._f.write(
            json.dumps({"content": record.content, **record.meta}, ensure_ascii=False) + "\n"
        )

    def write_event(self, event: dict) -> None:
        self._f.write(json.dumps(event, ensure_ascii=False) + "\n")

    def close(self) -> None:
        self._f.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False
