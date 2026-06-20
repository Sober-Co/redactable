import gzip
from collections.abc import Iterable
from typing import Any, Protocol


class Record:
    def __init__(self, content: str, meta: dict[str, Any] | None = None):
        self.content = content
        self.meta = meta or {}


class Reader(Protocol):
    def iter_records(self) -> Iterable[Record]: ...


class Writer(Protocol):
    def write_record(self, record: Record) -> None: ...
    def close(self) -> None: ...


def _open(path: str, mode: str):
    if str(path).endswith(".gz"):
        return gzip.open(path, mode)
    return open(path, mode, encoding="utf-8", newline="")
