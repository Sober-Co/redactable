import gzip
from typing import Iterable, Protocol, Dict, Any

class Record:
    def __init__(self, content: str, meta: Dict[str, Any] | None = None):
        self.content = content
        self.meta = meta or {}

class Reader(Protocol):
    def iter_records(self) -> Iterable[Record]: ...

class Writer(Protocol):
    def write_record(self, record: Record) -> None: ...
    def close(self) -> None: ...


def _open(path: str, mode: str):
    return gzip.open(path, mode) if str(path).endswith(".gz") else open(path, mode, encoding="utf-8", newline="")
