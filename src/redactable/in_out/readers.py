from .base import Record, Reader, _open

class TextFileReader(Reader):
    def __init__(self, path: str, by_line: bool = True):
        self.path = path; self.by_line = by_line
    def iter_records(self):
        with _open(self.path, "rt") as f:
            if self.by_line:
                for i, line in enumerate(f, 1):
                    yield Record(line.rstrip("\n"), {"source": self.path, "line": i})
            else:
                yield Record(f.read(), {"source": self.path})