import re

from .base import Finding, register

_EMAIL = re.compile(
    r"(?<![A-Za-z0-9._%+-])"  # left boundary
    r"([A-Za-z0-9._%+-]+@"  # local
    r"(?:[A-Za-z0-9-]+\.)+"  # subdomains
    r"[A-Za-z]{2,63})"  # TLD
    r"(?![A-Za-z0-9._%+-])"  # right boundary
)


class EmailDetector:
    name = "email"

    def detect(self, text: str):
        for m in _EMAIL.finditer(text):
            yield Finding(
                kind="email",
                value=m.group(1),
                span=(m.start(1), m.end(1)),
                confidence=0.95,
            )


register(EmailDetector())
