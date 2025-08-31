# redactable/detectors/entropy.py
import re
from typing import Iterable, Optional
from .base import Finding, register
from .utils import shannon_entropy, looks_like_secret

# Broad token pattern
_TOKEN = re.compile(r'([A-Za-z0-9_\-=+/]{20,})')

class HighEntropyTokenDetector:
    """
    Detect tokens/secrets with high entropy.
    """
    name = "high_entropy_token"
    labels = ("SECRET",)

    def __init__(self, entropy_threshold: float = 3.5, min_len: int = 24) -> None:
        self.entropy_threshold = entropy_threshold
        self.min_len = min_len

    def detect(self, text: str, *, context: Optional[dict] = None) -> Iterable[Finding]:
        threshold = (context or {}).get("entropy_threshold", self.entropy_threshold)
        for m in _TOKEN.finditer(text):
            raw = m.group(1)
            if len(raw) < self.min_len or not looks_like_secret(raw):
                continue
            ent = shannon_entropy(raw)
            if ent >= threshold:
                yield Finding(
                    kind="SECRET",
                    value=raw,
                    span=(m.start(1), m.end(1)),
                    confidence=min(0.99, 0.5 + ent / 8),
                    normalized=raw,
                    extras={"entropy": ent},
                )

register(HighEntropyTokenDetector())
