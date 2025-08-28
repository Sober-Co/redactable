# redactable/detectors/entropy.py

"""
Entropy-based detectors.

Detects high-entropy strings (likely secrets, tokens, API keys).
- Uses Shannon entropy as the metric.
- Looks for base64/base58/hex-like sequences.
- Configurable thresholds for entropy and minimum length.

Intended as a complement to regex-based detectors.
"""

from __future__ import annotations
from typing import Iterable
import re
import math

from .base import Finding, Detector

# --------------------------------------------------------------------
# Helpers

def shannon_entropy(s: str) -> float:
    """
    Calculate Shannon entropy of a string.
    Returns a value >= 0, higher means more random.
    """
    if not s:
        return 0.0
    freq = {ch: s.count(ch) for ch in set(s)}
    n = len(s)
    return -sum((c/n) * math.log2(c/n) for c in freq.values())

# --------------------------------------------------------------------
# Regex pattern: matches candidate secrets
BASELIKE_PATTERN = re.compile(
    r"""
    (                             # capture group
      [A-Za-z0-9+/=]{24,}          # base64-ish
      |[A-HJ-NP-Za-km-z1-9]{24,}   # base58-ish
      |[A-Fa-f0-9]{32,}            # long hex strings
    )
    """,
    re.VERBOSE,
)

# --------------------------------------------------------------------
# Detector

class HighEntropyTokenDetector:
    """
    Detect tokens/secrets with high entropy.

    Attributes:
        entropy_threshold: minimum Shannon entropy (default ~3.5).
        min_len: minimum string length to consider.
    """
    name = "high_entropy_token"

    def __init__(self, entropy_threshold: float = 3.5, min_len: int = 24) -> None:
        self.entropy_threshold = entropy_threshold
        self.min_len = min_len

    def detect(self, text: str) -> Iterable[Finding]:
        """
        Scan text for high-entropy sequences.
        Yields Finding objects for each match.
        """
        for m in BASELIKE_PATTERN.finditer(text):
            raw = m.group(0)
            if len(raw) < self.min_len:
                continue
            ent = shannon_entropy(raw)
            if ent >= self.entropy_threshold:
                yield Finding(
                    kind=self.name,
                    value=raw,
                    span=m.span(),
                    confidence=min(0.99, 0.5 + ent / 8),
                    normalized=raw,
                    extras={"entropy": ent},
                )
