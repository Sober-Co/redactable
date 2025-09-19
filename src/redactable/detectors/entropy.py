# redactable/detectors/entropy.py

"""
Entropy-based detectors.

Detects high-entropy strings (likely secrets, tokens, API keys).
- Uses Shannon entropy as the metric.
- Looks for base64/base58/hex-like sequences.
- Configurable thresholds for entropy and minimum length.

Intended as a complement to regex-based detectors.
"""

import re
from .base import Match, register, Finding, Detector
from .utils import shannon_entropy, looks_like_secret
from typing import Iterable
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


# Tokens separated by non-word; allow -,_,= typical in JWT/base64url
_TOKEN = re.compile(r'([A-Za-z0-9_\-=+/]{20,})')

class EntropyDetector:
    name = "entropy"
    labels = ("SECRET",)

    def __init__(self, *, threshold: float = 3.5):
        self.threshold = threshold

    def detect(self, text: str, *, context=None):
        threshold = (context or {}).get("entropy_threshold", self.threshold)
        for m in _TOKEN.finditer(text):
            token = m.group(1)
            if not looks_like_secret(token):
                continue
            H = shannon_entropy(token)
            if H >= threshold:
                yield Match("SECRET", m.start(1), m.end(1), token, min(0.99, 0.7 + (H-threshold)/4), {"entropy": H})

register(EntropyDetector())