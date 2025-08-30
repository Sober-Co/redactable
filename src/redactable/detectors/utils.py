import math
import re
from typing import Iterable

def luhn_check(digits: str) -> bool:
    s = 0
    alt = False
    for d in reversed(digits):
        n = ord(d) - 48
        if alt:
            n *= 2
            if n > 9:
                n -= 9
        s += n
        alt = not alt
    return s % 10 == 0

# Basic IBAN check (ISO 13616)
_IBAN_RE = re.compile(r'[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}$')
_IBAN_LEN = {
    # Common ones; extend as needed
    "GB": 22, "DE": 22, "FR": 27, "ES": 24, "IT": 27, "NL": 18, "BE": 16, "CH": 21, "IE": 22, "PL": 28
}
def iban_check(iban: str) -> bool:
    iban = iban.replace(' ', '').upper()
    country = iban[:2]
    if not _IBAN_RE.match(iban): return False
    if country in _IBAN_LEN and len(iban) != _IBAN_LEN[country]: return False
    # move 4 chars to end, convert letters to numbers (A=10 ... Z=35)
    rearranged = iban[4:] + iban[:4]
    digits = ''.join(str(ord(c)-55) if c.isalpha() else c for c in rearranged)
    # mod 97 == 1
    remainder = 0
    for ch in digits:
        remainder = (remainder*10 + ord(ch)-48) % 97
    return remainder == 1

# UK NHS number check (Mod 11)
def nhs_check(n: str) -> bool:
    n = re.sub(r'\D+', '', n)
    if len(n) != 10: return False
    weights = list(range(10, 1, -1))  # 10..2
    total = sum(int(d)*w for d, w in zip(n[:9], weights))
    check = 11 - (total % 11)
    if check == 11: check = 0
    if check == 10: return False
    return check == int(n[-1])

def shannon_entropy(s: str) -> float:
    if not s: return 0.0
    from collections import Counter
    counts = Counter(s)
    length = len(s)
    return -sum((c/length) * math.log2(c/length) for c in counts.values())

_BASE64ISH = re.compile(r'^[A-Za-z0-9+/=_-]+$')
_HEXISH    = re.compile(r'^[0-9a-fA-F]+$')
def looks_like_secret(token: str) -> bool:
    # quick heuristic: base64/hex-ish + length
    if len(token) < 20: return False
    return bool(_BASE64ISH.match(token) or _HEXISH.match(token))
