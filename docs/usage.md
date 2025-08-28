# Usage Guide

Redactable can process **text, structured data, and logs**.

## Detectors
- Regex libraries:
  - Emails
  - Credit cards
  - NHS numbers
  - SSNs
  - IBANs
  - Phone numbers
- High-entropy detector (tokens, secrets, API keys).
- Schema hints (field names like `dob`, `ssn`, `phone_number`).

## Transformations
- **Redaction** → `[REDACTED:TYPE]`
- **Masking** → `****1234`
- **Tokenisation / Hashing** → irreversible, format-preserving.

## Integration Points
- CLI tool
- Python SDK
- Pandas DataFrames

All actions are **policy-driven**.