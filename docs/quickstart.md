# Quickstart

## CLI
```bash
redactable --policy gdpr.yaml input.log output.redacted.log
```

## Python SDK

```python
from redactable import apply

data = "Customer email: test@example.com"
result = apply(data, policy="gdpr.yaml")
print(result)
# → "Customer email: ****@example.com"
```

## Pandas Integration

```python
import pandas as pd
import redactable.pandas

df = pd.DataFrame({
    "email": ["alice@example.com", "bob@corp.com"],
    "cc": ["4111111111111111", "5500000000000004"]
})

redacted = df.redact(policy="gdpr.yaml")
print(redacted)
```

## Audit Log Example

```json
{
  "field": "email",
  "action": "mask",
  "reason": "policy:gdpr.yaml:rule_3",
  "timestamp": "2025-08-28T12:00:00Z"
}
```

```yaml

---

### `/docs/usage.md`
```markdown
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
```