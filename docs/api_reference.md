# API Reference

_(Placeholder — auto-generated docs will be added in v0.2+.)_

## Core Functions
### `apply(data, policy, *, region="GB", return_findings=False)`
Apply redaction to input string or structured object using a policy file.

- Returns the transformed text by default.
- If `return_findings=True`, returns `(text, findings)` so you can inspect detector output.

### `df.redact(policy)`
Pandas DataFrame integration.

### `AuditLog`
JSONL-based audit log writer.
