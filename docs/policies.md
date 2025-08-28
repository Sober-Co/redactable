# Policies

Policies in Redactable are **declarative YAML or JSON files**.

## Example: GDPR
```yaml
rules:
  - field: email
    action: mask
  - field: credit_card
    action: redact
```
## Policy Hierarchy

- **Global** → dataset → field.
- Role-based overrides supported.
  - **Example:** Analyst sees masked, Admin sees tokenised.

## Safe Defaults
- Fail-closed behaviour: if no matching policy → data is redacted.