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
- By default, data is unchanged when no policy rule matches it.
- To enforce fail-closed behaviour, add a catch-all rule (for example, a final regex such as `.*`) that redacts anything not matched by earlier, more specific rules.
