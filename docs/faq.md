# FAQ

### Is Redactable production-ready?
🚧 Currently in v0.1 development. Stable core features, expanding integrations.

### Why not just regex?
Regex alone misses context and governance. Redactable combines regex, entropy detection, schema hints, and policies.

### How does it differ from DLP SaaS tools?
- Open-source
- Policy-driven
- Extensible & pluggable
- Works locally, not cloud-only

### What happens if no policy matches?
Data is left unchanged unless a policy rule matches it. To guarantee fail-closed behaviour, add a final "catch-all" rule in your policy (for example, a regex that matches `.*` and redacts) so anything that slips past specific rules is still removed.
