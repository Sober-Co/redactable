# Changelog

All notable changes to **Redactable** will be documented here.  
This project adheres to [Semantic Versioning](https://semver.org/).

---

## [Unreleased]
### Added
- Initial repository setup
- Core detection engine (regex for emails, credit cards, NHS numbers, SSNs, IBANs, phone numbers)
- High-entropy secret detection
- Basic transformations: redact, mask, tokenise
- Policy engine (YAML/JSON, role overrides)
- CLI tool, Python SDK, Pandas integration
- JSONL audit logging
- Documentation: README, CONTRIBUTING, SECURITY, etc.

---

## [0.1.0] - 2025-09-XX
**Milestone: Foundation Release**
- First tagged release with working v0.1 features
- Enough to redact/mask logs, CSVs, and LLM prompts
