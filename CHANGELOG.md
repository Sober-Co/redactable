# Changelog
All notable changes to **Redactable** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),  
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Planned (v0.2)
- Plugin system for detectors/transforms.
- Spark DataFrame + Kafka integrations.
- Policy inheritance and role overrides.
- Observability: metrics + OpenTelemetry.
- Full Pandas DataFrame accessor implementation.
- NLP/NER-based detection (spaCy/HuggingFace).

---

## [0.1.0] - 2025-09-19

### Added
- **Policy engine & transformations (MVP complete):**
  - Policy loading from YAML/JSON with flexible schema support.
  - Policy application engine with redact, mask, and tokenize actions.
  - Audit trail generation with detailed event tracking.
  - Transform registry for extensibility.

- **Pandas integration (beta):**
  - DataFrame accessor: `df.redact(policy)` for batch redaction.
  - Support for mixed data types with null value handling.

- **Audit logging:**
  - `AuditEvent` dataclass for tracking transformations.
  - Integration with policy engine to generate audit trails.
  - JSONL writer for audit log output.

- **Comprehensive test coverage:**
  - Transform operation tests (redact, mask, tokenize).
  - Policy engine tests with audit event validation.
  - CLI argument parsing and functionality tests.
  - Pandas integration tests with various edge cases.

### Changed
- Python version requirement: `>=3.12` (previously `>=3.13`).
- Pre-commit configuration now enforces ruff and mypy checks.
- README updated with clearer feature guidance and v0.2 roadmap.

### Fixed
- Pre-commit hook configuration (was empty).
- Python version constraint mismatch in CI.
- Pandas integration example in README (moved to v0.2).

### Known Limitations
- Role-based access control parsed but not enforced (v0.2).
- Plugin system not yet implemented (v0.2).
- Format-preserving encryption (FPE) deferred to v0.3.
- NLP/NER detection not available (v0.3).

---

## [0.1.0-alpha] - 2025-08-29

### Added
- **Detection suite (foundation):**
  - Email detector (regex).
  - Credit card detector with Luhn validation + brand inference.
  - IBAN detector with checksum validation.
  - NHS number detector (UK Mod11).
  - SSN detector (US, invalid pattern checks).
  - Phone detector (E.164 + UK formats).
  - Entropy/secret detector (base64/hex, Shannon entropy).
  - Schema-hint detector (field-name driven, for structured data).
- **Detectors framework:**
  - `Match` dataclass, registry, and `run_all()` fan-out runner.
  - Shared utils (Luhn, IBAN check, NHS Mod11, entropy calc).
  - Auto-registration of detectors via `run.py` and `__init__.py`.

### Changed
- Improved credit card regex to reliably capture spaced/dashed PANs.
- Hardened validation for NHS, IBAN, and SSN formats.

### Testing
- Added pytest coverage across all detectors.
- Verified Luhn, IBAN checksum, NHS Mod11, and SSN rules with fixtures.
- Included positive/negative test cases for each detector.

---

## [0.0.0] - 2025-08-15
### Added
- Project scaffolding (pyproject, repo structure, CI stubs).
- README, LICENSE (MIT), CONTRIBUTING, SECURITY, CODEOWNERS.
- Initial `apply()` placeholder and CLI skeleton.
