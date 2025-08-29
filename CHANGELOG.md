# Changelog
All notable changes to **Redactable** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),  
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Planned
- Plugin system for detectors/transforms.
- Spark DataFrame + Kafka integrations.
- Policy inheritance and role overrides.
- Observability: metrics + OpenTelemetry.

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
