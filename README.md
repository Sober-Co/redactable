[![CI](https://github.com/Sober-Co/redactable/actions/workflows/ci.yml/badge.svg)](…)
[![codecov](https://codecov.io/gh/Sober-Co/redactable/branch/main/graph/badge.svg)](…)
[![PyPI version](https://img.shields.io/pypi/v/redactable.svg)](https://pypi.org/project/redactable/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)


# 🛡️ redactable

**Redactable — protect what matters, without breaking what doesn’t.**  
A versatile, policy-driven open-source framework for **data redaction, masking, and privacy-preserving transformations**.

---

## ✨ Vision

Enable individuals and organisations to safely process, share, and analyse data **without leaking sensitive information**.

---

## 🚨 Why Redactable?

Organisations today face:

- 📜 **Rising regulations:** GDPR/UK GDPR, PCI DSS, HIPAA, NHS guidance.  
- 🔓 **Growing risks:** logs, analytics pipelines, LLM prompts, cross-border transfers.  
- 🧩 **Fragmented tools:** regex-only scrubbing, closed-source DLP, heavyweight SaaS.

⚡ **Gap:** No open-source, **policy-first, pluggable redaction framework** that works across modalities (text, logs, structured data, PDFs, images, audio) while being adaptable to enterprise-scale workflows.

---

## 🎯 Core Principles

- **Policy-first:** declarative, auditable YAML/JSON policies.  
- **Cross-modal:** text, structured data, logs; extensible to images/audio later.  
- **Pluggable:** detectors, transformations, integrations as plugins.  
- **Safe defaults:** fail-closed behaviour (no silent leaks).  
- **Enterprise-aligned:** GDPR, PCI, HIPAA compliance packs.  
- **Developer-friendly:** CLI, Python SDK, Pandas integration.  

---

## 🚀 Quickstart (v0.1)

### Installation

````bash
pip install redactable
````
_(pre-release, local install via pip install -e . until PyPI publish)_


### CLI Usage

````bash
redactable --policy gdpr.yaml input.log output.redacted.log
````


### Python SDK

````bash
from redactable import apply

data = "Customer email: test@example.com"
result, findings = apply(data, policy="gdpr.yaml", return_findings=True)
print(result)
# → "Customer email: ****@example.com"
print(findings[0])
# → <Finding email value='test@example.com' conf=1.00>
````


### Python SDK

````bash
from redactable import apply

data = "Customer email: test@example.com"
result, findings = apply(data, policy="gdpr.yaml", return_findings=True)
print(result)
# → "Customer email: ****@example.com"
print(findings[0])
# → <Finding email value='test@example.com' conf=1.00>
````

### Pandas Integration

````bash
import pandas as pd
import redactable.pandas

df = pd.DataFrame({
    "email": ["alice@example.com", "bob@corp.com"],
    "cc": ["4111111111111111", "5500000000000004"]
})

redacted = df.redact(policy="gdpr.yaml")
print(redacted)
````

### Audit Logs

````bash
{
  "field": "email",
  "action": "mask",
  "reason": "policy:gdpr.yaml:rule_3",
  "timestamp": "2025-08-28T12:00:00Z"
}
````

------
## 📦 Features (v0.1)

### ✅ Detection

- Regex libraries (emails, credit cards, NHS numbers, SSNs, IBANs, phone numbers).

- High-entropy secret detection.

- Schema hints (column names: dob, ssn, phone_number).

### ✅ Transformations

- Redaction: ``[REDACTED:TYPE]``

- Masking: ``****1234``

- Tokenisation/Hashing: irreversible, format-preserving

### ✅ Policy Engine

- Declarative YAML/JSON policies.

- Hierarchical (global → dataset → field).

- Role-based redaction (analyst vs admin).

- Fail-closed defaults.

### ✅ Integrations

- CLI Tool.

- Python SDK.

- Pandas UDF.

### ✅ Governance

- JSONL audit logs.

- Explainability: why was this redacted.

----
## 🗂️ Roadmap

### v0.1 (MVP) — Foundation

- Core detection (regex, entropy, schema hints).

- Transformations (redact, mask, tokenise).

- Policy engine (YAML/JSON).

- CLI, Python SDK, Pandas integration.

- JSONL audit logging.

### v0.2 — Extensibility

- Plugin system for detectors/transforms.

- Spark DataFrame + Kafka integration.

- Policy inheritance + role overrides.

- Observability: metrics + OpenTelemetry.

### v0.3 — Advanced

- NLP/NER-based detection (spaCy/HuggingFace).

- Encryption & KMS integration.

- OCR for PDFs/images.

- FastAPI middleware.

### v0.4 — Compliance & Enterprise

- Compliance packs (GDPR, PCI, HIPAA, NHS).

- Differential privacy module.

- Large-scale benchmarks.

- Documentation site + policy editor.

---
## 🔑 Use Cases

- Data Engineering | redact logs/events before analytics.

- LLM Pipelines | scrub sensitive input/output.

- Healthcare | pseudonymise patient data.

- Finance | PCI-compliant data handling.

- Legal |redact DSARs/disclosure documents.

- Media | blur/remove PII in transcripts.

---
## 🤝 Community & Contribution

Redactable is developed and stewarded by [Sober & Co.](https://soberand.co/) 

We’re building this framework as part of our wider mission to enable safe, ethical, and stylishly modern approaches 
to data and technology.

We welcome outside contributions — bug reports, feature proposals, pull requests, and discussions.

- Open an issue for bugs/ideas.
- Submit PRs following [CONTRIBUTING.md](CONTRIBUTING.md)

Join in early to help shape the roadmap.

📜 License

MIT License. Permissive and business-friendly.
- See [LICENSE](LICENSE) for details.

🧭 Status

🚧 v0.1 under development.
Led by Sober & Co., with community contributions encouraged.