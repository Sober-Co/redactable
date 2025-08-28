# 🤝 Contributing to Redactable

First off, thank you for considering contributing to **Redactable**! 🎉  
This project is driven by **[Sober & Co.](https://soberand.co)** but is intended to grow as a community-led open-source framework for data redaction, masking, and privacy-preserving transformations.  

We welcome contributions of all kinds... from bug reports and docs improvements to major feature proposals.  

---

## 📐 Code of Conduct

By participating, you agree to follow our [Code of Conduct](CODE_OF_CONDUCT.md) (coming soon).  
We expect a respectful, inclusive, and collaborative environment.

---

## 🛠️ How to Contribute

### 1. Reporting Issues
- Use the [GitHub Issues](https://github.com/soberandco/redactable/issues) tab.  
- Provide as much detail as possible:
  - Steps to reproduce  
  - Expected vs actual behaviour  
  - Relevant logs/config snippets  

### 2. Suggesting Enhancements
- Open an issue labelled **enhancement**.  
- Clearly explain the problem your proposal solves.  
- Where possible, suggest a policy/architecture-aligned solution (policy-first, pluggable, auditable).  

### 3. Submitting Pull Requests
- Fork the repo and create a feature branch:  
  ```bash
  git checkout -b feature/my-new-feature
- Ensure code is typed, linted, and tested:
  ```bash
  ruff check .
  mypy .
  pytest
- Write docstrings and update any relevant docs. 
- Commit with a clear message, e.g. ruff
  ```pgsql
  feat(detection): add regex for NHS numbers
  fix(policy): resolve role override precedence
  docs: expand README with Pandas example
- Push and open a Pull Request (PR).

    - Reference the issue number (if any). 
    - Describe what was changed and why.
    - Add tests where applicable.

---

## 📦 Development Setup

### Requirements

- Python 3.13.3+

- Poetry or pip

- pytest for testing
- ruff for linting

### Install

```bash
git clone https://github.com/soberandco/redactable.git
cd redactable
pip install -e ".[dev]"
```


---
✅ Contribution Checklist

- Lint clean (ruff)

- Type-check clean (mypy)

- Tests added/updated (pytest)

- Docs/examples updated if relevant

- PR description clear and linked to issue

---
## 🌍 Governance

- **Maintained by:** [Sober & Co.](https://soberand.co)

- **License:** MIT (permissive for commercial and open use)

- **Community contributions:** encouraged and credited

In the long term, we aim for neutral governance, but during early development Sober & Co. act as lead maintainers.

---
## 🙌 Recognition

All contributors will be acknowledged in [CHANGELOG.md](CHANGELOG.md)
 and, where meaningful, in release notes.

---
💡 Tagline:
**Redactable — protect what matters, without breaking what doesn’t.**