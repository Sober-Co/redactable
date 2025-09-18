"""Built-in policy templates for common privacy/compliance regimes.

The real project will eventually ship a full policy DSL.  For the early
alpha we provide a handful of opinionated defaults so that users can reach a
baseline of protection without having to write YAML first.  The goal is to
offer sensible "day zero" coverage for the most requested regimes:

* **GDPR** – mask direct identifiers and tokenise financial numbers.
* **PCI DSS** – fail closed on PANs/IBANs and secrets in payment flows.
* **HIPAA** – aggressively mask common US personal health identifiers.

These templates intentionally keep to the simplified :class:`Policy` model
implemented in the stub engine.  When the richer policy schema lands we can
swap these definitions to the new structure in a single place.
"""

from __future__ import annotations

from pathlib import PurePath
from typing import Dict, Iterable

from .model import Policy, Rule


def _mask_email_rule() -> Rule:
    """Mask the local part of e-mail addresses while keeping the domain."""

    return Rule(
        id="gdpr_mask_email",
        field="email",
        action="mask",
        keep_head=0,
        keep_tail=12,  # keeps "@example.com" for typical domains
        mask_glyph="*",
    )


def _mask_phone_rule(rule_id: str, *, keep_tail: int = 2) -> Rule:
    """Mask phone numbers, leaving only the last few digits visible."""

    return Rule(
        id=rule_id,
        field="phone",
        action="mask",
        keep_head=0,
        keep_tail=keep_tail,
        mask_glyph="•",
    )


def _tokenize_rule(rule_id: str, field: str, *, salt: str) -> Rule:
    """Create a simple hashing/tokenisation rule for the supplied field."""

    return Rule(
        id=rule_id,
        field=field,
        action="tokenize",
        salt=salt,
        replacement=None,
        keep_head=0,
        keep_tail=0,
    )


def _redact_rule(rule_id: str, field: str, placeholder: str) -> Rule:
    """Return a redaction rule with a fixed placeholder."""

    return Rule(
        id=rule_id,
        field=field,
        action="redact",
        replacement=placeholder,
    )


def _build_builtin_policies() -> Dict[str, Policy]:
    """Construct the built-in policy catalogue."""

    gdpr = Policy(
        version=1,
        name="gdpr",
        description=(
            "Default EU GDPR template. Masks direct identifiers and tokenises "
            "financial numbers to support data minimisation and pseudonymisation "
            "out of the box."
        ),
        rules=[
            _mask_email_rule(),
            _mask_phone_rule("gdpr_mask_phone", keep_tail=2),
            _tokenize_rule("gdpr_tokenize_pan", "credit_card", salt="gdpr::pan"),
            _tokenize_rule("gdpr_tokenize_iban", "iban", salt="gdpr::iban"),
            _redact_rule("gdpr_redact_secret", "high_entropy_token", "[GDPR-SECRET]"),
        ],
    )

    pci = Policy(
        version=1,
        name="pci-dss",
        description=(
            "PCI DSS focused defaults. PANs are fully redacted, IBANs are masked and "
            "potential secrets are removed to keep logs and telemetry compliant."
        ),
        rules=[
            _redact_rule("pci_redact_pan", "credit_card", "[PCI-PAN]"),
            Rule(
                id="pci_mask_iban",
                field="iban",
                action="mask",
                keep_head=4,
                keep_tail=4,
                mask_glyph="*",
            ),
            _redact_rule("pci_redact_secret", "high_entropy_token", "[PCI-SECRET]"),
        ],
    )

    hipaa = Policy(
        version=1,
        name="hipaa",
        description=(
            "HIPAA safe defaults for US healthcare workloads. Emails and phone numbers "
            "are masked for minimum necessary use, SSNs are fully redacted and "
            "machine detected secrets are stripped."
        ),
        rules=[
            _mask_email_rule().model_copy(update={"id": "hipaa_mask_email"}),
            _mask_phone_rule("hipaa_mask_phone", keep_tail=2),
            _redact_rule("hipaa_redact_ssn", "ssn_us", "[HIPAA-SSN]"),
            _redact_rule("hipaa_redact_secret", "high_entropy_token", "[HIPAA-SECRET]"),
        ],
    )

    return {
        "gdpr": gdpr,
        "gdpr-default": gdpr,
        "pci": pci,
        "pci-dss": pci,
        "hipaa": hipaa,
    }


_BUILTINS = _build_builtin_policies()


def _normalise_key(value: str) -> str:
    """Normalise a user provided identifier to the lookup key."""

    key = PurePath(value).name.casefold().strip()
    if key.endswith(('.yaml', '.yml', '.json')):
        key = key.rsplit('.', 1)[0]
    return key


def get_builtin_policy(name: str) -> Policy:
    """Return a deep copy of a built-in policy by name.

    Args:
        name: Identifier such as ``"gdpr"`` or ``"pci"``.  File-like names such
            as ``"gdpr.yaml"`` are also accepted for convenience.

    Raises:
        KeyError: If the supplied name does not resolve to a built-in policy.
    """

    key = _normalise_key(name)
    try:
        policy = _BUILTINS[key]
    except KeyError as exc:  # pragma: no cover - defensive branch
        raise KeyError(f"Unknown built-in policy: {name!r}") from exc
    return policy.model_copy(deep=True)


def builtin_policy_names() -> Iterable[str]:
    """Return the canonical names for all bundled policy templates."""

    # Only expose primary identifiers – aliases are intentionally hidden.
    canonical = {"gdpr", "pci", "hipaa"}
    return tuple(sorted(canonical))


def describe_builtin_policies() -> Dict[str, str]:
    """Return a mapping of policy name to its short description."""

    return {name: _BUILTINS[name].description or "" for name in builtin_policy_names()}


def is_builtin_policy(name: str) -> bool:
    """Return ``True`` if the supplied identifier resolves to a built-in policy."""

    try:
        _ = get_builtin_policy(name)
        return True
    except KeyError:
        return False

