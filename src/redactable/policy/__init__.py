"""
Policy subpackage.


Handles loading and representing redaction/masking/tokenisation
policies (YAML/JSON). Provides models, loaders, and an engine that
applies rules to detector findings.
"""


from .model import Policy, Rule
from .loader import load_policy
from .engine import apply_policy
from .defaults import (
    builtin_policy_names,
    describe_builtin_policies,
    get_builtin_policy,
    is_builtin_policy,
)


__all__ = [
    "Policy",
    "Rule",
    "load_policy",
    "apply_policy",
    "builtin_policy_names",
    "describe_builtin_policies",
    "get_builtin_policy",
    "is_builtin_policy",
]