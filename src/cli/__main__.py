from __future__ import annotations
import sys, argparse
from redactable.detectors import DetectorRegistry
from redactable.policy.loader import load_policy
from redactable.policy.defaults import describe_builtin_policies
from redactable.policy.engine import apply_policy

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="redactable")
    builtin = describe_builtin_policies()
    builtin_help = ", ".join(f"{name} ({desc})" if desc else name for name, desc in builtin.items())
    if builtin_help:
        policy_help = (
            "Path to YAML/JSON policy or built-in name. Available built-ins: "
            f"{builtin_help}"
        )
    else:
        policy_help = "Path to YAML/JSON policy"
    p.add_argument("--policy", "-p", required=False, help=policy_help)
    p.add_argument(
        "--list-policies",
        action="store_true",
        help="List bundled policy templates and exit.",
    )
    p.add_argument("--region", default="GB", help="Default phone region (e.g. GB, US)")
    args = p.parse_args(argv)

    if args.list_policies:
        for name, desc in builtin.items():
            line = f"{name}"
            if desc:
                line += f": {desc}"
            print(line)
        return 0

    text = sys.stdin.read()
    registry = DetectorRegistry.default(region=args.region)
    findings = list(registry.scan(text))

    pol = load_policy(args.policy) if args.policy else None
    out = apply_policy(pol, findings, text) if pol else text
    sys.stdout.write(out)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
