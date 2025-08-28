from __future__ import annotations
import sys, argparse
from redactable.detectors import DetectorRegistry
from redactable.policy.loader import load_policy
from redactable.policy.engine import apply_policy

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="redactable")
    p.add_argument("--policy", "-p", required=False, help="Path to YAML/JSON policy")
    p.add_argument("--region", default="GB", help="Default phone region (e.g. GB, US)")
    args = p.parse_args(argv)

    text = sys.stdin.read()
    registry = DetectorRegistry.default(region=args.region)
    findings = list(registry.scan(text))

    pol = load_policy(args.policy) if args.policy else None
    out = apply_policy(pol, findings, text) if pol else text
    sys.stdout.write(out)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
