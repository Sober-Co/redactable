from __future__ import annotations

import argparse
import sys

from redactable.detectors import DetectorRegistry
from redactable.policy.engine import apply_policy
from redactable.policy.loader import load_policy


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="redactable")
    parser.add_argument("--policy", "-p", required=False, help="Path to YAML/JSON policy")
    parser.add_argument("--region", default="GB", help="Default phone region (e.g. GB, US)")
    args = parser.parse_args(argv)

    text = sys.stdin.read()
    registry = DetectorRegistry.default(region=args.region)
    findings = list(registry.scan(text))

    policy = load_policy(args.policy) if args.policy else None
    output = apply_policy(policy, findings, text) if policy else text
    sys.stdout.write(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
