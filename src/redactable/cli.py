from __future__ import annotations

import argparse
import sys

from redactable.detectors import DetectorRegistry
from redactable.policy.engine import apply_policy
from redactable.policy.loader import load_policy


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="redactable",
        description="Policy-driven data redaction, masking, and privacy-preserving transformations.",
    )
    parser.add_argument("--policy", "-p", required=False, help="Path to YAML/JSON policy file")
    parser.add_argument("--region", default="GB", help="Default phone region (e.g. GB, US)")
    parser.add_argument("input", nargs="?", default=None, help="Input file (default: stdin)")
    parser.add_argument("--output", "-o", default=None, help="Output file (default: stdout)")
    args = parser.parse_args(argv)

    try:
        if args.input:
            with open(args.input, encoding="utf-8") as f:
                text = f.read()
        else:
            text = sys.stdin.read()
    except FileNotFoundError:
        print(f"Error: input file not found: {args.input}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130

    registry = DetectorRegistry.default(region=args.region)
    findings = list(registry.scan(text))

    try:
        policy = load_policy(args.policy) if args.policy else None
    except FileNotFoundError:
        print(f"Error: policy file not found: {args.policy}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error loading policy: {e}", file=sys.stderr)
        return 1

    output = apply_policy(policy, findings, text) if policy else text

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(output)
        except OSError as e:
            print(f"Error writing output: {e}", file=sys.stderr)
            return 1
    else:
        sys.stdout.write(output)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
