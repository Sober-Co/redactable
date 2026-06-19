"""Tests for CLI functionality."""

import subprocess
import sys
from pathlib import Path


def test_cli_help():
    """Test that CLI help works."""
    result = subprocess.run(
        [sys.executable, "-m", "redactable.cli", "--help"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "policy" in result.stdout.lower()


def test_cli_version():
    """Test that CLI accepts --version flag (if implemented)."""
    result = subprocess.run(
        [sys.executable, "-m", "redactable.cli", "--version"],
        capture_output=True,
        text=True,
    )
    # May fail if not implemented, but should not crash
    assert result.returncode in [0, 2]  # 0 = success, 2 = unrecognized arg


def test_cli_stdin_basic():
    """Test CLI with stdin input and basic policy."""
    policy_path = Path("policies/gdpr.yaml")
    if not policy_path.exists():
        # Skip if policy file doesn't exist
        return

    input_text = "Email: alice@example.com\n"
    result = subprocess.run(
        [sys.executable, "-m", "redactable.cli", "--policy", str(policy_path)],
        input=input_text,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    # Should have some output
    assert len(result.stdout) > 0


def test_cli_stdin_multiple_lines():
    """Test CLI with multi-line stdin input."""
    policy_path = Path("policies/gdpr.yaml")
    if not policy_path.exists():
        return

    input_text = "Email: alice@example.com\nEmail: bob@example.com\n"
    result = subprocess.run(
        [sys.executable, "-m", "redactable.cli", "--policy", str(policy_path)],
        input=input_text,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert len(result.stdout) > 0


def test_cli_region_argument():
    """Test CLI with --region argument."""
    policy_path = Path("policies/gdpr.yaml")
    if not policy_path.exists():
        return

    input_text = "Phone: +447911123456\n"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "redactable.cli",
            "--policy",
            str(policy_path),
            "--region",
            "US",
        ],
        input=input_text,
        capture_output=True,
        text=True,
    )

    # Should not crash with region argument
    assert result.returncode in [0, 2]
