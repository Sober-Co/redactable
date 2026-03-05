"""Tests for the CLI module."""

import tempfile
import os

from redactable.cli import main


class TestCLI:
    def test_stdin_passthrough(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin", __import__("io").StringIO("hello world"))
        ret = main([])
        assert ret == 0
        assert capsys.readouterr().out == "hello world"

    def test_file_input(self, tmp_path, capsys):
        inp = tmp_path / "input.txt"
        inp.write_text("Email: test@example.com", encoding="utf-8")
        ret = main([str(inp)])
        assert ret == 0
        assert "test@example.com" in capsys.readouterr().out

    def test_file_output(self, tmp_path, monkeypatch):
        monkeypatch.setattr("sys.stdin", __import__("io").StringIO("hello"))
        out = tmp_path / "output.txt"
        ret = main(["--output", str(out)])
        assert ret == 0
        assert out.read_text() == "hello"

    def test_missing_input_file(self, capsys):
        ret = main(["/nonexistent/file.txt"])
        assert ret == 1
        assert "not found" in capsys.readouterr().err

    def test_missing_policy_file(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin", __import__("io").StringIO("hello"))
        ret = main(["--policy", "/nonexistent/policy.yaml"])
        assert ret == 1
        assert "not found" in capsys.readouterr().err
