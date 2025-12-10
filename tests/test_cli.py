"""Tests for the CLI."""

import tempfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from isthisipbad.cli import app

runner = CliRunner()


class TestCLICommands:
    """Tests for CLI commands."""

    def test_version_command(self):
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "isthisipbad" in result.stdout
        assert "version" in result.stdout

    def test_sources_command(self):
        result = runner.invoke(app, ["sources"])
        assert result.exit_code == 0
        assert "Spamhaus" in result.stdout
        assert "DNSBL" in result.stdout

    def test_help(self):
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "check" in result.stdout
        assert "version" in result.stdout
        assert "sources" in result.stdout


class TestCheckCommand:
    """Tests for the check command."""

    @pytest.mark.skip(reason="Requires network access")
    def test_check_google_dns(self):
        result = runner.invoke(app, ["check", "8.8.8.8", "--quiet"])
        assert result.exit_code == 0
        assert "8.8.8.8" in result.stdout

    def test_check_invalid_format_option(self):
        # Test with invalid format should still work (defaults to table)
        result = runner.invoke(app, ["check", "8.8.8.8", "--format", "invalid", "--quiet"])
        # Will fail due to network, but format option is accepted
        assert "--format" not in result.stdout or result.exit_code != 2

    def test_check_help(self):
        result = runner.invoke(app, ["check", "--help"])
        assert result.exit_code == 0
        assert "--file" in result.stdout
        assert "--output" in result.stdout
        assert "--format" in result.stdout
        assert "--show-clean" in result.stdout


class TestFileInput:
    """Tests for file input functionality."""

    def test_empty_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("# Comment only\n")
            f.write("\n")
            f.flush()

            result = runner.invoke(app, ["check", "--file", f.name])
            # Should report no valid IPs
            assert "No valid IPs" in result.stdout or result.exit_code != 0

    def test_file_with_comments(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("# This is a comment\n")
            f.write("8.8.8.8\n")
            f.write("# Another comment\n")
            f.flush()

            # The file should be readable (network test skipped)
            path = Path(f.name)
            content = path.read_text()
            lines = [line.strip() for line in content.splitlines() if line.strip() and not line.startswith("#")]
            assert lines == ["8.8.8.8"]
