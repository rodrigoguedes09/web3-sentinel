"""Tests for the integration modules."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import subprocess

from sentinela.integrations.foundry import ForgeRunner, ForgeTestOutput
from sentinela.integrations.slither import SlitherRunner


class TestForgeRunner:
    """Tests for Forge integration."""

    def test_categorize_compilation_error(self):
        """Test error categorization for compilation errors."""
        runner = ForgeRunner()

        output = "Error (2314): Expected ';' but got '}'"
        error_type, error_msg = runner._categorize_error(output)

        assert error_type == "compilation"
        assert "Expected" in error_msg

    def test_categorize_revert_error(self):
        """Test error categorization for revert errors."""
        runner = ForgeRunner()

        output = "Revert: Insufficient balance"
        error_type, error_msg = runner._categorize_error(output)

        assert error_type == "revert"
        assert "Insufficient balance" in error_msg

    def test_categorize_assertion_error(self):
        """Test error categorization for assertion failures."""
        runner = ForgeRunner()

        output = "Assertion failed: expected 100 but got 50"
        error_type, error_msg = runner._categorize_error(output)

        assert error_type == "assertion"

    def test_categorize_out_of_gas(self):
        """Test error categorization for out of gas."""
        runner = ForgeRunner()

        output = "Transaction out of gas"
        error_type, error_msg = runner._categorize_error(output)

        assert error_type == "out_of_gas"

    def test_parse_test_summary(self):
        """Test parsing test summary from output."""
        runner = ForgeRunner()

        output = "Test result: ok. 5 passed; 2 failed; 1 skipped"
        passed, failed, skipped = runner._parse_test_summary(output)

        assert passed == 5
        assert failed == 2
        assert skipped == 1


class TestSlitherRunner:
    """Tests for Slither integration."""

    def test_build_command_basic(self):
        """Test building basic Slither command."""
        runner = SlitherRunner()

        with patch.object(runner, '_slither_path', 'slither'):
            from pathlib import Path
            cmd = runner._build_command(Path("/test/Contract.sol"))

        assert "slither" in cmd
        assert "/test/Contract.sol" in " ".join(cmd)
        assert "--json" in cmd

    def test_build_command_with_detectors(self):
        """Test building command with specific detectors."""
        runner = SlitherRunner()

        with patch.object(runner, '_slither_path', 'slither'):
            from pathlib import Path
            cmd = runner._build_command(
                Path("/test/Contract.sol"),
                detectors=["reentrancy-eth", "arbitrary-send"],
            )

        assert "--detect" in cmd
        assert "reentrancy-eth,arbitrary-send" in cmd

    def test_parse_empty_output(self):
        """Test parsing empty Slither output."""
        runner = SlitherRunner()

        result = MagicMock()
        result.returncode = 0
        result.stdout = ""
        result.stderr = ""

        output = runner._parse_output(result)

        assert "results" in output
        assert output["success"] is True


class TestErrorCategorization:
    """Integration tests for error categorization logic."""

    @pytest.fixture
    def forge_runner(self):
        return ForgeRunner()

    def test_parser_error(self, forge_runner):
        """Test ParserError categorization."""
        output = "ParserError: Expected primary expression"
        error_type, _ = forge_runner._categorize_error(output)
        assert error_type == "parser"

    def test_type_error(self, forge_runner):
        """Test TypeError categorization."""
        output = "TypeError: Member 'balance' not found in address"
        error_type, _ = forge_runner._categorize_error(output)
        assert error_type == "type_error"

    def test_declaration_error(self, forge_runner):
        """Test DeclarationError categorization."""
        output = "DeclarationError: Undeclared identifier"
        error_type, _ = forge_runner._categorize_error(output)
        assert error_type == "declaration"

    def test_unknown_error(self, forge_runner):
        """Test unknown error categorization."""
        output = "Some random error message"
        error_type, _ = forge_runner._categorize_error(output)
        assert error_type == "unknown"
