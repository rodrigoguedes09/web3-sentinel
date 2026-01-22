"""
Foundry Integration Module

Provides robust subprocess execution of Forge (testing) and Anvil (local node)
with output parsing, error categorization, and process management.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import signal
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sentinela.core.config import Settings, get_settings
from sentinela.core.state import TestResult


logger = logging.getLogger(__name__)


class FoundryError(Exception):
    """Custom exception for Foundry execution errors."""

    def __init__(
        self,
        message: str,
        stderr: str = "",
        return_code: int = -1,
        error_type: str = "unknown",
    ):
        super().__init__(message)
        self.stderr = stderr
        self.return_code = return_code
        self.error_type = error_type


@dataclass
class ForgeTestOutput:
    """Parsed output from forge test command."""

    success: bool
    passed: int
    failed: int
    skipped: int
    duration_ms: int
    gas_used: int
    test_results: dict[str, bool]
    stdout: str
    stderr: str
    error_type: str | None = None
    error_message: str | None = None


class ForgeRunner:
    """
    Manages Forge test execution.
    
    Features:
    - Async subprocess execution
    - Comprehensive output parsing
    - Error categorization (compilation vs runtime vs assertion)
    - Gas tracking
    - Timeout management
    """

    def __init__(
        self,
        settings: Settings | None = None,
        timeout: int | None = None,
    ) -> None:
        """
        Initialize ForgeRunner.
        
        Args:
            settings: Application settings
            timeout: Maximum execution time in seconds
        """
        self.settings = settings or get_settings()
        self.timeout = timeout or self.settings.exploit_timeout_seconds
        self._forge_path: str | None = None

    @property
    def forge_path(self) -> str:
        """Get validated Forge executable path."""
        if self._forge_path is None:
            self._forge_path = self._find_forge()
        return self._forge_path

    def _find_forge(self) -> str:
        """
        Locate Forge executable.
        
        Returns:
            Path to Forge executable
            
        Raises:
            FoundryError: If Forge is not found
        """
        if self.settings.forge_path:
            path = Path(self.settings.forge_path)
            if path.exists():
                return str(path)

        forge_path = shutil.which("forge")
        if forge_path:
            return forge_path

        raise FoundryError(
            "Forge not found. Install Foundry from https://getfoundry.sh",
            error_type="not_installed",
        )

    async def run_test(
        self,
        test_path: str | Path,
        test_function: str | None = None,
        verbosity: int = 3,
        fork_url: str | None = None,
        match_contract: str | None = None,
    ) -> TestResult:
        """
        Run Forge tests and return structured results.
        
        Args:
            test_path: Path to the test file
            test_function: Specific test function to run (all if None)
            verbosity: Output verbosity (0-5)
            fork_url: RPC URL for forking mainnet state
            match_contract: Only run tests in matching contract
            
        Returns:
            TestResult with execution details
        """
        test_path = Path(test_path)

        cmd = self._build_test_command(
            test_path=test_path,
            test_function=test_function,
            verbosity=verbosity,
            fork_url=fork_url,
            match_contract=match_contract,
        )

        logger.info(f"Running Forge test: {' '.join(cmd)}")

        try:
            result = await self._run_subprocess(cmd)
            output = self._parse_test_output(result)
            return self._create_test_result(output, test_function or test_path.stem)

        except asyncio.TimeoutError:
            return TestResult(
                hypothesis_id="",
                test_name=test_function or test_path.stem,
                success=False,
                error_type="timeout",
                error_message=f"Test timed out after {self.timeout} seconds",
                stdout="",
                stderr="",
            )

    def _build_test_command(
        self,
        test_path: Path,
        test_function: str | None = None,
        verbosity: int = 3,
        fork_url: str | None = None,
        match_contract: str | None = None,
    ) -> list[str]:
        """Build forge test command with arguments."""
        cmd = [
            self.forge_path,
            "test",
            "--match-path", str(test_path),
            "-" + "v" * verbosity,  # -vvv for verbosity 3
            "--json",  # JSON output for structured parsing
        ]

        if test_function:
            cmd.extend(["--match-test", test_function])

        if fork_url:
            cmd.extend(["--fork-url", fork_url])

        if match_contract:
            cmd.extend(["--match-contract", match_contract])

        # Note: --profile is not supported in all Forge versions, removed
        # Use FOUNDRY_PROFILE env var instead (set in _run_subprocess)

        return cmd

    async def _run_subprocess(self, cmd: list[str]) -> subprocess.CompletedProcess:
        """Execute subprocess asynchronously with timeout."""
        loop = asyncio.get_event_loop()

        def run_sync():
            return subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                cwd=self.settings.project_root,
                env={**os.environ, "FOUNDRY_PROFILE": "exploit"},
            )

        return await loop.run_in_executor(None, run_sync)

    def _parse_test_output(self, result: subprocess.CompletedProcess) -> ForgeTestOutput:
        """
        Parse Forge test output and categorize any errors.
        
        Args:
            result: Completed subprocess result
            
        Returns:
            Structured ForgeTestOutput
        """
        error_type = None
        error_message = None

        # Categorize errors based on output patterns
        combined_output = result.stdout + result.stderr

        if result.returncode != 0:
            error_type, error_message = self._categorize_error(combined_output)

        # Try to parse JSON output
        test_results: dict[str, bool] = {}
        passed = 0
        failed = 0
        skipped = 0
        gas_used = 0
        duration_ms = 0

        try:
            # Forge outputs JSON per line for each test
            for line in result.stdout.split("\n"):
                line = line.strip()
                if line.startswith("{"):
                    try:
                        data = json.loads(line)
                        if "test_results" in data:
                            for test_name, test_data in data["test_results"].items():
                                test_results[test_name] = test_data.get("success", False)
                                if test_data.get("success"):
                                    passed += 1
                                else:
                                    failed += 1
                                gas_used = max(gas_used, test_data.get("gas", 0))
                    except json.JSONDecodeError:
                        continue

        except Exception as e:
            logger.warning(f"Error parsing forge output: {e}")

        # Fallback: parse text output for test counts
        if not test_results:
            passed, failed, skipped = self._parse_test_summary(combined_output)

        # Critical: Check for [PASS] in output for accurate success detection
        # Forge sometimes returns non-zero exit code even when tests pass
        has_pass_marker = "[PASS]" in combined_output
        has_fail_marker = "[FAIL" in combined_output  # Matches [FAIL], [FAIL:...]
        
        # Test is successful if:
        # 1. We have [PASS] marker and no [FAIL] markers, OR
        # 2. Traditional check: returncode 0 and no failures
        test_success = (has_pass_marker and not has_fail_marker) or \
                      (result.returncode == 0 and failed == 0)

        return ForgeTestOutput(
            success=test_success,
            passed=passed,
            failed=failed,
            skipped=skipped,
            duration_ms=duration_ms,
            gas_used=gas_used,
            test_results=test_results,
            stdout=result.stdout,
            stderr=result.stderr,
            error_type=error_type,
            error_message=error_message,
        )

    def _categorize_error(self, output: str) -> tuple[str | None, str | None]:
        """
        Categorize error type from output.
        
        Returns:
            Tuple of (error_type, error_message)
        """
        output_lower = output.lower()

        # Check for "Compiler run failed" first - this is critical for reflection loop
        if "compiler run failed" in output_lower or "compilation failed" in output_lower:
            # Extract the actual Solidity error details
            error_match = re.search(r"Error \((\d+)\):[^\n]+", output, re.IGNORECASE)
            if error_match:
                # Get more context - extract surrounding lines
                lines = output.split('\n')
                error_context = []
                for i, line in enumerate(lines):
                    if error_match.group(0) in line:
                        # Include error and next 3 lines for context
                        error_context = lines[i:min(i+4, len(lines))]
                        break
                return "compilation_failed", '\n'.join(error_context)[:500]
            return "compilation_failed", "Compilation failed - check Solidity syntax"

        # Compilation errors
        compilation_patterns = [
            (r"Error \((\d+)\): (.+)", "compilation"),
            (r"ParserError: (.+)", "parser"),
            (r"TypeError: (.+)", "type_error"),
            (r"DeclarationError: (.+)", "declaration"),
            (r"CompilerError: (.+)", "compiler"),
        ]

        for pattern, error_type in compilation_patterns:
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                return error_type, match.group(0)[:500]

        # Runtime errors
        if "revert" in output_lower:
            revert_match = re.search(r"revert(?:ed)?(?:\s+with)?:?\s*(.+?)(?:\n|$)", output, re.IGNORECASE)
            if revert_match:
                return "revert", revert_match.group(1)[:500]
            return "revert", "Transaction reverted"

        # Assertion failures
        assertion_patterns = [
            r"assertion failed:?\s*(.+)",
            r"assertEq\s+failed:?\s*(.+)",
            r"assert(?:True|False|Eq|Ne|Gt|Lt|Ge|Le)\s+failed",
        ]

        for pattern in assertion_patterns:
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                return "assertion", match.group(0)[:500]

        # Out of gas
        if "out of gas" in output_lower or "gas exhausted" in output_lower:
            return "out_of_gas", "Transaction ran out of gas"

        # Stack errors
        if "stack" in output_lower and ("overflow" in output_lower or "underflow" in output_lower):
            return "stack_error", "Stack overflow/underflow"

        # Default unknown error
        if output.strip():
            return "unknown", output[:500]

        return None, None

    def _parse_test_summary(self, output: str) -> tuple[int, int, int]:
        """Parse test counts from text output."""
        passed = 0
        failed = 0
        skipped = 0

        # Look for summary line like "Test result: ok. 2 passed; 0 failed; 0 skipped"
        summary_match = re.search(
            r"(\d+)\s+passed.*?(\d+)\s+failed.*?(\d+)\s+skipped",
            output,
            re.IGNORECASE,
        )
        if summary_match:
            passed = int(summary_match.group(1))
            failed = int(summary_match.group(2))
            skipped = int(summary_match.group(3))
        else:
            # Alternative: Count [PASS] and [FAIL] markers
            passed = output.count("[PASS]")
            failed = output.count("[FAIL")
            # Don't count skipped this way

        return passed, failed, skipped

    def _create_test_result(
        self,
        output: ForgeTestOutput,
        test_name: str,
    ) -> TestResult:
        """Convert ForgeTestOutput to TestResult."""
        return TestResult(
            hypothesis_id="",  # Will be set by caller
            test_name=test_name,
            success=output.success,
            execution_time_ms=output.duration_ms,
            gas_used=output.gas_used,
            stdout=output.stdout,
            stderr=output.stderr,
            error_type=output.error_type,
            error_message=output.error_message,
        )

    async def build_project(self) -> bool:
        """
        Build the Foundry project.
        
        Returns:
            True if build succeeded
        """
        cmd = [self.forge_path, "build"]

        try:
            result = await self._run_subprocess(cmd)
            return result.returncode == 0
        except Exception as e:
            logger.error(f"Build failed: {e}")
            return False

    async def check_available(self) -> bool:
        """Check if Forge is available and functional."""
        try:
            cmd = [self.forge_path, "--version"]
            result = await self._run_subprocess(cmd)
            logger.info(f"Forge version: {result.stdout.strip()}")
            return True
        except Exception as e:
            logger.error(f"Forge not available: {e}")
            return False

    async def check_compilation(self, test_path: str | Path) -> tuple[bool, str | None]:
        """
        Check if a test file compiles without running it.
        
        Args:
            test_path: Path to the test file
            
        Returns:
            Tuple of (success, error_message)
        """
        cmd = [
            self.forge_path,
            "build",
            "--force",  # Force recompilation
        ]

        try:
            result = await self._run_subprocess(cmd)
            
            if result.returncode != 0:
                combined_output = result.stdout + result.stderr
                error_type, error_message = self._categorize_error(combined_output)
                return False, error_message
            
            return True, None
            
        except Exception as e:
            return False, str(e)


class AnvilManager:
    """
    Manages Anvil local Ethereum node.
    
    Features:
    - Start/stop Anvil processes
    - Port management
    - Fork mode support
    - State snapshot/restore
    """

    def __init__(
        self,
        settings: Settings | None = None,
        port: int | None = None,
    ) -> None:
        """
        Initialize AnvilManager.
        
        Args:
            settings: Application settings
            port: Port to run Anvil on
        """
        self.settings = settings or get_settings()
        self.port = port or self.settings.anvil_port
        self._process: subprocess.Popen | None = None
        self._anvil_path: str | None = None

    @property
    def anvil_path(self) -> str:
        """Get validated Anvil executable path."""
        if self._anvil_path is None:
            self._anvil_path = self._find_anvil()
        return self._anvil_path

    def _find_anvil(self) -> str:
        """Locate Anvil executable."""
        if self.settings.anvil_path:
            path = Path(self.settings.anvil_path)
            if path.exists():
                return str(path)

        anvil_path = shutil.which("anvil")
        if anvil_path:
            return anvil_path

        raise FoundryError(
            "Anvil not found. Install Foundry from https://getfoundry.sh",
            error_type="not_installed",
        )

    @property
    def rpc_url(self) -> str:
        """Get the RPC URL for this Anvil instance."""
        return f"http://127.0.0.1:{self.port}"

    @property
    def is_running(self) -> bool:
        """Check if Anvil is currently running."""
        return self._process is not None and self._process.poll() is None

    async def start(
        self,
        fork_url: str | None = None,
        fork_block: int | None = None,
        accounts: int = 10,
        balance: int = 10000,
    ) -> None:
        """
        Start Anvil local node.
        
        Args:
            fork_url: RPC URL to fork from
            fork_block: Block number to fork at
            accounts: Number of test accounts
            balance: Initial balance for test accounts (ETH)
        """
        if self.is_running:
            logger.warning("Anvil is already running")
            return

        cmd = [
            self.anvil_path,
            "--port", str(self.port),
            "--accounts", str(accounts),
            "--balance", str(balance),
            "--block-time", str(self.settings.anvil_block_time),
        ]

        if fork_url:
            cmd.extend(["--fork-url", fork_url])
            if fork_block:
                cmd.extend(["--fork-block-number", str(fork_block)])

        logger.info(f"Starting Anvil: {' '.join(cmd)}")

        self._process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # Wait for Anvil to be ready
        await asyncio.sleep(2)

        if not self.is_running:
            stderr = self._process.stderr.read().decode() if self._process.stderr else ""
            raise FoundryError(
                "Failed to start Anvil",
                stderr=stderr,
                error_type="startup_failed",
            )

        logger.info(f"Anvil started on {self.rpc_url}")

    async def stop(self) -> None:
        """Stop the Anvil process."""
        if self._process is None:
            return

        logger.info("Stopping Anvil...")

        try:
            self._process.terminate()
            self._process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._process.kill()
            self._process.wait()

        self._process = None
        logger.info("Anvil stopped")

    async def __aenter__(self) -> AnvilManager:
        """Context manager entry."""
        await self.start()
        return self

    async def __aexit__(self, *args: Any) -> None:
        """Context manager exit."""
        await self.stop()
