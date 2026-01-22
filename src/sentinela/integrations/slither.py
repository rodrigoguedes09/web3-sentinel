"""
Slither Integration Module

Provides robust subprocess execution of Slither static analysis
with JSON output parsing and error handling.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Any

from sentinela.core.config import Settings, get_settings


logger = logging.getLogger(__name__)


class SlitherError(Exception):
    """Custom exception for Slither execution errors."""
    
    def __init__(self, message: str, stderr: str = "", return_code: int = -1):
        super().__init__(message)
        self.stderr = stderr
        self.return_code = return_code


class SlitherRunner:
    """
    Manages Slither static analysis execution.
    
    Features:
    - Async subprocess execution
    - JSON output capture and parsing
    - Comprehensive error handling
    - Timeout management
    - Path validation
    """

    def __init__(
        self,
        settings: Settings | None = None,
        timeout: int = 300,
    ) -> None:
        """
        Initialize SlitherRunner.
        
        Args:
            settings: Application settings
            timeout: Maximum execution time in seconds
        """
        self.settings = settings or get_settings()
        self.timeout = timeout
        self._slither_path: str | None = None

    @property
    def slither_path(self) -> str:
        """Get validated Slither executable path."""
        if self._slither_path is None:
            self._slither_path = self._find_slither()
        return self._slither_path

    def _find_slither(self) -> str:
        """
        Locate Slither executable.
        
        Returns:
            Path to Slither executable
            
        Raises:
            SlitherError: If Slither is not found
        """
        # Check settings first
        if self.settings.slither_path:
            path = Path(self.settings.slither_path)
            if path.exists():
                return str(path)

        # Check system PATH
        slither_path = shutil.which("slither")
        if slither_path:
            return slither_path

        raise SlitherError(
            "Slither not found. Install with: pip install slither-analyzer"
        )

    async def analyze(
        self,
        contract_path: str | Path,
        detectors: list[str] | None = None,
        exclude_detectors: list[str] | None = None,
        solc_version: str | None = None,
    ) -> dict[str, Any]:
        """
        Run Slither analysis on a contract.
        
        Args:
            contract_path: Path to the Solidity file or project directory
            detectors: Specific detectors to run (all if None)
            exclude_detectors: Detectors to exclude
            solc_version: Specific Solidity compiler version
            
        Returns:
            Parsed JSON output from Slither
            
        Raises:
            SlitherError: If analysis fails
        """
        contract_path = Path(contract_path)
        if not contract_path.exists():
            raise SlitherError(f"Contract path does not exist: {contract_path}")

        # Build command
        cmd = self._build_command(
            contract_path=contract_path,
            detectors=detectors,
            exclude_detectors=exclude_detectors,
            solc_version=solc_version,
        )

        logger.info(f"Running Slither: {' '.join(cmd)}")

        try:
            result = await self._run_subprocess(cmd)
            return self._parse_output(result)

        except asyncio.TimeoutError:
            raise SlitherError(
                f"Slither analysis timed out after {self.timeout} seconds"
            )

    def _build_command(
        self,
        contract_path: Path,
        detectors: list[str] | None = None,
        exclude_detectors: list[str] | None = None,
        solc_version: str | None = None,
    ) -> list[str]:
        """Build Slither command with arguments."""
        cmd = [
            self.slither_path,
            str(contract_path),
            "--json", "-",  # Output JSON to stdout
        ]

        if detectors:
            cmd.extend(["--detect", ",".join(detectors)])

        if exclude_detectors:
            cmd.extend(["--exclude", ",".join(exclude_detectors)])

        if solc_version:
            cmd.extend(["--solc-solcs-select", solc_version])

        # Additional useful flags
        cmd.extend([
            "--exclude-informational",  # Focus on security issues
            "--exclude-low",  # Exclude low severity for cleaner output
        ])

        return cmd

    async def _run_subprocess(self, cmd: list[str]) -> subprocess.CompletedProcess:
        """
        Execute subprocess asynchronously with timeout.
        
        Args:
            cmd: Command and arguments to execute
            
        Returns:
            Completed process result
        """
        loop = asyncio.get_event_loop()

        def run_sync():
            return subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                cwd=self.settings.get_contracts_path(),
            )

        return await loop.run_in_executor(None, run_sync)

    def _parse_output(self, result: subprocess.CompletedProcess) -> dict[str, Any]:
        """
        Parse Slither JSON output.
        
        Args:
            result: Completed subprocess result
            
        Returns:
            Parsed JSON dictionary
            
        Raises:
            SlitherError: If parsing fails
        """
        # Slither may return non-zero even on success if vulnerabilities found
        # Only treat as error if stderr indicates actual failure
        if result.returncode != 0 and "error" in result.stderr.lower():
            # Check if it's a real error vs just findings
            if "compilation" in result.stderr.lower() or "exception" in result.stderr.lower():
                raise SlitherError(
                    f"Slither analysis failed",
                    stderr=result.stderr,
                    return_code=result.returncode,
                )

        try:
            # Try to parse stdout as JSON
            if result.stdout.strip():
                output = json.loads(result.stdout)
                return output
            else:
                # No output - try to create minimal result
                return {
                    "success": result.returncode == 0,
                    "results": {"detectors": []},
                    "error": result.stderr if result.stderr else None,
                }

        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse Slither JSON output: {e}")
            # Return empty results on parse failure
            return {
                "success": False,
                "results": {"detectors": []},
                "error": f"JSON parse error: {e}",
                "raw_stdout": result.stdout[:1000],
                "raw_stderr": result.stderr[:1000],
            }

    async def get_printers_output(
        self,
        contract_path: str | Path,
        printers: list[str],
    ) -> dict[str, str]:
        """
        Run Slither printers for additional analysis.
        
        Useful printers:
        - contract-summary: Overview of contracts
        - function-summary: Function details
        - call-graph: Call relationships
        - cfg: Control flow graph
        - inheritance: Inheritance tree
        
        Args:
            contract_path: Path to contract
            printers: List of printer names
            
        Returns:
            Dictionary mapping printer name to output
        """
        contract_path = Path(contract_path)
        outputs = {}

        for printer in printers:
            cmd = [
                self.slither_path,
                str(contract_path),
                "--print", printer,
            ]

            try:
                result = await self._run_subprocess(cmd)
                outputs[printer] = result.stdout
            except Exception as e:
                logger.warning(f"Printer {printer} failed: {e}")
                outputs[printer] = ""

        return outputs

    async def check_available(self) -> bool:
        """
        Check if Slither is available and functional.
        
        Returns:
            True if Slither is available
        """
        try:
            cmd = [self.slither_path, "--version"]
            result = await self._run_subprocess(cmd)
            logger.info(f"Slither version: {result.stdout.strip()}")
            return True
        except Exception as e:
            logger.error(f"Slither not available: {e}")
            return False


# Convenience function for quick analysis
async def analyze_contract(
    contract_path: str | Path,
    **kwargs: Any,
) -> dict[str, Any]:
    """
    Quick helper to analyze a contract with Slither.
    
    Args:
        contract_path: Path to the contract file
        **kwargs: Additional arguments for SlitherRunner.analyze
        
    Returns:
        Slither JSON output
    """
    runner = SlitherRunner()
    return await runner.analyze(contract_path, **kwargs)
