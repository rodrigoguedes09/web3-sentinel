"""
Explorer Agent (The Archivist)

Parses Solidity code, executes Slither analysis, extracts the Control Flow Graph,
and identifies critical entry points for security analysis.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from sentinela.agents.base import BaseAgent
from sentinela.core.state import (
    AgentPhase,
    AgentState,
    ContractEntryPoint,
    ExplorerOutput,
    SlitherFinding,
)
from sentinela.integrations.slither import SlitherRunner


EXPLORER_SYSTEM_PROMPT = """You are the Explorer Agent (codename: Archivist) in a smart contract security audit system.

Your role is to analyze Solidity smart contracts and identify critical security-relevant components.

RESPONSIBILITIES:
1. Parse contract structure and identify all public/external entry points
2. Analyze Slither static analysis results for security signals
3. Map the control flow and identify high-risk patterns
4. Prioritize entry points based on attack surface and risk factors

CRITICAL ENTRY POINT IDENTIFICATION:
Focus on functions that involve:
- Fund transfers (withdraw, transfer, send, call with value)
- State changes to critical variables (balances, ownership, permissions)
- External calls to untrusted contracts
- Access control patterns (onlyOwner, require statements)
- Token operations (mint, burn, approve, transferFrom)
- Proxy/upgrade patterns (delegatecall, implementation changes)

RISK SCORING CRITERIA (0.0 to 1.0):
- 0.9-1.0: Direct fund handling + external calls + state changes
- 0.7-0.8: Access control modifications or privileged operations
- 0.5-0.6: State changes with validation logic
- 0.3-0.4: View functions with complex calculations
- 0.1-0.2: Pure helper functions

OUTPUT REQUIREMENTS:
You MUST respond with EXACTLY this JSON structure:
{
  "contract_name": "string",
  "source_hash": "string",
  "entry_points": [...],
  "slither_findings": [...],
  "control_flow_summary": "string",
  "external_calls": [...],
  "state_variables": [...],
  "inheritance_chain": [...]
}

CRITICAL: Use "contract_name" not "main_contract". Include "source_hash" field.
Provide structured analysis focusing on BUSINESS LOGIC vulnerabilities, not just syntax issues.
Think about how an attacker would exploit the contract's intended functionality.
"""


class ExplorerAgent(BaseAgent[ExplorerOutput]):
    """
    The Explorer Agent analyzes smart contract structure and security surface.
    
    Primary functions:
    - Execute Slither static analysis
    - Parse and categorize findings
    - Identify critical entry points
    - Map external dependencies and attack surface
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.slither_runner = SlitherRunner(settings=self.settings)

    @property
    def system_prompt(self) -> str:
        return EXPLORER_SYSTEM_PROMPT

    @property
    def output_schema(self) -> type[ExplorerOutput]:
        return ExplorerOutput

    async def execute(self, state: AgentState) -> AgentState:
        """
        Execute the Explorer agent's analysis pipeline.
        
        Steps:
        1. Run Slither static analysis
        2. Parse Slither JSON output
        3. Analyze with LLM for entry point identification
        4. Return enriched state
        """
        source_code = state["source_code"]
        contract_path = state["contract_path"]

        # Generate source hash for caching
        source_hash = hashlib.sha256(source_code.encode()).hexdigest()[:16]

        # Step 1: Run Slither analysis
        slither_result = await self.slither_runner.analyze(contract_path)
        slither_findings = self._parse_slither_output(slither_result)

        # Step 2: Invoke LLM for deep analysis
        analysis_prompt = self._build_analysis_prompt(source_code, slither_findings)
        explorer_output = await self.invoke_with_structure(
            analysis_prompt,
            context={
                "source_code": source_code,
                "slither_findings": json.dumps(
                    [f.model_dump() for f in slither_findings], indent=2
                ),
            },
        )

        # Ensure hash is set
        explorer_output.source_hash = source_hash

        # Step 3: Update state
        state["explorer_output"] = explorer_output
        state["slither_raw_json"] = slither_result
        state["phase"] = AgentPhase.HYPOTHESIS_GENERATION

        return state

    def _parse_slither_output(self, slither_json: dict[str, Any]) -> list[SlitherFinding]:
        """
        Parse Slither JSON output into structured findings.
        
        Args:
            slither_json: Raw Slither JSON output
            
        Returns:
            List of structured SlitherFinding objects
        """
        findings: list[SlitherFinding] = []

        detectors = slither_json.get("results", {}).get("detectors", [])

        for detector in detectors:
            # Extract affected elements
            elements = detector.get("elements", [])
            contract_name = ""
            function_name = ""
            lines: list[int] = []

            for element in elements:
                if element.get("type") == "contract":
                    contract_name = element.get("name", "")
                elif element.get("type") == "function":
                    function_name = element.get("name", "")
                
                # Extract line numbers
                source = element.get("source_mapping", {})
                if "lines" in source:
                    lines.extend(source["lines"])

            finding = SlitherFinding(
                detector=detector.get("check", "unknown"),
                severity=detector.get("impact", "Unknown"),
                confidence=detector.get("confidence", "Unknown"),
                description=detector.get("description", ""),
                contract=contract_name,
                function=function_name,
                lines=sorted(set(lines)),
            )
            findings.append(finding)

        return findings

    def _build_analysis_prompt(
        self,
        source_code: str,
        slither_findings: list[SlitherFinding],
    ) -> str:
        """
        Build the analysis prompt for the LLM.
        
        Args:
            source_code: Solidity source code
            slither_findings: Parsed Slither findings
            
        Returns:
            Formatted prompt string
        """
        findings_summary = ""
        if slither_findings:
            high_severity = [f for f in slither_findings if f.severity == "High"]
            medium_severity = [f for f in slither_findings if f.severity == "Medium"]
            
            findings_summary = f"""
SLITHER ANALYSIS SUMMARY:
- High Severity: {len(high_severity)} findings
- Medium Severity: {len(medium_severity)} findings
- Total Findings: {len(slither_findings)}

KEY FINDINGS:
"""
            for finding in high_severity[:5]:  # Top 5 high severity
                findings_summary += f"- [{finding.severity}] {finding.detector}: {finding.description[:200]}\n"

        return f"""Analyze the following Solidity smart contract for security-critical entry points.

{findings_summary}

TASK:
1. Identify the main contract name
2. List all public/external functions that could be attack vectors
3. For each entry point, assess the risk level based on:
   - Fund handling capability
   - State modification scope
   - Access control implementation
   - External call patterns
4. Summarize the control flow and identify potential business logic flaws

Focus on LOGICAL VULNERABILITIES that static analysis cannot detect:
- Incorrect permission checks
- Missing validation edge cases
- Flawed economic incentives
- Race conditions in multi-step operations
- State inconsistencies across function calls

Provide your analysis in structured format.
"""
