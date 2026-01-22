"""
Auditor Agent (The Reporter)

Orchestrates the testing loop, runs Forge tests, captures output,
and generates final vulnerability reports.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from pydantic import BaseModel, Field

from sentinela.agents.base import BaseAgent
from sentinela.core.state import (
    AgentPhase,
    AgentState,
    AttackHypothesis,
    ExploitTest,
    HypothesisStatus,
    ReflectionFeedback,
    TestResult,
    VulnerabilityReport,
)
from sentinela.integrations.foundry import ForgeRunner

logger = logging.getLogger(__name__)


AUDITOR_SYSTEM_PROMPT = """You are the Auditor Agent (codename: Reporter) in a smart contract security audit system.

Your role is to:
1. Analyze test execution results
2. Determine if vulnerabilities are proven
3. Generate professional security reports
4. Provide reflection feedback for failed tests

TEST RESULT INTERPRETATION:
- Test PASSED + Assertion succeeded = Vulnerability PROVEN
- Test FAILED + Assertion failed = Vulnerability NOT exploitable
- Compilation Error = Code issue, needs reflection with specific fixes
- Runtime Error = Logic issue, may need hypothesis revision

COMPILATION ERROR REFLECTION:
When you see compilation errors, provide SPECIFIC fixes:

Common Solidity 0.8+ errors:
1. "Explicit type conversion not allowed from non-payable address"
   → Fix: Use `address payable` in constructor parameters
   → Example: `constructor(address payable _target)` not `constructor(address _target)`
   
2. "Type contract X is not implicitly convertible"
   → Fix: Use `payable(address(target))` when passing to constructor
   → Example: `new AttackerContract(payable(address(target)))`
   
3. "Wrong argument count for function call"
   → Fix: Specify the amount parameter
   → Example: `target.withdraw(1 ether)` not `target.withdraw()`
   
4. "Undeclared identifier"
   → Fix: Check import paths (use `../src/` from test directory)
   
5. "Member not found or not visible"
   → Fix: Check if functions are public/external

REFLECTION FEEDBACK FORMAT:
When reflection is needed, structure feedback as:
1. Identified Error: [specific Solidity error]
2. Root Cause: [why this happened]
3. Fix Required: [exact code change needed]
4. Example: [corrected code snippet]

REPORT GENERATION:
For proven vulnerabilities, generate reports with:
- Clear severity assessment (Critical, High, Medium, Low)
- Technical explanation of the vulnerability
- Step-by-step reproduction guide
- Remediation recommendations
- References to similar known vulnerabilities

SEVERITY CLASSIFICATION:
- CRITICAL: Direct fund loss, contract takeover
- HIGH: Significant fund loss, major state corruption
- MEDIUM: Limited fund loss, partial access control bypass
- LOW: Minor issues, theoretical attacks
- INFORMATIONAL: Best practice violations
"""


class AuditorOutput(BaseModel):
    """Structured output from the Auditor agent."""
    
    test_interpretation: str = Field(..., description="Interpretation of test results")
    vulnerability_proven: bool = Field(..., description="Whether vulnerability was proven")
    severity: str = Field(default="", description="Severity if proven")
    recommendations: list[str] = Field(default_factory=list, description="Fix recommendations")
    reflection_needed: bool = Field(default=False, description="Whether reflection is needed")
    reflection_feedback: str = Field(default="", description="Feedback for prover if needed")
    should_retry: bool = Field(default=False, description="Whether to retry with fixes")


class AuditorAgent(BaseAgent[AuditorOutput]):
    """
    The Auditor Agent orchestrates testing and generates reports.
    
    Responsibilities:
    - Execute Forge tests
    - Parse test output
    - Determine test success/failure
    - Generate reflection feedback
    - Produce final reports
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.forge_runner = ForgeRunner(settings=self.settings)

    @property
    def system_prompt(self) -> str:
        return AUDITOR_SYSTEM_PROMPT

    @property
    def output_schema(self) -> type[AuditorOutput]:
        return AuditorOutput

    async def execute(self, state: AgentState) -> AgentState:
        """
        Execute the Auditor's test orchestration pipeline.
        
        Steps:
        1. Run current exploit test with Forge
        2. Parse test results
        3. Analyze results with LLM
        4. Route to appropriate next phase
        """
        exploit_test = state.get("current_exploit_test")
        if exploit_test is None:
            state["phase"] = AgentPhase.REPORTING
            return state

        hypotheses = state.get("hypotheses", [])
        current_index = state.get("current_hypothesis_index", 0)
        current_hypothesis = hypotheses[current_index] if hypotheses else None

        # Step 1: Run the test
        test_result = await self.forge_runner.run_test(exploit_test.file_path)
        state["current_test_result"] = test_result

        test_results = state.get("test_results", [])
        test_results.append(test_result)
        state["test_results"] = test_results

        # Step 2: Check if test passed based on Forge output
        # CRITICAL: If test_result.success is True, trust it (contains [PASS] marker)
        logger.info(f"Test result: success={test_result.success}, stdout_len={len(test_result.stdout)}, stderr_len={len(test_result.stderr)}")
        
        if test_result.success:
            # Test passed - vulnerability is proven!
            logger.info(f"✅ VULNERABILITY CONFIRMED - Test passed with [PASS] marker!")
            auditor_output = AuditorOutput(
                test_interpretation=f"Test PASSED - [PASS] marker found in output. Vulnerability confirmed.",
                vulnerability_proven=True,
                severity="CRITICAL" if "unauthorized" in exploit_test.test_name.lower() else "HIGH",
                recommendations=[
                    "Implement proper access control checks",
                    "Add appropriate modifiers (e.g., onlyOwner)",
                    "Conduct thorough testing before deployment"
                ],
                reflection_needed=False,
                reflection_feedback="",
                should_retry=False
            )
        else:
            # Test failed - analyze why with LLM
            logger.info(f"❌ Test failed - Analyzing with LLM...")
            auditor_output = await self._analyze_test_result(
                test_result=test_result,
                exploit_test=exploit_test,
                hypothesis=current_hypothesis,
            )

        # Step 3: Route based on analysis
        state = await self._route_based_on_result(
            state=state,
            auditor_output=auditor_output,
            test_result=test_result,
            hypothesis=current_hypothesis,
        )

        return state

    async def _analyze_test_result(
        self,
        test_result: TestResult,
        exploit_test: ExploitTest,
        hypothesis: AttackHypothesis | None,
    ) -> AuditorOutput:
        """Analyze test results using LLM."""
        prompt = f"""Analyze the following Foundry test execution result.

TEST INFORMATION:
- Test Name: {exploit_test.test_name}
- Hypothesis: {hypothesis.title if hypothesis else 'Unknown'}
- Vulnerability Type: {hypothesis.vulnerability_type.value if hypothesis else 'Unknown'}

TEST RESULT:
- Success: {test_result.success}
- Execution Time: {test_result.execution_time_ms}ms
- Gas Used: {test_result.gas_used}

STDOUT:
{test_result.stdout[:2000] if test_result.stdout else 'No output'}

STDERR:
{test_result.stderr[:2000] if test_result.stderr else 'No errors'}

{f'ERROR TYPE: {test_result.error_type}' if test_result.error_type else ''}
{f'ERROR MESSAGE: {test_result.error_message}' if test_result.error_message else ''}

IMPORTANT - TEST SUCCESS INTERPRETATION:
- If you see "[PASS]" in STDOUT → Vulnerability is PROVEN
- If you see "[FAIL]" in STDOUT → Check the failure reason:
  * Assertion failed = Exploit didn't work as expected (vulnerability may not exist)
  * Revert/Error = Logic error in exploit code (needs reflection)
  * Compilation error = Syntax issue (needs reflection)

TASK:
1. Interpret whether the test proved the vulnerability
2. If proven, assess severity
3. If failed due to code issues, provide reflection feedback
4. Recommend next steps
"""
        return await self.invoke_with_structure(prompt)

    async def _route_based_on_result(
        self,
        state: AgentState,
        auditor_output: AuditorOutput,
        test_result: TestResult,
        hypothesis: AttackHypothesis | None,
    ) -> AgentState:
        """Route to next phase based on test analysis."""
        current_index = state.get("current_hypothesis_index", 0)
        hypotheses = state.get("hypotheses", [])
        reflection_count = state.get("reflection_count", 0)
        max_reflections = state.get("max_reflections", 3)

        # TRUST test_result.success (contains [PASS] marker) over LLM interpretation
        vulnerability_confirmed = test_result.success and hypothesis is not None
        
        if vulnerability_confirmed:
            # Vulnerability proven - add to proven list and generate report
            hypothesis.status = HypothesisStatus.PROVEN
            proven = state.get("proven_vulnerabilities", [])
            proven.append(hypothesis)
            state["proven_vulnerabilities"] = proven

            # Generate report
            report = await self._generate_report(
                hypothesis=hypothesis,
                exploit_test=state.get("current_exploit_test"),
                test_result=test_result,
                severity=auditor_output.severity,
                recommendations=auditor_output.recommendations,
            )
            reports = state.get("final_reports", [])
            reports.append(report)
            state["final_reports"] = reports

            # Move to next hypothesis
            state = self._advance_to_next_hypothesis(state)

        elif auditor_output.reflection_needed and auditor_output.should_retry:
            # Needs reflection - check if we have retries left
            if reflection_count < max_reflections:
                state["reflection_count"] = reflection_count + 1
                state["reflection_feedback"] = ReflectionFeedback(
                    original_error=test_result.error_message or test_result.stderr or "Unknown error",
                    error_category=self._categorize_error(test_result),
                    suggested_fixes=self._parse_suggested_fixes(auditor_output.reflection_feedback),
                    should_retry=True,
                    iteration_count=reflection_count,
                )
                state["phase"] = AgentPhase.REFLECTION
                if hypothesis:
                    hypothesis.status = HypothesisStatus.COMPILATION_ERROR
            else:
                # Max reflections reached - mark as failed and move on
                if hypothesis:
                    hypothesis.status = HypothesisStatus.DISPROVEN
                state = self._advance_to_next_hypothesis(state)

        else:
            # Hypothesis disproven or not exploitable
            if hypothesis:
                hypothesis.status = HypothesisStatus.DISPROVEN
            state = self._advance_to_next_hypothesis(state)

        return state

    def _advance_to_next_hypothesis(self, state: AgentState) -> AgentState:
        """Advance to the next hypothesis or complete."""
        current_index = state.get("current_hypothesis_index", 0)
        hypotheses = state.get("hypotheses", [])

        next_index = current_index + 1
        if next_index < len(hypotheses):
            state["current_hypothesis_index"] = next_index
            state["reflection_count"] = 0
            state["current_exploit_test"] = None
            state["current_test_result"] = None
            state["phase"] = AgentPhase.EXPLOIT_WRITING
        else:
            state["phase"] = AgentPhase.REPORTING

        return state

    def _categorize_error(self, test_result: TestResult) -> str:
        """Categorize the error type from test result."""
        error_msg = (test_result.error_message or "") + (test_result.stderr or "")
        error_lower = error_msg.lower()

        # Check for compilation failures first
        if any(keyword in error_lower for keyword in [
            "compiler run failed",
            "compilation failed",
            "compilererror",
            "parsererror",
            "typeerror",
            "declarationerror",
            "error (",  # Solidity errors like "Error (7398):"
        ]):
            return "compilation_failed"
        elif "revert" in error_lower:
            return "runtime_revert"
        elif "assertion" in error_lower or "failed" in error_lower:
            return "assertion_failure"
        elif "out of gas" in error_lower:
            return "out_of_gas"
        elif "stack" in error_lower:
            return "stack_error"
        else:
            return "unknown"

    def _parse_suggested_fixes(self, feedback: str) -> list[str]:
        """Parse suggested fixes from reflection feedback."""
        if not feedback:
            return []

        # Try to extract bullet points or numbered items
        fixes = []
        lines = feedback.split("\n")
        for line in lines:
            line = line.strip()
            if line and (line.startswith("-") or line.startswith("*") or 
                        (len(line) > 2 and line[0].isdigit() and line[1] in ".)")):
                fixes.append(line.lstrip("-*0123456789.) "))

        return fixes if fixes else [feedback]

    async def _generate_report(
        self,
        hypothesis: AttackHypothesis,
        exploit_test: ExploitTest | None,
        test_result: TestResult,
        severity: str,
        recommendations: list[str],
    ) -> VulnerabilityReport:
        """Generate a vulnerability report for a proven exploit."""
        return VulnerabilityReport(
            hypothesis=hypothesis,
            exploit_test=exploit_test or ExploitTest(
                hypothesis_id=hypothesis.id,
                test_name="Unknown",
                file_path="Unknown",
                solidity_code="",
            ),
            test_result=test_result,
            severity=severity or self._infer_severity(hypothesis),
            recommendations=recommendations,
            references=hypothesis.similar_hacks,
        )

    def _infer_severity(self, hypothesis: AttackHypothesis) -> str:
        """Infer severity from vulnerability type."""
        critical_types = {
            "reentrancy", "access_control", "delegatecall_injection",
            "uninitialized_proxy", "storage_collision"
        }
        high_types = {
            "logic_flaw", "oracle_manipulation", "flash_loan",
            "price_manipulation", "governance_attack"
        }

        vuln_type = hypothesis.vulnerability_type.value
        if vuln_type in critical_types:
            return "Critical"
        elif vuln_type in high_types:
            return "High"
        else:
            return "Medium"
