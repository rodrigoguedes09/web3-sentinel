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
from sentinela.integrations.rpc import NetworkType

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
        
        # Initialize RPC integration if enabled
        self.rpc_client: RPCClient | None = None
        self.explorer: UnifiedExplorer | None = None
        self.query_cache: QueryCache | None = None
        self.blockchain_cache: BlockchainQueryCache | None = None
        
        if self.settings.enable_rpc_integration:
            try:
                # Initialize RPC client
                self.rpc_client = RPCClient(
                    network=NetworkType.ETHEREUM_MAINNET,
                    rpc_url=self.settings.mainnet_rpc_url or None,
                )
                
                # Initialize explorer (RPC + optional Etherscan)
                self.explorer = UnifiedExplorer(
                    network=NetworkType.ETHEREUM_MAINNET,
                    rpc_url=self.settings.mainnet_rpc_url or None,
                    explorer_api_key=self.settings.etherscan_api_key or None,
                )
                
                # Initialize cache if enabled
                if self.settings.enable_query_cache:
                    self.query_cache = QueryCache(
                        cache_dir=self.settings.cache_dir,
                        ttl_seconds=self.settings.cache_ttl_seconds,
                        max_size_mb=self.settings.cache_max_size_mb,
                    )
                    self.blockchain_cache = BlockchainQueryCache(self.query_cache)
                
                logger.info("✅ RPC integration enabled with caching")
            except Exception as e:
                logger.warning(f"Failed to initialize RPC integration: {e}")
                self.rpc_client = None
                self.explorer = None

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

            # Enrich with on-chain data if RPC integration enabled
            onchain_data = None
            cross_chain_data = None
            
            # Try to extract contract address from state or test output
            contract_address = state.get("contract_address")
            
            # If no address provided, try to extract from test output (deployment logs)
            if not contract_address and test_result.stdout:
                # Look for deployment address in test output
                # Forge outputs: "Contract deployed at: 0x..."
                import re
                address_pattern = r"0x[a-fA-F0-9]{40}"
                matches = re.findall(address_pattern, test_result.stdout)
                if matches:
                    contract_address = matches[0]
                    logger.info(f"📍 Extracted contract address from test output: {contract_address}")
            
            if self.rpc_client and contract_address:
                logger.info("📊 Enriching report with on-chain data...")
                try:
                    onchain_data = await self.enrich_with_onchain_data(
                        contract_address=state["contract_address"],
                        hypothesis=hypothesis,
                    )
                    
                    if self.settings.enable_cross_chain_analysis:
                        cross_chain_data = await self.check_cross_chain_deployment(
                            contract_address=state["contract_address"],
                        )
                except Exception as e:
                    logger.error(f"Failed to enrich with on-chain data: {e}")

            # Generate report with enrichment
            report = await self._generate_report(
                hypothesis=hypothesis,
                exploit_test=state.get("current_exploit_test"),
                test_result=test_result,
                severity=auditor_output.severity,
                recommendations=auditor_output.recommendations,
                onchain_data=onchain_data,
                cross_chain_deployments=cross_chain_data,
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
        onchain_data: dict[str, Any] | None = None,
        cross_chain_deployments: dict[str, bool] | None = None,
    ) -> VulnerabilityReport:
        """Generate a vulnerability report for a proven exploit."""
        # Enhance recommendations based on on-chain data
        enhanced_recommendations = recommendations.copy()
        
        if onchain_data:
            # Add context-aware recommendations
            balance_eth = onchain_data.get("contract_balance_eth", 0)
            if balance_eth > 100:
                enhanced_recommendations.insert(0, 
                    f"⚠️ URGENT: Contract holds {balance_eth:.2f} ETH - Deploy fix immediately")
            
            if not onchain_data.get("is_verified"):
                enhanced_recommendations.append(
                    "Verify contract source code on block explorers for transparency")
        
        if cross_chain_deployments and len(cross_chain_deployments) > 1:
            networks = ", ".join(cross_chain_deployments.keys())
            enhanced_recommendations.insert(0,
                f"🌍 CRITICAL: Deploy fix on ALL chains simultaneously: {networks}")
        
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
            recommendations=enhanced_recommendations,
            references=hypothesis.similar_hacks,
            onchain_data=onchain_data,
            cross_chain_deployments=cross_chain_deployments,
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

    async def enrich_with_onchain_data(
        self,
        contract_address: str,
        hypothesis: AttackHypothesis,
    ) -> dict[str, Any]:
        """
        Enrich vulnerability analysis with on-chain data.
        
        Args:
            contract_address: Contract address to analyze
            hypothesis: Vulnerability hypothesis
            
        Returns:
            Dictionary with on-chain enrichment data
        """
        if not self.rpc_client or not self.explorer:
            logger.debug("RPC integration disabled, skipping on-chain enrichment")
            return {}

        enrichment = {}

        try:
            # Get current block for context
            current_block = await self.rpc_client.get_block_number()
            enrichment["current_block"] = current_block

            # Check if contract exists
            is_contract = await self.explorer.is_contract(contract_address)
            enrichment["is_deployed_contract"] = is_contract

            if not is_contract:
                logger.info(f"Address {contract_address} is not a deployed contract")
                return enrichment

            # Get contract balance (use cache if available)
            if self.blockchain_cache:
                balance = await self.blockchain_cache.get_balance(
                    contract_address,
                    "ethereum",
                    current_block,
                )
                if balance is None:
                    balance = await self.rpc_client.get_balance(contract_address)
                    await self.blockchain_cache.set_balance(
                        contract_address,
                        "ethereum",
                        current_block,
                        balance,
                    )
            else:
                balance = await self.rpc_client.get_balance(contract_address)

            enrichment["contract_balance_wei"] = balance
            enrichment["contract_balance_eth"] = float(
                self.rpc_client.w3.from_wei(balance, "ether")
            )

            # Get bytecode (cached long-term)
            if self.blockchain_cache:
                code = await self.blockchain_cache.get_contract_code(
                    contract_address,
                    "ethereum",
                )
                if code is None:
                    code = await self.rpc_client.get_code(contract_address)
                    await self.blockchain_cache.set_contract_code(
                        contract_address,
                        "ethereum",
                        code,
                    )
            else:
                code = await self.rpc_client.get_code(contract_address)

            enrichment["bytecode_size"] = len(code)

            # Try to get verified source code (if Etherscan key available)
            if self.settings.etherscan_api_key:
                source = await self.explorer.get_contract_source(contract_address)
                if source:
                    enrichment["is_verified"] = True
                    enrichment["compiler_version"] = source.compiler_version
                    enrichment["optimization_enabled"] = source.optimization_used
                    logger.info(f"✅ Contract verified on Etherscan")
                else:
                    enrichment["is_verified"] = False
            
            # Estimate risk based on balance
            balance_eth = enrichment["contract_balance_eth"]
            if balance_eth > 1000:
                enrichment["risk_level"] = "CRITICAL - High value contract"
            elif balance_eth > 100:
                enrichment["risk_level"] = "HIGH - Significant funds at risk"
            elif balance_eth > 10:
                enrichment["risk_level"] = "MEDIUM - Moderate funds at risk"
            else:
                enrichment["risk_level"] = "LOW - Limited funds at risk"

            logger.info(
                f"📊 On-chain enrichment: Balance {balance_eth:.4f} ETH, "
                f"Bytecode {enrichment['bytecode_size']} bytes"
            )

        except Exception as e:
            logger.error(f"Failed to enrich with on-chain data: {e}")
            enrichment["error"] = str(e)

        return enrichment

    async def check_cross_chain_deployment(
        self,
        contract_address: str,
    ) -> dict[str, bool]:
        """
        Check if contract is deployed on multiple chains.
        
        Args:
            contract_address: Contract address
            
        Returns:
            Dictionary mapping network to deployment status
        """
        if not self.settings.enable_cross_chain_analysis:
            return {}

        try:
            from sentinela.integrations.cross_chain import CrossChainAnalyzer
            from sentinela.integrations.explorer import MultiChainExplorer

            # Initialize multi-chain explorer
            multi_explorer = MultiChainExplorer()
            multi_explorer.add_network(NetworkType.ETHEREUM_MAINNET, self.settings.mainnet_rpc_url)
            multi_explorer.add_network(NetworkType.POLYGON, self.settings.polygon_rpc_url)
            multi_explorer.add_network(NetworkType.BSC, self.settings.bsc_rpc_url)

            # Find deployments
            analyzer = CrossChainAnalyzer(multi_explorer)
            deployments = await analyzer.find_contract_deployments(contract_address)

            result = {d.network.value: True for d in deployments}
            
            if len(deployments) > 1:
                logger.warning(
                    f"🌍 Contract deployed on {len(deployments)} chains! "
                    f"Vulnerability may propagate across: {', '.join(result.keys())}"
                )

            return result

        except Exception as e:
            logger.error(f"Cross-chain check failed: {e}")
            return {}
