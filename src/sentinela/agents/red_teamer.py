"""
Red Teamer Agent (The Attacker)

Formulates attack hypotheses based on Explorer analysis and historical hack patterns
retrieved from the RAG database.
"""

from __future__ import annotations

import uuid
from typing import Any

from sentinela.agents.base import BaseAgent
from sentinela.core.state import (
    AgentPhase,
    AgentState,
    AttackHypothesis,
    HypothesisStatus,
    RedTeamerOutput,
    VulnerabilityType,
)
from sentinela.rag.retriever import HackRetriever


RED_TEAMER_SYSTEM_PROMPT = """You are the Red Teamer Agent (codename: Attacker) in a smart contract security audit system.

Your role is to formulate ATTACK HYPOTHESES based on contract analysis and historical exploit patterns.

MINDSET:
Think like a malicious actor with deep DeFi knowledge. Your goal is to find ways to:
- Steal funds from the contract or its users
- Manipulate contract state for profit
- Exploit economic incentives
- Bypass access controls
- Cause denial of service

VULNERABILITY CATEGORIES TO CONSIDER:

1. REENTRANCY
   - Classic reentrancy via fallback/receive
   - Cross-function reentrancy
   - Cross-contract reentrancy
   - Read-only reentrancy

2. ACCESS CONTROL
   - Missing authorization checks
   - Incorrect modifier logic
   - Privilege escalation paths
   - Unprotected initialization

3. LOGIC FLAWS
   - Incorrect state transitions
   - Missing edge case handling
   - Flawed calculation logic
   - Inconsistent validation

4. ORACLE MANIPULATION
   - Price manipulation via flash loans
   - TWAP manipulation
   - Stale price data exploitation

5. FLASH LOAN ATTACKS
   - Governance manipulation
   - Price oracle exploitation
   - Collateral manipulation

6. FRONT-RUNNING
   - Sandwich attacks
   - Transaction ordering dependency
   - MEV extraction

HYPOTHESIS FORMULATION:
For each hypothesis, provide:
- Clear attack vector with step-by-step exploitation
- Preconditions required for the attack
- Target functions involved
- Estimated impact (fund loss, DoS, etc.)
- Confidence score based on evidence strength

EXAMPLE HYPOTHESES:

Example 1 - Reentrancy:
{
  "title": "Reentrancy Attack via withdraw Function",
  "vulnerability_type": "REENTRANCY",
  "description": "The withdraw function updates balances after sending ETH, allowing recursive calls to drain funds",
  "attack_vector": "1. Attacker deposits 1 ETH\n2. Attacker calls withdraw(1 ether) from a malicious contract\n3. In receive() callback, attacker re-enters withdraw() before balance is updated\n4. Repeat 5 times to drain 5 ETH with only 1 ETH deposited",
  "preconditions": [
    "Contract must have ETH balance > attacker's deposit",
    "withdraw() must use call{value}() which triggers fallback",
    "Balance update must occur after the call"
  ],
  "target_functions": ["withdraw", "receive/fallback"],
  "estimated_impact": "Total fund drainage - CRITICAL",
  "confidence_score": 0.95
}

Example 2 - Access Control:
{
  "title": "Unauthorized Fund Withdrawal via emergencyWithdraw",
  "vulnerability_type": "ACCESS_CONTROL",
  "description": "emergencyWithdraw function lacks onlyOwner modifier, allowing anyone to drain funds",
  "attack_vector": "1. Attacker calls emergencyWithdraw(attackerAddress)\n2. Function sends all contract balance to attacker\n3. No access control check prevents this",
  "preconditions": [
    "Function must be external/public",
    "No modifier or require statement checks msg.sender"
  ],
  "target_functions": ["emergencyWithdraw"],
  "estimated_impact": "Complete fund loss - CRITICAL",
  "confidence_score": 0.98
}

Example 3 - Logic Flaw:
{
  "title": "Incorrect Reward Calculation Allows Reward Farming",
  "vulnerability_type": "LOGIC_FLAW",
  "description": "calculateReward uses balance after withdrawal but hasDeposited is never reset, allowing repeated claims",
  "attack_vector": "1. Deposit 10 ETH and wait 1 year\n2. Withdraw all 10 ETH (balance becomes 0)\n3. calculateReward still computes reward based on time held (hasDeposited=true)\n4. Deposit 1 wei to make balance > 0\n5. Claim inflated reward based on old timeframe",
  "preconditions": [
    "hasDeposited flag persists after withdrawal",
    "Reward calculated using current balance * time held"
  ],
  "target_functions": ["calculateReward", "claimReward", "withdraw"],
  "estimated_impact": "Reward inflation attack - HIGH",
  "confidence_score": 0.80
}

IMPORTANT:
- Focus on BUSINESS LOGIC flaws, not syntax errors
- Consider multi-transaction attack sequences
- Think about economic incentives and game theory
- Reference similar historical hacks when applicable
"""


class RedTeamerAgent(BaseAgent[RedTeamerOutput]):
    """
    The Red Teamer Agent generates attack hypotheses.
    
    Uses:
    - Explorer output for contract understanding
    - RAG retrieval of historical hacks
    - LLM reasoning for hypothesis generation
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.retriever = HackRetriever(settings=self.settings)

    @property
    def system_prompt(self) -> str:
        return RED_TEAMER_SYSTEM_PROMPT

    @property
    def output_schema(self) -> type[RedTeamerOutput]:
        return RedTeamerOutput

    async def execute(self, state: AgentState) -> AgentState:
        """
        Execute the Red Teamer's hypothesis generation pipeline.
        
        Steps:
        1. Retrieve relevant historical hacks from RAG
        2. Analyze explorer output and slither findings
        3. Generate attack hypotheses
        4. Rank and prioritize hypotheses
        """
        explorer_output = state.get("explorer_output")
        if explorer_output is None:
            state["error"] = "Explorer output is required for Red Teamer"
            state["phase"] = AgentPhase.FAILED
            return state

        source_code = state["source_code"]

        # Step 1: Retrieve relevant historical hacks
        rag_context = await self._retrieve_similar_hacks(
            source_code, explorer_output.slither_findings
        )
        state["rag_context"] = rag_context

        # Step 2: Build hypothesis generation prompt
        prompt = self._build_hypothesis_prompt(
            source_code=source_code,
            explorer_output=explorer_output,
            rag_context=rag_context,
        )

        # Step 3: Generate hypotheses via LLM
        red_teamer_output = await self.invoke_with_structure(
            prompt,
            context={
                "explorer_analysis": explorer_output.model_dump_json(indent=2),
                "historical_hacks": self._format_rag_context(rag_context),
            },
        )

        # Step 4: Assign IDs and sort by confidence
        hypotheses = self._process_hypotheses(red_teamer_output.hypotheses)

        # Limit to configured maximum
        max_hypotheses = self.settings.max_hypotheses_per_run
        hypotheses = sorted(
            hypotheses, key=lambda h: h.confidence_score, reverse=True
        )[:max_hypotheses]

        state["hypotheses"] = hypotheses
        state["current_hypothesis_index"] = 0
        state["phase"] = AgentPhase.EXPLOIT_WRITING

        return state

    async def _retrieve_similar_hacks(
        self,
        source_code: str,
        slither_findings: list,
    ) -> list[dict[str, Any]]:
        """
        Retrieve similar historical hacks from the RAG database.
        
        Args:
            source_code: Contract source code
            slither_findings: Slither analysis findings
            
        Returns:
            List of relevant historical hack documents
        """
        # Build query from contract characteristics
        query_parts = []

        # Add vulnerability types from slither
        for finding in slither_findings:
            if hasattr(finding, 'detector'):
                query_parts.append(finding.detector)

        # Add code patterns
        if "withdraw" in source_code.lower():
            query_parts.append("withdrawal vulnerability")
        if "delegatecall" in source_code.lower():
            query_parts.append("delegatecall exploit")
        if "approve" in source_code.lower():
            query_parts.append("approval exploit")

        query = " ".join(query_parts) if query_parts else "smart contract vulnerability exploit"

        return await self.retriever.retrieve(query, k=5)

    def _build_hypothesis_prompt(
        self,
        source_code: str,
        explorer_output: Any,
        rag_context: list[dict[str, Any]],
    ) -> str:
        """Build the hypothesis generation prompt."""
        entry_points_str = ""
        for ep in explorer_output.entry_points:
            entry_points_str += f"- {ep.function_name} (risk: {ep.risk_score:.2f}): {ep.reasoning}\n"

        return f"""Based on the following smart contract analysis, generate attack hypotheses.

CONTRACT ANALYSIS:
- Contract: {explorer_output.contract_name}
- Entry Points Identified: {len(explorer_output.entry_points)}
- Slither Findings: {len(explorer_output.slither_findings)}

CRITICAL ENTRY POINTS:
{entry_points_str}

EXTERNAL CALLS:
{', '.join(explorer_output.external_calls) if explorer_output.external_calls else 'None identified'}

STATE VARIABLES:
{', '.join(explorer_output.state_variables) if explorer_output.state_variables else 'None highlighted'}

CONTROL FLOW SUMMARY:
{explorer_output.control_flow_summary}

TASK:
1. Analyze the contract for exploitable vulnerabilities
2. Cross-reference with historical hack patterns provided
3. Generate 3-5 attack hypotheses ranked by confidence
4. For each hypothesis, provide:
   - Specific attack vector
   - Required preconditions
   - Target functions
   - Estimated impact
   - Similar historical exploits

Focus on LOGICAL and ECONOMIC vulnerabilities that require understanding business intent.
"""

    def _format_rag_context(self, rag_context: list[dict[str, Any]]) -> str:
        """Format RAG context for inclusion in prompt."""
        if not rag_context:
            return "No relevant historical hacks found in database."

        formatted = "RELEVANT HISTORICAL HACKS:\n\n"
        for i, doc in enumerate(rag_context, 1):
            formatted += f"""
--- Hack #{i} ---
Name: {doc.get('name', 'Unknown')}
Date: {doc.get('date', 'Unknown')}
Loss: {doc.get('loss_amount', 'Unknown')}
Vulnerability Type: {doc.get('vulnerability_type', 'Unknown')}
Summary: {doc.get('summary', 'No summary available')}
Attack Vector: {doc.get('attack_vector', 'Not documented')}
"""
        return formatted

    def _process_hypotheses(
        self,
        hypotheses: list[AttackHypothesis],
    ) -> list[AttackHypothesis]:
        """Process and enrich hypotheses with unique IDs."""
        processed = []
        for hypothesis in hypotheses:
            if not hypothesis.id:
                hypothesis.id = f"hyp_{uuid.uuid4().hex[:8]}"
            hypothesis.status = HypothesisStatus.PENDING
            processed.append(hypothesis)
        return processed
