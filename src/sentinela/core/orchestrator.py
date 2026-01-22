"""
Sentinela Orchestrator - LangGraph Multi-Agent Pipeline

This module defines the main LangGraph workflow that orchestrates the
multi-agent security audit pipeline with reflection loops and error handling.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Literal

from langgraph.graph import END, StateGraph
from langgraph.checkpoint.memory import MemorySaver

from sentinela.agents.explorer import ExplorerAgent
from sentinela.agents.red_teamer import RedTeamerAgent
from sentinela.agents.prover import ProverAgent
from sentinela.agents.auditor import AuditorAgent
from sentinela.core.config import Settings, get_settings
from sentinela.core.state import (
    AgentPhase,
    AgentState,
    VulnerabilityReport,
    create_initial_state,
)


logger = logging.getLogger(__name__)


# =============================================================================
# Routing Functions
# =============================================================================


def route_after_exploration(state: AgentState) -> Literal["red_teamer", "error"]:
    """Route after Explorer phase based on results."""
    if state.get("error"):
        return "error"
    if state.get("explorer_output") is None:
        return "error"
    return "red_teamer"


def route_after_hypothesis(state: AgentState) -> Literal["prover", "report", "error"]:
    """Route after Red Teamer phase based on hypotheses generated."""
    if state.get("error"):
        return "error"
    
    hypotheses = state.get("hypotheses", [])
    if not hypotheses:
        logger.info("No hypotheses generated, moving to report")
        return "report"
    
    return "prover"


def route_after_testing(
    state: AgentState,
) -> Literal["prover", "reflection", "next_hypothesis", "report", "error"]:
    """
    Route after Auditor testing phase.
    
    This is the critical routing function that handles:
    - Successful exploits (move to next hypothesis or report)
    - Compilation errors (reflection loop)
    - Runtime errors (reflection or skip)
    - Max reflections reached (skip hypothesis)
    """
    if state.get("error"):
        return "error"

    phase = state.get("phase", AgentPhase.REPORTING)

    # Phase-based routing
    if phase == AgentPhase.REFLECTION:
        reflection_count = state.get("reflection_count", 0)
        max_reflections = state.get("max_reflections", 3)

        if reflection_count < max_reflections:
            logger.info(f"Entering reflection loop (attempt {reflection_count + 1}/{max_reflections})")
            return "reflection"
        else:
            logger.info("Max reflections reached, moving to next hypothesis")
            return "next_hypothesis"

    elif phase == AgentPhase.EXPLOIT_WRITING:
        # Ready for next hypothesis
        return "next_hypothesis"

    elif phase == AgentPhase.REPORTING:
        return "report"

    return "next_hypothesis"


def route_after_reflection(state: AgentState) -> Literal["prover", "next_hypothesis", "error"]:
    """Route after reflection - either retry or give up."""
    if state.get("error"):
        return "error"

    reflection = state.get("reflection_feedback")
    if reflection and reflection.should_retry:
        return "prover"

    return "next_hypothesis"


def should_continue_hypotheses(state: AgentState) -> Literal["prover", "report"]:
    """Check if there are more hypotheses to test."""
    hypotheses = state.get("hypotheses", [])
    current_index = state.get("current_hypothesis_index", 0)

    if current_index < len(hypotheses):
        return "prover"
    return "report"


# =============================================================================
# Node Functions
# =============================================================================


class SentinelaOrchestrator:
    """
    Main orchestrator for the Sentinela security audit pipeline.
    
    Implements a LangGraph workflow with the following phases:
    1. Exploration - Analyze contract with Slither
    2. Hypothesis Generation - Red Team generates attack hypotheses
    3. Exploit Writing - Prover writes Foundry tests
    4. Testing - Auditor runs tests and analyzes results
    5. Reflection - Handle errors and retry if needed
    6. Reporting - Generate final vulnerability reports
    
    The workflow supports:
    - Cyclic reflection loops for error recovery
    - Multiple hypothesis testing
    - Comprehensive error handling
    - State persistence via checkpointing
    """

    def __init__(
        self,
        settings: Settings | None = None,
        enable_checkpointing: bool = True,
    ) -> None:
        """
        Initialize the orchestrator.
        
        Args:
            settings: Application settings
            enable_checkpointing: Enable state checkpointing
        """
        self.settings = settings or get_settings()
        self.enable_checkpointing = enable_checkpointing

        # Initialize agents
        self.explorer = ExplorerAgent(settings=self.settings)
        self.red_teamer = RedTeamerAgent(settings=self.settings)
        self.prover = ProverAgent(settings=self.settings)
        self.auditor = AuditorAgent(settings=self.settings)

        # Build the graph
        self.graph = self._build_graph()

    def _build_graph(self) -> StateGraph:
        """
        Build the LangGraph workflow.
        
        Returns:
            Compiled StateGraph ready for execution
        """
        # Create the graph with AgentState
        workflow = StateGraph(AgentState)

        # Add nodes for each phase
        workflow.add_node("explorer", self._explorer_node)
        workflow.add_node("red_teamer", self._red_teamer_node)
        workflow.add_node("prover", self._prover_node)
        workflow.add_node("auditor", self._auditor_node)
        workflow.add_node("reflection", self._reflection_node)
        workflow.add_node("next_hypothesis", self._next_hypothesis_node)
        workflow.add_node("report", self._report_node)
        workflow.add_node("error", self._error_node)

        # Set entry point
        workflow.set_entry_point("explorer")

        # Add edges with conditional routing
        workflow.add_conditional_edges(
            "explorer",
            route_after_exploration,
            {
                "red_teamer": "red_teamer",
                "error": "error",
            },
        )

        workflow.add_conditional_edges(
            "red_teamer",
            route_after_hypothesis,
            {
                "prover": "prover",
                "report": "report",
                "error": "error",
            },
        )

        # Prover always goes to auditor
        workflow.add_edge("prover", "auditor")

        # Auditor has complex routing
        workflow.add_conditional_edges(
            "auditor",
            route_after_testing,
            {
                "prover": "prover",
                "reflection": "reflection",
                "next_hypothesis": "next_hypothesis",
                "report": "report",
                "error": "error",
            },
        )

        # Reflection routing
        workflow.add_conditional_edges(
            "reflection",
            route_after_reflection,
            {
                "prover": "prover",
                "next_hypothesis": "next_hypothesis",
                "error": "error",
            },
        )

        # Next hypothesis routing
        workflow.add_conditional_edges(
            "next_hypothesis",
            should_continue_hypotheses,
            {
                "prover": "prover",
                "report": "report",
            },
        )

        # Terminal nodes
        workflow.add_edge("report", END)
        workflow.add_edge("error", END)

        # Compile with optional checkpointing
        if self.enable_checkpointing:
            checkpointer = MemorySaver()
            return workflow.compile(checkpointer=checkpointer)
        else:
            return workflow.compile()

    # =========================================================================
    # Node Implementations
    # =========================================================================

    async def _explorer_node(self, state: AgentState) -> AgentState:
        """Execute the Explorer agent."""
        logger.info("Phase: EXPLORATION - Analyzing contract structure")
        try:
            state["phase"] = AgentPhase.EXPLORATION
            return await self.explorer.execute(state)
        except Exception as e:
            logger.error(f"Explorer failed: {e}")
            state["error"] = str(e)
            state["phase"] = AgentPhase.FAILED
            return state

    async def _red_teamer_node(self, state: AgentState) -> AgentState:
        """Execute the Red Teamer agent."""
        logger.info("Phase: HYPOTHESIS GENERATION - Formulating attack vectors")
        try:
            state["phase"] = AgentPhase.HYPOTHESIS_GENERATION
            return await self.red_teamer.execute(state)
        except Exception as e:
            logger.error(f"Red Teamer failed: {e}")
            state["error"] = str(e)
            state["phase"] = AgentPhase.FAILED
            return state

    async def _prover_node(self, state: AgentState) -> AgentState:
        """Execute the Prover agent."""
        current_index = state.get("current_hypothesis_index", 0)
        hypotheses = state.get("hypotheses", [])
        
        if hypotheses and current_index < len(hypotheses):
            hypothesis = hypotheses[current_index]
            logger.info(f"Phase: EXPLOIT WRITING - Generating test for: {hypothesis.title}")
        else:
            logger.info("Phase: EXPLOIT WRITING - Generating exploit test")

        try:
            state["phase"] = AgentPhase.EXPLOIT_WRITING
            return await self.prover.execute(state)
        except Exception as e:
            logger.error(f"Prover failed: {e}")
            state["error"] = str(e)
            state["phase"] = AgentPhase.FAILED
            return state

    async def _auditor_node(self, state: AgentState) -> AgentState:
        """Execute the Auditor agent."""
        logger.info("Phase: TESTING - Executing exploit and analyzing results")
        try:
            state["phase"] = AgentPhase.EXPLOIT_TESTING
            return await self.auditor.execute(state)
        except Exception as e:
            logger.error(f"Auditor failed: {e}")
            state["error"] = str(e)
            state["phase"] = AgentPhase.FAILED
            return state

    async def _reflection_node(self, state: AgentState) -> AgentState:
        """
        Handle the reflection loop.
        
        This node prepares the state for retrying the Prover with
        error feedback from the failed test.
        """
        reflection = state.get("reflection_feedback")
        iteration = reflection.iteration_count if reflection else 0

        logger.info(f"Phase: REFLECTION - Analyzing failure (iteration {iteration + 1})")

        # The state already has reflection_feedback set by the Auditor
        # Just update the phase and let the router decide next step
        state["phase"] = AgentPhase.EXPLOIT_WRITING

        return state

    async def _next_hypothesis_node(self, state: AgentState) -> AgentState:
        """
        Advance to the next hypothesis.
        
        Resets reflection state and increments the hypothesis index.
        """
        current_index = state.get("current_hypothesis_index", 0)
        hypotheses = state.get("hypotheses", [])

        next_index = current_index + 1
        state["current_hypothesis_index"] = next_index
        state["reflection_count"] = 0
        state["reflection_feedback"] = None
        state["current_exploit_test"] = None
        state["current_test_result"] = None

        if next_index < len(hypotheses):
            logger.info(f"Moving to hypothesis {next_index + 1}/{len(hypotheses)}")
            state["phase"] = AgentPhase.EXPLOIT_WRITING
        else:
            logger.info("All hypotheses tested, generating report")
            state["phase"] = AgentPhase.REPORTING

        return state

    async def _report_node(self, state: AgentState) -> AgentState:
        """
        Generate final audit report.
        
        Compiles all proven vulnerabilities into a comprehensive report.
        """
        logger.info("Phase: REPORTING - Generating final audit report")

        proven = state.get("proven_vulnerabilities", [])
        reports = state.get("final_reports", [])

        logger.info(f"Audit complete: {len(proven)} vulnerabilities proven")
        for vuln in proven:
            logger.info(f"  - {vuln.title} ({vuln.vulnerability_type.value})")

        state["phase"] = AgentPhase.COMPLETED
        return state

    async def _error_node(self, state: AgentState) -> AgentState:
        """Handle terminal error state."""
        error = state.get("error", "Unknown error")
        logger.error(f"Pipeline failed with error: {error}")
        state["phase"] = AgentPhase.FAILED
        return state

    # =========================================================================
    # Public API
    # =========================================================================

    async def audit(
        self,
        contract_path: str | Path,
        source_code: str | None = None,
        contract_name: str = "",
        thread_id: str = "default",
    ) -> AuditResult:
        """
        Run a complete security audit on a smart contract.
        
        Args:
            contract_path: Path to the Solidity contract file
            source_code: Optional pre-loaded source code
            contract_name: Name of the main contract
            thread_id: Thread ID for checkpointing
            
        Returns:
            AuditResult with findings and reports
        """
        contract_path = Path(contract_path)

        # Load source code if not provided
        if source_code is None:
            source_code = contract_path.read_text(encoding="utf-8")

        # Infer contract name if not provided
        if not contract_name:
            contract_name = contract_path.stem

        # Create initial state
        initial_state = create_initial_state(
            source_code=source_code,
            contract_path=str(contract_path),
            contract_name=contract_name,
            max_reflections=self.settings.max_reflection_loops,
        )

        logger.info(f"Starting audit of {contract_name}")

        # Run the graph
        config = {"configurable": {"thread_id": thread_id}}
        final_state = await self.graph.ainvoke(initial_state, config)

        return AuditResult(
            contract_name=contract_name,
            contract_path=str(contract_path),
            phase=final_state.get("phase", AgentPhase.FAILED),
            hypotheses_generated=len(final_state.get("hypotheses", [])),
            hypotheses_tested=final_state.get("current_hypothesis_index", 0),
            vulnerabilities_proven=final_state.get("proven_vulnerabilities", []),
            reports=final_state.get("final_reports", []),
            error=final_state.get("error"),
        )


# =============================================================================
# Result Types
# =============================================================================


class AuditResult:
    """Result of a security audit."""

    def __init__(
        self,
        contract_name: str,
        contract_path: str,
        phase: AgentPhase,
        hypotheses_generated: int,
        hypotheses_tested: int,
        vulnerabilities_proven: list,
        reports: list[VulnerabilityReport],
        error: str | None = None,
    ) -> None:
        self.contract_name = contract_name
        self.contract_path = contract_path
        self.phase = phase
        self.hypotheses_generated = hypotheses_generated
        self.hypotheses_tested = hypotheses_tested
        self.vulnerabilities_proven = vulnerabilities_proven
        self.reports = reports
        self.error = error

    @property
    def success(self) -> bool:
        """Whether the audit completed successfully."""
        return self.phase == AgentPhase.COMPLETED

    @property
    def vulnerabilities_found(self) -> int:
        """Number of vulnerabilities proven."""
        return len(self.vulnerabilities_proven)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "contract_name": self.contract_name,
            "contract_path": self.contract_path,
            "success": self.success,
            "phase": self.phase.value,
            "hypotheses_generated": self.hypotheses_generated,
            "hypotheses_tested": self.hypotheses_tested,
            "vulnerabilities_found": self.vulnerabilities_found,
            "vulnerabilities": [
                v.model_dump() if hasattr(v, "model_dump") else v
                for v in self.vulnerabilities_proven
            ],
            "error": self.error,
        }

    def __repr__(self) -> str:
        return (
            f"AuditResult(contract={self.contract_name}, "
            f"success={self.success}, "
            f"vulnerabilities={self.vulnerabilities_found})"
        )
