"""Tests for the Sentinela core module."""

import pytest
from sentinela.core.state import (
    AgentPhase,
    AgentState,
    AttackHypothesis,
    VulnerabilityType,
    HypothesisStatus,
    create_initial_state,
)


class TestAgentState:
    """Tests for AgentState creation and manipulation."""

    def test_create_initial_state(self):
        """Test creating an initial state."""
        state = create_initial_state(
            source_code="contract Test {}",
            contract_path="/test/Test.sol",
            contract_name="Test",
        )

        assert state["source_code"] == "contract Test {}"
        assert state["contract_path"] == "/test/Test.sol"
        assert state["contract_name"] == "Test"
        assert state["phase"] == AgentPhase.INITIALIZATION
        assert state["hypotheses"] == []
        assert state["proven_vulnerabilities"] == []

    def test_initial_state_defaults(self):
        """Test that initial state has correct defaults."""
        state = create_initial_state(
            source_code="",
            contract_path="",
        )

        assert state["max_reflections"] == 3
        assert state["reflection_count"] == 0
        assert state["current_hypothesis_index"] == 0
        assert state["error"] is None


class TestAttackHypothesis:
    """Tests for AttackHypothesis model."""

    def test_create_hypothesis(self):
        """Test creating an attack hypothesis."""
        hypothesis = AttackHypothesis(
            id="hyp_001",
            vulnerability_type=VulnerabilityType.REENTRANCY,
            title="Reentrancy in withdraw()",
            description="Classic reentrancy vulnerability",
            attack_vector="Call withdraw, reenter in fallback",
            target_functions=["withdraw"],
            confidence_score=0.85,
        )

        assert hypothesis.id == "hyp_001"
        assert hypothesis.vulnerability_type == VulnerabilityType.REENTRANCY
        assert hypothesis.confidence_score == 0.85
        assert hypothesis.status == HypothesisStatus.PENDING

    def test_hypothesis_validation(self):
        """Test hypothesis field validation."""
        with pytest.raises(ValueError):
            AttackHypothesis(
                id="test",
                vulnerability_type=VulnerabilityType.REENTRANCY,
                title="Test",
                description="Test",
                attack_vector="Test",
                confidence_score=1.5,  # Should be <= 1.0
            )


class TestVulnerabilityType:
    """Tests for VulnerabilityType enum."""

    def test_all_types_have_values(self):
        """Test that all vulnerability types have string values."""
        for vuln_type in VulnerabilityType:
            assert isinstance(vuln_type.value, str)
            assert len(vuln_type.value) > 0

    def test_reentrancy_type(self):
        """Test reentrancy type value."""
        assert VulnerabilityType.REENTRANCY.value == "reentrancy"

    def test_access_control_type(self):
        """Test access control type value."""
        assert VulnerabilityType.ACCESS_CONTROL.value == "access_control"


class TestAgentPhase:
    """Tests for AgentPhase enum."""

    def test_phase_progression(self):
        """Test that phases can progress logically."""
        phases = [
            AgentPhase.INITIALIZATION,
            AgentPhase.EXPLORATION,
            AgentPhase.HYPOTHESIS_GENERATION,
            AgentPhase.EXPLOIT_WRITING,
            AgentPhase.EXPLOIT_TESTING,
            AgentPhase.REPORTING,
            AgentPhase.COMPLETED,
        ]

        for i, phase in enumerate(phases[:-1]):
            assert phases[i] != phases[i + 1]

    def test_terminal_phases(self):
        """Test terminal phases."""
        assert AgentPhase.COMPLETED.value == "completed"
        assert AgentPhase.FAILED.value == "failed"
