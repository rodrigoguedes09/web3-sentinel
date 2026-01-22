"""
Sentinela Web3 - Autonomous Multi-Agent Security Swarm

An intelligent security auditing system for Ethereum Smart Contracts
that uses multi-agent orchestration to discover and prove vulnerabilities.
"""

__version__ = "0.1.0"
__author__ = "Sentinela Web3 Team"

from sentinela.core.state import AgentState
from sentinela.core.orchestrator import SentinelaOrchestrator

__all__ = [
    "AgentState",
    "SentinelaOrchestrator",
    "__version__",
]
