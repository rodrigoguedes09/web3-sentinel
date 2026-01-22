"""Pytest configuration and fixtures."""

import pytest
import asyncio
from pathlib import Path


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def sample_solidity_code():
    """Sample Solidity code for testing."""
    return """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SampleVault {
    mapping(address => uint256) public balances;
    
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
    
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient");
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] -= amount;
    }
}
"""


@pytest.fixture
def project_root():
    """Get the project root directory."""
    return Path(__file__).parent.parent


@pytest.fixture
def contracts_dir(project_root):
    """Get the contracts directory."""
    return project_root / "contracts"


@pytest.fixture
def sample_slither_output():
    """Sample Slither JSON output for testing."""
    return {
        "success": True,
        "results": {
            "detectors": [
                {
                    "check": "reentrancy-eth",
                    "impact": "High",
                    "confidence": "Medium",
                    "description": "Reentrancy vulnerability in withdraw()",
                    "elements": [
                        {
                            "type": "function",
                            "name": "withdraw",
                            "source_mapping": {"lines": [10, 11, 12, 13, 14]}
                        }
                    ]
                }
            ]
        }
    }
