"""
Prover Agent (The Exploit Engineer)

Receives attack hypotheses and writes real Solidity exploit test scripts
using the Foundry (Forge) framework.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from sentinela.agents.base import BaseAgent
from sentinela.core.state import (
    AgentPhase,
    AgentState,
    AttackHypothesis,
    ExploitTest,
    HypothesisStatus,
    ReflectionFeedback,
)


PROVER_SYSTEM_PROMPT = """You are the Prover Agent (codename: Exploit Engineer) in a smart contract security audit system.

Your role is to write REAL, EXECUTABLE Foundry test scripts that prove attack hypotheses.

FOUNDRY TEST STRUCTURE:
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/VulnerableContract.sol";

contract ExploitTest is Test {
    VulnerableContract target;
    address attacker = makeAddr("attacker");
    address victim = makeAddr("victim");
    
    function setUp() public {
        // Deploy contracts
        target = new VulnerableContract();
        
        // Fund accounts using vm.deal()
        vm.deal(attacker, 10 ether);
        vm.deal(victim, 100 ether);
        vm.deal(address(target), 100 ether);
    }
    
    function test_ExploitName() public {
        // Record initial state
        uint256 initialBalance = address(target).balance;
        
        // Execute exploit
        vm.startPrank(attacker);
        // ... exploit steps ...
        vm.stopPrank();
        
        // Assert exploit success
        assertGt(attacker.balance, 10 ether, "Attacker should have stolen funds");
    }
}
```

FOUNDRY CHEATCODES TO USE:
- vm.prank(address) / vm.startPrank(address) - Impersonate addresses
- vm.deal(address, amount) - Set ETH balance
- vm.warp(timestamp) - Set block timestamp
- vm.roll(blockNumber) - Set block number
- vm.expectRevert() - Expect a revert
- makeAddr(string) - Create labeled address
- deal(token, address, amount) - Set ERC20 balance

TEST DESIGN PRINCIPLES:
1. Each test should prove ONE specific vulnerability
2. Use descriptive test names: test_ReentrancyViaWithdraw
3. Include comments explaining each exploit step
4. Assert the IMPACT (stolen funds, changed state, DoS achieved)
5. Tests should PASS if the vulnerability exists

EXPLOIT PATTERNS:

For Reentrancy:
```solidity
contract AttackerContract {
    VulnerableContract public target;
    uint256 public attackCount;
    uint256 public initialDeposit;
    
    constructor(address payable _target) payable {
        target = VulnerableContract(_target);
    }
    
    receive() external payable {
        // CRITICAL: Stop before underflow - only withdraw initialDeposit per call
        if (attackCount < 5 && address(target).balance >= initialDeposit) {
            attackCount++;
            target.withdraw(initialDeposit);
        }
    }
    
    function attack(uint256 amount) external {
        initialDeposit = amount;
        target.deposit{value: amount}();
        target.withdraw(amount);
    }
}
```

REENTRANCY EXPLOIT RULES:
1. Target contract must have MORE funds than attacker deposit (vm.deal 100+ ETH)
2. Track initialDeposit to prevent arithmetic underflow
3. Attacker deposits 1 ETH, but can drain 5+ ETH via reentrancy
4. Assert: attacker.balance > initial + (stolen from contract)

CRITICAL SOLIDITY SYNTAX RULES (0.8+):
1. **address payable for contracts receiving funds**:
   ✅ constructor(address payable _target)
   ❌ constructor(address _target)
   
2. **Contracts with receive()/fallback() need payable addresses**:
   ✅ AttackerContract attacker = new AttackerContract(payable(address(target)));
   ❌ AttackerContract attacker = new AttackerContract(address(target));
   
3. **Always specify amounts in external calls**:
   ✅ target.withdraw(1 ether)
   ❌ target.withdraw()
   
4. **Use vm.deal() to fund contracts**:
   ✅ vm.deal(address(target), 100 ether);
   ❌ address(target).transfer(100 ether);
   
5. **Import paths are relative from test/ directory**:
   ✅ import "../src/ContractName.sol";
   ❌ import "src/ContractName.sol";

TEST SETUP BEST PRACTICES:
1. **Fund target contract generously**:
   vm.deal(address(target), 100 ether); // Much more than attacker needs
   
2. **Give attacker starting funds**:
   vm.deal(attacker, 10 ether); // For deposits and gas
   
3. **For reward/time-based exploits**:
   vm.warp(block.timestamp + 365 days); // Fast-forward time
   
4. **Assertions should prove impact**:
   assertGt(attacker.balance, 10 ether, "Attacker stole funds");
   assertEq(address(target).balance, 0, "Contract drained");

For Access Control:
```solidity
function test_UnauthorizedAccess() public {
    vm.prank(attacker);
    // Should revert but does not
    target.adminFunction();
    // If we reach here, access control is broken
    assertTrue(true, "Unauthorized access succeeded");
}
```

OUTPUT REQUIREMENTS:
- Complete, compilable Solidity code
- All necessary imports
- Proper setUp with realistic initial state
- Clear assertions that verify exploit success
"""


class ProverOutput(ExploitTest):
    """Extended exploit test with generation metadata."""
    pass


class ProverAgent(BaseAgent[ExploitTest]):
    """
    The Prover Agent writes Foundry exploit tests.
    
    Capabilities:
    - Generate complete .t.sol test files
    - Handle reflection feedback for compilation errors
    - Adapt tests based on hypothesis requirements
    """

    @property
    def system_prompt(self) -> str:
        return PROVER_SYSTEM_PROMPT

    @property
    def output_schema(self) -> type[ExploitTest]:
        return ExploitTest

    async def execute(self, state: AgentState) -> AgentState:
        """
        Execute the Prover's exploit generation pipeline.
        
        Steps:
        1. Get current hypothesis to prove
        2. Generate exploit test code
        3. Save to test directory
        4. Update state for testing phase
        """
        hypotheses = state.get("hypotheses", [])
        current_index = state.get("current_hypothesis_index", 0)

        if not hypotheses or current_index >= len(hypotheses):
            state["phase"] = AgentPhase.REPORTING
            return state

        hypothesis = hypotheses[current_index]
        hypothesis.status = HypothesisStatus.TESTING

        # Check for reflection feedback
        reflection = state.get("reflection_feedback")
        source_code = state["source_code"]
        contract_name = state.get("contract_name", "Target")

        # Generate exploit test
        prompt = self._build_exploit_prompt(
            hypothesis=hypothesis,
            source_code=source_code,
            contract_name=contract_name,
            reflection=reflection,
        )

        exploit_test = await self.invoke_with_structure(
            prompt,
            context={
                "hypothesis": hypothesis.model_dump_json(indent=2),
                "source_code": source_code,
            },
        )

        # Set test metadata
        exploit_test.hypothesis_id = hypothesis.id
        exploit_test.test_name = self._generate_test_name(hypothesis)
        exploit_test.file_path = self._get_test_file_path(hypothesis, state)

        # Save test file
        await self._save_test_file(exploit_test, state)

        # Update state
        state["current_exploit_test"] = exploit_test
        exploit_tests = state.get("exploit_tests", [])
        exploit_tests.append(exploit_test)
        state["exploit_tests"] = exploit_tests
        state["phase"] = AgentPhase.EXPLOIT_TESTING
        state["reflection_feedback"] = None  # Clear reflection feedback

        return state

    def _build_exploit_prompt(
        self,
        hypothesis: AttackHypothesis,
        source_code: str,
        contract_name: str,
        reflection: ReflectionFeedback | None = None,
    ) -> str:
        """Build the exploit generation prompt."""
        base_prompt = f"""Write a Foundry test to prove the following vulnerability hypothesis.

HYPOTHESIS:
- ID: {hypothesis.id}
- Type: {hypothesis.vulnerability_type.value}
- Title: {hypothesis.title}
- Description: {hypothesis.description}

ATTACK VECTOR:
{hypothesis.attack_vector}

PRECONDITIONS:
{chr(10).join(f'- {p}' for p in hypothesis.preconditions) if hypothesis.preconditions else 'None specified'}

TARGET FUNCTIONS:
{chr(10).join(f'- {f}' for f in hypothesis.target_functions) if hypothesis.target_functions else 'Not specified'}

CONTRACT NAME: {contract_name}

REQUIREMENTS:
1. Write a COMPLETE, COMPILABLE Foundry test file
2. Include setUp() with proper contract deployment
3. Include test function that executes the exploit
4. Use assertions to verify the exploit succeeded
5. Add comments explaining each step

The test should PASS if the vulnerability exists and is exploitable.
"""

        if reflection:
            base_prompt += f"""

PREVIOUS ATTEMPT FAILED:
Error Type: {reflection.error_category}
Error Message: {reflection.original_error}

Suggested Fixes:
{chr(10).join(f'- {fix}' for fix in reflection.suggested_fixes)}

Please fix the issues and regenerate the test.
This is attempt #{reflection.iteration_count + 1}.
"""

        return base_prompt

    def _generate_test_name(self, hypothesis: AttackHypothesis) -> str:
        """Generate a descriptive test function name."""
        # Convert vulnerability type to camel case
        vuln_type = hypothesis.vulnerability_type.value.replace("_", " ").title().replace(" ", "")
        
        # Clean title for use in function name
        title_clean = re.sub(r'[^a-zA-Z0-9]', '', hypothesis.title.title().replace(" ", ""))[:30]
        
        return f"test_{vuln_type}_{title_clean}"

    def _get_test_file_path(self, hypothesis: AttackHypothesis, state: AgentState) -> str:
        """Generate the test file path."""
        test_dir = self.settings.get_test_path()
        test_dir.mkdir(parents=True, exist_ok=True)
        
        filename = f"Exploit_{hypothesis.id}.t.sol"
        return str(test_dir / filename)

    async def _save_test_file(self, exploit_test: ExploitTest, state: AgentState) -> None:
        """Save the generated test file to disk."""
        file_path = Path(exploit_test.file_path)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_path.write_text(exploit_test.solidity_code, encoding="utf-8")
