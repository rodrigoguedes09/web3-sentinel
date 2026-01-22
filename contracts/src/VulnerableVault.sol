// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title VulnerableVault
 * @notice Example vulnerable contract for testing Sentinela Web3
 * @dev Contains multiple intentional vulnerabilities for educational purposes
 * 
 * VULNERABILITIES PRESENT:
 * 1. Reentrancy in withdraw()
 * 2. Access control flaw in emergencyWithdraw()
 * 3. Logic flaw in calculateReward()
 */
contract VulnerableVault {
    mapping(address => uint256) public balances;
    mapping(address => uint256) public lastDepositTime;
    mapping(address => bool) public hasDeposited;
    
    address public owner;
    uint256 public totalDeposits;
    uint256 public rewardRate = 10; // 10% reward
    
    bool private locked;
    
    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);
    event RewardClaimed(address indexed user, uint256 reward);
    
    constructor() {
        owner = msg.sender;
    }
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }
    
    // Note: This modifier is defined but NOT used on withdraw()
    modifier noReentrant() {
        require(!locked, "Reentrant call");
        locked = true;
        _;
        locked = false;
    }
    
    /**
     * @notice Deposit ETH into the vault
     */
    function deposit() external payable {
        require(msg.value > 0, "Must deposit something");
        
        balances[msg.sender] += msg.value;
        lastDepositTime[msg.sender] = block.timestamp;
        hasDeposited[msg.sender] = true;
        totalDeposits += msg.value;
        
        emit Deposit(msg.sender, msg.value);
    }
    
    /**
     * @notice Withdraw ETH from the vault
     * @dev VULNERABLE: No reentrancy protection, state update after external call
     */
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // VULNERABILITY: External call before state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        // State update happens AFTER the external call
        balances[msg.sender] -= amount;
        totalDeposits -= amount;
        
        emit Withdrawal(msg.sender, amount);
    }
    
    /**
     * @notice Withdraw all funds
     * @dev Uses the vulnerable withdraw function
     */
    function withdrawAll() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");
        
        // Calls the vulnerable withdraw function
        this.withdraw(amount);
    }
    
    /**
     * @notice Calculate reward based on deposit time
     * @dev VULNERABLE: Integer overflow in older Solidity, logic flaw in calculation
     */
    function calculateReward(address user) public view returns (uint256) {
        if (!hasDeposited[user]) return 0;
        
        uint256 depositTime = lastDepositTime[user];
        uint256 timeHeld = block.timestamp - depositTime;
        
        // VULNERABILITY: Logic flaw - reward calculated on balance that might be 0
        // after withdrawal, but hasDeposited is never reset
        uint256 reward = (balances[user] * rewardRate * timeHeld) / (100 * 365 days);
        
        return reward;
    }
    
    /**
     * @notice Claim accumulated rewards
     */
    function claimReward() external {
        uint256 reward = calculateReward(msg.sender);
        require(reward > 0, "No reward");
        require(address(this).balance >= reward, "Insufficient contract balance");
        
        // Reset deposit time to prevent double claiming
        lastDepositTime[msg.sender] = block.timestamp;
        
        (bool success, ) = msg.sender.call{value: reward}("");
        require(success, "Reward transfer failed");
        
        emit RewardClaimed(msg.sender, reward);
    }
    
    /**
     * @notice Emergency withdrawal by owner
     * @dev VULNERABLE: Missing onlyOwner modifier!
     */
    function emergencyWithdraw(address to) external {
        // VULNERABILITY: onlyOwner modifier is missing!
        // Anyone can call this function
        
        uint256 contractBalance = address(this).balance;
        require(contractBalance > 0, "No funds");
        
        (bool success, ) = to.call{value: contractBalance}("");
        require(success, "Emergency withdrawal failed");
    }
    
    /**
     * @notice Update reward rate
     */
    function setRewardRate(uint256 newRate) external onlyOwner {
        require(newRate <= 100, "Rate too high");
        rewardRate = newRate;
    }
    
    /**
     * @notice Get contract balance
     */
    function getContractBalance() external view returns (uint256) {
        return address(this).balance;
    }
    
    /**
     * @notice Get user info
     */
    function getUserInfo(address user) external view returns (
        uint256 balance,
        uint256 depositTime,
        uint256 pendingReward
    ) {
        return (
            balances[user],
            lastDepositTime[user],
            calculateReward(user)
        );
    }
    
    receive() external payable {
        // Accept ETH
    }
}
