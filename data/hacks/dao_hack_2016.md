# The DAO Hack (2016)

## Overview
The DAO hack was one of the most significant security incidents in Ethereum history. An attacker exploited a reentrancy vulnerability to drain approximately 3.6 million ETH (worth ~$70 million at the time).

## Vulnerability Type
- **Primary**: Reentrancy Attack
- **Secondary**: Logic Error in State Management

## Technical Details

### Attack Mechanism
The vulnerable `splitDAO` function allowed an attacker to recursively call the withdrawal function before the internal balance was updated. This is a classic reentrancy vulnerability.

### Vulnerable Code Pattern
```solidity
function splitDAO(uint256 proposalId, address newCurator) {
    // ... validation checks ...
    
    // VULNERABLE: External call before state update
    if (balances[msg.sender] > 0) {
        msg.sender.call.value(balances[msg.sender])();  // External call
        balances[msg.sender] = 0;  // State update AFTER external call
    }
}
```

### Exploit Flow
1. Attacker calls `splitDAO` with valid parameters
2. Contract sends ETH to attacker's contract
3. Attacker's fallback function recursively calls `splitDAO` again
4. Since `balances[msg.sender]` hasn't been zeroed yet, the check passes
5. Repeat until desired amount is drained

## Root Causes
1. **State Update After External Call**: The contract updated the user's balance AFTER sending funds
2. **Lack of Reentrancy Guard**: No mutex or check-effects-interactions pattern
3. **Complex Control Flow**: Multiple possible execution paths made vulnerability hard to spot

## Impact
- **Amount Lost**: 3.6 million ETH (~$70 million USD at the time)
- **Ecosystem Impact**: Led to Ethereum hard fork (ETH/ETC split)
- **Reputation**: Major blow to smart contract security confidence

## Remediation Patterns

### 1. Checks-Effects-Interactions Pattern
```solidity
function splitDAO(uint256 proposalId, address newCurator) {
    // CHECKS: Validate inputs
    require(proposals[proposalId].executed == false);
    
    // EFFECTS: Update state FIRST
    uint256 amount = balances[msg.sender];
    balances[msg.sender] = 0;
    
    // INTERACTIONS: External calls LAST
    msg.sender.call.value(amount)();
}
```

### 2. Reentrancy Guard
```solidity
modifier noReentrant() {
    require(!locked, "Reentrant call");
    locked = true;
    _;
    locked = false;
}

function splitDAO(...) noReentrant {
    // Function logic
}
```

### 3. Use `transfer()` Instead of `call.value()`
```solidity
// Safer: transfer() limits gas to 2300, preventing complex callbacks
msg.sender.transfer(amount);
```

## Detection Strategies

### Static Analysis Indicators
- External calls before state changes
- State variables modified after external calls
- Use of `call.value()` without reentrancy protection
- Missing reentrancy guards on withdrawal functions

### Dynamic Analysis
- Test with malicious contract that re-enters
- Fuzz test with various call sequences
- Monitor for unexpected multiple state transitions

## Similar Historical Exploits
- **Lendf.Me (2020)**: Reentrancy on ERC777 tokens, $25M stolen
- **Uniswap/Lendf.Me (2020)**: ERC777 reentrancy, $25M stolen
- **Cream Finance (2021)**: Reentrancy via flash loans, $34M stolen
- **Grim Finance (2021)**: Reentrancy in vault strategy, $30M stolen

## Prevention Checklist
- [ ] Follow Checks-Effects-Interactions pattern
- [ ] Use OpenZeppelin's ReentrancyGuard
- [ ] Prefer `transfer()` over `call.value()` when possible
- [ ] Update all state before external calls
- [ ] Add comprehensive reentrancy tests
- [ ] Audit all functions that make external calls
- [ ] Consider using pull-payment patterns instead of push

## References
- [Original DAO Hack Analysis](https://hackingdistributed.com/2016/06/18/analysis-of-the-dao-exploit/)
- [Ethereum Post-Mortem](https://blog.ethereum.org/2016/06/17/critical-update-re-dao-vulnerability)
- [Consensys Reentrancy Best Practices](https://consensys.github.io/smart-contract-best-practices/attacks/reentrancy/)

## Key Takeaways
1. **Never trust external calls**: Any external call can potentially re-enter your contract
2. **State before interactions**: Always update state variables before making external calls
3. **Defense in depth**: Use multiple protection mechanisms (pattern + guard + tests)
4. **Audit critical functions**: Pay special attention to functions handling value transfers
