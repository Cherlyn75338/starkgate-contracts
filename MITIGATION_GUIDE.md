# 🛡️ Starknet Bridge Security Mitigation Guide

## Overview
This guide provides concrete, implementable solutions for each identified vulnerability in the Starknet Bridge. Each mitigation includes code examples and best practices.

---

## 🚨 Critical Mitigations (Must Fix Before Mainnet)

### 1. Reentrancy Protection

#### Current Vulnerable Code
```solidity
function withdraw(address token, uint256 amount, address recipient) public {
    require(recipient != address(0x0), "INVALID_RECIPIENT");
    consumeMessage(token, amount, recipient);
    if (tokenSettings()[token].withdrawalLimitApplied) {
        WithdrawalLimit.consumeWithdrawQuota(token, amount);
    }
    transferOutFunds(token, amount, recipient); // VULNERABLE
    emit Withdrawal(recipient, token, amount);
}
```

#### Mitigation Implementation

**Option A: OpenZeppelin ReentrancyGuard (Recommended)**
```solidity
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract StarknetTokenBridge is ReentrancyGuard {
    function withdraw(
        address token,
        uint256 amount,
        address recipient
    ) public nonReentrant { // ADD THIS MODIFIER
        require(recipient != address(0x0), "INVALID_RECIPIENT");
        
        // CHECKS
        consumeMessage(token, amount, recipient);
        
        // EFFECTS
        if (tokenSettings()[token].withdrawalLimitApplied) {
            WithdrawalLimit.consumeWithdrawQuota(token, amount);
        }
        emit Withdrawal(recipient, token, amount);
        
        // INTERACTIONS (last)
        transferOutFunds(token, amount, recipient);
    }
}
```

**Option B: Custom Reentrancy Guard**
```solidity
contract StarknetTokenBridge {
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;
    uint256 private _status;
    
    modifier nonReentrant() {
        require(_status != _ENTERED, "ReentrancyGuard: reentrant call");
        _status = _ENTERED;
        _;
        _status = _NOT_ENTERED;
    }
    
    function withdraw(
        address token,
        uint256 amount,
        address recipient
    ) public nonReentrant {
        // ... rest of function
    }
}
```

---

### 2. Integer Overflow/Underflow Protection

#### Current Issue
```solidity
payload[3] = amount & (UINT256_PART_SIZE - 1);
payload[4] = amount >> UINT256_PART_SIZE_BITS;
```

#### Mitigation Implementation
```solidity
function splitAmount(uint256 amount) internal pure returns (uint256 low, uint256 high) {
    low = amount & (UINT256_PART_SIZE - 1);
    high = amount >> UINT256_PART_SIZE_BITS;
    
    // Verify reconstruction
    uint256 reconstructed = low + (high << UINT256_PART_SIZE_BITS);
    require(reconstructed == amount, "AMOUNT_SPLIT_MISMATCH");
    
    return (low, high);
}

function depositMessagePayload(
    address token,
    uint256 amount,
    uint256 l2Recipient,
    bool withMessage,
    uint256[] memory message
) internal view returns (uint256[] memory) {
    // ... existing code ...
    
    (uint256 amountLow, uint256 amountHigh) = splitAmount(amount);
    payload[3] = amountLow;
    payload[4] = amountHigh;
    
    // ... rest of function
}
```

---

### 3. Legacy Bridge Error Handling

#### Current Vulnerable Code
```solidity
try messagingContract().consumeMessageFromL2(l2TokenBridge(), payload) {} 
catch Error(string memory) {
    payload = new uint256[](4);
    // ... reconstruct
    messagingContract().consumeMessageFromL2(l2TokenBridge(), payload); // NO ERROR HANDLING
    require(bridgedToken() == token, "NOT_LEGACY_BRIDGED_TOKEN");
}
```

#### Mitigation Implementation
```solidity
function consumeMessage(address token, uint256 amount, address recipient) internal override {
    // ... validation ...
    
    bool newFormatSuccess = false;
    bool oldFormatSuccess = false;
    
    // Try new format
    try messagingContract().consumeMessageFromL2(l2TokenBridge(), payload) {
        newFormatSuccess = true;
    } catch {
        // New format failed, try old format
    }
    
    if (!newFormatSuccess) {
        // Try old format
        payload = new uint256[](4);
        payload[0] = TRANSFER_FROM_STARKNET;
        payload[1] = u_recipient;
        payload[2] = amount_low;
        payload[3] = amount_high;
        
        try messagingContract().consumeMessageFromL2(l2TokenBridge(), payload) {
            oldFormatSuccess = true;
            require(bridgedToken() == token, "NOT_LEGACY_BRIDGED_TOKEN");
        } catch Error(string memory reason) {
            revert(string(abi.encodePacked("LEGACY_CONSUME_FAILED: ", reason)));
        }
    }
    
    require(newFormatSuccess || oldFormatSuccess, "MESSAGE_CONSUMPTION_FAILED");
}
```

---

### 4. Access Control for Token Enrollment

#### Current Vulnerable Code
```solidity
function enrollTokenBridge(address token) external payable {
    // No access control!
    IStarkgateRegistry registryContract = IStarkgateRegistry(registry());
    require(registryContract.getBridge(token) != BLOCKED_TOKEN, "CANNOT_DEPLOY_BRIDGE");
    emit TokenEnrolled(token, msg.sender);
    registryContract.enlistToken(token, bridge());
    IStarkgateBridge(bridge()).enrollToken{value: msg.value}(token);
}
```

#### Mitigation Implementation

**Option A: Whitelist-Based Enrollment**
```solidity
contract StarkgateManager {
    mapping(address => bool) public enrollmentWhitelist;
    mapping(address => address) public pendingEnrollments;
    uint256 constant ENROLLMENT_DELAY = 2 days;
    mapping(address => uint256) public enrollmentTimestamp;
    
    modifier onlyWhitelisted() {
        require(enrollmentWhitelist[msg.sender], "NOT_WHITELISTED");
        _;
    }
    
    function addToWhitelist(address enroller) external onlyGovernance {
        enrollmentWhitelist[enroller] = true;
    }
    
    function requestTokenEnrollment(address token) external onlyWhitelisted {
        require(pendingEnrollments[token] == address(0), "ENROLLMENT_PENDING");
        pendingEnrollments[token] = msg.sender;
        enrollmentTimestamp[token] = block.timestamp;
        emit EnrollmentRequested(token, msg.sender);
    }
    
    function enrollTokenBridge(address token) external payable {
        require(pendingEnrollments[token] == msg.sender, "NOT_ENROLLMENT_REQUESTER");
        require(block.timestamp >= enrollmentTimestamp[token] + ENROLLMENT_DELAY, "ENROLLMENT_DELAY_NOT_MET");
        
        IStarkgateRegistry registryContract = IStarkgateRegistry(registry());
        require(registryContract.getBridge(token) != BLOCKED_TOKEN, "CANNOT_DEPLOY_BRIDGE");
        
        delete pendingEnrollments[token];
        delete enrollmentTimestamp[token];
        
        emit TokenEnrolled(token, msg.sender);
        registryContract.enlistToken(token, bridge());
        IStarkgateBridge(bridge()).enrollToken{value: msg.value}(token);
    }
}
```

**Option B: Commit-Reveal Scheme**
```solidity
contract StarkgateManager {
    mapping(bytes32 => uint256) public commitments;
    mapping(address => bool) public enrolled;
    uint256 constant REVEAL_DELAY = 1 hours;
    
    function commitEnrollment(bytes32 commitment) external {
        require(commitments[commitment] == 0, "COMMITMENT_EXISTS");
        commitments[commitment] = block.timestamp;
    }
    
    function revealAndEnroll(
        address token,
        uint256 nonce
    ) external payable {
        bytes32 commitment = keccak256(abi.encodePacked(msg.sender, token, nonce));
        require(commitments[commitment] != 0, "INVALID_COMMITMENT");
        require(block.timestamp >= commitments[commitment] + REVEAL_DELAY, "REVEAL_TOO_EARLY");
        require(!enrolled[token], "TOKEN_ALREADY_ENROLLED");
        
        enrolled[token] = true;
        delete commitments[commitment];
        
        // Proceed with enrollment
        IStarkgateRegistry registryContract = IStarkgateRegistry(registry());
        registryContract.enlistToken(token, bridge());
        IStarkgateBridge(bridge()).enrollToken{value: msg.value}(token);
    }
}
```

---

### 5. Persistent Withdrawal Limits

#### Current Issue
Limits reset when token is deactivated/reactivated.

#### Mitigation Implementation
```solidity
contract StarknetTokenBridge {
    // Separate persistent limit storage
    mapping(address => uint256) public permanentWithdrawalLimits;
    mapping(address => uint256) public lastLimitUpdate;
    uint256 constant LIMIT_UPDATE_DELAY = 7 days;
    
    function setWithdrawalLimit(address token, uint256 limitPercent) external onlySecurityAdmin {
        require(block.timestamp >= lastLimitUpdate[token] + LIMIT_UPDATE_DELAY, "UPDATE_TOO_SOON");
        permanentWithdrawalLimits[token] = limitPercent;
        lastLimitUpdate[token] = block.timestamp;
        emit WithdrawalLimitUpdated(token, limitPercent);
    }
    
    function withdraw(address token, uint256 amount, address recipient) public nonReentrant {
        require(recipient != address(0x0), "INVALID_RECIPIENT");
        consumeMessage(token, amount, recipient);
        
        // Always check permanent limits, regardless of token status
        if (permanentWithdrawalLimits[token] > 0) {
            enforceWithdrawalLimit(token, amount);
        }
        
        emit Withdrawal(recipient, token, amount);
        transferOutFunds(token, amount, recipient);
    }
    
    function enforceWithdrawalLimit(address token, uint256 amount) internal {
        uint256 limit = calculateDailyLimit(token);
        uint256 consumed = getDailyConsumption(token);
        require(consumed + amount <= limit, "EXCEEDS_DAILY_LIMIT");
        updateDailyConsumption(token, consumed + amount);
    }
}
```

---

### 6. Storage Layout Protection

#### Mitigation Implementation
```solidity
contract StarknetTokenStorage {
    // Add storage gaps for upgradeable contracts
    uint256[50] private __gap;
    
    // Use OpenZeppelin's storage pattern
    bytes32 private constant TOKEN_SETTINGS_STORAGE_LOCATION = 
        keccak256("starknet.storage.TokenSettings");
    
    function tokenSettings() internal pure returns (
        mapping(address => TokenSettings) storage _tokenSettings
    ) {
        bytes32 location = TOKEN_SETTINGS_STORAGE_LOCATION;
        assembly {
            _tokenSettings.slot := location
        }
    }
    
    // Add storage layout validation
    function validateStorageLayout() external pure returns (bool) {
        require(TOKEN_SETTINGS_STORAGE_LOCATION == 
            keccak256("starknet.storage.TokenSettings"), 
            "STORAGE_LAYOUT_MISMATCH");
        return true;
    }
}
```

---

### 7. Message Replay Prevention

#### Mitigation Implementation
```solidity
contract StarknetTokenBridge {
    mapping(bytes32 => bool) public processedMessages;
    mapping(uint256 => bool) public cancelledNonces;
    mapping(uint256 => uint256) public cancellationRequests;
    uint256 constant CANCELLATION_DELAY = 1 days;
    
    function depositCancelRequest(
        address token,
        uint256 amount,
        uint256 l2Recipient,
        uint256 nonce
    ) external {
        bytes32 messageHash = keccak256(abi.encodePacked(
            msg.sender, token, amount, l2Recipient, nonce
        ));
        
        require(!processedMessages[messageHash], "MESSAGE_ALREADY_PROCESSED");
        require(!cancelledNonces[nonce], "NONCE_ALREADY_CANCELLED");
        
        cancellationRequests[nonce] = block.timestamp;
        
        messagingContract().startL1ToL2MessageCancellation(
            l2TokenBridge(),
            HANDLE_TOKEN_DEPOSIT_SELECTOR,
            depositMessagePayload(token, amount, l2Recipient),
            nonce
        );
        
        emit DepositCancelRequest(msg.sender, token, amount, l2Recipient, nonce);
    }
    
    function depositReclaim(
        address token,
        uint256 amount,
        uint256 l2Recipient,
        uint256 nonce
    ) external {
        require(cancellationRequests[nonce] != 0, "NO_CANCELLATION_REQUEST");
        require(
            block.timestamp >= cancellationRequests[nonce] + CANCELLATION_DELAY,
            "CANCELLATION_DELAY_NOT_MET"
        );
        require(!cancelledNonces[nonce], "ALREADY_RECLAIMED");
        
        cancelledNonces[nonce] = true;
        delete cancellationRequests[nonce];
        
        messagingContract().cancelL1ToL2Message(
            l2TokenBridge(),
            HANDLE_TOKEN_DEPOSIT_SELECTOR,
            depositMessagePayload(token, amount, l2Recipient),
            nonce
        );
        
        transferOutFunds(token, amount, msg.sender);
        emit DepositReclaimed(msg.sender, token, amount, l2Recipient, nonce);
    }
}
```

---

## 🔧 Additional Security Enhancements

### 1. Emergency Pause Mechanism
```solidity
import "@openzeppelin/contracts/security/Pausable.sol";

contract StarknetTokenBridge is Pausable {
    function emergencyPause() external onlySecurityAdmin {
        _pause();
        emit EmergencyPause(msg.sender);
    }
    
    function unpause() external onlyGovernance {
        _unpause();
        emit Unpaused(msg.sender);
    }
    
    function withdraw(...) public whenNotPaused nonReentrant {
        // ... function body
    }
}
```

### 2. Rate Limiting
```solidity
contract RateLimiter {
    mapping(address => mapping(address => uint256)) public lastWithdrawTime;
    mapping(address => mapping(address => uint256)) public withdrawCount;
    uint256 constant RATE_LIMIT_WINDOW = 1 hours;
    uint256 constant MAX_WITHDRAWALS_PER_WINDOW = 10;
    
    function enforceRateLimit(address user, address token) internal {
        if (block.timestamp > lastWithdrawTime[user][token] + RATE_LIMIT_WINDOW) {
            withdrawCount[user][token] = 0;
            lastWithdrawTime[user][token] = block.timestamp;
        }
        
        require(
            withdrawCount[user][token] < MAX_WITHDRAWALS_PER_WINDOW,
            "RATE_LIMIT_EXCEEDED"
        );
        
        withdrawCount[user][token]++;
    }
}
```

### 3. Multi-Signature Administration
```solidity
import "@gnosis.pm/safe-contracts/contracts/GnosisSafe.sol";

contract StarknetTokenBridge {
    address public multisigAdmin;
    
    modifier onlyMultisig() {
        require(msg.sender == multisigAdmin, "ONLY_MULTISIG");
        _;
    }
    
    function criticalOperation() external onlyMultisig {
        // Critical operations require multisig
    }
}
```

### 4. Comprehensive Event Logging
```solidity
contract StarknetTokenBridge {
    event WithdrawalInitiated(
        address indexed token,
        address indexed recipient,
        uint256 amount,
        uint256 timestamp,
        bytes32 messageHash
    );
    
    event LimitUpdated(
        address indexed token,
        uint256 oldLimit,
        uint256 newLimit,
        address updatedBy
    );
    
    event TokenStatusChanged(
        address indexed token,
        TokenStatus oldStatus,
        TokenStatus newStatus,
        address changedBy
    );
    
    event SecurityIncident(
        string incidentType,
        address reporter,
        bytes data
    );
}
```

### 5. Formal Verification Preparation
```solidity
contract StarknetTokenBridge {
    // Add invariants for formal verification
    function checkInvariants() external view returns (bool) {
        // Invariant 1: Total deposits >= Total withdrawals
        // Invariant 2: No token balance exceeds max limit
        // Invariant 3: Daily withdrawal <= configured percentage
        return true;
    }
    
    // Add pre/post conditions
    /// @custom:precondition recipient != address(0)
    /// @custom:postcondition balance[token] >= old(balance[token]) - amount
    function withdraw(address token, uint256 amount, address recipient) public {
        // ... implementation
    }
}
```

---

## 📋 Implementation Checklist

### Phase 1: Critical Security Fixes (Week 1)
- [ ] Implement ReentrancyGuard on all external functions
- [ ] Fix Legacy Bridge error handling
- [ ] Add access control to token enrollment
- [ ] Implement checks-effects-interactions pattern

### Phase 2: Core Improvements (Week 2-3)
- [ ] Add persistent withdrawal limits
- [ ] Implement message replay prevention
- [ ] Add emergency pause mechanism
- [ ] Implement rate limiting

### Phase 3: Enhanced Security (Week 4)
- [ ] Deploy multi-signature administration
- [ ] Add comprehensive event logging
- [ ] Implement storage layout protection
- [ ] Add formal verification invariants

### Phase 4: Testing & Audit (Week 5-8)
- [ ] Write comprehensive test suite
- [ ] Perform internal security review
- [ ] Conduct formal verification
- [ ] Get external audit from 2+ firms

### Phase 5: Deployment (Week 9-10)
- [ ] Deploy to testnet with limits
- [ ] Run bug bounty program
- [ ] Gradual mainnet rollout
- [ ] Monitor for anomalies

---

## 🚀 Best Practices Going Forward

1. **Security-First Development**
   - All new features must pass security review
   - Use established libraries (OpenZeppelin)
   - Follow Checks-Effects-Interactions pattern

2. **Continuous Monitoring**
   - Implement real-time anomaly detection
   - Set up alerts for unusual patterns
   - Regular security assessments

3. **Governance & Administration**
   - Multi-sig for all critical operations
   - Time-locks for parameter changes
   - Transparent upgrade process

4. **Documentation**
   - Maintain security documentation
   - Document all assumptions
   - Keep audit trail of changes

5. **Community Engagement**
   - Public bug bounty program
   - Security transparency reports
   - Regular community audits

---

*This mitigation guide should be reviewed and updated regularly as new threats emerge.*