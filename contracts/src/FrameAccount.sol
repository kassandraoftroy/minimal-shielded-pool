// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @notice Minimal 4337-shaped account for FrameTx tails. `executeBatch` is
/// callable by the owner or by the shielded pool (the FrameTx sender).
contract FrameAccount {
    address public immutable owner;
    address public immutable pool;

    struct Call {
        address target;
        uint256 value;
        bytes data;
    }

    error NotAuthorized();
    error CallFailed(uint256 index);

    constructor(address owner_, address pool_) {
        owner = owner_;
        pool = pool_;
    }

    receive() external payable {}

    function executeBatch(Call[] calldata calls) external {
        if (msg.sender != owner && msg.sender != pool) revert NotAuthorized();
        for (uint256 i = 0; i < calls.length; i++) {
            (bool ok,) = calls[i].target.call{value: calls[i].value}(calls[i].data);
            if (!ok) revert CallFailed(i);
        }
    }
}
