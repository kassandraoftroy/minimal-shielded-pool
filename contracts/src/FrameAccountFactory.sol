// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {FrameAccount} from "./FrameAccount.sol";

/// @notice CREATE2 factory for [`FrameAccount`]. Permissionless; no-ops if the
/// account is already deployed (4337 initCode pattern).
contract FrameAccountFactory {
    address public immutable pool;

    error CreateFailed();

    constructor(address pool_) {
        pool = pool_;
    }

    function getAddress(address owner, bytes32 salt) public view returns (address) {
        bytes32 h = keccak256(abi.encodePacked(bytes1(0xff), address(this), salt, keccak256(_initCode(owner))));
        return address(uint160(uint256(h)));
    }

    function createAccount(address owner, bytes32 salt) external returns (address account) {
        account = getAddress(owner, salt);
        if (account.code.length != 0) return account;
        bytes memory code = _initCode(owner);
        assembly {
            account := create2(0, add(code, 0x20), mload(code), salt)
        }
        if (account == address(0)) revert CreateFailed();
    }

    function _initCode(address owner) internal view returns (bytes memory) {
        return abi.encodePacked(type(FrameAccount).creationCode, abi.encode(owner, pool));
    }
}
