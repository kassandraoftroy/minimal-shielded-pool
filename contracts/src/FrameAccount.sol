// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @notice Minimal account for FrameTx tails. The owner may call
/// [`executeBatch`] directly. Any other caller — including the shielded pool
/// as FrameTx sender — must supply the owner's ECDSA signature over
/// `(chainId, this, nonce, calls)`. The pool is not a privileged executor:
/// a later spend could otherwise target this account in its execute frame.
contract FrameAccount {
    address public immutable owner;
    address public immutable pool;
    uint256 public nonce;

    struct Call {
        address target;
        uint256 value;
        bytes data;
    }

    error NotAuthorized();
    error BadSignature();
    error CallFailed(uint256 index);

    constructor(address owner_, address pool_) {
        owner = owner_;
        pool = pool_;
    }

    receive() external payable {}

    /// @notice EIP-191 digest the owner signs for `calls` at the current nonce.
    function executeDigest(Call[] calldata calls) public view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n32",
                keccak256(abi.encode(block.chainid, address(this), nonce, calls))
            )
        );
    }

    function executeBatch(Call[] calldata calls, bytes calldata signature) external {
        if (msg.sender != owner) {
            if (_recover(executeDigest(calls), signature) != owner) revert NotAuthorized();
        }
        nonce++;
        for (uint256 i = 0; i < calls.length; i++) {
            (bool ok,) = calls[i].target.call{value: calls[i].value}(calls[i].data);
            if (!ok) revert CallFailed(i);
        }
    }

    function _recover(bytes32 digest, bytes calldata signature) internal pure returns (address) {
        if (signature.length != 65) revert BadSignature();
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        if (v < 27) v += 27;
        if (
            uint256(s)
                > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
        ) revert BadSignature();
        address recovered = ecrecover(digest, v, r, s);
        if (recovered == address(0)) revert BadSignature();
        return recovered;
    }
}
