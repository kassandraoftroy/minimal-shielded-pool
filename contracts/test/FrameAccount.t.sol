// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {FrameAccount} from "../src/FrameAccount.sol";
import {FrameAccountFactory} from "../src/FrameAccountFactory.sol";
import {ShieldedPoolLogic} from "../src/ShieldedPoolLogic.sol";

interface Vm {
    function deal(address, uint256) external;
    function expectRevert(bytes4) external;
    function addr(uint256) external returns (address);
    function prank(address) external;
    function startPrank(address) external;
    function stopPrank() external;
    function store(address, bytes32, bytes32) external;
    function sign(uint256 privateKey, bytes32 digest) external pure returns (uint8 v, bytes32 r, bytes32 s);
}

contract MockPoseidonT3 {
    uint256 constant P = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    function hash2(uint256 x0, uint256 x1) external pure returns (uint256) {
        return uint256(keccak256(abi.encode(x0, x1))) % P;
    }
}

contract MockPoseidonT4 {
    uint256 constant P = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    function hash3(uint256 x0, uint256 x1, uint256 x2) external pure returns (uint256) {
        return uint256(keccak256(abi.encode(x0, x1, x2))) % P;
    }
}

contract LogicProxy {
    address immutable implementation;

    constructor(address implementation_) {
        implementation = implementation_;
    }

    fallback() external payable {
        address target = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), target, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch ok
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    receive() external payable {}
}

contract Target {
    uint256 public hits;

    function ping() external payable {
        hits++;
    }
}

contract FrameAccountTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function _sig(uint256 pk, FrameAccount account, FrameAccount.Call[] memory calls)
        internal
        view
        returns (bytes memory)
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, account.executeDigest(calls));
        return abi.encodePacked(r, s, v);
    }

    function testFactoryCreateAndExecute() public {
        address pool = address(0xBEEF);
        FrameAccountFactory factory = new FrameAccountFactory(pool);
        uint256 ownerPk = 1;
        address owner = vm.addr(ownerPk);
        bytes32 salt = bytes32(uint256(7));
        address predicted = factory.getAddress(owner, salt);
        address created = factory.createAccount(owner, salt);
        require(created == predicted, "predict");
        require(factory.createAccount(owner, salt) == created, "idempotent");

        Target t = new Target();
        FrameAccount.Call[] memory calls = new FrameAccount.Call[](1);
        calls[0] = FrameAccount.Call({target: address(t), value: 0, data: abi.encodeCall(Target.ping, ())});
        FrameAccount account = FrameAccount(payable(created));

        vm.prank(owner);
        account.executeBatch(calls, "");
        require(t.hits() == 1, "owner");
        require(account.nonce() == 1, "nonce");

        bytes memory sig = _sig(ownerPk, account, calls);
        vm.prank(pool);
        account.executeBatch(calls, sig);
        require(t.hits() == 2, "pool+sig");
        require(account.nonce() == 2, "nonce2");

        vm.prank(pool);
        vm.expectRevert(FrameAccount.NotAuthorized.selector);
        account.executeBatch(calls, sig);

        vm.expectRevert(FrameAccount.BadSignature.selector);
        account.executeBatch(calls, "");
    }

    function testPoolCannotExecuteWithoutOwnerSignature() public {
        address pool = address(0xBEEF);
        FrameAccountFactory factory = new FrameAccountFactory(pool);
        address owner = vm.addr(1);
        address created = factory.createAccount(owner, bytes32(uint256(1)));
        FrameAccount.Call[] memory calls = new FrameAccount.Call[](0);

        vm.prank(pool);
        vm.expectRevert(FrameAccount.BadSignature.selector);
        FrameAccount(payable(created)).executeBatch(calls, "");

        bytes memory other = _sig(2, FrameAccount(payable(created)), calls);
        vm.prank(pool);
        vm.expectRevert(FrameAccount.NotAuthorized.selector);
        FrameAccount(payable(created)).executeBatch(calls, other);
    }

    function testEnsureAndClaimZeroRecipientIsNoop() public {
        ShieldedPoolLogic logic = new ShieldedPoolLogic(address(new MockPoseidonT3()), address(new MockPoseidonT4()));
        LogicProxy proxy = new LogicProxy(address(logic));
        ShieldedPoolLogic(address(proxy)).ensureAndClaim(address(0), address(0), bytes32(0), payable(address(0)));
    }

    function testEnsureAndClaimDeploysAndPays() public {
        ShieldedPoolLogic logic = new ShieldedPoolLogic(address(new MockPoseidonT3()), address(new MockPoseidonT4()));
        LogicProxy proxy = new LogicProxy(address(logic));
        FrameAccountFactory factory = new FrameAccountFactory(address(proxy));
        address owner = vm.addr(2);
        bytes32 salt = bytes32(uint256(9));
        address who = factory.getAddress(owner, salt);

        vm.store(
            address(proxy),
            keccak256(abi.encode(who, uint256(24))),
            bytes32(uint256(1 ether))
        );
        vm.deal(address(proxy), 1 ether);

        ShieldedPoolLogic(address(proxy)).ensureAndClaim(address(factory), owner, salt, payable(who));
        require(who.code.length > 0, "deployed");
        require(who.balance == 1 ether, "paid");
        require(ShieldedPoolLogic(address(proxy)).withdrawalCredit(who) == 0, "cleared");
    }
}
