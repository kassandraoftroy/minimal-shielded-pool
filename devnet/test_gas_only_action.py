#!/usr/bin/env python3
"""Focused builder and option vectors for a generic DEFAULT tail."""
import contextlib
import io
import json

from eth_keys import keys

import pool_frametx as builder
from pool_frametx import (
    EIP7825_TX_GAS_CAP,
    ETHEX_MEMPOOL_MAX_BYTES,
    RECENT_ROOT_ADDRESS,
    RECENT_ROOT_FRAME_GAS,
    SETTLE_FRAME_GAS,
    SETTLE_FRAME_STATE_GAS,
    SPEND_TUPLE,
    VERIFY_FRAME_GAS,
    VERIFY_FRAME_STATE_GAS,
    _keccak,
    action_options,
    check_tx_resource_limits,
    spend_tail_frame,
)
from frametx import Frame, FrameSig, FrameTx


POOL = 0xBEEF
ACCOUNT = 0xA11CE
ACTION_GAS = 300_000


def settlement(public_amount=0, recipient=0):
    words = [1, 1, 0, 2, 3, 4, 5, 6, public_amount, 7, recipient, 8]
    selector = _keccak(f"settle({SPEND_TUPLE})".encode())[:4]
    return selector + b"".join(word.to_bytes(32, "big") for word in words)


def _spend_tx(tail):
    return FrameTx(
        chain_id=1, nonce_keys=[3, 4], nonce_seq=0, sender=POOL,
        frames=[
            Frame(1, 0, int(RECENT_ROOT_ADDRESS, 16), RECENT_ROOT_FRAME_GAS, 0, b"\x00" * 72),
            Frame(1, 3, POOL, VERIFY_FRAME_GAS, 0, b"\x00" * 256,
                  state_limit=VERIFY_FRAME_STATE_GAS),
            Frame(2, 0, POOL, SETTLE_FRAME_GAS, 0, settlement(),
                  state_limit=SETTLE_FRAME_STATE_GAS),
            tail,
        ],
        signatures=[FrameSig(1, ACCOUNT, b"", b"\x00" * 65)],
        max_priority_fee=1, max_fee=10,
    )


def rejects(fn, text=None):
    try:
        fn()
    except ValueError as error:
        if text is not None:
            assert text in str(error), (text, str(error))
        return 1
    raise AssertionError("expected ValueError")


def exits(fn, text):
    try:
        fn()
    except SystemExit as error:
        assert text in str(error), (text, str(error))
        return 1
    raise AssertionError("expected SystemExit")


def run_broadcast_case(simulation, receipt, action, rpc_calls, allow_failed_claim=False,
                       calldata=None):
    """Run the real send path against fixed RPC/simulation responses."""
    def fake_rpc(_url, method, _params):
        rpc_calls.append(method)
        if method == "eth_chainId":
            return "0x1"
        if method == "eth_getTransactionCount":
            return "0x0"
        if method == "eth_getBlockByNumber":
            return {"baseFeePerGas": "0x1"}
        if method == "eth_sendRawTransaction":
            return "0x" + "12" * 32
        if method == "eth_getTransactionReceipt":
            return receipt
        raise AssertionError(method)

    old_rpc, old_simulate, old_sleep = builder.rpc, builder.simulate, builder.time.sleep
    builder.rpc = fake_rpc
    builder.simulate = lambda _url, _raw: simulation
    builder.time.sleep = lambda _seconds: None
    private_key = keys.PrivateKey((1).to_bytes(32, "big"))
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            builder.build_and_send(
                "http://unused", private_key, POOL, 0, calldata or settlement(),
                protocol_nonces=[3, 4], proof_verify=True,
                recent_root=b"\x00" * 72, sender_override=POOL,
                max_fee_override=10, max_priority_override=1,
                frame0_data=b"\x00" * 256, allow_failed_claim=allow_failed_claim,
                action=action,
            )
    finally:
        builder.rpc, builder.simulate, builder.time.sleep = old_rpc, old_simulate, old_sleep


def main():
    checked = 0
    assert action_options([]) is None
    checked += 1

    argv = [
        "--action-target", hex(ACCOUNT),
        "--action-call", "0x",
        "--action-gas", str(ACTION_GAS),
        "--action-state-gas", "0",
    ]
    action = action_options(argv)
    assert action == {
        "target": ACCOUNT,
        "data": b"",
        "gas_limit": ACTION_GAS,
        "state_limit": 0,
    }
    frame = spend_tail_frame(POOL, settlement(), action)
    assert (frame.mode, frame.flags, frame.target, frame.gas_limit, frame.value,
            frame.data, frame.state_limit) == (
                0, 0, ACCOUNT, ACTION_GAS, 0, b"", 0)
    checked += 2

    assert spend_tail_frame(POOL, settlement()) is None
    checked += 1

    withdrawal = settlement(public_amount=1, recipient=ACCOUNT)
    claim = spend_tail_frame(POOL, withdrawal)
    assert claim.target == POOL and claim.mode == 0 and claim.flags == 0 and claim.value == 0
    assert len(claim.data) == 36
    checked += 1
    assert spend_tail_frame(POOL, withdrawal, omit=True) is None
    checked += 1
    checked += rejects(
        lambda: spend_tail_frame(POOL, withdrawal, action, omit=True), "omit cannot")
    custom = spend_tail_frame(POOL, withdrawal, action)
    assert custom.target == ACCOUNT and custom.gas_limit == ACTION_GAS
    checked += 1
    pool_claim_action = dict(action, target=POOL, data=claim.data,
                             gas_limit=100_000, state_limit=183_600)
    asserted = spend_tail_frame(POOL, withdrawal, pool_claim_action)
    assert asserted.target == POOL and asserted.data == claim.data
    checked += 1

    flags = ["--action-target", "--action-call", "--action-gas", "--action-state-gas"]
    pairs = dict(zip(flags, [hex(ACCOUNT), "0x00", "1", "0"]))
    for omitted in flags:
        partial = []
        for flag in flags:
            if flag != omitted:
                partial.extend((flag, pairs[flag]))
        checked += rejects(lambda args=partial: action_options(args), omitted)
    checked += rejects(lambda: action_options(argv + ["--action-gas", "1"]), "exactly once")
    checked += rejects(lambda: action_options(["--action-gaas", "1"]), "unknown")
    checked += rejects(lambda: action_options([
        "--action-target", hex(ACCOUNT), "--action-call", "0x0",
        "--action-gas", "1", "--action-state-gas", "0",
    ]), "invalid --action-call")
    checked += rejects(lambda: action_options([
        "--action-target", hex(ACCOUNT), "--action-call", "0xgg",
        "--action-gas", "1", "--action-state-gas", "0",
    ]), "invalid --action-call")

    invalid_actions = [
        (dict(action, target=0), "nonzero"),
        (dict(action, target=POOL), "nonzero non-pool"),
        (dict(action, target=1 << 160), "nonzero"),
        (dict(action, data="0x00"), "calldata must be bytes"),
        (dict(action, gas_limit=0), "execution gas"),
        (dict(action, state_limit=-1), "state gas"),
    ]
    for candidate, message in invalid_actions:
        checked += rejects(lambda a=candidate: spend_tail_frame(POOL, settlement(), a), message)
    checked += rejects(
        lambda: spend_tail_frame(POOL, settlement(), {"target": ACCOUNT}), "requires target")
    checked += rejects(
        lambda: spend_tail_frame(POOL, settlement(public_amount=1, recipient=0)), "both be zero")
    checked += rejects(
        lambda: spend_tail_frame(POOL, settlement(public_amount=0, recipient=ACCOUNT)), "both be zero")
    checked += rejects(lambda: spend_tail_frame(POOL, settlement()[:-1], action), "canonical")

    modest = spend_tail_frame(POOL, settlement(), action)
    check_tx_resource_limits(_spend_tx(modest))
    checked += 1
    huge_exec = dict(action, gas_limit=EIP7825_TX_GAS_CAP)
    checked += rejects(
        lambda: check_tx_resource_limits(_spend_tx(spend_tail_frame(POOL, settlement(), huge_exec))),
        "EIP-7825")
    huge_data = dict(action, data=b"\xff" * (ETHEX_MEMPOOL_MAX_BYTES + 1))
    checked += rejects(
        lambda: check_tx_resource_limits(_spend_tx(spend_tail_frame(POOL, settlement(), huge_data))),
        "mempool")


    settled_then_action_failed = {
        "valid": False,
        "violation": "frame 3 reverted",
        "frames": [
            {"succeeded": True}, {"succeeded": True},
            {"succeeded": True}, {"succeeded": False},
        ],
    }
    simulation_calls = []

    def simulation_failure():
        run_broadcast_case(
            settled_then_action_failed, None, action, simulation_calls,
            allow_failed_claim=True)

    checked += exits(simulation_failure, "gas-only action frame would fail")
    assert "eth_sendRawTransaction" not in simulation_calls
    checked += 1

    successful_simulation = {
        "valid": True,
        "executionStatus": "success",
        "frames": [{"succeeded": True} for _ in range(4)],
    }
    failed_action_receipt = {
        "blockNumber": "0x2", "type": "0x6", "status": "0x0", "gasUsed": "0x100",
        "frameReceipts": [
            {"status": "0x1"}, {"status": "0x1"},
            {"status": "0x1"}, {"status": "0x0"},
        ],
    }
    mined_calls = []

    def mined_action_failure():
        run_broadcast_case(successful_simulation, failed_action_receipt, action, mined_calls)

    checked += exits(mined_action_failure, "notes were consumed")
    assert mined_calls.count("eth_sendRawTransaction") == 1
    checked += 1

    missing_action_receipt = {
        "blockNumber": "0x3", "type": "0x6", "status": "0x1", "gasUsed": "0x100",
        "frameReceipts": [
            {"status": "0x1"}, {"status": "0x1"}, {"status": "0x1"},
        ],
    }
    missing_calls = []

    def missing_outcome():
        run_broadcast_case(successful_simulation, missing_action_receipt, action, missing_calls)

    checked += exits(missing_outcome, "gas-only action outcome is unknown")
    assert missing_calls.count("eth_sendRawTransaction") == 1
    checked += 1

    print(json.dumps({
        "checked_cases": checked,
        "default_transfer_frames_added": 0,
        "gas_only_action_frames_added": 1,
        "withdrawal_default_claim": True,
        "withdrawal_custom_action": True,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
