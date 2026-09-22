#!/usr/bin/env python3
"""Executable complete-intent binding vector for the one-time authorizer."""
import copy
import json
from pathlib import Path

from eth_hash.auto import keccak
from eth_keys import keys

from frametx import Frame, FrameSig, FrameTx
from pool_frametx import (
    CLAIM_FRAME_GAS,
    CLAIM_FRAME_STATE_GAS,
    RECENT_ROOT_ADDRESS,
    RECENT_ROOT_FRAME_GAS,
    SETTLE_FRAME_GAS,
    SETTLE_FRAME_STATE_GAS,
    SPEND_TUPLE,
    VERIFY_FRAME_GAS,
    VERIFY_FRAME_STATE_GAS,
    cast_calldata,
    proof_bytes,
    spend_args,
    spend_tail_frame,
)

HERE = Path(__file__).parent
FIXTURE = HERE.parent / "wallet" / "smoke_fixture.json"


def root_tuple(source, slot, root):
    return source + slot.to_bytes(8, "big") + root


def _signed(entry_key, action=None, *, omit=False):
    fixture = json.loads(FIXTURE.read_text())
    entry = copy.deepcopy(fixture[entry_key])
    entry["root_slot"] = "1"
    pool = int(fixture["pool_address"], 16)
    epoch = int(entry["epoch"])
    source = keccak(pool.to_bytes(20, "big") + epoch.to_bytes(32, "big"))
    root = bytes.fromhex(entry["root"][2:])
    settle = cast_calldata(f"settle({SPEND_TUPLE})", spend_args(entry))
    authorizer = int(entry["authorizer"], 16)
    pk = keys.PrivateKey(bytes.fromhex(entry["authorizer_private_key"][2:]))
    frames = [
        Frame(1, 0, int(RECENT_ROOT_ADDRESS, 16), RECENT_ROOT_FRAME_GAS, 0,
              root_tuple(source, 1, root)),
        Frame(1, 3, pool, VERIFY_FRAME_GAS, 0, proof_bytes(entry),
              state_limit=VERIFY_FRAME_STATE_GAS),
        Frame(2, 0, pool, SETTLE_FRAME_GAS, 0, settle,
              state_limit=SETTLE_FRAME_STATE_GAS),
    ]
    tail = spend_tail_frame(pool, settle, action, omit=omit)
    if tail is not None:
        frames.append(tail)
    tx = FrameTx(
        chain_id=int(fixture["chain_id"]),
        nonce_keys=sorted([int(entry["nf1"], 16), int(entry["nf2"], 16)]),
        nonce_seq=0,
        sender=pool,
        frames=frames,
        signatures=[FrameSig(FrameSig.SECP256K1, authorizer, b"", b"")],
        max_priority_fee=1,
        max_fee=10,
    )
    sig = pk.sign_msg_hash(tx.sig_hash())
    encoded = bytes([sig.v]) + sig.r.to_bytes(32, "big") + sig.s.to_bytes(32, "big")
    tx.signatures[0].signature = encoded
    assert sig.recover_public_key_from_msg_hash(tx.sig_hash()).to_canonical_address() == authorizer.to_bytes(20, "big")
    return tx, authorizer


def common_mutations(tx):
    mutations = []

    def add(name, fn):
        candidate = copy.deepcopy(tx)
        fn(candidate)
        mutations.append((name, candidate))

    add("chain_id", lambda x: setattr(x, "chain_id", x.chain_id + 1))
    add("nonce_key", lambda x: x.nonce_keys.__setitem__(0, x.nonce_keys[0] ^ 1))
    add("nonce_seq", lambda x: setattr(x, "nonce_seq", 1))
    add("sender", lambda x: setattr(x, "sender", x.sender ^ 1))
    add("verify_mode", lambda x: setattr(x.frames[1], "mode", 0))
    add("verify_flags", lambda x: setattr(x.frames[1], "flags", 2))
    add("verify_target", lambda x: setattr(x.frames[1], "target", x.frames[1].target ^ 1))
    add("verify_gas", lambda x: setattr(x.frames[1], "gas_limit", VERIFY_FRAME_GAS - 1))
    add("verify_state_gas", lambda x: setattr(
        x.frames[1], "state_limit", VERIFY_FRAME_STATE_GAS - 1))
    add("verify_value", lambda x: setattr(x.frames[1], "value", 1))
    for word in range(8):
        add(f"proof_word_{word}", lambda x, w=word: setattr(
            x.frames[1], "data", x.frames[1].data[:w * 32] +
            bytes([x.frames[1].data[w * 32] ^ 1]) + x.frames[1].data[w * 32 + 1:]))
    add("settle_mode", lambda x: setattr(x.frames[2], "mode", 1))
    add("settle_target", lambda x: setattr(x.frames[2], "target", x.frames[2].target ^ 1))
    add("settle_gas", lambda x: setattr(x.frames[2], "gas_limit", SETTLE_FRAME_GAS - 1))
    add("settle_state_gas", lambda x: setattr(
        x.frames[2], "state_limit", SETTLE_FRAME_STATE_GAS - 1))
    for word in range(12):
        add(f"settle_word_{word}", lambda x, w=word: setattr(
            x.frames[2], "data", x.frames[2].data[:4 + w * 32] +
            bytes([x.frames[2].data[4 + w * 32] ^ 1]) + x.frames[2].data[5 + w * 32:]))
    add("signature_scheme", lambda x: setattr(x.signatures[0], "scheme", 2))
    add("signature_signer", lambda x: setattr(x.signatures[0], "signer", x.signatures[0].signer ^ 1))
    add("signature_message", lambda x: setattr(x.signatures[0], "msg", b"\x01" * 32))
    add("priority_fee", lambda x: setattr(x, "max_priority_fee", 2))
    add("max_fee", lambda x: setattr(x, "max_fee", 11))
    add("blob_fee", lambda x: setattr(x, "max_blob_fee", 1))
    add("blob_hashes", lambda x: x.blob_hashes.append(b"\x01" * 32))
    add("root_source", lambda x: setattr(x.frames[0], "data", root_tuple(b"\x01" * 32, 1, b"\x02" * 32)))
    add("root_slot", lambda x: setattr(x.frames[0], "data", root_tuple(b"\x01" * 32, 2, b"\x02" * 32)))
    add("root_value", lambda x: setattr(x.frames[0], "data", root_tuple(b"\x01" * 32, 1, b"\x03" * 32)))
    add("root_frame_target", lambda x: setattr(x.frames[0], "target", x.frames[0].target ^ 1))
    add("root_frame_flags", lambda x: setattr(x.frames[0], "flags", 1))
    add("root_frame_gas", lambda x: setattr(x.frames[0], "gas_limit", RECENT_ROOT_FRAME_GAS - 1))
    add("root_frame_state_gas", lambda x: setattr(x.frames[0], "state_limit", 1))
    return mutations


def claim_mutations(tx):
    mutations = []

    def add(name, fn):
        candidate = copy.deepcopy(tx)
        fn(candidate)
        mutations.append((name, candidate))

    add("claim_mode", lambda x: setattr(x.frames[3], "mode", 2))
    add("claim_flags", lambda x: setattr(x.frames[3], "flags", 1))
    add("claim_target", lambda x: setattr(x.frames[3], "target", x.frames[3].target ^ 1))
    add("claim_gas", lambda x: setattr(x.frames[3], "gas_limit", CLAIM_FRAME_GAS - 1))
    add("claim_state_gas", lambda x: setattr(
        x.frames[3], "state_limit", CLAIM_FRAME_STATE_GAS - 1))
    add("claim_value", lambda x: setattr(x.frames[3], "value", 1))
    add("claim_selector", lambda x: setattr(
        x.frames[3], "data", bytes([x.frames[3].data[0] ^ 1]) + x.frames[3].data[1:]))
    add("claim_recipient", lambda x: setattr(
        x.frames[3], "data", x.frames[3].data[:-1] + bytes([x.frames[3].data[-1] ^ 1])))
    return mutations


def action_mutations(tx):
    mutations = []

    def add(name, fn):
        candidate = copy.deepcopy(tx)
        fn(candidate)
        mutations.append((name, candidate))

    add("action_mode", lambda x: setattr(x.frames[3], "mode", 2))
    add("action_flags", lambda x: setattr(x.frames[3], "flags", 1))
    add("action_target", lambda x: setattr(x.frames[3], "target", x.frames[3].target ^ 1))
    add("action_gas", lambda x: setattr(x.frames[3], "gas_limit", x.frames[3].gas_limit - 1))
    add("action_state_gas", lambda x: setattr(
        x.frames[3], "state_limit", x.frames[3].state_limit - 1))
    add("action_value", lambda x: setattr(x.frames[3], "value", 1))
    add("action_calldata", lambda x: setattr(x.frames[3], "data", x.frames[3].data + b"\x00"))
    add("action_removed", lambda x: x.frames.pop())
    add("action_duplicated", lambda x: x.frames.append(copy.deepcopy(x.frames[3])))
    return mutations


def assert_unbound(tx, authorizer, mutations):
    original_hash = tx.sig_hash()
    original_signature = tx.signatures[0].signature
    for name, candidate in mutations:
        assert candidate.sig_hash() != original_hash, f"signature hash did not bind {name}"
        sig = keys.Signature(vrs=(original_signature[0],
                                  int.from_bytes(original_signature[1:33], "big"),
                                  int.from_bytes(original_signature[33:65], "big")))
        recovered = sig.recover_public_key_from_msg_hash(candidate.sig_hash()).to_canonical_address()
        assert recovered != authorizer.to_bytes(20, "big"), f"old signature authorized {name}"
    raw_changed = copy.deepcopy(tx)
    raw_changed.signatures[0].signature = bytes([original_signature[0]]) + bytes([original_signature[1] ^ 1]) + original_signature[2:]
    assert raw_changed.sig_hash() == original_hash, "empty-msg raw signature bytes must be elided"


def main():
    transfer, transfer_auth = _signed("transfer")
    assert len(transfer.frames) == 3, "private transfers keep three frames"
    transfer_mutations = common_mutations(transfer)
    assert_unbound(transfer, transfer_auth, transfer_mutations)

    action = {
        "target": 0xA11CE,
        "data": bytes.fromhex("12345678") + b"owner-authorized-action",
        "gas_limit": 300_000,
        "state_limit": 100_000,
    }
    action_tx, action_auth = _signed("transfer", action)
    assert len(action_tx.frames) == 4, "gas-only action adds one frame"
    tail = action_tx.frames[3]
    assert tail.mode == 0 and tail.flags == 0 and tail.value == 0, "action must be DEFAULT with zero value"
    assert tail.target == action["target"] and tail.data == action["data"], "action changed"
    action_bound = common_mutations(action_tx) + action_mutations(action_tx)
    assert_unbound(action_tx, action_auth, action_bound)

    withdraw, withdraw_auth = _signed("withdraw")
    assert len(withdraw.frames) == 4, "wallet default withdraw adds a DEFAULT claim"
    assert withdraw.frames[3].mode == 0, "default withdraw tail is DEFAULT"
    withdraw_mutations = common_mutations(withdraw) + claim_mutations(withdraw)
    assert_unbound(withdraw, withdraw_auth, withdraw_mutations)

    withdraw_credit, withdraw_credit_auth = _signed("withdraw", omit=True)
    assert len(withdraw_credit.frames) == 3, "withdrawals may omit the tail"
    withdraw_credit_mutations = common_mutations(withdraw_credit)
    assert_unbound(withdraw_credit, withdraw_credit_auth, withdraw_credit_mutations)

    withdraw_action_tx, withdraw_action_auth = _signed("withdraw", action)
    assert len(withdraw_action_tx.frames) == 4, "custom withdraw tail stays at four frames"
    wtail = withdraw_action_tx.frames[3]
    assert wtail.target == action["target"] and wtail.data == action["data"]
    withdraw_action_bound = common_mutations(withdraw_action_tx) + action_mutations(withdraw_action_tx)
    assert_unbound(withdraw_action_tx, withdraw_action_auth, withdraw_action_bound)

    print(json.dumps({"transfer_frames": 3,
                      "withdraw_frames": 4,
                      "withdraw_credit_frames": 3,
                      "action_frames": 4,
                      "withdraw_action_frames": 4,
                      "claim_mode": 0,
                      "bound_mutations_transfer": len(transfer_mutations),
                      "bound_mutations_withdraw": len(withdraw_mutations),
                      "bound_mutations_withdraw_credit": len(withdraw_credit_mutations),
                      "bound_mutations_action": len(action_bound),
                      "bound_mutations_withdraw_action": len(withdraw_action_bound),
                      "raw_signature_elision_only": True,
                      "proof_bytes_bound": True,
                      "settlement_words_bound": 12}, sort_keys=True))


if __name__ == "__main__":
    main()
