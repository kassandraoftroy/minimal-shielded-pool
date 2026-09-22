#!/usr/bin/env python3
"""Build and submit the minimal pool's ethrex v23 Hegotá FrameTxs.

This tool targets the EIP-8141/8250/8272 dialect of the upgraded chain 8141: EIP-8250
at f3079a09e8 and EIP-8272 at 824cbc0b0e.

Spends use one base grammar:

  VERIFY(0x…8272, tuple) -> VERIFY(pool, proof, execution+payment)
    -> SENDER(pool, settle(Spend))

Every spend is three frames and may append one DEFAULT tail. The wallet
default for a withdrawal is DEFAULT(pool, claimWithdrawal(recipient)) at
CLAIM_FRAME_GAS / CLAIM_FRAME_STATE_GAS — the budgets the dispatcher used
to pin. Omitting the tail leaves withdrawalCredit. Any other target and
calldata is a custom tail: the wallet raises declared gas above those
defaults, inside remaining EIP-7825 execution capacity. That frame has
zero value and is fully
covered by the proof-selected authorizer's FrameTx signature.

The leading frame is EIP-8272's canonical recent-root verifier: the predeploy checks the
`(source_id, slot, root)` tuple in its data and reverts otherwise. The pool is sender and
payer. EIP-8250 keys are the two proof nullifiers. The sole secp256k1 signature comes from
the fresh authorizer selected by the proof, so it binds the complete transaction, including
proof bytes, gas, fees and the exact tuple. The tuple's slot is read from EIP-7843
`slotNumber`; timestamp derivation is intentionally unsupported.

Usage (append --dry-run to simulate without submitting):
  pool_frametx.py <rpc> config.json fixture.json shield   <funded-private-key>
  pool_frametx.py <rpc> config.json fixture.json publish  <funded-private-key> [--epoch N]
  pool_frametx.py <rpc> config.json fixture.json transfer <unused>
  pool_frametx.py <rpc> config.json fixture.json withdraw <unused>
  pool_frametx.py ... transfer|withdraw <unused> --action-target 0x... \
      --action-call 0x... --action-gas N --action-state-gas N
  pool_frametx.py ... withdraw <unused> --no-tail

Spend signing keys come from the fixture's proof-bound
`authorizer_private_key`. `--root-slot N` supplies the consensus slot in which
`publishEpochRoot(epoch)` committed the root. `--allow-failed-claim` sends a
withdrawal whose default claim tail is expected to revert, leaving
withdrawalCredit for a later claim. Negative-vector flags include
`--flip-proof`, `--nonce-keys`, `--settle-gas`, and `--sender`.
"""
import json
import os
import subprocess
import sys
import time
import urllib.request

from eth_keys import keys

from frametx import Frame, FrameSig, FrameTx
from gas_profile import (
    CLAIM_FRAME_GAS,
    CLAIM_FRAME_STATE_GAS,
    EIP7825_TX_GAS_CAP,
    ETHEX_MEMPOOL_MAX_BYTES,
    POOL_PROFILE,
    RECENT_ROOT_FRAME_GAS,
    SETTLE_FRAME_GAS,
    SETTLE_FRAME_STATE_GAS,
    VERIFY_FRAME_GAS,
    VERIFY_FRAME_STATE_GAS,
)


SPEND_TUPLE = "(bytes32,uint64,uint64,bytes32,bytes32,bytes32,bytes32,bytes32,uint256,uint256,address,address)"


def _limits(execution, state):
    """Frame keyword arguments: the two declared budgets of a frame."""
    return {"gas_limit": execution, "state_limit": state}


def rpc(url, method, params):
    req = urllib.request.Request(
        url, headers={"content-type": "application/json"},
        data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode())
    r = json.loads(urllib.request.urlopen(req, timeout=20).read())
    if "error" in r:
        raise RuntimeError(f"{method} -> {r['error']}")
    return r["result"]


def simulate(url, raw):
    """Dry-run a built frame tx via ethrex_simulateFrameTransaction (the
    ethrex_ namespace, ethrex >= v17, commit e7e495f): the frame-native
    counterpart to eth_estimateGas, which cannot represent a multi-frame tx.
    Runs the mempool validation prefix and, if it passes, a full read-only
    multi-frame execution at head. Returns the result dict, or None if the
    endpoint does not expose the method (-32601). Raises on any other RPC
    error (malformed tx). A tx over the per-tx gas cap comes back as a result
    with valid=False, not an error."""
    req = urllib.request.Request(
        url, headers={"content-type": "application/json"},
        data=json.dumps({"jsonrpc": "2.0", "id": 1,
                         "method": "ethrex_simulateFrameTransaction",
                         "params": [raw]}).encode())
    r = json.loads(urllib.request.urlopen(req, timeout=20).read())
    if "error" in r:
        if r["error"].get("code") == -32601:
            return None
        raise SystemExit(f"  simulate RPC error: {r['error']}")
    return r["result"]


def cast_calldata(sig, *args):
    """Build ABI calldata with foundry's cast (correct for the nested Spend
    struct without hand-rolling an ABI encoder)."""
    out = subprocess.run(["cast", "calldata", sig, *[str(a) for a in args]],
                         capture_output=True, text=True)
    if out.returncode != 0:
        raise SystemExit(f"cast calldata failed: {out.stderr}")
    return bytes.fromhex(out.stdout.strip().removeprefix("0x"))


def spend_args(entry):
    """The publics-only Spend tuple literal (for cast) from a fixture entry."""
    return (f'({entry["root"]},{entry["root_slot"]},{entry["epoch"]},'
            f'{entry["domain"]},{entry["nf1"]},{entry["nf2"]},'
            f'{entry["out_cm1"]},{entry["out_cm2"]},{entry["public_amount"]},'
            f'{entry["fee"]},{entry["recipient"]},{entry["authorizer"]})')


def proof_bytes(entry):
    """The raw 256-byte proof (pA || pB || pC in snarkjs calldata word order):
    frame 0's calldata. The frame-0 verifier reads these eight words directly;
    settlement never carries them."""
    p = entry["proof"]
    words = [p["pA"][0], p["pA"][1], p["pB"][0][0], p["pB"][0][1],
             p["pB"][1][0], p["pB"][1][1], p["pC"][0], p["pC"][1]]
    return b"".join(int(w, 16).to_bytes(32, "big") for w in words)


RECENT_ROOT_ADDRESS = "0x0000000000000000000000000000000000008272"
RECENT_ROOT_LENGTH = 8192


def _keccak(b):
    from eth_hash.auto import keccak
    return keccak(b)


ACTION_OPTION_FLAGS = {
    "--action-target": "target",
    "--action-call": "data",
    "--action-gas": "gas_limit",
    "--action-state-gas": "state_limit",
}


def action_options(argv):
    """Parse one all-or-none raw DEFAULT tail from command-line arguments.

    The calldata already contains whatever authorization the target requires.
    The pool wallet neither understands nor creates that signature.
    """
    unknown = sorted({arg for arg in argv
                      if arg.startswith("--action-") and arg not in ACTION_OPTION_FLAGS})
    if unknown:
        raise ValueError("unknown action option: " + ", ".join(unknown))
    present = {flag for flag in ACTION_OPTION_FLAGS if flag in argv}
    if not present:
        return None
    missing = set(ACTION_OPTION_FLAGS) - present
    if missing:
        raise ValueError("action requires " + ", ".join(sorted(missing)))

    values = {}
    for flag, name in ACTION_OPTION_FLAGS.items():
        if argv.count(flag) != 1:
            raise ValueError(f"{flag} must be supplied exactly once")
        index = argv.index(flag)
        if index + 1 >= len(argv) or argv[index + 1].startswith("--"):
            raise ValueError(f"{flag} requires a value")
        raw = argv[index + 1]
        try:
            if name == "data":
                encoded = raw.removeprefix("0x").removeprefix("0X")
                if len(encoded) % 2:
                    raise ValueError
                values[name] = bytes.fromhex(encoded)
            else:
                values[name] = int(raw, 0)
        except ValueError:
            raise ValueError(f"invalid {flag} value: {raw}") from None
    return values


def recent_root_window_error(slot, latest_slot, epoch=0):
    """Why the node would refuse this publication slot, or None if it would accept.

    Kept apart from the RPC so the boundary is testable without a chain, and stated
    once so the wallet and the node cannot drift.

    EIP-8272 public mempool handling judges a transaction against the earliest block
    that could carry it, so `current_slot` is the head slot PLUS ONE. Comparing
    against the head slot directly is one slot too generous: at a protocol age of
    exactly `RECENT_ROOT_USABLE_WINDOW + 1` the node computes an age one higher and
    refuses, while a head-relative test still passes and signs a doomed transaction.
    """
    current_slot = latest_slot + 1
    if slot >= current_slot:
        return (f"  recent-root ref is not yet referenceable: publication slot {slot} is not "
                f"earlier than current slot {current_slot}. A root written in slot S is only "
                f"usable from S+1 on; wait one slot and re-sign.")
    if current_slot - slot >= RECENT_ROOT_LENGTH:
        return (f"  recent-root ref expired: publication slot {slot} is outside the "
                f"{RECENT_ROOT_LENGTH}-slot window at current slot {current_slot}. If the tree "
                f"has not changed since the proof's root, call publishEpochRoot({epoch}), read "
                f"that block's slotNumber, and re-sign with --root-slot set to that consensus "
                f"slot.")
    return None


def recent_root_tuple(url, cfg, e):
    """Pack and locally verify the exact EIP-8272 tuple the verifier frame carries:
    `source_id(32) || uint64_be(slot) || root(32)`.

    The slot is the consensus `slotNumber` returned by EIP-7843. It is never
    reconstructed from timestamps. The epoch selects the pool's deterministic
    EIP-8272 source while the nullifier domain remains stable across epochs.
    """
    slot = int(e["root_slot"])
    epoch = int(e["epoch"])
    pool = int(cfg["pool"], 16)
    source_id = _keccak(pool.to_bytes(20, "big") + epoch.to_bytes(32, "big"))
    root = bytes.fromhex(e["root"].removeprefix("0x"))

    head = rpc(url, "eth_getBlockByNumber", ["latest", False])
    if "slotNumber" not in head:
        raise SystemExit("latest block has no EIP-7843 slotNumber; refusing timestamp derivation")
    problem = recent_root_window_error(slot, int(head["slotNumber"], 16), epoch)
    if problem:
        raise SystemExit(problem)

    # Self-check: the committed entry the protocol will validate against must
    # already exist for this (source_id, slot, root). One definition, shared
    # with RecentRootReference::{entry_hash, storage_key} in ethrex-common.
    entry = _keccak(_keccak(b"RECENT_ROOT_ENTRY") + source_id + slot.to_bytes(8, "big") + root)
    skey = _keccak(_keccak(b"RECENT_ROOT_STORAGE") + source_id + (slot % RECENT_ROOT_LENGTH).to_bytes(8, "big"))
    stored = rpc(url, "eth_getStorageAt", [RECENT_ROOT_ADDRESS, "0x" + skey.hex(), "latest"])
    if bytes.fromhex(stored.removeprefix("0x").rjust(64, "0")) != entry:
        raise SystemExit(
            f"  recent-root ref self-check failed at consensus slot {slot}. The "
            f"fixture root differs from the root committed at that slot (a fixture generated "
            f"against an empty tree cannot spend into a pool that already has leaves; regenerate "
            f"against a fresh deployment), or the wrong epoch/slot was supplied. Either would be "
            f"rejected as FrameTxRecentRootNotCommitted.")
    return source_id + slot.to_bytes(8, "big") + root


def check_tx_resource_limits(tx):
    """Reject a built spend that does not fit chain-wide transaction limits.

    Execution usage is intrinsic plus frame execution budgets versus the
    EIP-7976 calldata floor. State is not added: 10M execution plus 10M
    state can still fit EIP-7825. Encoded size is the whole FrameTx,
    including proof, signatures, other frames and RLP overhead — not a
    tail-only allowance.
    """
    used = tx.execution_cap_usage()
    if used > EIP7825_TX_GAS_CAP:
        raise ValueError(
            f"declared execution {used} exceeds EIP-7825 cap {EIP7825_TX_GAS_CAP}"
        )
    encoded = len(tx.raw())
    if encoded > ETHEX_MEMPOOL_MAX_BYTES:
        raise ValueError(
            f"encoded transaction {encoded} bytes exceeds ethrex "
            f"{ETHEX_MEMPOOL_MAX_BYTES}-byte mempool limit"
        )


def spend_tail_frame(pool, settle_calldata, action=None, *, omit=False):
    """Derive the optional fourth DEFAULT frame from a canonical settlement.

    The fourth frame is optional on every spend. Withdrawals default to the
    permissionless pool claim at the old pinned claimWithdrawal gas. omit=True
    skips that default and leaves withdrawalCredit. Any spend may instead
    append one explicitly authorized DEFAULT call. Resource limits are
    checked on the assembled transaction so they include the proof,
    signatures, other frames and encoding overhead. A zero-public-amount
    tail cannot target the pool.
    """
    selector = _keccak(f"settle({SPEND_TUPLE})".encode())[:4]
    if len(settle_calldata) != 4 + 12 * 32 or settle_calldata[:4] != selector:
        raise ValueError("tail frame requires canonical settle(Spend) calldata")
    amount = int.from_bytes(settle_calldata[4 + 8 * 32:4 + 9 * 32], "big")
    recipient = int.from_bytes(settle_calldata[4 + 10 * 32:4 + 11 * 32], "big")
    if not 0 < pool < 1 << 160 or recipient >= 1 << 160 or amount >= 1 << 128:
        raise ValueError("invalid pool, recipient, or public amount")
    if (amount == 0) != (recipient == 0):
        raise ValueError("public amount and recipient must both be zero or both nonzero")
    if omit:
        if action is not None:
            raise ValueError("omit cannot be combined with a custom action")
        return None
    if action is None:
        if amount == 0:
            return None
        data = _keccak(b"claimWithdrawal(address)")[:4] + recipient.to_bytes(32, "big")
        return Frame(0, 0, pool, CLAIM_FRAME_GAS, 0, data,
                     state_limit=CLAIM_FRAME_STATE_GAS)

    expected = {"target", "data", "gas_limit", "state_limit"}
    if not isinstance(action, dict) or set(action) != expected:
        raise ValueError("action requires target, data, gas_limit, and state_limit")
    target = action["target"]
    data = action["data"]
    execution = action["gas_limit"]
    state = action["state_limit"]
    if not isinstance(target, int) or not 0 < target < 1 << 160:
        raise ValueError("action target must be a nonzero address")
    if amount == 0 and target == pool:
        raise ValueError("action target must be a nonzero non-pool address")
    if not isinstance(data, bytes):
        raise ValueError("action calldata must be bytes")
    if not isinstance(execution, int) or execution <= 0:
        raise ValueError("action execution gas must be positive")
    if not isinstance(state, int) or state < 0:
        raise ValueError("action state gas must be nonnegative")
    return Frame(0, 0, target, execution, 0, data, state_limit=state)


def claim_frame(pool, settle_calldata):
    """Backward-compatible exact withdrawal claim builder."""
    return spend_tail_frame(pool, settle_calldata)


def build_and_send(url, pk, pool, value, calldata, protocol_nonces=None, proof_verify=None,
                   recent_root=None, dry_run=False, sender_override=None,
                   max_fee_override=None, max_priority_override=None,
                   settle_gas_override=None, save_raw=None, frame0_data=b"",
                   allow_failed_claim=False, action=None, omit_tail=False):
    try:
        tail = (spend_tail_frame(pool, calldata, action, omit=omit_tail)
                if proof_verify else None)
    except ValueError as error:
        raise SystemExit(str(error)) from None
    if action is not None and not proof_verify:
        raise SystemExit("action requires a proof-carrying spend")
    tail_kind = "action" if action is not None else ("claim" if tail is not None else None)
    signer = int.from_bytes(pk.public_key.to_canonical_address(), "big")
    sender = sender_override if sender_override is not None else signer
    chain_id = int(rpc(url, "eth_chainId", []), 16)
    signer_address = pk.public_key.to_checksum_address()
    nonce_address = "0x" + sender.to_bytes(20, "big").hex()
    nonce = int(rpc(url, "eth_getTransactionCount", [nonce_address, "latest"]), 16)
    blk = rpc(url, "eth_getBlockByNumber", ["latest", False])
    base_fee = int(blk.get("baseFeePerGas", "0x0"), 16)
    max_priority = max_priority_override if max_priority_override is not None else 10**9
    max_fee = max_fee_override if max_fee_override is not None else base_fee * 2 + max_priority
    if max_fee < base_fee or max_priority > max_fee:
        raise SystemExit("fee overrides require max_fee >= base_fee and max_priority <= max_fee")
    nonce_keys = protocol_nonces if protocol_nonces else [0]
    nonce_seq = 0 if protocol_nonces else nonce
    if value:
        bal = int(rpc(url, "eth_getBalance", [nonce_address, "latest"]), 16)
        if bal < value:
            raise SystemExit(
                f"  sender {nonce_address} has {bal} wei; this frame moves {value} wei plus gas "
                "(deployer balance after contract creates is a common cause)")

    def build(sender_gas=SETTLE_FRAME_GAS):
        if proof_verify:
            # EIP-8272: the canonical recent-root verifier frame leads; the proof
            # frame follows and reads the proven tuple back with FRAMEDATALOAD.
            frames = [
                Frame(mode=1, flags=0x00, target=int(RECENT_ROOT_ADDRESS, 16), value=0,
                      data=recent_root, **_limits(RECENT_ROOT_FRAME_GAS, 0)),
                Frame(mode=1, flags=0x03, target=sender, value=0, data=frame0_data,
                      **_limits(VERIFY_FRAME_GAS, VERIFY_FRAME_STATE_GAS)),
            ]
        else:
            # Ordinary shield shape: one lightweight self-verify frame approves
            # execution and payment, so the sender is its own payer. This is
            # separate from the proof-carrying spend profile above.
            frames = [Frame(mode=1, flags=0x03, target=sender, value=0, data=b"",
                            **_limits(80_000, 0))]
        # The SENDER frame is not part of the capped prefix. It starts
        # fixed to the fork-scoped cap proved by the activation profile. An OOG
        # after payment approval burns the notes, so wallets may not resize a
        # spend below that immutable cap.
        frames.append(Frame(mode=2, flags=0, target=pool, value=value, data=calldata,
                            **_limits(sender_gas, SETTLE_FRAME_STATE_GAS)))
        if tail is not None:
            frames.append(tail)
        tx = FrameTx(
            chain_id=chain_id, nonce_keys=nonce_keys, nonce_seq=nonce_seq, sender=sender,
            frames=frames,
            signatures=[FrameSig(FrameSig.SECP256K1, signer, b"", b"")],
            max_priority_fee=max_priority, max_fee=max_fee)
        s = pk.sign_msg_hash(tx.sig_hash())
        # EIP-8141 encodes the bare recovery id, 0 or 1. The legacy EVM
        # convention 27/28 is statically invalid for frame signatures.
        sig = bytes([s.v]) + s.r.to_bytes(32, "big") + s.s.to_bytes(32, "big")
        tx.signatures = [FrameSig(FrameSig.SECP256K1, signer, b"", sig)]
        check_tx_resource_limits(tx)
        return tx

    try:
        tx = build() if settle_gas_override is None else build(sender_gas=settle_gas_override)
    except ValueError as error:
        raise SystemExit(str(error)) from None
    raw = "0x" + tx.raw().hex()
    if save_raw:
        with open(save_raw, "w") as f:
            f.write(raw)
    # Dry-run first: pre-check validity, report the resolved payer, and size
    # the (uncapped) SENDER frame from the simulated gas. Degrades to the
    # default limits on an endpoint that does not expose the ethrex_ namespace.
    sim = simulate(url, raw)
    if dry_run:
        if sim is None:
            print("  dry-run: ethrex_simulateFrameTransaction unavailable on this endpoint")
        else:
            per = ", ".join(f"f{i}={int(f['gasUsed'],16):,}" for i, f in enumerate(sim.get("frames") or []))
            g = int(sim["gasUsed"], 16) if sim.get("gasUsed") else None
            print(f"  dry-run: valid={sim.get('valid')}  shape={sim.get('prefixShape')}  "
                  f"payer={sim.get('payer')}  status={sim.get('executionStatus')}")
            print(f"           violation={sim.get('violation')}")
            print(f"           max_cost={tx.max_cost()}  total_gas_limit={tx.total_gas_limit()}")
            if g is not None:
                print(f"           gas={g:,}  ({per})")
        return
    eff = sim  # the simulation the send is gated on (resized one if adopted)
    if sim is None:
        # A spend that mines with a reverting SENDER frame still consumes its
        # nullifiers as protocol keyed nonces at payment approval but never
        # inserts the outputs: the notes are burned for good. The SENDER-revert
        # guard below is the only pre-send defense, so refuse to fly blind on
        # spends. A shield that reverts loses nothing (the deposit stays with
        # the sender), so shields may proceed on default limits.
        if protocol_nonces:
            raise SystemExit(
                "  simulate: ethrex_simulateFrameTransaction unavailable here; refusing to "
                "send a nullifier-consuming spend without a pre-send simulation "
                "(a mined tx whose SENDER frame reverts burns the spent notes)")
        print("  simulate: ethrex_simulateFrameTransaction unavailable here; default gas limits")
    elif sim.get("valid"):
        # gasUsed (top-level and per-frame) is a hex string on success, but the
        # node may return null; guard so a cosmetic gap never aborts a valid send.
        hexint = lambda v: int(v, 16) if isinstance(v, str) else None
        per = ", ".join(f"f{i}={hexint(f.get('gasUsed'))}" for i, f in enumerate(sim.get("frames") or []))
        total = hexint(sim.get("gasUsed"))
        print(f"  simulate: valid  shape={sim.get('prefixShape')}  payer={sim.get('payer')}  "
              f"status={sim.get('executionStatus')}  gas={total}  ({per})")
        # Down-size the SENDER frame from the simulated gas ONLY for
        # non-spends. EIP-8037 state-dimension accounting varies 2-4x across
        # blocks, so measured + 25% is not a safe margin when the failure is
        # irreversible: a spend whose SENDER frame OOGs after payment approval
        # burns the notes (nullifiers consumed, outputs never inserted). For
        # spends the generous default stays; the payer's worst case is
        # prepaying more gas, refunded on success.
        #
        # Prefix `valid` is MATCHA only. A reverting SENDER still reports
        # per-frame gasUsed; do not adopt that as a size.
        used = hexint((sim.get("frames") or [{}])[-1].get("gasUsed"))
        if (used is not None and not protocol_nonces
                and sim.get("executionStatus") == "success"):
            sized = max(used + used // 4, 80_000)
            tx2 = build(sender_gas=sized)
            raw2 = "0x" + tx2.raw().hex()
            s2 = simulate(url, raw2)
            if s2 and s2.get("valid") and s2.get("executionStatus") == "success":
                tx, raw, eff = tx2, raw2, s2
                print(f"  sized SENDER frame to {sized:,} gas (measured {used:,} + 25%, floor 80k)")
            elif s2 and s2.get("valid"):
                print(f"  sized SENDER {sized:,} did not execute; keeping default {SETTLE_FRAME_GAS:,}")
    else:
        # A DEFAULT tail revert is not a prefix failure. Distinguish an
        # explicitly allowed claim failure from an action failure: the latter
        # must never be broadcast after simulation has shown it will fail.
        outcomes = (sim.get("frames") or []) if protocol_nonces else []
        settled = len(outcomes) > 2 and outcomes[2].get("succeeded") is True
        if settled and tail_kind == "action":
            raise SystemExit(
                "  simulate: settlement would succeed but the gas-only action frame would fail; "
                "not sending. Fix the account calldata or limits and rebuild from the unspent notes.")
        if settled and tail_kind == "claim" and allow_failed_claim:
            print(f"  simulate: valid={sim.get('valid')} violation={sim.get('violation')}; "
                  "settlement succeeded and failed claim is allowed")
        else:
            msg = f"  simulate: INVALID ({sim.get('violation')}); not sending"
            if protocol_nonces and "Nonce mismatch" in str(sim.get("violation", "")):
                msg += ("\n  a nullifier keyed nonce was already consumed. If this spend comes from a"
                        "\n  second deterministic fixture against an already-used deployment, the fixed"
                        "\n  seed reuses the dummy note and its nullifier collides; regenerate with"
                        "\n  gen_smoke.py --random or deploy a fresh pool.")
            raise SystemExit(msg)

    # Require frame 2 itself to succeed. A failed DEFAULT tail does not undo
    # settlement; an aggregate executionStatus cannot distinguish these outcomes.
    if protocol_nonces:
        outcomes = (eff or {}).get("frames") or []
        if len(outcomes) <= 2 or outcomes[2].get("succeeded") is not True:
            raise SystemExit("  simulate: settlement frame 2 did not explicitly succeed; not sending")
        tail_failed = tail is not None and (
            len(outcomes) <= 3 or outcomes[3].get("succeeded") is not True)
        if tail_failed and tail_kind == "action":
            raise SystemExit(
                "  simulate: settlement succeeded but the gas-only action frame failed; not sending. "
                "Fix the account calldata or limits and rebuild from the unspent notes.")
        if tail_failed and tail_kind == "claim" and not allow_failed_claim:
            raise SystemExit("  simulate: settlement succeeded but the claim frame failed; "
                             "not sending. The credit would remain and can be claimed later.")
        other_failed = len(outcomes) != len(tx.frames) or any(
            i != 3 and f.get("succeeded") is not True for i, f in enumerate(outcomes))
        if other_failed:
            raise SystemExit("  simulate: settlement succeeded but another frame failed; not sending")
        if tail_failed:
            print("  simulate: settlement succeeded; claim frame failed (allowed); "
                  "credit will remain for a later claim")
    elif eff and eff.get("executionStatus") and eff["executionStatus"] != "success":
        hint = ""
        if value:
            hint = (f"; this frame moves {value} wei — if the sender is short after "
                    "contract creates, top up and redeploy from scratch")
        else:
            hint = " (if root-not-recent, retry one block later)"
        raise SystemExit(f"  simulate: execution did not succeed "
                         f"({eff.get('executionError') or eff['executionStatus']}); not sending"
                         f"{hint}")

    print(f"  frame tx: sender=0x{sender:040x} signer={signer_address} nonce_keys={nonce_keys} "
          f"raw_len={len(tx.raw())} max_cost={tx.max_cost()} sig_hash={tx.sig_hash().hex()[:18]}...")
    txhash = rpc(url, "eth_sendRawTransaction", [raw])
    print("  submitted:", txhash)
    for _ in range(30):
        rcpt = rpc(url, "eth_getTransactionReceipt", [txhash])
        if rcpt:
            status = int(rcpt.get('status', '0x0'), 16)
            print(f"  MINED block={int(rcpt['blockNumber'],16)} type={rcpt.get('type')} "
                  f"status={rcpt.get('status')} gasUsed={int(rcpt.get('gasUsed','0x0'),16)}")
            if protocol_nonces:
                outcomes = rcpt.get("frameReceipts") or []
                settlement_status = outcomes[2].get("status") if len(outcomes) > 2 else None
                if settlement_status not in ("0x0", "0x1", "0x2"):
                    raise SystemExit("  settlement outcome unavailable; inspect frame receipts before retrying")
                if settlement_status != "0x1":
                    raise SystemExit("  settlement frame did not succeed; nullifiers may have been consumed "
                                     "without creating outputs. Inspect frame receipts before retrying.")
                if tail is not None:
                    if len(outcomes) <= 3 or outcomes[3].get("status") not in ("0x0", "0x1", "0x2"):
                        if tail_kind == "action":
                            raise SystemExit(
                                "  settlement succeeded, but the gas-only action outcome is unknown. "
                                "The input notes may already be consumed; inspect the nullifiers, outputs, "
                                "and account state. Do not retry or re-sign using those notes.")
                        raise SystemExit("  settlement succeeded, but the claim frame outcome is unknown. "
                                         "Inspect the pool credit before taking any recovery action.")
                    if outcomes[3].get("status") != "0x1":
                        if tail_kind == "action":
                            raise SystemExit(
                                "  settlement succeeded, but the gas-only action frame failed. The input "
                                "notes were consumed and settlement outputs were created; inspect them and "
                                "the account state. Do not retry or re-sign using those notes.")
                        if not allow_failed_claim:
                            raise SystemExit("  settlement succeeded, but the claim frame failed. "
                                             "The settled credit remains recoverable.")
                        print("  settlement succeeded, but the claim frame failed (allowed). "
                              "The settled credit remains recoverable.")
                claim_reverted = (
                    tail_kind == "claim" and allow_failed_claim
                    and len(outcomes) > 3 and outcomes[3].get("status") != "0x1")
                if status != 1 and not claim_reverted:
                    raise SystemExit(f'  tx reverted (status {rcpt.get("status")}) after successful '
                                     "settlement; inspect frame receipts")
            elif status != 1:
                raise SystemExit(f'  tx reverted (status {rcpt.get("status")}); aborting')
            return rcpt
        time.sleep(2)
    raise SystemExit("  not mined within timeout")


def wait_published_slot(url, rcpt, timeout=180):
    """Two successor blocks, then the publication block's EIP-7843 slotNumber."""
    pub_block = int(rcpt["blockNumber"], 16)
    pub_hash = rcpt["blockHash"]
    deadline = time.time() + timeout
    while True:
        head = int(rpc(url, "eth_blockNumber", []), 16)
        print(f"  confirmations: head={head} publish_block={pub_block} (need +2)", flush=True)
        if head >= pub_block + 2:
            break
        if time.time() >= deadline:
            raise SystemExit(
                f"  timed out waiting for 2 blocks after publish at {pub_block} (head {head})")
        time.sleep(2)
    block = rpc(url, "eth_getBlockByHash", [pub_hash, False])
    slot = block.get("slotNumber")
    if slot in (None, ""):
        raise SystemExit("  publication block has no slotNumber")
    return int(slot, 0) if isinstance(slot, str) else int(slot)


def main():
    url, cfg_path, fix_path, op, priv = sys.argv[1:6]
    cfg = json.loads(open(cfg_path).read())
    fix = json.loads(open(fix_path).read())
    pool = int(cfg["pool"], 16)
    if op in ("transfer", "withdraw"):
        if cfg.get("profile") != POOL_PROFILE:
            raise SystemExit(f"spends require profile={POOL_PROFILE}; use a fresh deployment of this profile")
        if cfg.get("claimGas") != CLAIM_FRAME_GAS or cfg.get("claimStateGas") != CLAIM_FRAME_STATE_GAS:
            raise SystemExit(f"spends require claimGas/claimStateGas matching {POOL_PROFILE}")
    omit_tail = "--no-tail" in sys.argv
    try:
        action = action_options(sys.argv[6:])
    except ValueError as error:
        raise SystemExit(str(error)) from None
    if omit_tail and action is not None:
        raise SystemExit("--no-tail cannot be combined with action options")
    if (action is not None or omit_tail) and op not in ("transfer", "withdraw"):
        raise SystemExit("action options and --no-tail are valid only for transfer or withdraw")
    pk = keys.PrivateKey(bytes.fromhex(priv.removeprefix("0x")))
    dry = "--dry-run" in sys.argv
    sender_override = None
    if "--sender" in sys.argv:
        i = sys.argv.index("--sender")
        if i + 1 >= len(sys.argv):
            raise SystemExit("--sender requires an address")
        try:
            sender_override = int(sys.argv[i + 1], 16)
        except ValueError:
            raise SystemExit(f"invalid sender address: {sys.argv[i + 1]}") from None
        if sender_override == 0 or sender_override >= 1 << 160:
            raise SystemExit(f"invalid sender address: {sys.argv[i + 1]}")
    max_fee_override = None
    max_priority_override = None
    settle_gas_override = None
    save_raw = None
    nonce_keys_override = None
    note_index = None
    spend_key_override = None
    root_slot_override = None
    epoch_override = 0
    flip_proof = "--flip-proof" in sys.argv
    allow_failed_claim = "--allow-failed-claim" in sys.argv
    if "--note" in sys.argv:
        i = sys.argv.index("--note")
        if i + 1 >= len(sys.argv):
            raise SystemExit("--note requires an index into fixture['shields']")
        note_index = int(sys.argv[i + 1], 0)
    if "--spend-key" in sys.argv:
        i = sys.argv.index("--spend-key")
        if i + 1 >= len(sys.argv):
            raise SystemExit("--spend-key requires a fixture key (e.g. transfer_c)")
        spend_key_override = sys.argv[i + 1]
    if "--root-slot" in sys.argv:
        i = sys.argv.index("--root-slot")
        if i + 1 >= len(sys.argv):
            raise SystemExit("--root-slot requires the consensus slot that published the root")
        root_slot_override = int(sys.argv[i + 1], 0)
    if "--epoch" in sys.argv:
        i = sys.argv.index("--epoch")
        if i + 1 >= len(sys.argv):
            raise SystemExit("--epoch requires the epoch to publish")
        epoch_override = int(sys.argv[i + 1], 0)
    if "--settle-gas" in sys.argv:
        i = sys.argv.index("--settle-gas")
        if i + 1 >= len(sys.argv):
            raise SystemExit("--settle-gas requires a gas value")
        settle_gas_override = int(sys.argv[i + 1], 0)
    if "--save-raw" in sys.argv:
        i = sys.argv.index("--save-raw")
        if i + 1 >= len(sys.argv):
            raise SystemExit("--save-raw requires a path")
        save_raw = sys.argv[i + 1]
    if "--nonce-keys" in sys.argv:
        i = sys.argv.index("--nonce-keys")
        if i + 1 >= len(sys.argv):
            raise SystemExit("--nonce-keys requires 0x..,0x..")
        nonce_keys_override = sorted(int(x, 16) for x in sys.argv[i + 1].split(","))
        if len(nonce_keys_override) != 2:
            raise SystemExit("--nonce-keys requires exactly two keys")
    for flag, target in (("--max-fee-per-gas", "max_fee"),
                         ("--max-priority-fee-per-gas", "max_priority")):
        if flag in sys.argv:
            i = sys.argv.index(flag)
            if i + 1 >= len(sys.argv):
                raise SystemExit(f"{flag} requires a wei value")
            try:
                value = int(sys.argv[i + 1], 0)
            except ValueError:
                raise SystemExit(f"invalid {flag} value: {sys.argv[i + 1]}") from None
            if value < 0:
                raise SystemExit(f"{flag} must be non-negative")
            if target == "max_fee":
                max_fee_override = value
            else:
                max_priority_override = value
    if op in ("transfer", "withdraw"):
        if sender_override is None:
            sender_override = pool
    if allow_failed_claim and op != "withdraw":
        raise SystemExit("--allow-failed-claim is only valid on withdraw")
    if allow_failed_claim and omit_tail:
        raise SystemExit("--allow-failed-claim cannot be combined with --no-tail")

    def spend_setup(op_name):
        """Protocol nonces, validation data, and recent-root tuple for a
        settle-only spend. The proof-selected one-time signer authorizes the
        three- or four-frame transaction.

        `--spend-key KEY` reads the spend entry from fix[KEY] instead of
        fix[op_name] (the nonce-race fixture carries two transfers, `transfer`
        and `transfer_c`, against one shared root). `--root-slot N` overrides
        the recent-root publication block: both race transfers bind the SAME
        root R, so they share the block where the second shield completed the
        tree, rather than distinct cfg _slot_transfer/_slot_withdraw values."""
        fix_key = spend_key_override if spend_key_override is not None else op_name
        # Copy before adversarial mutation so the loaded fixture remains an
        # immutable source of truth for subsequent operations in this process.
        e = json.loads(json.dumps(fix[fix_key]))
        if flip_proof:
            e["proof"]["pA"][0] = hex(int(e["proof"]["pA"][0], 16) ^ 1)
        protocol_nonces = sorted([int(e["nf1"], 16), int(e["nf2"], 16)])  # strictly increasing
        slot = root_slot_override if root_slot_override is not None else cfg[f"_slot_{op_name}"]
        e["root_slot"] = str(slot)
        refs = recent_root_tuple(url, cfg, e)
        auth_pk = keys.PrivateKey(bytes.fromhex(e["authorizer_private_key"].removeprefix("0x")))
        if auth_pk.public_key.to_checksum_address().lower() != e["authorizer"].lower():
            raise SystemExit("fixture authorizer private key does not match the proof public")
        return e, protocol_nonces, True, refs, auth_pk

    if op == "shield":
        if "shields" in fix:
            # nonce-race fixture: shield the note at --note N from the shields
            # array (both notes go into one tree; the second shield publishes
            # the shared root R the two race transfers reference).
            if note_index is None:
                raise SystemExit("this fixture has a 'shields' array; pass --note N (0-based)")
            s = fix["shields"][note_index]
            value, inner = int(s["value"]), s["inner"]
        else:
            value, inner = int(fix["shield_value"]), fix["inner_a"]
        calldata = cast_calldata("shield(bytes32)", inner)
        print(f"shield {value} wei via frame tx -> pool {cfg['pool']}")
        build_and_send(url, pk, pool, value, calldata, dry_run=dry)
    elif op == "publish":
        # Same SelfVerify+SENDER shape as shield. A legacy cast send can sit in
        # the Hegotá mempool forever when a non-frame tx fails to apply.
        calldata = cast_calldata("publishEpochRoot(uint64)", str(epoch_override))
        print(f"publishEpochRoot({epoch_override}) via frame tx -> pool {cfg['pool']}")
        rcpt = build_and_send(url, pk, pool, 0, calldata, dry_run=dry)
        if not dry and rcpt:
            slot = wait_published_slot(url, rcpt)
            print(f"ROOT_SLOT {slot}", flush=True)
    elif op == "transfer":
        e, protocol_nonces, verify, refs, auth_pk = spend_setup("transfer")
        if nonce_keys_override is not None:
            protocol_nonces = nonce_keys_override
        calldata = cast_calldata(f"settle({SPEND_TUPLE})", spend_args(e))
        print(f"join-split transfer via frame tx (pool {cfg['pool']} self-pays)")
        build_and_send(url, auth_pk, pool, 0, calldata, protocol_nonces, verify, refs,
                       dry_run=dry, sender_override=sender_override,
                       max_fee_override=max_fee_override, max_priority_override=max_priority_override,
                       settle_gas_override=settle_gas_override, save_raw=save_raw,
                       frame0_data=proof_bytes(e), action=action, omit_tail=omit_tail)
    elif op == "withdraw":
        e, protocol_nonces, verify, refs, auth_pk = spend_setup("withdraw")
        if nonce_keys_override is not None:
            protocol_nonces = nonce_keys_override
        calldata = cast_calldata(f"settle({SPEND_TUPLE})", spend_args(e))
        print(f"join-split withdraw via frame tx (pool {cfg['pool']} self-pays)")
        build_and_send(url, auth_pk, pool, 0, calldata, protocol_nonces, verify, refs,
                       dry_run=dry, sender_override=sender_override,
                       max_fee_override=max_fee_override, max_priority_override=max_priority_override,
                       settle_gas_override=settle_gas_override, save_raw=save_raw,
                       frame0_data=proof_bytes(e), allow_failed_claim=allow_failed_claim,
                       action=action, omit_tail=omit_tail)
    else:
        raise SystemExit(f"unknown op {op}")


if __name__ == "__main__":
    main()
