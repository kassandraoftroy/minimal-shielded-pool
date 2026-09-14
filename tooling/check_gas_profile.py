#!/usr/bin/env python3
"""Check the EIP-8141 the current spec gas profile: two declared dimensions per frame.

the frozen profile derives the execution/state split at runtime, so a frame declares one number and the
state charges spill into it. the current spec makes the split explicit — each frame declares
`limits = [execution, state]`, and the two pools never lend to each other. For this pool
that is not merely a re-encoding, it changes what has to be bounded:

  * the state growth the settlement performs leaves the execution budget, so the execution
    cap can drop by exactly the state-growth charge it used to have to cover;
  * the state budget becomes a separate declared number the dispatcher must pin, because on
    the current spec `max_gas` includes the declared state budgets and the pool is the payer. An unpinned
    `limits.state` is an unbounded charge against the pool.

The bounds keep the frozen file's method: start from a measured worst-case execution, then add
the full current-fork charge for every reachable SSTORE, and account state growth separately
rather than folding it in.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "devnet"))

from gas_profile import (  # noqa: E402
    KEYED_NONCE_FIRST_USE_STATE_GAS,
    SETTLE_FRAME_GAS,
    SETTLE_FRAME_STATE_GAS,
    SPEND_NONCE_KEY_COUNT,
    VERIFY_FRAME_GAS,
    VERIFY_FRAME_STATE_GAS,
)

PRE_PR_12279_MAX_OBSERVED_VERIFY_EXECUTION_GAS = 294_401
PRE_PR_12279_KEYED_NONCE_EXECUTION_GAS = 2 * 20_000
CONSERVATIVE_VERIFY_STATE_BOUND = (
    SPEND_NONCE_KEY_COUNT * KEYED_NONCE_FIRST_USE_STATE_GAS
)

# Rollover + two outputs + a first withdrawal credit performs at most 33 SSTORE operations.
# Five end in previously absent slots: finalized root, epoch counter, two leaf markers, and
# the withdrawal credit. Only those five grow the state.
MAX_SSTORE_OPERATIONS = 33
MAX_NEW_STORAGE_SLOTS = 5

LOCAL_WORST_SETTLEMENT_GAS = 832_626
# EIP-8038: cold access (2,100) + STORAGE_WRITE (10,000).
EIP_8038_COLD_WRITE_GAS = 12_100
# EIP-8037 uses the same state gas for any new storage slot.
EIP_8037_NEW_SLOT_STATE_GAS = KEYED_NONCE_FIRST_USE_STATE_GAS

# The execution dimension no longer carries state growth.
CONSERVATIVE_SETTLEMENT_EXECUTION_BOUND = (
    LOCAL_WORST_SETTLEMENT_GAS + MAX_SSTORE_OPERATIONS * EIP_8038_COLD_WRITE_GAS
)
CONSERVATIVE_SETTLEMENT_STATE_BOUND = MAX_NEW_STORAGE_SLOTS * EIP_8037_NEW_SLOT_STATE_GAS

# What the frozen profile had to declare for the same work, as one number.
FROZEN_SETTLE_FRAME_GAS = 2_000_000


def main():
    # This is a conservative comparison only. The measurement came from a node
    # that charged 40,000 keyed nonce gas as execution. No PR 12279 node exists
    # yet, so there is no post-change execution measurement.
    assert PRE_PR_12279_MAX_OBSERVED_VERIFY_EXECUTION_GAS < VERIFY_FRAME_GAS
    assert CONSERVATIVE_SETTLEMENT_EXECUTION_BOUND < SETTLE_FRAME_GAS
    assert CONSERVATIVE_SETTLEMENT_STATE_BOUND < SETTLE_FRAME_STATE_GAS
    # The proof itself writes nothing. This exact budget exists only because its
    # payment APPROVE creates the two EIP-8250 keyed-nonce slots.
    assert VERIFY_FRAME_STATE_GAS == CONSERVATIVE_VERIFY_STATE_BOUND

    declared_split = (VERIFY_FRAME_GAS + VERIFY_FRAME_STATE_GAS
                   + SETTLE_FRAME_GAS + SETTLE_FRAME_STATE_GAS)
    declared_single = VERIFY_FRAME_GAS + FROZEN_SETTLE_FRAME_GAS
    pre_pr_12279_split = declared_split - CONSERVATIVE_VERIFY_STATE_BOUND
    pre_pr_12279_saving = declared_single - pre_pr_12279_split
    extra_over_frozen = declared_split - declared_single
    assert pre_pr_12279_saving == 50_000
    assert extra_over_frozen == 145_840
    assert extra_over_frozen == CONSERVATIVE_VERIFY_STATE_BOUND - pre_pr_12279_saving

    # The dispatcher must enforce the same four limits the wallet emits. Yul
    # cannot import the Python module, so check its unavoidable literals here.
    dispatcher = (ROOT / "devnet" / "ShieldedPoolDispatcher.yul").read_text()
    dispatcher_pins = (
        f"if iszero(eq(frameParam(0, 0x01), {VERIFY_FRAME_GAS})) {{ fail(errShape()) }}",
        f"if iszero(eq(frameParam(0, 0x09), {VERIFY_FRAME_STATE_GAS})) {{ fail(errShape()) }}",
        f"if iszero(eq(frameParam(1, 0x01), {SETTLE_FRAME_GAS})) {{ fail(errShape()) }}",
        f"if iszero(eq(frameParam(1, 0x09), {SETTLE_FRAME_STATE_GAS})) {{ fail(errShape()) }}",
    )
    assert all(pin in dispatcher for pin in dispatcher_pins), \
        "dispatcher gas limits differ from devnet/gas_profile.py"

    # Keep the checked-in deployment record aligned as well. The live runner
    # rewrites these fields from the activation manifest after deployment.
    cfg = json.loads((ROOT / "devnet" / "deploy_config.json").read_text())
    assert cfg["profile"] == "eip8250-state-gas-pre-8272-frame"
    assert cfg["verifyGas"] == VERIFY_FRAME_GAS
    assert cfg["verifyStateGas"] == VERIFY_FRAME_STATE_GAS
    assert cfg["settleGas"] == SETTLE_FRAME_GAS
    assert cfg["settleStateGas"] == SETTLE_FRAME_STATE_GAS

    print(json.dumps({
        "verify": {
            "execution_cap": VERIFY_FRAME_GAS,
            "state_cap": VERIFY_FRAME_STATE_GAS,
            "pre_pr_12279_observed_execution": PRE_PR_12279_MAX_OBSERVED_VERIFY_EXECUTION_GAS,
            "pre_pr_12279_keyed_nonce_execution_gas": PRE_PR_12279_KEYED_NONCE_EXECUTION_GAS,
            "post_pr_12279_observed_execution": None,
            "keyed_nonce_state_bound": CONSERVATIVE_VERIFY_STATE_BOUND,
        },
        "settlement": {
            "execution_cap": SETTLE_FRAME_GAS,
            "state_cap": SETTLE_FRAME_STATE_GAS,
            "conservative_execution_bound": CONSERVATIVE_SETTLEMENT_EXECUTION_BOUND,
            "conservative_state_bound": CONSERVATIVE_SETTLEMENT_STATE_BOUND,
            "execution_margin": SETTLE_FRAME_GAS - CONSERVATIVE_SETTLEMENT_EXECUTION_BOUND,
            "state_margin": SETTLE_FRAME_STATE_GAS - CONSERVATIVE_SETTLEMENT_STATE_BOUND,
        },
        "declared_total": {
            "frozen_single_dimension": declared_single,
            "pre_pr_12279_two_dimensions": pre_pr_12279_split,
            "spec_two_dimensions": declared_split,
            "pr_12279_state_gas_increase": CONSERVATIVE_VERIFY_STATE_BOUND,
            "extra_over_frozen": extra_over_frozen,
        },
    }, sort_keys=True))


if __name__ == "__main__":
    main()
