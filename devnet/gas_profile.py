"""Gas limits shared by the pool builder and its checks.

This profile follows EIP-8250 PR 12279 (keyed-nonce first use as state gas) and EIP-8272 at
824cbc0b0e (PRs 12281 and 12302): the recent root travels in a canonical VERIFY frame that
leads the transaction, and that frame's execution budget counts toward the public mempool's
verify budget.
"""

# The recent-root verifier frame: cold access to the predeploy at entry, then the contract's
# validation operation over one 72-byte tuple (two keccaks, one cold SLOAD). Pinned by the
# dispatcher like every other budget: unpinned, it is the pool's money.
RECENT_ROOT_FRAME_GAS = 30_000
RECENT_ROOT_TUPLE_BYTES = 72
POOL_PROFILE = "recipient-pull-v2"
VERIFY_FRAME_GAS = 320_000
SETTLE_FRAME_GAS = 1_400_000
SETTLE_FRAME_STATE_GAS = 550_000
# Frame 3 of a public withdrawal, pool-target branch: exact DEFAULT
# claimWithdrawal. On native ethrex commit 247e2dd2, a DEFAULT claim to a new
# EOA used 14,716 execution gas and 183,600 state gas. Boundary tests lower
# each limit by one.
CLAIM_FRAME_GAS = 100_000
CLAIM_FRAME_STATE_GAS = 183_600
CLAIM_WITHDRAWAL_CALLDATA = 36
# Frame 3 recipient-target branch: DEFAULT call to settle.recipient. These are
# immutable maxima, not defaults. A wallet that declares the cap forces a
# join-split fee covering that max_cost; unused fee - actual_gas_cost stays in
# the pool and is not claimable.
RECIPIENT_FRAME_MAX_GAS = 5_000_000
RECIPIENT_FRAME_MAX_STATE_GAS = 5_000_000
RECIPIENT_FRAME_MAX_DATA = 32_768

STATE_BYTES_PER_STORAGE_SET = 64
CPSB = 1_530
SPEND_NONCE_KEY_COUNT = 2
KEYED_NONCE_FIRST_USE_STATE_GAS = STATE_BYTES_PER_STORAGE_SET * CPSB
VERIFY_FRAME_STATE_GAS = SPEND_NONCE_KEY_COUNT * KEYED_NONCE_FIRST_USE_STATE_GAS

# The public mempool budgets the two prefix frames and the signature together. The Hegotá
# testnet admits up to 500,000 (`--mempool.max-verify-gas`); EIP-8141's published default is
# 100,000, which this profile has never fit.
SIGNATURE_GAS = 2_800
REQUIRED_VERIFY_BUDGET = RECENT_ROOT_FRAME_GAS + VERIFY_FRAME_GAS + SIGNATURE_GAS
HEGOTA_TESTNET_MAX_VERIFY_GAS = 500_000
# EIP-8141 `MAX_VERIFY_STATE_GAS`: the prefix frames' state budgets together.
MAX_VERIFY_STATE_GAS = 500_000
