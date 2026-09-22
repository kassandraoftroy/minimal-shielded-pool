# Security

## Status

Unaudited research software. Do not use the committed proving key or deployed
testnet pool for real value. The repository setup uses public test-only phase-2
entropy, so its toxic waste can be recovered to forge arbitrary spends.

The previously identified implementation blockers are fixed in the active
code: complete-envelope authorization, positional sinks, pre-insert epoch
rollover, separate root publication, canonical Groth16 encodings, direct-call
rejection, exact three/four-frame self-payment, and EIP-7843 slot handling. Production
activation remains blocked on a real ceremony, independent audit, cross-client
evidence, and fork-specific gas proof.

The active transaction encoder and dispatcher target EIP-8141 as currently
specified: nested fees and separate execution and state gas limits. The
pre-relaunch Hegotá testnet profile they previously targeted is archived under
`devnet/vectors/2026-09-01-hegota-final-profile/` and is not usable against any
live network. A client
upgrade to that format requires a new immutable pool profile and deployment.

## Security model

The pool holds native ETH. Notes, fees, withdrawals, and payer costs are all
wei-denominated. The pool is the EIP-8141 sender and payer. There is no
external paymaster or caller-selected fee recipient.

The circuit selects a fresh nonzero secp256k1 authorizer. EIP-8141 validates
its canonical low-s signature over the complete FrameTx hash. The dispatcher
requires that recovered signer through `SIGPARAM`, one signature, a three- or
four-frame spend grammar, the complete two-key
EIP-8250 nonce set, and the exact EIP-8272 tuple proven by the leading
recent-root verifier frame. A copied or rerandomized proof cannot be rewrapped
without the one-time private key.

Payment approval consumes the EIP-8250 keys before SENDER settlement. Safety
therefore requires settlement to be total for every proof-valid admitted
transaction under the pinned fork gas profile. Previously, a duplicate output
could revert settlement after consuming the input keys. Position-bound
nullifiers let settlement append that separately funded occurrence instead.
This removes the duplicate failure path; arbitrary post-approval failures
remain unsafe, so the supported settlement gas bounds are still load-bearing.
A failed tail frame does not undo settlement. If a withdrawal tail reverts or
runs out of gas, the credit created by frame 2 remains on `recipient` and can
be claimed later. The optional generic tail is outside settlement's failure
scope. The proof-bound fee must cover the complete transaction's maximum
cost. The wallet allocates any tail inside remaining EIP-7825 execution
capacity and the chain's transaction size limits; the dispatcher does not
add a pool-specific tail gas or calldata ceiling. Required Poseidon
operations use fixed-code
static calls to two immutable, deployment-verified libraries. Settlement
execution is pinned at 2M because 1.4M OOGs long-carry after approval;
that 2M execution and 550k state budgets must be re-proved before every
gas repricing fork.

The active tree rolls before any non-sink insertion when the current epoch
lacks capacity. Final roots remain authenticated by pool state. EIP-8272 source
IDs are distinct per epoch, preventing same-slot historical-publication
contention. Nullifiers bind chain, pool, the authenticated input epoch, the
commitment and its constrained Merkle index. They never use the changing root,
publication slot or current output epoch, so rollover and republication cannot
make an old occurrence spendable twice. Zero-value dummy inputs retain the
commitment binding, preventing them from copying a funded note's nullifier.

This is a fresh-deployment change. Reusing an old pool's spent-note state with
the new nullifier formula could permit double spending. The versioned profile
rejects historical deployment configs. Wallets must retain duplicate
commitments as distinct occurrences and rebuild canonical positions and spend
IDs after a reorg. Native tests simulate removed and replacement state; they
do not implement consensus fork choice or a production wallet database.

Two distinct position-specific zero commitments represent no-output slots.
They are never inserted. Positive outputs cannot use either reserved inner,
the two output commitments must differ, and a spend must consume positive
private value. A full-tree withdrawal therefore creates only a pull credit and
does not roll or insert.

Root publication is not part of settlement. `publishEpochRoot(epoch)` accepts
no caller-supplied root, reads the active or finalized authenticated root, and
may safely be retried. A publication failure cannot consume note keys.
Withdrawals use checks-effects-interactions; a failed claim reverts and restores
the credit.

The Solidity implementation rejects direct state-changing calls. The immutable
dispatcher owns funds and storage. Deployment verifies the verifier,
dispatcher, logic, and both Poseidon runtimes before the pool is used.

## Generic DEFAULT tail

A spend may append one `DEFAULT` frame whose target and calldata are chosen by
the note authorizer and bound by the complete transaction signature. The frame
has zero value and flags and cannot target the zero address. The dispatcher
does not pin tail execution, state gas, or calldata. The wallet allocates the
requested budget inside remaining transaction capacity: EIP-7825's `2^24`
execution cap covers intrinsic gas, every frame's execution budget, and the
EIP-7976 calldata floor. State gas is accounted separately; native testing
admitted 10M execution plus 10M state. The pinned ethrex client applies a
128 KiB mempool limit to the entire encoded transaction, not to the tail
alone. Wallets default the tail to the old `claimWithdrawal` budgets (100,000
execution / 183,600 state) and only raise gas for a custom target or
calldata. Settlement remains the
only `SENDER` frame. The fourth frame is optional on every spend, including
withdrawals: omitting it leaves `withdrawalCredit`. A zero-withdrawal tail
cannot target the pool. A withdrawal tail may target the pool so
`DEFAULT(pool, claimWithdrawal(recipient))` remains valid.

`recipient` is the payout key, not the frame target. `claimWithdrawal(who)`
always pays `who`. Anyone can still call `claimWithdrawal` later. The authorizer
does not have to pull the credit in the tail; a later standalone claim remains.

The account sees EIP-8141's shared entry point (`0xaa`) as its caller, not
the pool or the account owner. Trusting that caller alone would let any frame
transaction operate the account. The account must independently authenticate
its owner's action and prevent replay. The pool's proof-selected authorizer
only authorizes spending the shielded notes and paying gas.

A wallet must select an execution path compatible with this call. Supporting
EIP-8141, EIP-7702 or ERC-4337 does not by itself establish compatibility.

After successful settlement, a failed tail still spends the input notes
and pays fees; private change outputs and any withdrawal credit remain. The
wallet must inspect the individual frame receipts and must not retry the
consumed spend. An independently submitted account signature may execute
before the pool transaction unless its authorization also binds the intended
execution context.

The existing settlement-failure blocker above is unchanged. An account that
requires settlement to succeed must verify that status before acting. This
extension neither repairs that blocker nor provides full-spend atomicity.

## Assumptions and remaining gates

- Groth16 soundness, BN254 pairing security, Poseidon collision resistance,
  Keccak collision resistance, and secp256k1 unforgeability.
- A production multi-party phase-2 ceremony with destroyed contributions and
  independent transcript verification.
- Correct ethrex v23 implementations of EIP-8141, EIP-8250, EIP-8272 and
  EIP-7843 at the pins the activation manifest records.
- An explicitly supported verification budget of at least 352,800 gas: the
  recent-root verifier frame's 30,000, the proof frame's 320,000, and 2,800 for
  the signature. The published EIP-8141 public-mempool value is 100,000 and is
  insufficient.
- A fork-scoped proof that the settlement limits cover all cold-state, rollover,
  credit, proxy, and static-call paths. The current profile declares 2,000,000
  execution gas and 550,000 state gas. Native testing on ethrex `247e2dd2`
  reproduced valid spends at 262,143 and 524,287 leaves where both VERIFY
  frames succeed, approval consumes the input keys, and settlement then fails
  at the previous 1,400,000 execution pin. Changing the dispatcher pin and
  signed frame limit to 2,000,000 makes those cases succeed; 2M is not by
  itself a proof of every settlement shape. Unsupported repricing forks
  require a new immutable profile.
- Independent circuit, Solidity, Yul, wallet, and deployment review.

EIP-8369 remains an open Informational proposal. Its current `2^20` per-IL
budget is provisional and does not activate or guarantee a per-transaction
limit. Hegotá's configured Profile 2 behavior is testnet evidence only.

The proving compiler and snark tooling remain pinned to the committed artifact
provenance. Transitive packages are overridden to patched versions where this
does not change circuit outputs. A direct compiler upgrade requires a new
artifact set, ceremony, activation manifest, and circuit review.

The wallet is a fixture generator, not a production keystore. Random note
secrets and one-time authorizer keys are not durably backed up.

## Evidence

The Forge suite covers actual Poseidon runtimes, a 2M-capped worst-shape
rollover with two outputs and a new credit, long-carry at 262,143 and 524,287
leaves under EIP-150 forwarding of that 2M budget, pre-insert rollover, full-tree
exit, sink rules, separate publication failure/retry, pull-credit failure,
direct-call rejection, valid proof verification, coordinate aliases, infinity,
and authorizer mutation. The circuit generator rejects same-note inputs,
duplicate outputs, dummy-only spends, wrong sinks, sink-valued positive outputs,
zero authorizers, and recipient mismatches. The envelope vector mutates 48
signed transfer components, 56 signed withdrawal components, 57 signed
gas-only tails, and 57 signed custom withdrawal tails.

The position-bound note suite passes 20 native scenarios using 23 real Groth16
proofs, plus two client-policy tests. It covers duplicate deposits and outputs,
replay, epoch binding, database rollback and proof rebuilding, and settlement
gas boundaries. The highest measured settlement execution cost is 1,423,709;
the old 1.4M limit fails after consuming input keys. The new 2M limit includes
additional margin, not a formal proof of a universal bound. See
[`devnet/native_occurrence/README.md`](devnet/native_occurrence/README.md).

The earlier profile's gas derivation is recorded in
[`devnet/vectors/2026-08-14-tight-gas-profile.md`](devnet/vectors/2026-08-14-tight-gas-profile.md).

The 2026-08-14 ethrex run completed shield, transfer, root refresh, withdrawal,
claim, and replay rejection. It proves compatibility with that one testnet
configuration, not production readiness or cross-client interoperability.

## Reporting

Report vulnerabilities privately to the repository owner before opening a
public issue. Include the affected commit, a minimal reproduction, impact, and
proposed mitigation. Do not test public deployments without permission.
