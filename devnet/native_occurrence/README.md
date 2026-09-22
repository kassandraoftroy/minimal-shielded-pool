# Native occurrence tests

These tests execute real Groth16 proofs and signed frame transactions in the
native LEVM from ethrex `247e2dd2c4d4c526dcc64ac1c025bd2319e7a10e`. They deploy
the contracts from this checkout and check frame results, nonce keys, tree
storage, withdrawal credits, recipient balances and gas payments.

Run after installing the repository's Python, Node, Foundry and Rust dependencies:

```sh
ETHREX_SOURCE=/path/to/pinned/ethrex python3 devnet/native_occurrence/run.py
```

Add `--offline` when Cargo dependencies are cached. `--skip-generate` reuses
locally generated vectors; a normal run recompiles contracts and regenerates
vectors. Cached proofs are keyed by their witness, proving key and circuit
WASM. No setup ceremony runs here. The repository's proving key is test-only.
Generated vectors and proof files are ignored by Git; the reports are kept.

The recorded run passes 20 native scenarios and two client-policy tests, using
23 real Groth16 proofs. The highest measured settlement execution cost is
1,423,709 gas (long carry plus withdrawal credit). The conservative five-slot
state test uses 489,600 state gas, below the 550,000 cap. The reports contain
each transaction hash and per-frame results.

The scenarios cover both copies of identical funded deposits being withdrawn
in one history, an identical private output and its original both being spent,
replay against a later root and slot, epoch/domain changes, and failed recipient
calls retaining their credit. Rejected transactions must leave the complete
EVM account state unchanged, including nonce keys and balances.

The reorg scenario checkpoints the EVM database, executes and spends on one
branch, restores the checkpoint, and reverses two deposit transactions. The
old proof fails both with its old root and when rebound to the new root. A
rebuilt proof for the new position succeeds. This tests application recovery
under database rollback, not consensus fork choice or network reorganization.

Large-tree tests seed the exact frontier and balance of repeated funded
deposits, then execute proof verification and settlement normally. They cover
the longest carry, nearly full and full tree rollover, and spending a newly
created output from the rolled epoch. They do not execute a million deposit
transactions. Two additional tests inject conservative storage-bound states
(an empty active epoch and a zero frontier); those states are not claimed to
have been reached by deposits.

The settlement profile allows 2,000,000 execution gas and 550,000 state gas.
The old-limit regression deploys a separate dispatcher with only the pinned
settlement limit changed back to 1.4 million. It requires settlement to fail
after the nonce keys are consumed. The same long carry must settle successfully
under the new profile. Both execution and state gas are checked against each
frame's declared limits.

`policy/` runs the real validation observer, Profile 2 checks and direct client
mempool insertion with two independently signed, disjoint spends. It requires
zero sender-storage reads and both transactions to remain pending, and includes
storage-read and overlapping-key negative controls. This is not a test of full
blockchain admission, inclusion-list omission processing, block import or
networking. The 352,800 declared validation budget still exceeds the standard
100,000 public-mempool default and requires the existing testnet profile.
