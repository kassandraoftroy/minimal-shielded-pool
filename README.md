# Minimal shielded pool

An immutable, native-ETH shielded pool built for the ethrex Hegotá testnet's
EIP-8141 Frame Transactions, EIP-8250 keyed nonces, and EIP-8272 recent roots.
It has no ERC-20 path, admin, governance, external paymaster, or MATCHA-specific
mempool mechanism.

This repository is research software. The committed Groth16 proving key uses
public test-only phase-2 entropy and must never protect real value.

## Design

A note commitment is `Poseidon3(2, Poseidon2(owner_pk, rho), value)`, where
`owner_pk = Poseidon3(1, spend_key, 0)`. A spend proves
a 2-input/2-output join-split with ten public signals:

`[nf1, nf2, outCm1, outCm2, root, domain, publicAmount, fee, recipient, authorizer]`

The circuit enforces membership for positive inputs, value conservation,
128-bit amounts, at least one positive input, distinct nullifiers, distinct
outputs, two position-specific zero-value sinks, a nonzero `uint160`
authorizer, and the transfer/withdrawal recipient shape.

Each funded insertion is a separate note, identified by its tree epoch and
leaf index. The index comes from the same path bits that prove membership:

```text
D  = Keccak(domain_tag || chain_id || padded_pool_address || input_epoch) mod Fr
nf = Poseidon3(4, Poseidon2(D, spend_key), Poseidon2(commitment, leaf_index))
```

The domain fields are each 32 bytes; `domain_tag` is
`Keccak("minimal-shielded-pool:occurrence-domain:v1")`. The dispatcher binds
the input epoch to the authenticated recent-root source. Identical funded
commitments at different positions have different nullifiers, so neither
deposit nor settlement needs a commitment-uniqueness registry. Wallets track
each occurrence separately and rebuild positions after a reorg.

Private transfers use three frames. Public withdrawals add a fourth:

1. `VERIFY(0x…8272, tuple)`, EIP-8272's canonical recent-root verifier. The
   protocol runs `RECENT_ROOT_CODE` over the 72-byte tuple before any pool code
   runs, so the root is already proven when frame 1 begins.
2. `VERIFY(pool, proof)`, which verifies the proof and exact envelope, then
   approves execution and payment.
3. `SENDER(pool, settle(Spend))`, which performs bounded internal settlement.
4. When `publicAmount` is nonzero, `DEFAULT(pool, claimWithdrawal(recipient))`.
   Anyone can call `claimWithdrawal`, so this frame does not use `SENDER`.
   If it fails, the credit created by settlement remains and can be claimed
   later. Standalone `claimWithdrawal` remains for leftover credits.

The proof chooses a fresh secp256k1 authorizer. Its sole EIP-8141 empty-message
signature covers the canonical hash of the complete transaction, including
the proof bytes, nonce keys, the recent-root frame, frames, gas limits, fee
fields, and settlement calldata. Raw signature bytes alone are elided by EIP-8141.

The pool is both sender and payer. Its two proof nullifiers are the complete
EIP-8250 key set at sequence zero. The transaction leads with EIP-8272's
canonical recent-root verifier frame, whose 72-byte `(source_id, slot, root)`
tuple the predeploy checks before any pool code runs; the dispatcher binds that
exact tuple through `FRAMEDATALOAD` and requires the frame's shape and success
through `FRAMEPARAM`. Slots come directly from EIP-7843 `slotNumber`;
timestamp reconstruction is rejected.

Settlement never publishes a root or calls a recipient. It rolls to a fresh
Merkle epoch before inserting outputs when capacity is insufficient. The two
zero sinks consume no capacity, so an exit remains possible at a full tree.
Withdrawals are pull credits claimed by the optional fourth frame. Root publication is
a separate permissionless call that reads only the active or finalized root
stored by the pool.

## Active implementation

```
circuits/spend.circom
contracts/src/Groth16Verifier.sol
contracts/src/ShieldedPoolLogic.sol
contracts/src/PoseidonT3.sol
contracts/src/PoseidonT4.sol
devnet/ShieldedPoolDispatcher.yul
devnet/dispatcher.py
devnet/pool_frametx.py
wallet/wallet.py
wallet/gen_smoke.py
```

Unsafe historical standalone, sponsored, probe, and monolithic pool variants
were removed. Git history retains them for research, but they are not supported
deployment paths.

## Compatibility target

The active encoder and immutable dispatcher follow current EIP-8141, EIP-8250 at
`f3079a09e8` (merged PRs 12279 and 12316), and EIP-8272 at `824cbc0b0e` (PRs 12281
and 12302). They use EIP-8141's nested `fees` field and separate execution and
state gas limits for each frame; the envelope has eight fields. PR 12316 is what
put the nested `fees` list back into EIP-8250's own payload block, which had
flattened the three fee parameters into the outer list; the encoder here always
nested them, so the correction confirms the shape rather than changing it. Every private
spend gives its proof frame `195,840` state gas to create its two nullifier
keys, and leads with a `30,000`-gas recent-root verifier frame that counts
toward the public mempool's verify budget. The gas schedule is recorded in the
testbed activation manifest, pool profile `position-notes-v1`.

This profile requires a fresh deployment. Its nullifier formula, verifier
and storage layout differ from `recipient-pull-v1`; replacing the verifier
under an old pool could make spent notes spendable again. The recorded
`devnet/deploy_config.json` remains historical and the spend CLI rejects it
until a new deployment writes the new profile and addresses.

This profile targets the chain 8141 testnet's next re-genesis, which moves the
node to those revisions; the chain launched on September 3 runs the older
EIP-8250 gas rule and the envelope-field form of EIP-8272 and cannot decode
these transactions. The dialect deployed on the pre-relaunch chain-8141 testnet
(11-field envelope, one gas limit per frame) is archived byte-exact under
`devnet/vectors/2026-09-01-hegota-final-profile/`, the auditable record of that
deployment.

The Ethereum EIPs remain drafts, so each supported combination is a separate
versioned profile. The archived profiles and the active profile are not wire
compatible.

## Test

```sh
npm ci --prefix tooling
python3 -m pip install --requirement requirements.txt

python3 devnet/frametx.py
python3 devnet/test_pool_envelope_binding.py
python3 devnet/test_occurrence_profile.py
python3 wallet/test_occurrence.py
python3 tooling/check_gas_profile.py
python3 tooling/check_activation.py activation_manifest.testbed.json --allow-testbed
python3 wallet/wallet.py
python3 reference/poseidon_bn254.py

forge fmt --root contracts --check
forge lint --root contracts --deny warnings
forge test --root contracts --force -vv
```

CI also recompiles the circuit in a temporary directory and compares the R1CS
and WASM byte for byte with the committed artifacts. Run `tooling/setup.sh`
only when intentionally replacing the disposable proving setup. It randomizes
the phase-2 contribution and changes the proving key, verification key, and
verifier, so the activation manifest and proof fixtures must then be rebuilt.
`tooling/check_activation.py` checks every pinned active artifact and fails
closed on the testbed manifest unless `--allow-testbed` is explicit. CI checks
the archived manifest against its original Git snapshot, not the new circuit.

Native duplicate, replay, reorg and gas tests are documented in
[`devnet/native_occurrence/README.md`](devnet/native_occurrence/README.md).
They execute the pinned ethrex VM locally; they do not establish network,
cross-client or full FOCIL integration.

The direct proving-tool versions are also pinned to the committed artifact
provenance. In particular, circom2 0.2.23 does not reproduce the committed
0.2.8 R1CS or WASM byte for byte, so a compiler upgrade belongs to a new
reviewed artifact set rather than routine dependency maintenance.

## Compatibility

| Dependency | Status |
|---|---|
| Ethrex v23 Hegotá FrameTx ABI | Earlier profiles mined the lifecycle on a devnet; this circuit change uses local native VM tests |
| Current EIP-8141 wire format | Frame grammar unchanged; the new circuit and storage layout require a fresh deployment |
| EIP-8141 published 100k public mempool budget | Not compatible: the two validation frames and the signature need 352.8k execution gas |
| EIP-8250 keyed nonces | The pool follows PR 12279: two fresh keys cost `195,840` state gas in the proof frame |
| EIP-8272 recent roots | The pool follows `824cbc0b0e`: the root travels in the canonical verifier frame that leads the transaction |
| EIP-7843 slot number | Implemented: wallet requires the RPC `slotNumber` field |
| EIP-8369 | The open draft does not set a final per-transaction budget; the devnet used for this profile admits the 352.8k budget |
| Current ethrex privacy testnet | The live chain runs the older EIP-8250 gas rule and the envelope form of EIP-8272, so it cannot decode these transactions; this profile needs the chain's next re-genesis |

Earlier testnet evidence is in
[`devnet/vectors/2026-08-14-tight-gas-profile.md`](devnet/vectors/2026-08-14-tight-gas-profile.md).
The published EIP-8141 100k policy remains a portability blocker. The pool must
use a network profile that explicitly admits its 352.8k validation budget, which
the live chain does not yet. [EIP-8369](https://github.com/ethereum/EIPs/pull/12110)
is still an open Informational proposal; its `2^20` per-IL value is a benchmark
candidate, not a finalized per-transaction consensus limit.

## Production gates

- Replace the single-party zkey with a documented multi-party phase-2
  ceremony and independent verification.
- Pin and publish the final circuit, zkey, verifier, dispatcher, logic, and
  Poseidon runtime hashes.
- Re-run the full signature-mutation, capacity, reorg, gas-boundary, and
  cross-client vectors on the exact activation fork.
- Re-run the 2M execution / 550k state settlement bounds on every supported gas schedule.
  Deactivate the profile before an unsupported repricing fork.
- Obtain an independent contract and circuit audit.

See [`SECURITY.md`](SECURITY.md) for the precise trust and failure boundaries.
