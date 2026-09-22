"""Focused occurrence-nullifier circuit checks, using generated R1CS/WASM.

Run after compiling/setup: python3 wallet/test_occurrence.py
This exercises real witness constraints and one real Groth16 proof. It does
not emulate the protocol's consumed-key registry or authenticate epoch roots;
the native integration tests cover those boundaries separately.
"""
import copy
import json
import subprocess
import time
from pathlib import Path

import wallet as w

ROOT = Path(__file__).resolve().parent.parent
BUILD = ROOT / "build"
WORK = BUILD / "occurrence-tests"
RESULTS = []


def run(args):
    return subprocess.run([str(x) for x in args], cwd=ROOT / "tooling",
                          capture_output=True, text=True)


def must(args):
    result = run(args)
    assert result.returncode == 0, result.stdout + result.stderr
    return result


def witness_case(name, witness, expected=True):
    start = time.monotonic()
    source = WORK / (name + ".json")
    target = WORK / (name + ".wtns")
    source.write_text(json.dumps(witness))
    result = run(["npx", "snarkjs", "wtns", "calculate",
                  BUILD / "spend_js/spend.wasm", source, target])
    assert (result.returncode == 0) == expected, name + "\n" + result.stdout + result.stderr
    publics = None
    if expected:
        must(["npx", "snarkjs", "wtns", "check", BUILD / "spend.r1cs", target])
        exported = WORK / (name + ".witness.json")
        must(["npx", "snarkjs", "wtns", "export", "json", target, exported])
        # Constant wire 1, four outputs, six public inputs.
        publics = [int(x) for x in json.loads(exported.read_text())[1:11]]
    RESULTS.append({"name": name, "accepted": expected,
                    "seconds": round(time.monotonic() - start, 4)})
    print("PASS", name, "accepted" if expected else "rejected", flush=True)
    return publics


def main():
    WORK.mkdir(exist_ok=True)
    w.set_seed(20260921)
    pool = "0x" + "12" * 20
    domain0 = w.domain_scalar(31337, pool, 0)
    domain1 = w.domain_scalar(31337, pool, 1)
    sk, rho = w.new_note()
    real = {"sk": sk, "rho": rho, "value": 100, "idx": 0}
    cm = w.commitment(sk, rho, 100)
    tree = w.Tree()
    tree.append(cm)
    tree.append(cm)
    tree.append(w.commitment(*w.new_note(), 17))
    duplicate = dict(real, idx=1)
    dummy = w.dummy_input()
    _, authorizer = w.new_authorizer()

    def make(inputs, domain=domain0):
        return w.build_witness(tree, inputs, w.sink_outputs(), domain,
                               authorizer=authorizer,
                               public_amount=sum(n["value"] for n in inputs),
                               recipient="0x" + "34" * 20)

    first = make([real, dummy])
    second = make([duplicate, dummy])
    public_first = witness_case("first-occurrence", first)
    public_second = witness_case("identical-second-occurrence", second)
    assert public_first[0] != public_second[0]
    assert public_first[:2] == w.input_nullifiers(domain0, [real, dummy])
    assert public_second[:2] == w.input_nullifiers(domain0, [duplicate, dummy])
    public_pair = witness_case("both-identical-funded-occurrences", make([real, duplicate]))
    assert public_pair[:2] == [public_first[0], public_second[0]]

    witness_case("same-occurrence-twice", make([real, real]), False)
    bad = make([real, duplicate])
    bad["out_inner"] = [str(w.inner(sk, rho))] * 2
    bad["out_value"] = ["100", "100"]
    bad["public_amount"] = "0"
    bad["recipient"] = "0"
    witness_case("same-output-twice-in-one-spend", bad, False)
    bad = copy.deepcopy(first)
    bad["in_bits"][0][1] = "1"  # Selects a different non-identical branch.
    witness_case("forged-real-position", bad, False)
    bad = copy.deepcopy(first)
    bad["in_bits"][0][0] = "2"
    witness_case("nonboolean-path-bit", bad, False)
    bad = copy.deepcopy(first)
    bad["root"] = str((int(first["root"]) + 1) % w.P)
    witness_case("incorrect-root", bad, False)

    # The same input epoch, commitment and position retain their spending
    # identity when the root changes. Publication slot is intentionally absent.
    tree.append(w.commitment(*w.new_note(), 29))
    later = make([real, dummy])
    public_later = witness_case("same-occurrence-later-root", later)
    assert public_later[4] != public_first[4]
    assert public_later[:2] == public_first[:2]

    # Both epochs have to be authenticated independently by the dispatcher.
    # This circuit test only checks domain separation, not root provenance.
    other_epoch = make([real, dummy], domain1)
    public_epoch = witness_case("same-position-other-authenticated-epoch", other_epoch)
    assert public_epoch[0] != public_later[0]

    # A reorg can change the insertion order. Reconstruct the canonical tree
    # and input index before reproving; retaining the old path must fail.
    branch_a = w.Tree()
    other_cm = w.commitment(*w.new_note(), 37)
    branch_a.append(cm)
    branch_a.append(other_cm)
    branch_b = w.Tree()
    branch_b.append(other_cm)
    branch_b.append(cm)
    original = w.build_witness(branch_a, [real, dummy], w.sink_outputs(), domain0,
                               authorizer=authorizer, public_amount=100,
                               recipient="0x" + "34" * 20)
    stale = copy.deepcopy(original)
    stale["root"] = str(branch_b.root())
    witness_case("reorg-stale-membership-path", stale, False)
    rebuilt_input = dict(real, idx=1)
    rebuilt = w.build_witness(branch_b, [rebuilt_input, dummy], w.sink_outputs(), domain0,
                              authorizer=authorizer, public_amount=100,
                              recipient="0x" + "34" * 20)
    public_rebuilt = witness_case("reorg-rebuilt-tree-and-index", rebuilt)
    assert public_rebuilt[0] != public_first[0]
    assert public_rebuilt[:2] == w.input_nullifiers(domain0, [rebuilt_input, dummy])

    same_secrets_dummy = {"sk": sk, "rho": rho, "value": 0, "idx": None}
    public_dummy = witness_case("dummy-same-secret-and-position", make([real, same_secrets_dummy]))
    assert public_dummy[0] != public_dummy[1]
    dummy_at_max = make([real, same_secrets_dummy])
    dummy_at_max["in_bits"][1] = ["1"] * w.DEPTH
    public_dummy_max = witness_case("dummy-arbitrary-maximum-position", dummy_at_max)
    assert public_dummy_max[1] == w.nullifier(domain0, sk, w.commitment(sk, rho, 0), (1 << w.DEPTH) - 1)
    assert public_dummy_max[1] != public_later[0]

    # Epoch and index range checks in the reference helper must agree with
    # canonical dispatcher uint64 epochs and depth-20 path indices.
    for invalid_epoch in [-1, 1 << 64]:
        try:
            w.domain_scalar(31337, pool, invalid_epoch)
            raise AssertionError("accepted invalid epoch")
        except ValueError:
            pass
    for invalid_index in [-1, 1 << w.DEPTH]:
        try:
            w.nullifier(domain0, sk, cm, invalid_index)
            raise AssertionError("accepted invalid index")
        except ValueError:
            pass
    RESULTS.append({"name": "reference-canonical-epoch-and-index-bounds", "passed": True})

    proof = WORK / "proof.json"
    publics = WORK / "public.json"
    start = time.monotonic()
    must(["npx", "snarkjs", "groth16", "prove", BUILD / "spend_final.zkey",
          WORK / "first-occurrence.wtns", proof, publics])
    prove_seconds = time.monotonic() - start
    key = ROOT / "contracts/vectors/spend_vkey.json"
    must(["npx", "snarkjs", "groth16", "verify", key, publics, proof])
    RESULTS.append({"name": "real-groth16-proof", "passed": True,
                    "prove_seconds": round(prove_seconds, 4)})
    mutated = json.loads(publics.read_text())
    mutated[5] = str(domain1)
    mutated_path = WORK / "mutated-epoch-domain.json"
    mutated_path.write_text(json.dumps(mutated))
    rejected = run(["npx", "snarkjs", "groth16", "verify", key, mutated_path, proof])
    assert rejected.returncode != 0 or "Invalid proof" in rejected.stdout, rejected.stdout
    RESULTS.append({"name": "proof-rejects-mutated-epoch-domain", "passed": True})
    (WORK / "report.json").write_text(json.dumps({"cases": RESULTS}, indent=2) + "\n")
    print(f"PASS {len(RESULTS)} focused circuit/reference/proof cases", flush=True)


if __name__ == "__main__":
    main()
