#!/usr/bin/env python3
"""Fail-closed artifact, ceremony, and gas-profile activation gate."""
import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "devnet"))

from gas_profile import (  # noqa: E402
    CLAIM_FRAME_GAS,
    CLAIM_FRAME_STATE_GAS,
    POOL_PROFILE,
    RECENT_ROOT_FRAME_GAS,
    SETTLE_FRAME_GAS,
    SETTLE_FRAME_STATE_GAS,
    VERIFY_FRAME_GAS,
    VERIFY_FRAME_STATE_GAS,
)

# The settlement budgets each supported wire profile is allowed to declare, keyed by
# the manifest's `wire_profile`. An unlisted profile is rejected: the gate stays
# fail-closed, and adding a dialect means adding its budgets here deliberately rather
# than letting a manifest name its own.
#
# Split profiles declare execution and state independently. Historical budgets
# stay frozen here; position-notes-v1 pins settlement execution at 2M because
# native spends at 262,143 and 524,287 leaves OOG at 1.4M after VERIFY and
# approval succeed. State remains 550,000. 2M is the reproduced fix, not a
# proof of every settlement shape.
PROFILES = {
    "ethrex-v23-hegota-testnet": {
        "verify_frame_gas": 320_000,
        "signature_gas": 2_800,
        "verify_frame_state_gas": None,
        "settle_frame_gas": 2_000_000,
        "settle_frame_state_gas": None,
    },
    "ethrex-v23-spec-2026-08-31": {
        "verify_frame_gas": 320_000,
        "signature_gas": 2_800,
        "verify_frame_state_gas": 0,
        "settle_frame_gas": 1_400_000,
        "settle_frame_state_gas": 550_000,
    },
    "eip8250-state-gas-pre-8272-frame": {
        "verify_frame_gas": 320_000,
        "signature_gas": 2_800,
        "verify_frame_state_gas": 195_840,
        "settle_frame_gas": 1_400_000,
        "settle_frame_state_gas": 550_000,
    },
    # EIP-8272 at 824cbc0b0e: the recent root travels in a canonical verifier frame that
    # leads the transaction and counts toward the verify budget.
    "eip8272-canonical-frame": {
        "recent_root_frame_gas": RECENT_ROOT_FRAME_GAS,
        "verify_frame_gas": VERIFY_FRAME_GAS,
        "signature_gas": 2_800,
        "verify_frame_state_gas": VERIFY_FRAME_STATE_GAS,
        "settle_frame_gas": 1_400_000,
        "settle_frame_state_gas": SETTLE_FRAME_STATE_GAS,
    },
    # Withdrawals add an exact DEFAULT claim frame. A 3-frame eip8272-canonical-frame
    # pool is not compatible with this wallet.
    "recipient-pull-v1": {
        "recent_root_frame_gas": RECENT_ROOT_FRAME_GAS,
        "verify_frame_gas": VERIFY_FRAME_GAS,
        "signature_gas": 2_800,
        "verify_frame_state_gas": VERIFY_FRAME_STATE_GAS,
        "settle_frame_gas": 1_400_000,
        "settle_frame_state_gas": SETTLE_FRAME_STATE_GAS,
        "pool_profile": "recipient-pull-v1",
        "claim_frame_gas": CLAIM_FRAME_GAS,
        "claim_frame_state_gas": CLAIM_FRAME_STATE_GAS,
    },
}

# Same frame grammar plus an optional generic DEFAULT tail, new
# circuit/nullifier identities and storage layout. Fresh deployment required.
PROFILES["position-notes-v1"] = {
    **PROFILES["recipient-pull-v1"], "pool_profile": POOL_PROFILE,
    "settle_frame_gas": SETTLE_FRAME_GAS,
}


def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--allow-testbed", action="store_true")
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text())

    for rel, expected in manifest["artifacts"].items():
        actual = sha256(ROOT / rel)
        if actual != expected:
            raise SystemExit(f"artifact hash mismatch: {rel}\nexpected {expected}\nactual   {actual}")

    profile = manifest["profile"]
    expected = PROFILES.get(profile["wire_profile"])
    if expected is None:
        raise SystemExit(f"unsupported transaction wire profile: {profile['wire_profile']!r}")
    if "claim_frame_gas" in expected:
        for field in ("pool_profile", "claim_frame_gas", "claim_frame_state_gas"):
            if profile.get(field) != expected[field]:
                raise SystemExit(f"{field} does not match the immutable dispatcher profile")
    # A profile with a recent-root verifier frame budgets it in the prefix.
    recent_root_gas = profile.get("recent_root_frame_gas", 0)
    if recent_root_gas != expected.get("recent_root_frame_gas", 0):
        raise SystemExit("recent-root frame gas does not match the immutable dispatcher profile")
    required = recent_root_gas + profile["verify_frame_gas"] + profile["signature_gas"]
    if required != profile["required_verify_budget"]:
        raise SystemExit("required verify budget is inconsistent")
    if profile["verify_frame_gas"] != expected["verify_frame_gas"]:
        raise SystemExit("VERIFY execution gas does not match the immutable dispatcher profile")
    if profile["signature_gas"] != expected["signature_gas"]:
        raise SystemExit("signature gas does not match the immutable dispatcher profile")
    if required > profile["hegota_profile_2_budget"]:
        raise SystemExit("transaction exceeds the configured Hegota Profile 2 budget")
    if profile["wire_profile"] in (
            "eip8250-state-gas-pre-8272-frame", "eip8272-canonical-frame", "recipient-pull-v1",
            "position-notes-v1"):
        historical_verify_gas = profile["pre_pr_12279_max_observed_verify_execution_gas"]
        # The field is required even before a measurement exists. Its explicit
        # null records the remaining live-test gap; omitting it must not look
        # like completed evidence.
        if "post_pr_12279_max_observed_verify_execution_gas" not in profile:
            raise SystemExit("missing PR 12279 VERIFY execution measurement status")
        measured_verify_gas = profile["post_pr_12279_max_observed_verify_execution_gas"]
    else:
        historical_verify_gas = profile["max_observed_verify_gas"]
        measured_verify_gas = None
    if historical_verify_gas >= profile["verify_frame_gas"]:
        raise SystemExit("VERIFY frame does not cover the historical valid path")
    if measured_verify_gas is not None and measured_verify_gas >= profile["verify_frame_gas"]:
        raise SystemExit("VERIFY frame does not cover the PR 12279 valid path")
    if profile["settle_frame_gas"] != expected["settle_frame_gas"]:
        raise SystemExit("settlement gas does not match the immutable dispatcher profile")
    if profile["conservative_settle_bound"] >= profile["settle_frame_gas"]:
        raise SystemExit("settlement frame does not cover the conservative fork bound")
    # The state dimension is only declared by profiles that have one, and when a profile
    # has one it is mandatory: a spec-profile manifest silently missing `settle_frame_state_gas`
    # would deploy a pool whose settlement frame declares no state budget at all.
    if expected["settle_frame_state_gas"] is None:
        if "settle_frame_state_gas" in profile:
            raise SystemExit("profile declares a state budget it has no dimension for")
    else:
        if profile.get("settle_frame_state_gas") != expected["settle_frame_state_gas"]:
            raise SystemExit("settlement state gas does not match the immutable dispatcher profile")
        if profile["conservative_settle_state_bound"] >= profile["settle_frame_state_gas"]:
            raise SystemExit("settlement frame does not cover the conservative state bound")
    if expected["verify_frame_state_gas"] is None:
        if "verify_frame_state_gas" in profile:
            raise SystemExit("profile declares a VERIFY state budget it has no dimension for")
    elif profile.get("verify_frame_state_gas") != expected["verify_frame_state_gas"]:
        raise SystemExit("VERIFY state gas does not match the immutable dispatcher profile")

    ceremony = manifest["ceremony"]
    if not manifest["production"]:
        if not args.allow_testbed:
            raise SystemExit("activation blocked: manifest is testbed-only")
    elif ceremony["phase2_contributions"] < 2 or not ceremony["independent_verification"]:
        raise SystemExit("activation blocked: production ceremony evidence is incomplete")

    print(json.dumps({"artifacts": "match", "profile": "match",
                      "production": manifest["production"]}, sort_keys=True))


if __name__ == "__main__":
    main()
