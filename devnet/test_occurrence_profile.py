#!/usr/bin/env python3
"""The new proof format must not be submitted to the recorded old deployment."""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from gas_profile import POOL_PROFILE

ROOT = Path(__file__).resolve().parent.parent


def main():
    assert POOL_PROFILE == "position-notes-v1"
    original = json.loads((ROOT / "devnet/deploy_config.json").read_text())
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "config.json"
        for profile in ("recipient-pull-v1", "eip8272-canonical-frame", None):
            cfg = dict(original, profile=profile)
            path.write_text(json.dumps(cfg))
            for operation in ("transfer", "withdraw"):
                result = subprocess.run([
                    sys.executable, str(ROOT / "devnet/pool_frametx.py"),
                    "http://127.0.0.1:1", str(path), str(ROOT / "wallet/smoke_fixture.json"),
                    operation, "01" * 32, "--dry-run",
                ], capture_output=True, text=True)
                assert result.returncode != 0, (profile, operation)
                assert f"spends require profile={POOL_PROFILE}" in result.stderr, result.stderr
    print("PASS: six incompatible deployment-profile submissions rejected before RPC")


if __name__ == "__main__":
    main()
