#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Run the real-hybrid lifecycle in an isolated source copy, never a live node.

Only FUNDED_DELEGATION_ACTIVATION_EPOCH changes, to zero in the temporary copy.
The shipping source, validator keys, deployed binary, all other fork gates,
and the real 2,048-epoch withdrawal delay remain unchanged.
"""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PARAMS = Path("crates/bloch-pos-committee/src/params.rs")
OLD = "pub const FUNDED_DELEGATION_ACTIVATION_EPOCH: u64 = u64::MAX;"
NEW = "pub const FUNDED_DELEGATION_ACTIVATION_EPOCH: u64 = 0;"


def main():
    original = (ROOT / PARAMS).read_bytes()
    if original.decode().count(OLD) != 1:
        raise SystemExit("Shipping gate is not the expected unarmed constant")
    files = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=ROOT
    ).decode().split("\0")
    try:
        with tempfile.TemporaryDirectory(prefix="bloch-funded-delegation-rehearsal-") as tmp:
            copy = Path(tmp)
            for name in filter(None, files):
                relative = Path(name)
                if relative.is_absolute() or ".." in relative.parts:
                    raise SystemExit("Unexpected source inventory path")
                source = ROOT / relative
                if source.is_symlink():
                    raise SystemExit("Source inventory contains a symlink")
                if source.is_file():
                    target = copy / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(source, target)
            (copy / PARAMS).write_text(original.decode().replace(OLD, NEW))
            env = {k: v for k, v in os.environ.items() if not k.startswith("BLOCH_")}
            env["CARGO_TARGET_DIR"] = str(ROOT / "target/funded-delegation-rehearsal")
            subprocess.run([
                "cargo", "test", "--locked", "--offline", "-p", "bloch-pos-node", "--bin", "bloch-pos",
                "engine::funded_delegation_tests::real_hybrid_funded_delegation_full_lifecycle",
                "--", "--ignored", "--exact", "--nocapture",
            ], cwd=copy, env=env, check=True)
    finally:
        if (ROOT / PARAMS).read_bytes() != original:
            raise SystemExit("Shipping activation source changed during rehearsal")
    print("PASS: real hybrid lifecycle; shipping delegation gate remains unarmed.")


if __name__ == "__main__":
    main()
