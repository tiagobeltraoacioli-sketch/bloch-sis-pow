#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Run the real-hybrid lifecycle in an isolated source copy, never a live node.

Only FUNDED_DELEGATION_ACTIVATION_EPOCH changes, to zero in the temporary copy.
The shipping source, validator keys, deployed binary, all other fork gates,
and the real 2,048-epoch withdrawal delay remain unchanged.
"""
import argparse
import os
import re
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PARAMS = Path("crates/bloch-pos-committee/src/params.rs")
GATE = r"pub const FUNDED_DELEGATION_ACTIVATION_EPOCH: u64 = (?:u64::MAX|[0-9_]+);"
NEW = "pub const FUNDED_DELEGATION_ACTIVATION_EPOCH: u64 = 0;"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--admission-only", action="store_true",
                        help="run the short state-aware relay and input-reservation test")
    args = parser.parse_args()
    test = ("funded_delegation_admission_refuses_forgery_and_reserves_inputs"
            if args.admission_only else "real_hybrid_funded_delegation_full_lifecycle")
    original = (ROOT / PARAMS).read_bytes()
    if len(re.findall(GATE, original.decode())) != 1:
        raise SystemExit("Shipping gate is not a unique recognized constant")
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
            (copy / PARAMS).write_text(re.sub(GATE, NEW, original.decode()))
            env = {k: v for k, v in os.environ.items() if not k.startswith("BLOCH_")}
            env["CARGO_TARGET_DIR"] = str(ROOT / "target/funded-delegation-rehearsal")
            subprocess.run([
                "cargo", "test", "--locked", "--offline", "-p", "bloch-pos-node", "--bin", "bloch-pos",
                f"engine::funded_delegation_tests::{test}",
                "--", "--ignored", "--exact", "--nocapture",
            ], cwd=copy, env=env, check=True)
    finally:
        if (ROOT / PARAMS).read_bytes() != original:
            raise SystemExit("Shipping activation source changed during rehearsal")
    print(f"PASS: {test}; shipping delegation gate remains unchanged.")


if __name__ == "__main__":
    main()
