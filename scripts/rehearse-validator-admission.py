#!/usr/bin/env python3
"""Run the funded-admission node test in an isolated, compile-time devnet.

The checked-out source is never edited. The shipping activation remains
unarmed; there is no feature, environment variable or node option that can
change consensus on a running network. CI tests the positive path by compiling
a disposable copy with exactly one reviewed constant changed to epoch zero.
"""
import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PARAMS = Path("crates/bloch-pos-committee/src/params.rs")
OLD = "pub const FUNDED_VALIDATOR_ADMISSION_ACTIVATION_EPOCH: u64 = u64::MAX;"
NEW = "pub const FUNDED_VALIDATOR_ADMISSION_ACTIVATION_EPOCH: u64 = 0;"
TEST = "engine::validator_admission_tests::funded_validator_two_nodes_rehearsal"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shipping-tests", action="store_true",
                        help="also run the full shipping node suite before the isolated activation")
    args = parser.parse_args()
    source = (ROOT / PARAMS).read_text()
    if source.count(OLD) != 1:
        raise SystemExit("Expected exactly one unarmed admission constant; review the rehearsal before running it.")
    pin = re.search(r'^channel\s*=\s*"([^"]+)"', (ROOT / "crates/bloch-pos-node/rust-toolchain.toml").read_text(), re.M)
    if not pin:
        raise SystemExit("Missing pinned toolchain")
    files = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=ROOT
    ).decode().split("\0")
    with tempfile.TemporaryDirectory(prefix="bloch-admission-rehearsal-") as temp:
        checkout = Path(temp)
        for name in files:
            if not name:
                continue
            relative = Path(name)
            if relative.is_absolute() or ".." in relative.parts:
                raise SystemExit("Unexpected path in source inventory")
            source_file = ROOT / relative
            if not source_file.is_file():
                continue
            destination = checkout / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_file, destination)
        env = os.environ.copy()
        # A separate target prevents the epoch-zero artifact from being mistaken
        # for the mainnet release binary. It is removed with the source copy.
        env["CARGO_TARGET_DIR"] = str(checkout / "target")
        if args.shipping_tests:
            subprocess.run(
                ["cargo", f"+{pin.group(1)}", "test", "--locked", "-p", "bloch-pos-node"],
                cwd=checkout, env=env, check=True,
            )
        (checkout / PARAMS).write_text(source.replace(OLD, NEW))
        subprocess.run(
            ["cargo", f"+{pin.group(1)}", "test", "--locked", "-p", "bloch-pos-node",
             "--bin", "bloch-pos", TEST, "--", "--ignored", "--exact"],
            cwd=checkout, env=env, check=True,
        )
    if (ROOT / PARAMS).read_text() != source:
        raise SystemExit("Shipping activation source changed during the rehearsal")
    print("Admission rehearsal passed; the shipping source remains unarmed.")


if __name__ == "__main__":
    main()
