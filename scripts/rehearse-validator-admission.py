#!/usr/bin/env python3
"""Run the funded-admission node test in an isolated, compile-time devnet.

The checked-out source is never edited. The shipping activation remains
unarmed; there is no feature, environment variable or node option that can
change consensus on a running network. CI tests the positive path by compiling
a disposable copy with the five co-activated ADR-041 constants changed to epoch zero.
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
GATES = ["FUNDED_VALIDATOR_ADMISSION", "EXIT_AUTH", "WITHDRAWAL",
         "SLASHING_EVIDENCE", "RANDAO_RECOMMIT"]
TEST = "engine::validator_admission_tests::"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shipping-tests", action="store_true",
                        help="also run the full shipping node suite before the isolated activation")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--audit-mempool", action="store_true",
                        help="run the regression proving invalid funding is refused before relay")
    mode.add_argument("--randao-only", action="store_true",
                        help="run only the short-chain automatic renewal rehearsal")
    args = parser.parse_args()
    source = (ROOT / PARAMS).read_text()
    armed = source
    for gate in GATES:
        old = f"pub const {gate}_ACTIVATION_EPOCH: u64 = u64::MAX;"
        if source.count(old) != 1:
            raise SystemExit(f"Expected exactly one unarmed {gate} constant; review the rehearsal.")
        armed = armed.replace(old, f"pub const {gate}_ACTIVATION_EPOCH: u64 = 0;")
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
        # Separate artifacts are explicitly devnet-only. Retaining dependency
        # builds makes reruns practical without touching the shipping target.
        env["CARGO_TARGET_DIR"] = str(ROOT / "target" / "validator-lifecycle-rehearsal")
        if args.shipping_tests:
            subprocess.run(
                ["cargo", f"+{pin.group(1)}", "test", "--locked", "-p", "bloch-pos-node"],
                cwd=checkout, env=env, check=True,
            )
        (checkout / PARAMS).write_text(armed)
        test_name = TEST + ("funded_mempool_rejects_invalid_state_rehearsal" if args.audit_mempool else "")
        test_options = ["--ignored", "--nocapture", "--skip", "randao_automatic_recommit_rehearsal"]
        if not args.randao_only:
            subprocess.run(
                ["cargo", f"+{pin.group(1)}", "test", "--locked", "-p", "bloch-pos-node",
                 "--bin", "bloch-pos", test_name, "--", *test_options],
                cwd=checkout, env=env, check=True,
            )
        if not args.audit_mempool:
            short = "pub const RANDAO_CHAIN_LENGTH: u32 = 8_192;"
            if armed.count(short) != 1:
                raise SystemExit("RANDAO chain length changed; review the renewal rehearsal")
            (checkout / PARAMS).write_text(armed.replace(short, "pub const RANDAO_CHAIN_LENGTH: u32 = 16;"))
            subprocess.run(
                ["cargo", f"+{pin.group(1)}", "test", "--locked", "-p", "bloch-pos-node",
                 "--bin", "bloch-pos", TEST + "randao_automatic_recommit_rehearsal",
                 "--", "--ignored", "--exact", "--nocapture"],
                cwd=checkout, env=env, check=True,
            )
    if (ROOT / PARAMS).read_text() != source:
        raise SystemExit("Shipping activation source changed during the rehearsal")
    if args.audit_mempool:
        print("Mempool regression passed: invalid funding refused before relay. Shipping source remains unarmed.")
    else:
        print("Validator lifecycle rehearsal passed; the shipping source remains unarmed.")


if __name__ == "__main__":
    main()
