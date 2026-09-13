#!/usr/bin/env python3
"""Qualify a finite lifecycle flag day in an isolated current-regime devnet.

Only a disposable source copy is changed. Existing finite activation gates
move to epoch one; the five ADR-041 gates move to L > 1. No other unarmed feature is
enabled. This is compressed-regime qualification, not historical mainnet replay.
Logs, parameter diff and a result manifest are retained in a new output directory.
"""
import argparse
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PARAMS = Path("crates/bloch-pos-committee/src/params.rs")
CURRENT = {"LEAKED_ROSTER": "1400", "TRANSFER_WITNESS_DEDUP": "800",
           "BLOCK_BYTES_V2": "800", "LEAK_RECOVERY": "2_880"}
LIFECYCLE = ("FUNDED_VALIDATOR_ADMISSION", "EXIT_AUTH", "WITHDRAWAL",
             "SLASHING_EVIDENCE", "RANDAO_RECOMMIT")
SHIPPING_LIFECYCLE = "2_884"
TEST = "engine::validator_admission_tests::funded_activation_boundary_rehearsal"


def rewrite_params(source, activation):
    if not 2 <= activation <= 16:
        raise ValueError("Rehearsal activation must be between epochs 2 and 16")
    finite = dict(re.findall(r"^pub const ([A-Z0-9_]+)_ACTIVATION_EPOCH: u64 = ([0-9_]+);$", source, re.M))
    if finite != {**CURRENT, **{name: SHIPPING_LIFECYCLE for name in LIFECYCLE}}:
        raise ValueError("Finite shipping gates changed; review the current-regime inventory")
    result = source
    # Keep a pre-gate epoch: existing boundary tests compile expressions for
    # the slot preceding the byte-accounting flag day, even when filtered out.
    overrides = {**{name: (value, 1) for name, value in CURRENT.items()},
                 **{name: (SHIPPING_LIFECYCLE, activation) for name in LIFECYCLE}}
    for name, (old, new) in overrides.items():
        anchor = f"pub const {name}_ACTIVATION_EPOCH: u64 = {old};"
        if result.count(anchor) != 1:
            raise ValueError(f"Review changed activation constant: {name}")
        result = result.replace(anchor, f"pub const {name}_ACTIVATION_EPOCH: u64 = {new};")
    return result


def run(command, cwd, env, log, timeout):
    print(f"Running {log.name}", flush=True)
    with log.open("w") as output:
        child = subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                 stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = child.wait(timeout=timeout)
        except BaseException:
            os.killpg(child.pid, signal.SIGTERM)
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()
            raise
    if code:
        raise RuntimeError(f"{log.name} failed with exit {code}; inspect {log}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="new evidence directory")
    parser.add_argument("--activation-epoch", type=int, default=4)
    parser.add_argument("--network", action="store_true", help="also run four-process control and partition")
    args = parser.parse_args()
    source = (ROOT / PARAMS).read_text()
    armed = rewrite_params(source, args.activation_epoch)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    pin = re.search(r'^channel\s*=\s*"([^"]+)"',
                    (ROOT / "crates/bloch-pos-node/rust-toolchain.toml").read_text(), re.M)
    if not pin:
        raise SystemExit("Missing pinned toolchain")
    report = {"status": "running", "activation_epoch": args.activation_epoch,
              "regime": "finite shipping gates compressed to epoch one",
              "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
              "shipping_params_sha256": hashlib.sha256(source.encode()).hexdigest(),
              "completed": [], "network": args.network}
    (output / "params.diff").write_text("".join(difflib.unified_diff(
        source.splitlines(True), armed.splitlines(True), fromfile="shipping/params.rs", tofile="devnet/params.rs")))
    try:
        files = subprocess.check_output(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=ROOT
        ).decode().split("\0")
        with tempfile.TemporaryDirectory(prefix="bloch-finite-activation-") as temp:
            checkout = Path(temp)
            for name in files:
                if not name:
                    continue
                relative = Path(name)
                if relative.is_absolute() or ".." in relative.parts:
                    raise ValueError("Unexpected source path")
                origin = ROOT / relative
                if origin.is_file() and output not in origin.resolve().parents:
                    dest = checkout / relative
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(origin, dest)
            (checkout / PARAMS).write_text(armed)
            env = os.environ.copy()
            target = ROOT / "target" / "validator-current-regime"
            env["CARGO_TARGET_DIR"] = str(target)
            env["BLOCH_ACTIVATION_FIXTURE"] = str(output / "pre-activation")
            env["BLOCH_ACTIVATION_TEST_EPOCH"] = str(args.activation_epoch)
            cargo = ["cargo", f"+{pin.group(1)}"]
            log = output / "boundary.log"
            run([*cargo, "test", "--locked", "-p", "bloch-pos-node", "--bin", "bloch-pos", TEST,
                 "--", "--ignored", "--exact", "--nocapture"], checkout, env, log, 900)
            if "test result: ok. 1 passed; 0 failed; 0 ignored;" not in log.read_text():
                raise RuntimeError("Boundary test did not execute exactly once")
            report["completed"].append("finite-boundary-and-replay")
            control = armed
            for name in LIFECYCLE:
                control = control.replace(
                    f"pub const {name}_ACTIVATION_EPOCH: u64 = {args.activation_epoch};",
                    f"pub const {name}_ACTIVATION_EPOCH: u64 = u64::MAX;")
            (checkout / PARAMS).write_text(control)
            log = output / "pre-activation-compatibility.log"
            run([*cargo, "test", "--locked", "-p", "bloch-pos-node", "--bin", "bloch-pos",
                 "engine::validator_admission_tests::funded_pre_activation_compatibility_rehearsal",
                 "--", "--ignored", "--exact", "--nocapture"], checkout, env, log, 900)
            if "test result: ok. 1 passed; 0 failed; 0 ignored;" not in log.read_text():
                raise RuntimeError("Compatibility test did not execute exactly once")
            report["completed"].append("unarmed-build-pre-activation-compatibility")
            (checkout / PARAMS).write_text(armed)
            if args.network:
                run([*cargo, "build", "--locked", "-p", "bloch-pos-node", "--bin", "bloch-pos"],
                    checkout, env, output / "build.log", 900)
                env["BLOCH_POS_BIN"] = str(target / "debug" / "bloch-pos")
                env["BLOCH_KEYSTORE_ALLOW_PLAINTEXT"] = "1"
                # Fixed copied script; editing the working tree cannot alter a running shell.
                for mode in ("control", "split"):
                    run(["bash", str(checkout / "scripts/devnet-particao.sh"),
                         str(output / mode), "4", "500", "30", "330", "490", mode],
                        checkout, env, output / f"{mode}.log", 360)
                    report["completed"].append(mode)
            report["status"] = "passed"
    except BaseException as error:
        report["status"] = "failed"
        report["error"] = str(error)
        raise
    finally:
        report["shipping_source_unchanged"] = (ROOT / PARAMS).read_text() == source
        if not report["shipping_source_unchanged"]:
            report["status"] = "failed"
            report["error"] = "Shipping activation source changed during rehearsal"
        (output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    if report["status"] != "passed":
        raise SystemExit(report["error"])
    print(f"Qualification passed; shipping source unchanged. Evidence: {output}")


if __name__ == "__main__":
    main()
