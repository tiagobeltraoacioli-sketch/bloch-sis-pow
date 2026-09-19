#!/usr/bin/env python3
"""Exercise funded admission between independent, throwaway node processes."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("activation", ROOT / "scripts/rehearse-validator-activation.py")
activation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(activation)


def rpc(port, method, params=()):
    request = urllib.request.Request(f"http://127.0.0.1:{port}",
        data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": list(params)}).encode(),
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=2) as response:
        return json.load(response)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    source = (ROOT / activation.PARAMS).read_text()
    armed = activation.rewrite_params(source, 4)
    report = {"status": "running", "activation_epoch": 4, "throwaway_devnet": True,
              "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
              "shipping_params_sha256": hashlib.sha256(source.encode()).hexdigest(),
              "regime": "finite shipping gates compressed to epoch one; lifecycle at epoch four",
              "devnet_only_flags": ["--allow-plaintext-keystore"],
              "completed": []}
    children, logs = [], []
    try:
        with tempfile.TemporaryDirectory(prefix="bloch-joining-network-") as temp:
            checkout = Path(temp)
            files = subprocess.check_output(["git", "ls-files", "--cached", "--others",
                "--exclude-standard", "-z"], cwd=ROOT).decode().split("\0")
            for name in files:
                if not name:
                    continue
                relative = Path(name)
                if relative.is_absolute() or ".." in relative.parts:
                    raise ValueError("Unexpected source path")
                origin = ROOT / relative
                if origin.is_file():
                    destination = checkout / relative
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(origin, destination)
            (checkout / activation.PARAMS).write_text(armed)
            env = os.environ.copy()
            target = ROOT / "target/validator-current-regime"
            env["CARGO_TARGET_DIR"] = str(target)
            fixture = output / "throwaway-fixture"
            env["BLOCH_JOINING_NETWORK_FIXTURE"] = str(fixture)
            pin = re.search(r'^channel\s*=\s*"([^"]+)"',
                (checkout / "crates/bloch-pos-node/rust-toolchain.toml").read_text(), re.M).group(1)
            cargo = ["cargo", f"+{pin}"]
            activation.run([*cargo, "build", "--locked", "-p", "bloch-pos-node", "--bin", "bloch-pos"],
                checkout, env, output / "build.log", 900)
            binary = output / "throwaway-bloch-pos"
            shutil.copy2(target / "debug/bloch-pos", binary)
            report["binary_sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
            activation.run([*cargo, "test", "--locked", "-p", "bloch-pos-node", "--bin", "bloch-pos",
                "engine::validator_admission_tests::funded_joining_network_fixture", "--", "--ignored",
                "--exact", "--nocapture"], checkout, env, output / "fixture.log", 900)
            if "test result: ok. 1 passed; 0 failed; 0 ignored;" not in (output / "fixture.log").read_text():
                raise RuntimeError("Fixture exporter did not execute exactly once")
            reservations = [socket.socket() for _ in range(4)]
            for sock in reservations:
                sock.bind(("127.0.0.1", 0))
            ports = [sock.getsockname()[1] for sock in reservations]
            for sock in reservations:
                sock.close()
            runtime_env = os.environ.copy()
            runtime_env.pop("BLOCH_NO_DOPPELGANGER", None)
            stop = (4 + 18) * 32
            for i, name in enumerate(("founder", "joining")):
                log = (output / f"{name}.log").open("w")
                logs.append(log)
                children.append(subprocess.Popen([str(binary), "run", "--data-dir", str(fixture / name),
                    "--genesis", str(fixture / "genesis.bin"), "--transport", "devnet",
                    "--listen", str(ports[i]), "--listen-addr", "127.0.0.1",
                    "--peers", f"127.0.0.1:{ports[1-i]}", "--rpc-bind", "127.0.0.1",
                    "--rpc-port", str(ports[2+i]), "--stop-at-slot", str(stop),
                    # Only the freshly generated devnet identities use plaintext keys.
                    "--allow-plaintext-keystore"],
                    env=runtime_env, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT))
            deadline = time.monotonic() + 600
            while True:
                if time.monotonic() >= deadline or any(p.poll() is not None for p in children):
                    raise RuntimeError("Node failed to become ready before the activation boundary")
                try:
                    chain = rpc(ports[2], "getchaininfo")["result"]
                    break
                except (OSError, KeyError):
                    time.sleep(0.2)
            if chain["epoch"] >= 4:
                raise RuntimeError("Missed the pre-activation check")
            deposit = (fixture / "deposit.bin").read_bytes().hex()
            before = rpc(ports[2], "sendrawtransaction", [deposit])
            if "error" not in before:
                raise RuntimeError("Funded admission unexpectedly opened before L")
            report["pre_activation_refusal"] = before
            report["completed"].append("network-pre-activation-refusal")
            print("Pre-activation refusal verified", flush=True)
            sent = False
            while any(p.poll() is None for p in children):
                if time.monotonic() >= deadline:
                    raise TimeoutError("Joining network rehearsal exceeded its deadline")
                if any(p.poll() not in (None, 0) for p in children):
                    raise RuntimeError("A network process failed")
                try:
                    chain = rpc(ports[2], "getchaininfo")["result"]
                    if not sent and chain["epoch"] >= 4:
                        response = rpc(ports[2], "sendrawtransaction", [deposit])
                        if "error" in response:
                            raise RuntimeError(f"Post-L funded deposit refused: {response}")
                        report["submission"] = response
                        report["completed"].append("network-post-activation-admission")
                        sent = True
                        print("Funded deposit submitted after L", flush=True)
                    if sent and "network-finalized-registration-and-activation" not in report["completed"]:
                        records = [rpc(port, "getvalidator", [1]).get("result") for port in ports[2:]]
                        if all(record and record.get("state") == "active" for record in records):
                            report["active_records"] = records
                            report["activation_observed_epoch"] = chain["epoch"]
                            report["completed"].append("network-finalized-registration-and-activation")
                            print("Both processes observe the funded validator active", flush=True)
                except (OSError, KeyError):
                    pass
                time.sleep(0.5)
            if any(p.returncode != 0 for p in children):
                raise RuntimeError("A node exited unsuccessfully")
            for log in logs:
                log.flush()
            joining_log = (output / "joining.log").read_text()
            if "proposing block" not in joining_log or "attested (" not in joining_log:
                raise RuntimeError("The independently running joining validator did not perform both duties")
            terminal = []
            for name in ("founder", "joining"):
                node_log = (output / f"{name}.log").read_text()
                window = re.search(r"observing after replay through wall slot (\d+)", node_log)
                if not window or "DOPPELGANGER DETECTED" in node_log:
                    raise RuntimeError(f"Default duplicate protection did not finish cleanly: {name}")
                duty_slots = [int(slot) for slot in re.findall(
                    r"\[slot (\d+)\] (?:proposing block|attested \()", node_log)]
                if not duty_slots or min(duty_slots) < int(window.group(1)):
                    raise RuntimeError(f"Duties bypassed the observation window: {name}")
                matches = re.findall(r"STOP at slot \d+: head slot (\d+), (\d+) blocks, state root ([0-9a-f]{64})",
                    (output / f"{name}.log").read_text())
                if not matches:
                    raise RuntimeError(f"Missing complete terminal state: {name}")
                terminal.append(matches[-1])
            if terminal[0] != terminal[1]:
                raise RuntimeError(f"Independent processes diverged: {terminal}")
            if "network-finalized-registration-and-activation" not in report["completed"]:
                raise RuntimeError("Registration never activated on both processes")
            activation.run([*cargo, "test", "--locked", "-p", "bloch-pos-node", "--bin", "bloch-pos",
                "engine::validator_admission_tests::funded_joining_network_evidence", "--", "--ignored",
                "--exact", "--nocapture"], checkout, env, output / "committed-duties.log", 900)
            if "test result: ok. 1 passed; 0 failed; 0 ignored;" not in (output / "committed-duties.log").read_text():
                raise RuntimeError("Committed-duty check did not execute exactly once")
            report["terminal"] = terminal
            report["completed"].append("joining-proposal-attestation-and-terminal-agreement")
            report["completed"].append("joining-duties-included-in-both-committed-logs")
            report["completed"].append("default-doppelganger-observation-before-duties")
            if (ROOT / activation.PARAMS).read_text() != source:
                raise RuntimeError("Shipping activation parameters changed during the rehearsal")
            report["status"] = "passed"
    except BaseException as error:
        report["status"] = "failed"
        report["error"] = str(error)
        raise
    finally:
        for child in children:
            if child.poll() is None:
                child.terminate()
        for child in children:
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
        for log in logs:
            log.close()
        report["shipping_source_unchanged"] = (ROOT / activation.PARAMS).read_text() == source
        (output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print("Independent-process funded joining passed", flush=True)


if __name__ == "__main__":
    main()
