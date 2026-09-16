#!/usr/bin/env python3
"""Isolated native-lab process/RPC/restart smoke; no external RPC or real assets."""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import urllib.request


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    args = parser.parse_args()
    binary = str(args.binary.resolve())
    env = dict(os.environ, BLOCH_KEYSTORE_ALLOW_PLAINTEXT="1")
    with tempfile.TemporaryDirectory(prefix="bloch-native-lab-") as directory:
        root = Path(directory)
        node = root / "validator"
        genesis = root / "genesis.blg"
        subprocess.run([binary, "keygen", "--allow-plaintext-keystore", "--dir", str(node), "--index", "0"], env=env, check=True, stdout=subprocess.DEVNULL)
        committee = root / "committee"
        subprocess.run([binary, "keygen", "--allow-plaintext-keystore", "--dir", str(committee), "--index", "1"], env=env, check=True, stdout=subprocess.DEVNULL)
        subprocess.run([binary, "genesis", "--native-lab", "--keys", str(node), "--out", str(genesis), "--slot-ms", "250", "--start-in", "2"], env=env, check=True, stdout=subprocess.DEVNULL)
        assert genesis.read_bytes()[:8] == b"BPOSLAB1"
        rpc_port, mesh_port = port(), port()
        def call(method, params=None):
            payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []}).encode()
            request = urllib.request.Request(f"http://127.0.0.1:{rpc_port}", data=payload, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(request, timeout=2) as response:
                return json.load(response)
        command = [binary, "run", "--native-lab", "--data-dir", str(node), "--genesis", str(genesis), "--transport", "devnet", "--listen", str(mesh_port), "--rpc-port", str(rpc_port)]
        with (root / "node.log").open("w+") as log:
            process = subprocess.Popen(command, env=env, stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 55
                last = None
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        log.seek(0)
                        raise AssertionError("laboratory node exited: " + log.read()[-3000:])
                    try:
                        result = call("getchaininfo")
                        last = result.get("result")
                        if last and last["height"] >= 2:
                            break
                    except OSError:
                        pass
                    time.sleep(0.2)
                assert last and last["height"] >= 2, "laboratory did not produce blocks"
                previous = None
                confirmed = []
                for kind, expected_supply in [("bootstrap", 0), ("import", 100), ("withdraw", 0)]:
                    info = call("getchaininfo")["result"]
                    build = [binary, "native-lab-fixture", "--kind", kind, "--genesis", str(genesis), "--sponsor", str(node), "--committee", str(committee), "--base-fee", str(info["next_base_fee_millisat_per_gas"])]
                    if previous:
                        build += ["--input-txid", previous["output_txid"], "--input-value", previous["output_value"]]
                    transaction = json.loads(subprocess.check_output(build, env=env, text=True))
                    response = call("sendrawtransaction", [transaction["hex"]])
                    assert response.get("result", {}).get("accepted"), (kind, response)
                    deadline = time.monotonic() + 12
                    ledger = None
                    while time.monotonic() < deadline:
                        output = call("gettxout", [transaction["output_txid"], 0]).get("result")
                        if output:
                            candidate = call("getnativelabstate", [transaction["native_asset"], transaction["route"]])["result"]
                            report = candidate.get("ledger")
                            if report and int(report["supply"]) == expected_supply and (kind != "withdraw" or int(report["burned"]) == 100):
                                ledger = candidate
                                break
                        time.sleep(0.1)
                    assert ledger and int(ledger["ledger"]["supply"]) == expected_supply, (kind, ledger)
                    assert ledger["native_domain"] == transaction["native_domain"]
                    if kind == "withdraw":
                        assert int(ledger["ledger"]["imported"]) == 100
                        assert int(ledger["ledger"]["burned"]) == 100
                        assert ledger["ledger"]["first_release_burn"] == transaction["native_burn"]
                    confirmed.append(kind)
                    previous = transaction
                saved_ledger = ledger["ledger"]
                last = call("getchaininfo")["result"]
                refused = call("sendrawtransaction", ["100100000000"])
                assert "error" in refused, "malformed import must be refused through RPC"
            finally:
                process.terminate()
                process.wait(timeout=10)
            # Replay occurs before RPC becomes available. A fresh process spends
            # its doppelganger window observing, so its recovered head is stable.
            process = subprocess.Popen(command, env=env, stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 15
                restored = None
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        log.seek(0)
                        raise AssertionError("laboratory restart exited: " + log.read()[-3000:])
                    try:
                        restored = call("getchaininfo").get("result")
                        if restored:
                            break
                    except OSError:
                        pass
                    time.sleep(0.2)
                assert restored and restored["height"] >= last["height"]
                if restored["height"] == last["height"]:
                    assert restored["block_id"] == last["block_id"]
                    assert restored["state_root"] == last["state_root"]
                assert (node / "native-component.bin").exists()
                recovered_ledger = call("getnativelabstate", [previous["native_asset"], previous["route"]])["result"]
                assert recovered_ledger["ledger"] == saved_ledger
                assert "error" in call("sendrawtransaction", [previous["hex"]]), "withdrawal replay must fail"

                print(json.dumps({"native_lab_process_rpc_restart": "passed", "confirmed_native_operations": confirmed, "height": restored["height"], "slot": restored["slot"], "settlement": "none", "temporary_keys_removed": True}))
            finally:
                process.terminate()
                process.wait(timeout=10)


if __name__ == "__main__":
    main()
