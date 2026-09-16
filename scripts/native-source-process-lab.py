#!/usr/bin/env python3
"""Bind an actual disposable source deposit to native RPC mint/burn and replay.
Source release is a separate explicit step consuming native-burn.local.json.
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import time
import urllib.parse
import urllib.request


def rpc(endpoint, method, params=None):
    parsed = urllib.parse.urlparse(endpoint)
    if parsed.scheme != "http" or not ipaddress.ip_address(parsed.hostname).is_loopback:
        raise ValueError("laboratory RPC must be numeric loopback HTTP")
    if parsed.username or parsed.password:
        raise ValueError("credentials are not supported")
    request = urllib.request.Request(endpoint, data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []}).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=3) as response:
        return json.load(response)


def validate_deposit(source, receipt):
    assert int(source["amount"]) == 100 and int(source["cap"]) == 1000 and int(source["decimals"]) == 6
    address = lambda value: bytes.fromhex(value.removeprefix("0x")).rjust(32, b"\0")
    fixed = lambda value: bytes.fromhex(value.removeprefix("0x"))
    word = lambda value: int(value).to_bytes(32, "big")
    route_bytes = b"BLOCH-USDT-ROUTE-v1".ljust(32, b"\0") + fixed(source["source_domain"]) + fixed(source["native_domain"]) + fixed(source["native_asset"]) + address(source["token"]) + address(source["vault"]) + word(6) + word(1000)
    assert "0x" + hashlib.sha256(route_bytes).hexdigest() == source["route_id"]
    selected = [event for event in receipt["logs"] if int(event["logIndex"], 16) == int(source["event_index"])]
    assert len(selected) == 1
    event = selected[0]
    assert not event["removed"] and event["address"].lower() == source["vault"].lower()
    assert event["transactionHash"] == source["source_txid"] and event["blockHash"] == source["source_block_hash"]
    assert event["topics"] == ["0x86f22d28da637559602e716d294d9c661cb8177451cfdf19c194c0c79503c174", source["deposit_id"], source["route_id"]]
    expected_data = word(source["deposit_nonce"]) + address(source["deposit_sender"]) + word(100) + fixed(source["pq_recipient_hash"])
    assert fixed(event["data"]) == expected_data
    deposit_bytes = b"BLOCH-USDT-DEPOSIT-v1".ljust(32, b"\0") + fixed(source["route_id"]) + expected_data
    assert "0x" + hashlib.sha256(deposit_bytes).hexdigest() == source["deposit_id"]
    transfers = [event for event in receipt["logs"] if event["address"].lower() == source["token"].lower() and event["topics"][0] == "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"]
    assert len(transfers) == 1 and not transfers[0]["removed"]
    assert transfers[0]["topics"][1:] == ["0x" + address(source["deposit_sender"]).hex(), "0x" + address(source["vault"]).hex()]
    assert fixed(transfers[0]["data"]) == word(100)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--native-directory", type=Path, required=True)
    parser.add_argument("--source-manifest", type=Path, required=True)
    parser.add_argument("--source-compact", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rpc-port", type=int, default=19431)
    parser.add_argument("--mesh-port", type=int, default=19331)
    args = parser.parse_args()
    binary, directory = str(args.binary.resolve()), args.native_directory.resolve()
    manifest = json.loads(args.source_manifest.read_text())
    source = json.loads(args.source_compact.read_text())
    if manifest["environment"] != "disposable-local-anvil" or manifest["publicDeployment"] is not False:
        raise ValueError("source is not the disposable laboratory")
    assert manifest["chainId"] == 31337
    assert rpc(manifest["rpc"], "eth_chainId")["result"] == "0x7a69"
    assert rpc(manifest["rpc"], "eth_getBlockByNumber", ["0x0", False])["result"]["hash"] == manifest["genesisHash"]
    receipt = rpc(manifest["rpc"], "eth_getTransactionReceipt", [source["source_txid"]])["result"]
    assert receipt["status"] == "0x1" and receipt["blockHash"] == source["source_block_hash"]
    assert rpc(manifest["rpc"], "eth_getBlockByNumber", [hex(int(source["source_height"])), False])["result"]["hash"] == source["source_block_hash"]
    code = rpc(manifest["rpc"], "eth_getCode", [source["vault"], "latest"])["result"]
    assert "0x" + hashlib.sha256(bytes.fromhex(code[2:])).hexdigest() == source["vault_runtime_sha256"]
    validate_deposit(source, receipt)
    args.output.mkdir(parents=True, exist_ok=False)
    def save(name, value):
        (args.output / name).write_text(json.dumps(value, indent=2) + "\n")
    save("source-manifest.local.json", manifest)
    save("source-deposit-rechecked.local.json", receipt)
    env = dict(os.environ, BLOCH_KEYSTORE_ALLOW_PLAINTEXT="1")
    endpoint = f"http://127.0.0.1:{args.rpc_port}"
    command = [binary, "run", "--native-lab", "--data-dir", str(directory / "validator"), "--genesis", str(directory / "genesis.blg"), "--transport", "devnet", "--listen", str(args.mesh_port), "--rpc-port", str(args.rpc_port)]
    route_flags = []
    for flag, field in [("source-domain", "source_domain"), ("token", "token"), ("vault", "vault"), ("vault-code-hash", "vault_runtime_sha256")]:
        route_flags += ["--" + flag, source[field]]
    def call(method, params=None):
        return rpc(endpoint, method, params)
    with (args.output / "native-node.log").open("w+") as log:
        process = subprocess.Popen(command, env=env, stdout=log, stderr=log)
        def wait(check, seconds=120):
            deadline = time.monotonic() + seconds
            next_progress = time.monotonic() + 15
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    log.seek(0)
                    raise RuntimeError("node exited: " + log.read()[-3000:])
                try:
                    result = check()
                    if result:
                        return result
                except OSError:
                    pass
                if time.monotonic() >= next_progress:
                    print("waiting for local native consensus", flush=True)
                    next_progress += 15
                time.sleep(0.2)
            raise TimeoutError("laboratory consensus condition not reached")
        try:
            wait(lambda: call("getchaininfo").get("result"), 15)
            previous = None
            operations = []
            for kind, expected in [("bootstrap", 0), ("import", 100), ("withdraw", 0)]:
                info = call("getchaininfo")["result"]
                build = [binary, "native-lab-fixture", "--kind", kind, "--genesis", str(directory / "genesis.blg"), "--sponsor", str(directory / "validator"), "--committee", str(directory / "committee"), "--base-fee", str(info["next_base_fee_millisat_per_gas"])] + route_flags
                if previous:
                    build += ["--input-txid", previous["output_txid"], "--input-value", previous["output_value"]]
                if kind == "import":
                    for flag, field in [("source-tx", "source_txid"), ("source-block", "source_block_hash"), ("event-index", "event_index"), ("deposit-nonce", "deposit_nonce"), ("deposit-sender", "deposit_sender")]:
                        build += ["--" + flag, str(source[field])]
                transaction = json.loads(subprocess.check_output(build, env=env, text=True))
                assert transaction["native_domain"] == source["native_domain"].removeprefix("0x")
                assert transaction["native_asset"] == source["native_asset"].removeprefix("0x")
                assert transaction["route"] == source["route_id"].removeprefix("0x")
                assert transaction["recipient_hash"] == source["pq_recipient_hash"].removeprefix("0x")
                save(kind + ".wire.local.json", transaction)
                submitted = call("sendrawtransaction", [transaction["hex"]])
                assert submitted.get("result", {}).get("accepted"), submitted
                save(kind + ".submission.local.json", submitted)
                def confirmed():
                    report = call("getnativelabstate", [transaction["native_asset"], transaction["route"]]).get("result")
                    ledger = report and report.get("ledger")
                    status = call("gettxstatus", [transaction["txid"]]).get("result", {}).get("status")
                    return report if status in ["included", "justified", "finalized"] and ledger and int(ledger["supply"]) == expected and (kind != "withdraw" or int(ledger["burned"]) == 100) else None
                report = wait(confirmed)
                save(kind + ".state.local.json", report)
                save(kind + ".block.local.json", call("getblockbyid", [report["block_id"]]))
                save(kind + ".status.local.json", call("gettxstatus", [transaction["txid"]]))
                print(json.dumps({"confirmed": kind, "slot": report["slot"], "supply": report["ledger"]["supply"]}), flush=True)
                operations.append(kind)
                previous = transaction
            ledger = report["ledger"]
            assert ledger["first_release_burn"] == transaction["native_burn"]
            # Local FFG evidence only; this does not turn the external vault into a light client.
            finality = wait(lambda: (lambda r: r if r.get("result", {}).get("finalized") is True else None)(call("getblockbyid", [report["block_id"]])), 150)
            save("withdraw.finalized-block.local.json", finality)
            process.terminate()
            process.wait(timeout=10)
            process = subprocess.Popen(command, env=env, stdout=log, stderr=log)
            restored = wait(lambda: call("getnativelabstate", [transaction["native_asset"], transaction["route"]]).get("result"), 20)
            assert restored["ledger"] == ledger
            save("restart.state.local.json", restored)
            replay = call("sendrawtransaction", [transaction["hex"]])
            assert "error" in replay
            save("withdraw.replay-refusal.local.json", replay)
            burn = {"native_domain": "0x" + transaction["native_domain"], "route_id": "0x" + transaction["route"], "native_burn": "0x" + transaction["native_burn"], "nonce": 0, "recipient": "0x" + "0f" * 20, "amount": 100}
            save("native-burn.local.json", burn)
            save("native-phase.local.json", {"environment": "isolated-local-laboratory", "operations": operations, "sourceDepositRechecked": True, "localNativeFinalityObserved": True, "restartLedgerEqual": True, "withdrawReplayRefused": True, "externalReleaseExecuted": False})
            print(json.dumps({"native_phase": "passed", "burn_file": str(args.output / "native-burn.local.json")}), flush=True)
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=10)


if __name__ == "__main__":
    main()
