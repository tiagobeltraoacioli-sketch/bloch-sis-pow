#!/usr/bin/env python3
"""Local EVM/SVM tooling and a versioned, offline integration export."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import urllib.request

VERSION = "0.2.0"
DOMAIN = b"BLOCH-DEVKIT-OBSERVATION-V1\x00"
MAX_BYTES = 16 * 1024 * 1024
ROOT = Path(__file__).resolve().parent


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def rpc(port, method, params):
    data = canonical({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
    req = urllib.request.Request(f"http://127.0.0.1:{port}", data,
                                 {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as response:
        raw = response.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("RPC response exceeds 16 MiB")
    result = json.loads(raw)
    if result.get("id") != 1 or result.get("jsonrpc") != "2.0" or "error" in result:
        raise ValueError(f"RPC rejected {method}: {result.get('error', 'invalid envelope')}")
    return result["result"]


def runtime(vm):
    name = "anvil" if vm == "evm" else "solana-test-validator"
    candidates = [shutil.which(name),
                  str(Path.home() / ".foundry/bin" / name),
                  str(Path.home() / ".local/share/bloch-dev/runtimes/solana-release/bin" / name)]
    for candidate in candidates:
        if candidate and Path(candidate).is_file() and os.access(candidate, os.X_OK):
            return candidate
    raise ValueError(f"Missing {name}; see README.md runtime installation instructions")


def port_number(value):
    number = int(value)
    if not 1024 <= number <= 65500:
        raise argparse.ArgumentTypeError("port must be between 1024 and 65500")
    return number


def load_config(project):
    config = json.loads((project / "bloch-dev.json").read_text())
    if config.get("schema") != 1 or config.get("vm") not in ("evm", "svm"):
        raise ValueError("Unsupported project configuration")
    config["port"] = port_number(config["port"])
    if config["vm"] == "evm" and config.get("chain_id") != 31337:
        raise ValueError("Local EVM chain_id must be 31337; network profiles are not activated")
    return config


def command(config, project):
    vm, port = config["vm"], config["port"]
    data = project / ".bloch-dev"
    if vm == "evm":
        return [runtime(vm), "--host", "127.0.0.1", "--port", str(port),
                "--chain-id", "31337", "--hardfork", "cancun", "--gas-limit", "30000000",
                "--state", str(data / "evm-state.json"), "--state-interval", "5"]
    return [runtime(vm), "--bind-address", "127.0.0.1", "--rpc-port", str(port),
            "--faucet-port", str(port + 2), "--ledger", str(data / "svm-ledger")]


def initialize(args):
    project = Path(args.directory).resolve()
    # Creating into an existing directory could overwrite a developer's work.
    project.mkdir(parents=True, exist_ok=False)
    shutil.copytree(ROOT / "templates" / args.vm, project, dirs_exist_ok=True)
    config = {"schema": 1, "vm": args.vm, "port": args.port or (8545 if args.vm == "evm" else 8899),
              "chain_id": 31337 if args.vm == "evm" else None}
    (project / "bloch-dev.json").write_text(json.dumps(config, indent=2) + "\n")
    (project / ".gitignore").write_text(".bloch-dev/\ntarget/\nout/\ncache/\nnode_modules/\n")
    print(f"Created {args.vm.upper()} project: {project}\nRun: bloch-dev run --project '{project}'")


def observe(config):
    port = config["port"]
    if config["vm"] == "evm":
        chain_id = rpc(port, "eth_chainId", [])
        if chain_id != hex(config["chain_id"]):
            raise ValueError("RPC chain identity does not match this project")
        genesis = rpc(port, "eth_getBlockByNumber", ["0x0", False])
        block = rpc(port, "eth_getBlockByNumber", ["latest", True])
        if not block or not block.get("stateRoot") or not genesis:
            raise ValueError("RPC returned an incomplete EVM block")
        return {"chain_id": chain_id, "genesis_hash": genesis["hash"], "block": block}
    genesis = rpc(port, "getGenesisHash", [])
    slot = rpc(port, "getSlot", [{"commitment": "finalized"}])
    block = rpc(port, "getBlock", [slot, {"commitment": "finalized", "encoding": "base64",
                 "transactionDetails": "full", "rewards": False, "maxSupportedTransactionVersion": 0}])
    if not block or not block.get("blockhash"):
        raise ValueError("Finalized SVM block is unavailable; retry after the validator advances")
    return {"genesis_hash": genesis, "slot": slot, "block": block}


def export_observation(config, output, source=None):
    payload = {"schema": "bloch.vm.observation/1", "vm": config["vm"],
               "runtime": "anvil" if config["vm"] == "evm" else "agave-test-validator",
               "mode": "local-development", "observation": observe(config)}
    if source is not None:
        payload["bloch_source"] = source
    digest = hashlib.sha256(DOMAIN + canonical(payload)).hexdigest()
    artifact = {"payload": payload, "sha256": digest}
    with Path(output).open("x") as stream:
        json.dump(artifact, stream, indent=2, allow_nan=False)
        stream.write("\n")
    print(f"Exported {output}\nSHA-256: {digest}\nIntegrity record only; not a Bloch settlement or validity proof.")


def verify_artifact(path):
    if path.stat().st_size > MAX_BYTES:
        raise ValueError("Artifact exceeds 16 MiB")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON key")
            result[key] = value
        return result
    artifact = json.loads(path.read_text(), object_pairs_hook=unique)
    payload = artifact["payload"]
    if (payload.get("schema") != "bloch.vm.observation/1"
            or payload.get("vm") not in ("evm", "svm")
            or payload.get("mode") != "local-development"):
        raise ValueError("Unsupported observation schema")
    expected = hashlib.sha256(DOMAIN + canonical(payload)).hexdigest()
    if expected != artifact.get("sha256"):
        raise ValueError("Artifact digest mismatch")
    print("Integrity verified. Execution validity and Bloch inclusion are not verified.")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Bloch DevKit — local EVM/SVM, future Bloch integration")
    parser.add_argument("--version", action="version", version=VERSION)
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("doctor", help="Check installed runtimes")
    init = sub.add_parser("init", help="Create a Solidity or Solana project")
    init.add_argument("vm", choices=["evm", "svm"])
    init.add_argument("directory")
    init.add_argument("--port", type=port_number)
    for name in ("run", "status", "export", "network-sync"):
        child = sub.add_parser(name)
        child.add_argument("--project", type=Path, default=Path.cwd())
        if name == "export":
            child.add_argument("--output", required=True)
            child.add_argument("--bloch-source", action="store_true",
                               help="Refresh and attach a Genesis-4 source checkpoint")
    verify = sub.add_parser("verify", help="Verify exported file integrity offline")
    verify.add_argument("file", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.action == "doctor":
            missing = False
            for vm in ("evm", "svm"):
                try:
                    binary = runtime(vm)
                    result = subprocess.run([binary, "--version"], text=True, capture_output=True, timeout=15)
                    if result.returncode:
                        raise ValueError(result.stderr.strip() or "Runtime failed to start")
                    print(f"{vm.upper()}: {result.stdout.strip()} ({binary})")
                except (ValueError, subprocess.TimeoutExpired) as error:
                    print(f"{vm.upper()}: {error}")
                    missing = True
            return int(missing)
        if args.action == "init":
            initialize(args)
        elif args.action == "verify":
            verify_artifact(args.file)
        else:
            project = args.project.resolve()
            config = load_config(project)
            if args.action == "network-sync":
                import bloch_network
                result = bloch_network.sync(project / ".bloch-dev/bloch-source.json")
                print(json.dumps(result, indent=2))
            elif args.action == "run":
                ports = [config["port"]] if config["vm"] == "evm" else [config["port"], config["port"] + 1, config["port"] + 2]
                for port in ports:
                    with socket.socket() as check:
                        check.bind(("127.0.0.1", port))
                cmd = command(config, project)
                (project / ".bloch-dev").mkdir(exist_ok=True, mode=0o700)
                print(f"Local {config['vm'].upper()} RPC: http://127.0.0.1:{config['port']}\n"
                      "Development funds only. Stop with Ctrl-C; state is retained.", flush=True)
                os.execv(cmd[0], cmd)
            elif args.action == "status":
                print(json.dumps(observe(config), indent=2))
            else:
                source = None
                if args.bloch_source:
                    import bloch_network
                    source = bloch_network.sync(project / ".bloch-dev/bloch-source.json")
                export_observation(config, args.output, source)
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as error:
        print(f"bloch-dev: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
