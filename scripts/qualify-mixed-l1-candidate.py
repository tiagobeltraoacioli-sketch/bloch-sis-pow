#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Qualify two shipping binaries on a disposable, loopback-only L1 network.

Three validators (old/new/old) and one late new observer use real hybrid keys,
libp2p, the unchanged shipping gates, and the normal doppelganger window.
Compare finalized blocks, then replay the same stopped log with both binaries
and both transports. This does not qualify mainnet history or an armed fork.
No existing work directory is accepted; no production key or state is read.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import time
import urllib.request


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ("baseline", "candidate", "work"):
        ap.add_argument("--" + name, required=True, type=Path)
    for name in ("baseline", "candidate"):
        ap.add_argument("--" + name + "-sha256", required=True)
    ap.add_argument("--port-base", type=int, default=29400)
    ap.add_argument("--slot-ms", type=int, default=1000)
    args = ap.parse_args()
    assert 500 <= args.slot_ms <= 2000
    assert 1024 <= args.port_base <= 64000
    bins = [args.baseline.resolve(), args.candidate.resolve()]
    for binary, expected in zip(bins, [args.baseline_sha256, args.candidate_sha256]):
        assert binary.is_file() and sha(binary) == expected, "binary SHA-256 mismatch"
    assert bins[0] != bins[1], "distinct binaries required"
    work = args.work.resolve()
    work.mkdir(mode=0o700, parents=False, exist_ok=False)
    env = {k: v for k, v in os.environ.items() if not k.startswith("BLOCH_")}
    env["BLOCH_KEYSTORE_ALLOW_PLAINTEXT"] = "1"
    processes, handles = [], []
    report = {"status": "RUNNING", "production_qualified": False,
              "activation_boundary_qualified": False, "mainnet_history_qualified": False,
              "slot_ms": args.slot_ms, "stop_slot": 256, "transport": "libp2p",
              "normal_doppelganger_window": True, "binary_sha256": [sha(b) for b in bins]}
    def save():
        (work / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    def run(binary, *command, timeout=60):
        result = subprocess.run([str(binary), *map(str, command)], env=env,
                                capture_output=True, text=True, timeout=timeout)
        assert result.returncode == 0, (command[0], result.stderr[-2000:])
        return result.stdout
    def rpc(i, method, params=None):
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                           "params": params or []}).encode()
        req = urllib.request.Request(f"http://127.0.0.1:{args.port_base+i}",
                                     data=body, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=2) as response:
            return json.load(response)
    def launch(i):
        binary = bins[0] if i in (0, 2) else bins[1]
        data = work / f"node{i}"
        data.mkdir(mode=0o700)
        if i < 3:
            shutil.copy2(work / f"key{i}" / "validator.key", data / "validator.key")
        else:
            assert not any(data.iterdir()), "cold observer must start empty"
        handle = (work / f"node{i}.log").open("w")
        handles.append(handle)
        command = [str(binary), "run", "--data-dir", str(data), "--genesis", str(work / "genesis.bin"),
                   "--transport", "libp2p", "--p2p-listen", f"/ip4/127.0.0.1/tcp/{args.port_base+100+i}",
                   "--rpc-bind", "127.0.0.1", "--rpc-port", str(args.port_base+i), "--stop-at-slot", "256"]
        for peer in range(4):
            if peer != i:
                command += ["--p2p-peer", f"/ip4/127.0.0.1/tcp/{args.port_base+100+peer}"]
        proc = subprocess.Popen(command, env=env, stdout=handle, stderr=subprocess.STDOUT)
        processes.append(proc)
        return proc
    try:
        for offset in [0, 1, 2, 3, 100, 101, 102, 103, 200, 201, 202, 203]:
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", args.port_base + offset))
        report["buildinfo"] = [json.loads(run(b, "buildinfo")) for b in bins]
        for i in range(3):
            run(bins[1], "keygen", "--allow-plaintext-keystore", "--dir", work/f"key{i}", "--index", i)
        run(bins[1], "genesis", "--keys", ",".join(str(work/f"key{i}") for i in range(3)),
            "--out", work/"genesis.bin", "--slot-ms", args.slot_ms, "--start-in", 10, "--bind-genesis")
        for i in range(3):
            launch(i)
        deadline = time.monotonic() + 10 + 256 * args.slot_ms / 1000 + 90
        checked = False
        rounds = []
        while time.monotonic() < deadline:
            snapshots = []
            for i in range(len(processes)):
                try:
                    result = rpc(i, "getchaininfo")
                    snapshots.append(result.get("result"))
                except (OSError, ValueError):
                    snapshots.append(None)
            rounds.append(snapshots)
            current = [s for s in snapshots if s]
            if len(processes) == 3 and len(current) == 3 and min(s["slot"] for s in current) >= 100:
                report["observer_join_head_slot"] = min(s["slot"] for s in current)
                launch(3)
                print("late observer started", flush=True)
            if not checked and len(snapshots) == 4 and all(snapshots) and min(s["finalized"]["epoch"] for s in snapshots) >= 5:
                # Pick the least advanced final checkpoint. Every node must classify
                # its exact block as finalized, then independently agree on every
                # existing block between the first duties and that checkpoint.
                checkpoint = min(snapshots, key=lambda s: s["finalized"]["epoch"])["finalized"]
                blocks = [rpc(i, "getblockbyid", [checkpoint["root"]])["result"] for i in range(4)]
                assert all(b["finalized"] for b in blocks), "checkpoint is not final on every node"
                assert len({(b["block_id"], b["state_root"], b["height"]) for b in blocks}) == 1
                end_slot = min(b["slot"] for b in blocks)
                compared, proposers = [], set()
                for slot in range(64, end_slot + 1):
                    responses = [rpc(i, "getblockbyslot", [slot]) for i in range(4)]
                    if all("error" in r and r["error"]["code"] == -32007 for r in responses):
                        continue
                    assert all("result" in r for r in responses), ("inconsistent canonical slot", slot)
                    values = [r["result"] for r in responses]
                    assert all(v["finalized"] for v in values), ("nonfinal block", slot)
                    assert len({(v["block_id"], v["state_root"], v["height"]) for v in values}) == 1, ("divergence", slot)
                    compared.append(values[0])
                    proposers.add(values[0]["proposer_index"])
                assert len(compared) >= 64, "insufficient finalized history"
                assert proposers == {0, 1, 2}, "every old/new validator must propose"
                assert any(b["slot"] < report["observer_join_head_slot"] for b in compared)
                assert sum(b["attestation_count"] for b in compared) > 0
                (work/"compared-finalized-blocks.json").write_text(json.dumps(compared, indent=2)+"\n")
                report.update(finalized_checkpoint=checkpoint, compared_finalized_blocks=len(compared),
                              proposer_indices=sorted(proposers), late_observer_history_verified=True)
                checked = True
                save()
                print(f"compared {len(compared)} finalized blocks across four nodes", flush=True)
            if all(p.poll() is not None for p in processes):
                break
            time.sleep(1)
        (work/"rpc-rounds.json").write_text(json.dumps(rounds)+"\n")
        assert checked, "finalized comparison did not complete"
        assert len(processes) == 4 and all(p.poll() == 0 for p in processes), "node failure or timeout"
        replays = []
        for i, (binary, transport) in enumerate([(bins[0],"devnet"),(bins[1],"devnet"),
                                                  (bins[0],"libp2p"),(bins[1],"libp2p")]):
            data = work/f"replay{i}"
            data.mkdir(mode=0o700)
            shutil.copy2(work/"node0"/"blocks.log", data/"blocks.log")
            command = ["run", "--data-dir", data, "--genesis", work/"genesis.bin", "--transport", transport,
                       "--rpc-port", "off", "--stop-at-slot", "1", "--replay-from-genesis"]
            if transport == "devnet":
                command += ["--listen", args.port_base+200+i, "--listen-addr", "127.0.0.1"]
            else:
                command += ["--p2p-listen", f"/ip4/127.0.0.1/tcp/{args.port_base+200+i}"]
            result = run(binary, *command, timeout=120)
            (work/f"replay{i}.log").write_text(result)
            match = re.search(r"STOP at slot 1: head slot (\d+), (\d+) blocks, state root ([0-9a-f]{64}), justified e(\d+) \(([0-9a-f]+)\), finalized e(\d+) \(([0-9a-f]+)\)", result)
            assert match, "missing replay result"
            replays.append(list(match.groups()))
        assert all(r == replays[0] for r in replays), "old/new replay mismatch"
        report.update(status="PASS", replay_results=replays, synthetic_history_replay_qualified=True,
                      mixed_shipping_versions_below_gate_qualified=True,
                      source_log_sha256=sha(work/"node0"/"blocks.log"))
        print(json.dumps(report, indent=2), flush=True)
    except BaseException as error:
        report.update(status="FAIL", error=str(error))
        raise
    finally:
        for proc in processes:
            if proc.poll() is None:
                proc.terminate()
        for proc in processes:
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        for handle in handles:
            handle.close()
        save()


if __name__ == "__main__":
    main()
