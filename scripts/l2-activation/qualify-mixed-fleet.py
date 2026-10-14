#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Mixed-fleet qualification of the native-L2 flag day on a disposable,
loopback-only devnet (M9).

Four validators on one fresh devnet (equal stake, real hybrid keys, the devnet
TCP mesh the Genesis-4 fleet runs):

  node0          BASELINE   the release the fleet runs (no L2 gate at all)
  node1..node3   REHEARSAL  this branch built with `--features
                            l2-activation-rehearsal` and
                            BLOCH_L2_REHEARSAL_ACTIVATION_EPOCH=<E>
  node4          INERT      (optional) this branch built for mainnet: the gate
                            is the sentinel; keyless observer

Expected, and asserted:

  * before epoch E every node follows the same chain and finalizes it: the
    finalized checkpoint and every canonical block below slot E*32 are
    identical (block id, state root, height) on all nodes;
  * at the first block of epoch E the rehearsal nodes install the L2 (the
    state root now carries the 0x21 leaf); the baseline and the inert build
    refuse that block (state root mismatch) and diverge there, not at the
    first L2 transaction;
  * the rehearsal side (3 of 4 stake, > 2/3) keeps finalizing past E; the
    baseline side (1 of 4) cannot finalize anything at or after E.

No existing work directory is accepted; no production key, host or state is
read. Rehearsal builds refuse the Genesis-4 mainnet manifest.
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

SLOTS_PER_EPOCH = 32


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--baseline", required=True, type=Path)
    ap.add_argument("--rehearsal", required=True, type=Path)
    ap.add_argument("--inert", type=Path, help="this branch's mainnet build (optional observer)")
    ap.add_argument("--activation-epoch", required=True, type=int,
                    help="the epoch the rehearsal binary was compiled with")
    ap.add_argument("--work", required=True, type=Path)
    ap.add_argument("--port-base", type=int, default=29600)
    ap.add_argument("--slot-ms", type=int, default=1000)
    ap.add_argument("--epochs-after", type=int, default=5)
    args = ap.parse_args()
    assert 500 <= args.slot_ms <= 2000
    assert 3 <= args.activation_epoch <= 20, "pick an activation epoch between 3 and 20"
    epoch = args.activation_epoch
    gate_slot = epoch * SLOTS_PER_EPOCH
    stop_slot = (epoch + args.epochs_after) * SLOTS_PER_EPOCH
    bins = {"baseline": args.baseline.resolve(), "rehearsal": args.rehearsal.resolve()}
    if args.inert:
        bins["inert"] = args.inert.resolve()
    for b in bins.values():
        assert b.is_file() and os.access(b, os.X_OK), f"{b} is not an executable"
    assert len({sha(b) for b in bins.values()}) == len(bins), "distinct binaries required"
    roles = ["baseline", "rehearsal", "rehearsal", "rehearsal"] + (["inert"] if args.inert else [])
    work = args.work.resolve()
    work.mkdir(mode=0o700, parents=False, exist_ok=False)
    env = {k: v for k, v in os.environ.items() if not k.startswith("BLOCH_")}
    env["BLOCH_KEYSTORE_ALLOW_PLAINTEXT"] = "1"
    processes, handles = [], []
    report = {"status": "RUNNING", "activation_epoch": epoch, "gate_slot": gate_slot, "stop_slot": stop_slot,
              "slot_ms": args.slot_ms, "roles": roles, "transport": "devnet",
              "binary_sha256": {k: sha(v) for k, v in bins.items()}}

    def save():
        (work / "report.json").write_text(json.dumps(report, indent=2) + "\n")

    def run(binary, *command, timeout=60):
        result = subprocess.run([str(binary), *map(str, command)], env=env,
                                capture_output=True, text=True, timeout=timeout)
        assert result.returncode == 0, (command[0], result.stderr[-2000:])
        return result.stdout

    def rpc(i, method, params=None):
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []}).encode()
        req = urllib.request.Request(f"http://127.0.0.1:{args.port_base + i}", data=body,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=3) as response:
            return json.load(response)

    def block_at(i, slot):
        r = rpc(i, "getblockbyslot", [slot])
        return r.get("result")

    def launch(i):
        binary = bins[roles[i]]
        data = work / f"node{i}"
        data.mkdir(mode=0o700)
        if i < 4:
            shutil.copy2(work / f"key{i}" / "validator.key", data / "validator.key")
        handle = (work / f"node{i}.log").open("w")
        handles.append(handle)
        # The devnet TCP mesh is the transport the Genesis-4 fleet runs; full
        # mesh, every node lists every other one. (On libp2p this Mac's
        # port-reuse dials left each node attached to node0 only: a star
        # through the BASELINE, which stops relaying the rehearsal side's
        # blocks at the gate and partitions it. Mainnet lesson: upgraded
        # nodes must peer with each other directly, not via old relays.)
        command = [str(binary), "run", "--data-dir", str(data), "--genesis", str(work / "genesis.bin"),
                   "--transport", "devnet", "--listen", str(args.port_base + 100 + i), "--listen-addr", "127.0.0.1",
                   "--peers", ",".join(f"127.0.0.1:{args.port_base + 100 + p}" for p in range(len(roles)) if p != i),
                   "--rpc-bind", "127.0.0.1", "--rpc-port", str(args.port_base + i),
                   "--stop-at-slot", str(stop_slot)]
        processes.append(subprocess.Popen(command, env=env, stdout=handle, stderr=subprocess.STDOUT))

    try:
        for offset in [*range(len(roles)), *range(100, 100 + len(roles))]:
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", args.port_base + offset))
        report["buildinfo"] = {k: json.loads(run(b, "buildinfo")) for k, b in bins.items()}
        assert "l2-activation-rehearsal" in report["buildinfo"]["rehearsal"]["build_version"], \
            "the rehearsal binary must be built with --features l2-activation-rehearsal"
        for k in ("baseline", "inert"):
            if k in report["buildinfo"]:
                assert "rehearsal" not in report["buildinfo"][k]["build_version"], f"{k} is a rehearsal build"
        for i in range(4):
            run(bins["baseline"], "keygen", "--allow-plaintext-keystore", "--dir", work / f"key{i}", "--index", i)
        run(bins["baseline"], "genesis", "--keys", ",".join(str(work / f"key{i}") for i in range(4)),
            "--out", work / "genesis.bin", "--slot-ms", args.slot_ms, "--start-in", 30, "--bind-genesis")
        # Staggered: a node dials only listeners that are already up (the
        # swarm does not redial a failed bootstrap peer).
        for i in range(len(roles)):
            launch(i)
        deadline = time.monotonic() + 10 + stop_slot * args.slot_ms / 1000 + 120
        pre_gate_checked = False
        rounds = []
        while time.monotonic() < deadline:
            snapshots = []
            for i in range(len(roles)):
                try:
                    snapshots.append(rpc(i, "getchaininfo").get("result"))
                except (OSError, ValueError):
                    snapshots.append(None)
            rounds.append(snapshots)
            # Phase A: everyone finalized something, nobody is past the gate yet.
            if (not pre_gate_checked and all(snapshots)
                    and min(s["finalized"]["epoch"] for s in snapshots) >= 2
                    and max(s["slot"] for s in snapshots) < gate_slot):
                checkpoint = min(snapshots, key=lambda s: s["finalized"]["epoch"])["finalized"]
                blocks = [rpc(i, "getblockbyid", [checkpoint["root"]])["result"] for i in range(len(roles))]
                assert all(b["finalized"] for b in blocks), "pre-gate checkpoint is not final on every node"
                assert len({(b["block_id"], b["state_root"], b["height"]) for b in blocks}) == 1
                report["pre_gate_finalized_checkpoint"] = checkpoint
                pre_gate_checked = True
                save()
                print(f"pre-gate: all {len(roles)} nodes finalized epoch {checkpoint['epoch']} identically", flush=True)
            if all(p.poll() is not None for p in processes):
                break
            time.sleep(1)
        (work / "rpc-rounds.json").write_text(json.dumps(rounds) + "\n")
        # The live pre-gate snapshot is best effort (RPC timing); the replayed
        # comparison below is the assertion.
        report["pre_gate_live_snapshot"] = pre_gate_checked
        # The nodes stop at stop_slot; restart them read-only would replay.
        # Instead, query the final state from the last RPC round of each node
        # and from the stopped logs.
        final = rounds[-1] if rounds and all(rounds[-1]) else None
        full = [r for r in rounds if all(r)]
        report["peers_last_round"] = [s["transport"]["peers"] for s in full[-1]] if full else []
        report["exit_codes"] = [p.wait(timeout=30) for p in processes]
        stop_lines = []
        for i in range(len(roles)):
            text = (work / f"node{i}.log").read_text(errors="replace")
            m = re.findall(r"STOP at slot \d+: head slot (\d+), (\d+) blocks, state root ([0-9a-f]{64}), "
                           r"justified e(\d+) \(([0-9a-f]+)\), finalized e(\d+) \(([0-9a-f]+)\)", text)
            assert m, f"node{i} has no STOP line"
            stop_lines.append(m[-1])
            report.setdefault("root_mismatch_log_lines", []).append(
                sum(1 for line in text.splitlines() if "StateRootMismatch" in line))
        report["stop"] = stop_lines
        save()
        # Phase B, from the replayed logs (deterministic, no live RPC race):
        # replay each node's own log with RPC on, read the canonical chains.
        for i in range(len(roles)):
            data = work / f"replay{i}"
            data.mkdir(mode=0o700)
            shutil.copy2(work / f"node{i}" / "blocks.log", data / "blocks.log")
        finalized = [int(s[5]) for s in stop_lines]
        new = [i for i, r in enumerate(roles) if r == "rehearsal"]
        old = [i for i, r in enumerate(roles) if r != "rehearsal"]
        # Epoch E's checkpoint is the first block at or after slot 32*E: the
        # activation block's epoch. Finalizing it finalizes the L2 boundary.
        assert all(finalized[i] >= epoch for i in new), ("rehearsal side must finalize the gate epoch", finalized)
        assert all(2 <= finalized[i] < epoch for i in old), \
            ("baseline/inert side must finalize before the gate and not at or after it", finalized)
        report["finalized_epochs"] = finalized
        report.update(status="PHASE-B-RPC")
        save()
        # Re-serve each stopped data dir (replay, no peers) to compare blocks by slot.
        for i in range(len(roles)):
            binary = bins[roles[i]]
            handle = (work / f"serve{i}.log").open("w")
            handles.append(handle)
            processes.append(subprocess.Popen(
                [str(binary), "run", "--data-dir", str(work / f"replay{i}"), "--genesis", str(work / "genesis.bin"),
                 "--transport", "devnet", "--listen", str(args.port_base + 200 + i), "--listen-addr", "127.0.0.1",
                 "--rpc-bind", "127.0.0.1", "--rpc-port", str(args.port_base + i), "--replay-from-genesis"],
                env=env, stdout=handle, stderr=subprocess.STDOUT))
        ready = time.monotonic() + 180
        while time.monotonic() < ready:
            try:
                if all(rpc(i, "getchaininfo").get("result") for i in range(len(roles))):
                    break
            except (OSError, ValueError):
                pass
            time.sleep(1)
        shared, first_new = 0, None
        for slot in range(1, stop_slot + 1):
            values = [block_at(i, slot) for i in range(len(roles))]
            if slot < gate_slot:
                ids = {(v["block_id"], v["state_root"], v["height"]) if v else None for v in values}
                assert len(ids) == 1, ("divergence before the gate", slot)
                shared += values[0] is not None
            elif first_new is None and values[new[0]] is not None:
                first_new = values[new[0]]
                assert len({(values[i] or {}).get("block_id") for i in new}) == 1, "rehearsal nodes disagree"
                for i in old:
                    r = rpc(i, "getblockbyid", [first_new["block_id"]])
                    assert "result" not in r or r["result"] is None, (f"node{i} accepted the activation block", slot)
        assert first_new is not None, "no rehearsal block at or after the gate"
        l2 = [rpc(i, "getl2settlement").get("result") for i in new]
        assert all(x and x["profile"]["activated"] for x in l2), ("L2 not installed on rehearsal nodes", l2)
        if "inert" in roles:
            assert rpc(roles.index("inert"), "getl2settlement").get("result") is None, "inert build installed an L2"
        report.update(status="PASS", shared_blocks_before_gate=shared,
                      first_activation_block=first_new, l2_on_rehearsal_nodes=l2)
        print(json.dumps({k: report[k] for k in ("status", "finalized_epochs", "shared_blocks_before_gate",
                                                 "root_mismatch_log_lines")}, indent=2), flush=True)
    except BaseException as error:
        report.update(status="FAIL", error=repr(error))
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
