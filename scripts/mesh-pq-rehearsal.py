#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Rehearse the --mesh-security rollout on a throwaway local devnet.

Four validators and one keyless observer on the devnet TCP mesh, then the
exact rollout the operator runbook prescribes, one node at a time:

  phase 0  everyone `plain` (today's fleet)            -> finality advances
  phase 1  rolling restart into `offer`                -> finality never stops,
           mixed plain/offer pairs keep talking          observer keeps following
  phase 2  rolling restart into `require` + allow-list -> finality never stops
  phase 3  negative checks against the sealed fleet:
           - a legacy `plain` node cannot follow
           - a `require` node whose identity is not on the allow-list cannot follow
           - a raw plain get-blocks frame gets no answer
  final    every node agrees on the finalized checkpoint

Throwaway keys, throwaway chain, loopback only. Usage:

  scripts/mesh-pq-rehearsal.py --bin target/release/bloch-pos --out /tmp/mesh-pq-run
"""

import argparse
import json
import os
import re
import signal
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

N_VALIDATORS = 4
SLOTS_PER_EPOCH = 32


class Rehearsal:
    def __init__(self, args):
        self.bin = str(Path(args.bin).resolve())
        self.out = Path(args.out).resolve()
        self.slot_ms = args.slot_ms
        self.rpc_base = args.port_base
        self.mesh_base = args.port_base + 100
        self.env = dict(os.environ, BLOCH_KEYSTORE_ALLOW_PLAINTEXT="1")
        self.procs = {}
        self.modes = {}
        self.checks = []
        self.allow_file = self.out / "mesh-allow.txt"
        self.t0 = time.time()

    # ── plumbing ─────────────────────────────────────────────────────────
    def log(self, msg):
        line = f"[{time.time() - self.t0:7.1f}s] {msg}"
        print(line, flush=True)
        with open(self.out / "rehearsal.log", "a") as f:
            f.write(line + "\n")

    def check(self, name, ok, detail=None):
        self.checks.append({"check": name, "ok": bool(ok), "detail": detail})
        self.log(f"{'PASS' if ok else 'FAIL'}: {name}" + (f" — {json.dumps(detail)}" if detail is not None else ""))
        return ok

    def rpc(self, i, method, params=()):
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.rpc_base + i}",
            data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": list(params)}).encode(),
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=2) as r:
            body = json.load(r)
        if "error" in body and body["error"]:
            raise RuntimeError(body["error"])
        return body["result"]

    def info(self, i):
        try:
            return self.rpc(i, "getchaininfo")
        except Exception:
            return None

    def wait(self, what, cond, timeout):
        deadline = time.time() + timeout
        while time.time() < deadline:
            v = cond()
            if v:
                return v
            time.sleep(1)
        self.log(f"timed out after {timeout}s waiting for {what}")
        return None

    def epoch_s(self):
        return SLOTS_PER_EPOCH * self.slot_ms / 1000

    # ── nodes ────────────────────────────────────────────────────────────
    def node_dir(self, i):
        return self.out / f"node{i}"

    def peers_for(self, i, members):
        return ",".join(f"127.0.0.1:{self.mesh_base + j}" for j in members if j != i)

    def start(self, i, mode, members, allow=False):
        d = self.node_dir(i)
        d.mkdir(parents=True, exist_ok=True)
        cmd = [self.bin, "run", "--data-dir", str(d), "--genesis", str(self.genesis),
               "--transport", "devnet", "--no-doppelganger-check",
               "--listen", str(self.mesh_base + i), "--listen-addr", "127.0.0.1",
               "--peers", self.peers_for(i, members),
               "--rpc-bind", "127.0.0.1", "--rpc-port", str(self.rpc_base + i)]
        if mode != "plain":
            cmd += ["--mesh-security", mode]
        if allow:
            cmd += ["--mesh-allow", str(self.allow_file)]
        logf = open(d / "node.log", "a")
        logf.write(f"\n# {' '.join(cmd)}\n")
        logf.flush()
        self.procs[i] = subprocess.Popen(cmd, stdout=logf, stderr=subprocess.STDOUT, env=self.env)
        self.modes[i] = mode
        if not self.wait(f"node{i} RPC", lambda: self.info(i), 60):
            raise SystemExit(f"node{i} did not come up; see {d / 'node.log'}")

    def stop(self, i):
        p = self.procs.pop(i, None)
        if p and p.poll() is None:
            p.send_signal(signal.SIGTERM)
            try:
                p.wait(timeout=30)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()

    def stop_all(self):
        for i in list(self.procs):
            self.stop(i)

    def identity(self, i):
        text = (self.node_dir(i) / "node.log").read_text(errors="replace")
        ids = re.findall(r"mesh security: \w+ \(ML-KEM-768\+X25519, ML-DSA-65 identity ([0-9a-f]{64})", text)
        return ids[-1] if ids else None

    # ── observations ─────────────────────────────────────────────────────
    def snapshot(self, nodes):
        return {i: self.info(i) for i in nodes}

    def finalized(self, nodes):
        snap = self.snapshot(nodes)
        if any(v is None for v in snap.values()):
            return None
        return {i: v["finalized"]["epoch"] for i, v in snap.items()}

    def wait_finality_advances(self, nodes, by, label):
        base = self.finalized(nodes)
        floor = min(base.values()) if base else 0
        target = floor + by
        got = self.wait(f"finality >= epoch {target} on {nodes}",
                        lambda: (f := self.finalized(nodes)) and min(f.values()) >= target and f,
                        timeout=int(self.epoch_s() * (by + 6)))
        return self.check(f"{label}: finality advanced by {by} epochs on every validator",
                          got, {"from": floor, "now": got})

    def wait_caught_up(self, i, nodes, label):
        def ok():
            snap = self.snapshot(sorted(set(nodes) | {i}))
            if any(v is None for v in snap.values()):
                return None
            top = max(v["slot"] for v in snap.values())
            return snap[i]["slot"] >= top - 4 and snap[i]["slot"]
        got = self.wait(f"node{i} caught up", ok, timeout=int(self.epoch_s() * 4))
        return self.check(f"{label}: node{i} back at the head after restart", got, {"slot": got})

    def follows(self, i, seconds):
        a = self.info(i)
        time.sleep(seconds)
        b = self.info(i)
        if not a or not b:
            return False, {"before": a and a["height"], "after": b and b["height"]}
        return b["height"] > a["height"], {"height_before": a["height"], "height_after": b["height"]}

    # ── the run ──────────────────────────────────────────────────────────
    def setup(self):
        self.out.mkdir(parents=True, exist_ok=False)
        keydirs = []
        for i in range(N_VALIDATORS):
            d = self.node_dir(i)
            d.mkdir(parents=True)
            subprocess.run([self.bin, "keygen", "--allow-plaintext-keystore", "--dir", str(d), "--index", str(i)],
                           check=True, env=self.env, capture_output=True)
            keydirs.append(str(d))
        self.genesis = self.out / "genesis.blg"
        subprocess.run([self.bin, "genesis", "--keys", ",".join(keydirs), "--out", str(self.genesis),
                        "--slot-ms", str(self.slot_ms), "--start-in", "8"],
                       check=True, env=self.env, capture_output=True)
        self.validators = list(range(N_VALIDATORS))
        self.observer = N_VALIDATORS
        self.members = self.validators + [self.observer]

    def run(self):
        self.setup()
        build = subprocess.run([self.bin, "--version"], capture_output=True, text=True).stdout.strip()
        self.log(f"binary {self.bin} {build}; {N_VALIDATORS} validators + 1 observer, {self.slot_ms} ms slots")

        # phase 0
        for i in self.members:
            self.start(i, "plain", self.members)
        self.log("phase 0: everyone plain")
        self.wait_finality_advances(self.validators, 2, "phase 0 (plain)")

        # phase 1
        self.log("phase 1: rolling plain -> offer")
        for i in self.members:
            self.stop(i)
            self.start(i, "offer", self.members)
            self.wait_caught_up(i, self.validators, "phase 1")
            if i == 1:
                ok, d = self.follows(self.observer, self.epoch_s() / 2)
                self.check("phase 1 mid-rollout: plain observer still follows a half-offer fleet", ok, d)
        ids = {i: self.identity(i) for i in self.members}
        self.check("phase 1: every node printed an ML-DSA-65 transport identity", all(ids.values()), ids)
        self.wait_finality_advances(self.validators, 2, "phase 1 (offer)")

        # phase 2
        self.allow_file.write_text("# rehearsal fleet\n" + "".join(f"{ids[i]}  # node{i}\n" for i in self.members))
        self.log("phase 2: rolling offer -> require + allow-list")
        for i in self.members:
            self.stop(i)
            self.start(i, "require", self.members, allow=True)
            self.wait_caught_up(i, self.validators, "phase 2")
        self.wait_finality_advances(self.validators, 2, "phase 2 (require + allow-list)")
        ok, d = self.follows(self.observer, self.epoch_s() / 2)
        self.check("phase 2: allow-listed require observer follows", ok, d)

        # phase 3: negative checks
        self.log("phase 3: outsiders against the sealed fleet")
        legacy, stranger = N_VALIDATORS + 1, N_VALIDATORS + 2
        self.start(legacy, "plain", self.validators + [legacy])
        self.start(stranger, "require", self.validators + [stranger])
        time.sleep(self.epoch_s())
        for i, label in [(legacy, "legacy plain node"), (stranger, "require node NOT on the allow-list")]:
            v = self.info(i)
            self.check(f"phase 3: {label} cannot follow (height stays 0)", v and v["height"] == 0,
                       {"height": v and v["height"]})
        self.stop(legacy)
        self.stop(stranger)
        self.check("phase 3: raw plain get-blocks frame gets no answer from a require node",
                   self.raw_plain_probe(0), None)
        refusals = sum((self.node_dir(i) / "node.log").read_text(errors="replace").count("mesh handshake from")
                       for i in self.validators)
        self.check("phase 3: validators logged the refused handshakes", refusals > 0, {"lines": refusals})

        # final
        snap = self.snapshot(self.members)
        fin = {i: (v["finalized"]["epoch"], v["finalized"]["root"]) for i, v in snap.items() if v}
        epochs = {e for e, _ in fin.values()}
        same_root_at_same_epoch = len({r for e, r in fin.values() if e == max(epochs)}) == 1
        self.check("final: every node on one finalized checkpoint (same root at the highest shared epoch)",
                   same_root_at_same_epoch, {"finalized": {f"node{i}": list(v) for i, v in fin.items()}})
        self.wait_finality_advances(self.validators, 1, "final")

    def raw_plain_probe(self, i):
        frame = bytes([0x03]) + (0).to_bytes(8, "little")
        try:
            with socket.create_connection(("127.0.0.1", self.mesh_base + i), timeout=5) as s:
                s.sendall(len(frame).to_bytes(4, "little") + frame)
                s.settimeout(15)
                data = s.recv(4)
                return data == b""
        except (ConnectionResetError, BrokenPipeError, socket.timeout):
            return True

    def report(self):
        passed = all(c["ok"] for c in self.checks)
        summary = {"status": "PASS" if passed else "FAIL", "slot_ms": self.slot_ms,
                   "duration_s": round(time.time() - self.t0), "checks": self.checks}
        (self.out / "report.json").write_text(json.dumps(summary, indent=2) + "\n")
        self.log(f"RESULT: {summary['status']} ({sum(c['ok'] for c in self.checks)}/{len(self.checks)} checks)")
        return passed


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bin", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--slot-ms", type=int, default=500)
    ap.add_argument("--port-base", type=int, default=23400)
    r = Rehearsal(ap.parse_args())
    try:
        r.run()
    finally:
        r.stop_all()
    sys.exit(0 if r.report() else 1)


if __name__ == "__main__":
    main()
