#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Rehearse a binary upgrade of the devnet mesh next to the released binary.

The fleet upgrades in waves and external validators upgrade later, so a new
binary started with the argv the fleet runs today (`--transport devnet
--mesh-security offer`) has to work for weeks next to nodes that still run the
released binary. This puts both binaries in one throwaway local devnet:

  phase 0  everyone on the RELEASED binary, `offer`         -> finality advances
  phase 1  rolling upgrade of validators 0..2 to the CANDIDATE binary, argv
           unchanged; validator 3 and the observer stay released, like an
           external validator that upgrades later            -> finality never stops
           every candidate node: all sessions sealed, none plain
  phase 2  a released `plain` node (no handshake at all) joins
           -> it follows, and the candidates count and name its plain sessions
  phase 3  candidates move to `require`
           -> the released `offer` validator and observer stay connected, sealed
           -> a released `plain` node is cut off and the refusals are counted
  phase 4  one candidate adds `--mesh-plain-allow` for the loopback address
           -> a released `plain` node that only knows that candidate follows
  phase 5  rollback: candidates back to `offer`, the flag left in the argv
           -> finality advances
  phase 6  rollback of the binary: one candidate goes back to the released
           binary on the same data dir                       -> it catches up
  final    every node agrees on the finalized checkpoint, and no node logged
           a refused handshake while everyone ran `offer`

Throwaway keys, throwaway chain, loopback only. Usage:

  scripts/mesh-pq-mixed-version-rehearsal.py \\
      --released-bin <bloch-pos built from the released commit> \\
      --bin <bloch-pos built from the candidate> --out /tmp/mesh-mixed-run
"""

import argparse
import importlib.util
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

_spec = importlib.util.spec_from_file_location("mesh_pq_rehearsal", Path(__file__).with_name("mesh-pq-rehearsal.py"))
_base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_base)

N_VALIDATORS = _base.N_VALIDATORS


class MixedRehearsal(_base.Rehearsal):
    def __init__(self, args):
        super().__init__(args)
        self.released = str(Path(args.released_bin).resolve())
        self.candidate = self.bin
        # Keys and genesis come from the released binary: the chain exists
        # before the upgrade does.
        self.bin = self.released
        self.metrics_base = args.port_base + 200
        self.binaries = {}
        self.plain_allow_file = self.out / "mesh-plain-allow.txt"
        self.start_in = args.start_in
        # The run keeps its signer anchors to itself instead of adding
        # throwaway keys to the operator's ~/.bloch-signer.
        self.env["BLOCH_SIGNER_ANCHOR_DIR"] = str(self.out / "signer-anchor")

    def setup(self):
        self.out.mkdir(parents=True, exist_ok=False)
        (self.out / "signer-anchor").mkdir(mode=0o700)
        keydirs = []
        for i in range(N_VALIDATORS):
            d = self.node_dir(i)
            d.mkdir(parents=True)
            subprocess.run([self.released, "keygen", "--allow-plaintext-keystore", "--dir", str(d), "--index", str(i)],
                           check=True, env=self.env, capture_output=True)
            keydirs.append(str(d))
        self.genesis = self.out / "genesis.blg"
        # Every node must be running before the first slot: a validator that
        # boots after its duties began refuses to sign without a protection
        # record.
        subprocess.run([self.released, "genesis", "--keys", ",".join(keydirs), "--out", str(self.genesis),
                        "--slot-ms", str(self.slot_ms), "--start-in", str(self.start_in)],
                       check=True, env=self.env, capture_output=True)
        self.validators = list(range(N_VALIDATORS))
        self.observer = N_VALIDATORS
        self.members = self.validators + [self.observer]

    # ── nodes ────────────────────────────────────────────────────────────
    def start(self, i, mode, members, binary=None, plain_allow=False, wait=True):
        binary = binary or self.released
        d = self.node_dir(i)
        d.mkdir(parents=True, exist_ok=True)
        cmd = [binary, "run", "--data-dir", str(d), "--genesis", str(self.genesis),
               "--transport", "devnet", "--no-doppelganger-check",
               "--listen", str(self.mesh_base + i), "--listen-addr", "127.0.0.1",
               "--peers", self.peers_for(i, members),
               "--rpc-bind", "127.0.0.1", "--rpc-port", str(self.rpc_base + i),
               "--metrics-bind", "127.0.0.1", "--metrics-port", str(self.metrics_base + i)]
        if mode != "plain":
            cmd += ["--mesh-security", mode]
        if plain_allow:
            cmd += ["--mesh-plain-allow", str(self.plain_allow_file)]
        logf = open(d / "node.log", "a")
        logf.write(f"\n# {' '.join(cmd)}\n")
        logf.flush()
        self.procs[i] = subprocess.Popen(cmd, stdout=logf, stderr=subprocess.STDOUT, env=self.env)
        self.modes[i] = mode
        self.binaries[i] = binary
        if wait:
            self.wait_up(i)

    def wait_up(self, i, timeout=90):
        if not self.wait(f"node{i} RPC", lambda: self.info(i), timeout):
            raise SystemExit(f"node{i} did not come up; see {self.node_dir(i) / 'node.log'}")

    def metrics(self, i):
        try:
            text = urllib.request.urlopen(f"http://127.0.0.1:{self.metrics_base + i}/metrics", timeout=4).read().decode()
        except Exception:
            return None
        out = {}
        for line in text.splitlines():
            if line.startswith("bloch_pos_mesh_"):
                name, _, value = line.partition(" ")
                out[name[len("bloch_pos_mesh_"):]] = int(float(value))
        return out

    def log_text(self, i):
        return (self.node_dir(i) / "node.log").read_text(errors="replace")

    def log_since_last_start(self, i):
        return self.log_text(i).rsplit("\n# ", 1)[-1]

    def version(self, binary):
        return subprocess.run([binary, "--version"], capture_output=True, text=True).stdout.strip()

    def wait_all_sealed(self, i, peers, label):
        """Candidate node `i` has one sealed session per peer in each
        direction and no plain session, and never had a plain one."""
        want = 2 * peers

        def ok():
            m = self.metrics(i)
            return m and m.get("sealed_sessions") == want and m
        got = self.wait(f"node{i}: {want} sealed sessions", ok, timeout=int(self.epoch_s() * 2) + 30) or self.metrics(i)
        clean = bool(got) and got.get("sealed_sessions") == want and all(
            got.get(k) == 0 for k in ("plain_sessions_outbound", "plain_sessions_inbound",
                                      "plain_sessions_outbound_total", "plain_sessions_inbound_total"))
        return self.check(f"{label}: node{i} runs {want} sealed sessions and has never had a plain one", clean, got)

    def cannot_follow(self, i, label):
        v = self.info(i)
        return self.check(f"{label}: node{i} cannot follow (height stays 0)", v and v["height"] == 0,
                          {"height": v and v["height"]})

    # ── the run ──────────────────────────────────────────────────────────
    def run(self):
        self.setup()
        self.log(f"released  {self.released} {self.version(self.released)}")
        self.log(f"candidate {self.candidate} {self.version(self.candidate)}")
        self.log(f"{N_VALIDATORS} validators + 1 observer, {self.slot_ms} ms slots")
        upgraded = self.validators[:-1]
        external = self.validators[-1]
        peers = len(self.members) - 1

        # phase 0
        # Started together and awaited together: the RPC answers from slot 0.
        for i in self.members:
            self.start(i, "offer", self.members, wait=False)
        for i in self.members:
            self.wait_up(i, timeout=self.start_in + 90)
        self.log("phase 0: everyone on the released binary, offer")
        self.wait_finality_advances(self.validators, 2, "phase 0 (released, offer)")

        # phase 1
        self.log(f"phase 1: rolling upgrade of validators {upgraded} to the candidate, argv unchanged")
        for i in upgraded:
            self.stop(i)
            self.start(i, "offer", self.members, binary=self.candidate)
            self.wait_caught_up(i, self.validators, "phase 1")
            self.wait_all_sealed(i, peers, "phase 1")
            if i == upgraded[0]:
                self.wait_finality_advances(self.validators, 1, "phase 1 mid-rollout (1 candidate, 3 released)")
        self.wait_finality_advances(self.validators, 2, "phase 1 (3 candidates, released validator and observer)")
        self.wait_caught_up(external, self.validators, "phase 1: released validator")
        ok, d = self.follows(self.observer, self.epoch_s() / 2)
        self.check("phase 1: released observer follows the mixed fleet", ok, d)
        for i in upgraded:
            self.wait_all_sealed(i, peers, "phase 1 steady state")
        modes = {i: self.metrics(i).get("security_mode") for i in upgraded}
        self.check("phase 1: candidates report mesh_security_mode 1 (offer)", set(modes.values()) == {1}, modes)
        refusals = {i: self.log_text(i).count("mesh handshake") for i in self.members}
        self.check("phases 0-1: no node, released or candidate, logged a refused handshake",
                   not any(refusals.values()), refusals)

        # phase 2
        self.log("phase 2: a released plain node joins the offer fleet")
        legacy = N_VALIDATORS + 1
        self.start(legacy, "plain", self.validators + [legacy])
        ok, d = self.follows(legacy, self.epoch_s())
        self.check("phase 2: released plain node follows the offer fleet", ok, d)
        seen = {i: self.metrics(i).get("plain_sessions_inbound") for i in upgraded}
        self.check("phase 2: every candidate counts its plain inbound session", all(v == 1 for v in seen.values()), seen)
        named = {i: "is PLAIN, not encrypted" in self.log_since_last_start(i) for i in upgraded}
        self.check("phase 2: every candidate names the plain peer in its log", all(named.values()), named)
        self.stop(legacy)
        gone = self.wait("plain gauges back to 0",
                         lambda: all((self.metrics(i) or {}).get("plain_sessions_inbound") == 0 for i in upgraded), 60)
        self.check("phase 2: the plain gauge returns to 0 when the plain peer leaves", gone, None)

        # phase 3
        self.log(f"phase 3: candidates {upgraded} offer -> require; released nodes stay on offer")
        for i in upgraded:
            self.stop(i)
            self.start(i, "require", self.members, binary=self.candidate)
            self.wait_caught_up(i, self.validators, "phase 3")
        self.wait_finality_advances(self.validators, 2, "phase 3 (require candidates, released offer validator)")
        self.wait_caught_up(external, self.validators, "phase 3: released offer validator")
        ok, d = self.follows(self.observer, self.epoch_s() / 2)
        self.check("phase 3: released offer observer follows require candidates", ok, d)
        for i in upgraded:
            self.wait_all_sealed(i, peers, "phase 3")
        cut_off = N_VALIDATORS + 2
        self.start(cut_off, "plain", upgraded + [cut_off])
        time.sleep(self.epoch_s())
        self.cannot_follow(cut_off, "phase 3: released plain node against require candidates")
        refused = {i: self.metrics(i).get("plain_refused_total") for i in upgraded}
        self.check("phase 3: candidates count the refused plain connections", all(v and v > 0 for v in refused.values()), refused)
        self.stop(cut_off)

        # phase 4
        self.log("phase 4: one candidate excepts the loopback address with --mesh-plain-allow")
        self.plain_allow_file.write_text("# rehearsal: the legacy node\n127.0.0.1\n")
        gate = upgraded[0]
        self.stop(gate)
        self.start(gate, "require", self.members, binary=self.candidate, plain_allow=True)
        self.wait_caught_up(gate, self.validators, "phase 4")
        excepted = N_VALIDATORS + 3
        self.start(excepted, "plain", [gate, excepted])
        ok, d = self.follows(excepted, self.epoch_s())
        self.check("phase 4: released plain node follows through the excepting candidate", ok, d)
        m = self.metrics(gate)
        self.check("phase 4: the excepting candidate counts the plain session and keeps its sealed ones",
                   m and m.get("plain_sessions_inbound") == 1 and m.get("sealed_sessions") == 2 * peers, m)
        self.stop(excepted)

        # phase 5
        self.log("phase 5: rollback of the mode, require -> offer, --mesh-plain-allow left in the argv")
        for i in upgraded:
            self.stop(i)
            self.start(i, "offer", self.members, binary=self.candidate, plain_allow=(i == gate))
            self.wait_caught_up(i, self.validators, "phase 5")
        self.wait_finality_advances(self.validators, 2, "phase 5 (back on offer)")

        # phase 6
        self.log(f"phase 6: rollback of the binary on node{gate}, same data dir")
        self.stop(gate)
        self.start(gate, "offer", self.members)
        self.wait_caught_up(gate, self.validators, "phase 6: node back on the released binary")
        self.wait_finality_advances(self.validators, 2, "phase 6")

        # final
        snap = self.snapshot(self.members)
        fin = {i: (v["finalized"]["epoch"], v["finalized"]["root"]) for i, v in snap.items() if v}
        epochs = {e for e, _ in fin.values()}
        same_root = len(fin) == len(self.members) and len({r for e, r in fin.values() if e == max(epochs)}) == 1
        self.check("final: every node on one finalized checkpoint (same root at the highest shared epoch)",
                   same_root, {"finalized": {f"node{i}": list(v) for i, v in fin.items()}})


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--released-bin", required=True, help="bloch-pos built from the released commit")
    ap.add_argument("--bin", required=True, help="bloch-pos built from the candidate")
    ap.add_argument("--out", required=True)
    ap.add_argument("--slot-ms", type=int, default=500)
    ap.add_argument("--port-base", type=int, default=23700)
    ap.add_argument("--start-in", type=int, default=45,
                    help="seconds from genesis creation to slot 0; all five nodes must be running by then")
    r = MixedRehearsal(ap.parse_args())
    try:
        r.run()
    finally:
        r.stop_all()
    sys.exit(0 if r.report() else 1)


if __name__ == "__main__":
    main()
