#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Local HF1/HF2/HF3 activation rehearsal on a throwaway loopback devnet.

Normally started by `scripts/hf-rehearsal/run.sh`, which builds the two
binaries this script needs from armed source copies (see arm.py):

  --candidate-bin  the upgraded build: past flag days armed early, HF1/HF2/HF3
                   gates at --hf1/--hf2/--hf3 (defaults e10/e14/e18)
  --baseline-bin   the NON-upgraded build: the same past flag days, no HF gates

Network: N validators (default 12, Genesis-4 devnet manifest, fresh plaintext
throwaway keys generated here, uneven 1x/2x/3x stakes as `genesis` assigns
them) running the candidate, plus one keyless observer running the baseline
(the node that does not upgrade). Everything binds 127.0.0.1; every node
dials only harness relays (one per ordered pair) so a partition is a real
cut; there are no bootnodes, no libp2p, and the manifest is new, so the
genesis digest — the network identity every data dir and handshake binds —
is unique to the run. Nothing reads or writes outside --work.

Timeline (epochs; 32 slots each):

  e3        pre-activation offence: validator P re-signs its own recent block
            (devnet-equivocate --evidence-out), evidence held, NOT sent; an
            immediate submission must be refused (slashing not active yet)
  e6        past flag days (2884 group) activate — SLASHING_EVIDENCE included
  e10 HF1   finality must cross the boundary
  e11-e13   partition: a minority of ~1/3 stake is cut off; majority keeps
            finalizing, minority freezes; heal at e13, everyone reconverges
  e14 HF2   finality must cross the boundary
  e15       the held pre-activation evidence is submitted -> must be refused;
            a NEW offence by validator Q is sent to an observer -> Q must be
            slashed on every upgraded node
  e16       (if the build has a suite-0x0003 keygen) spend of the 0x0003
            allocation before HF3 -> must be refused
  e18 HF3   finality must cross the boundary
  e19       KES rotation (if the build has one), 0x0003 spend (if the build
            has the suite), and an ordinary TransferV2 spend as a control
  e21-e27   inactivity: validators holding > 1/3 of the remaining stake are
            stopped; finality must stall and the leak must bite; restarted at
            e27, finality must resume
  e31       stop; every data dir is replayed offline from genesis by its own
            binary and the canonical chains are compared slot by slot

Checks print PASS / FAIL / SKIP; exit status is 0 only with no FAIL. A SKIP
is something this build cannot do (e.g. no KES CLI on b4a21fb6) — read them.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import lifecycle_devnet_soak_lib as lib  # noqa: E402
from lifecycle_devnet_soak_lib import RpcError, SoakError  # noqa: E402

SPE = 32
PANIC_RE = re.compile(r"panicked at|RUST_BACKTRACE|stack overflow|SIGSEGV")


class Check:
    def __init__(self):
        self.rows: list[dict] = []

    def add(self, name: str, status: str, evidence) -> None:
        assert status in ("PASS", "FAIL", "SKIP")
        self.rows.append({"name": name, "status": status, "evidence": evidence})
        print(f"[{status}] {name}: {json.dumps(evidence, default=str)[:400]}", flush=True)

    def ok(self, name: str, cond: bool, evidence) -> bool:
        self.add(name, "PASS" if cond else "FAIL", evidence)
        return cond


class Rehearsal:
    def __init__(self, args):
        self.a = args
        self.work = args.work.resolve()
        self.n = args.validators
        self.obs = self.n  # index of the non-upgraded observer
        self.total_nodes = self.n + 1
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("BLOCH_")}
        self.env["BLOCH_KEYSTORE_ALLOW_PLAINTEXT"] = "1"
        self.cand = lib.Bin(args.candidate_bin.resolve(), self.env, self.work / "commands.log")
        self.base = lib.Bin(args.baseline_bin.resolve(), self.env, self.work / "commands.log")
        self.genesis = self.work / "genesis.bin"
        self.checks = Check()
        self.samples: list[dict] = []
        self.events: list[dict] = []
        self.stop_sampler = threading.Event()
        self.nodes: list[lib.Node] = []
        self.mesh: lib.RelayMesh | None = None
        self.arming = json.loads(args.arming.read_text()) if args.arming and args.arming.exists() else {}
        self.hf_armed = bool(self.arming.get("hf_constants")) or bool(self.arming.get("feature_mode"))
        self.stakes: dict[int, int] = {}
        # (label, epoch) whose first block must be finalized and shared; the
        # KES driver replaces these with its own schedule.
        self.boundaries = [("HF1", args.hf1), ("HF2", args.hf2), ("HF3", args.hf3)]
        self.proposers: dict[int, int] = {}
        self.allocs: dict[str, dict] = {}

    # ── ports ────────────────────────────────────────────────────────────
    def rpc_port(self, i): return self.a.port_base + i
    def metrics_port(self, i): return self.a.port_base + 100 + i
    def mesh_port(self, i): return self.a.port_base + 200 + i
    def replay_rpc(self, i): return self.a.port_base + 300 + i
    def replay_mesh(self, i): return self.a.port_base + 400 + i
    def relay_base(self): return self.a.port_base + 1000

    def log(self, msg: str) -> None:
        line = f"{time.strftime('%H:%M:%S')} e{self.clock.wall_epoch() if hasattr(self, 'clock') else '-'} {msg}"
        print(line, flush=True)
        with open(self.work / "events.log", "a") as fh:
            fh.write(line + "\n")

    def event(self, kind: str, **kw) -> None:
        kw.update(kind=kind, wall_epoch=self.clock.wall_epoch(), wall_slot=self.clock.wall_slot())
        self.events.append(kw)
        self.log(f"{kind}: {json.dumps(kw, default=str)[:300]}")

    def rpc(self, i, method, params=None, port=None, timeout=3.0):
        return lib.rpc(port or self.rpc_port(i), method, params, timeout=timeout)

    # ── setup ────────────────────────────────────────────────────────────
    def preflight(self) -> None:
        import socket
        for off in [*range(0, 500), *range(1000, 1000 + 16 * 16)]:
            with socket.socket() as s:
                try:
                    s.bind(("127.0.0.1", self.a.port_base + off))
                except OSError:
                    raise SoakError(f"port {self.a.port_base + off} is busy; pick another --port-base")
        bi = {"candidate": self.cand.buildinfo(), "baseline": self.base.buildinfo()}
        (self.work / "buildinfo.json").write_text(json.dumps(bi, indent=2) + "\n")
        self.cand_help = self.cand.run(["--help"], timeout=30).stdout
        self.log(f"candidate {bi['candidate'].get('build_version')} / baseline {bi['baseline'].get('build_version')}")

    def keys_and_genesis(self) -> None:
        keydirs = []
        for i in range(self.n):
            d = self.work / "keys" / f"v{i}"
            self.base.keygen(d, i)
            keydirs.append(d)
        allocs: list[tuple[str, int]] = []
        names: list[str] = []
        # Control funder (classic suite) — an ordinary TransferV2 after HF3.
        fdir = self.work / "keys" / "funder-classic"
        self.base.keygen(fdir, 900)
        _, pk, _ = self.base.keygen_public(fdir)
        allocs.append((lib.sha3_hex(pk), 1_000 * 100_000_000)); names.append("classic")
        self.keys = {"classic": fdir}
        # Suite 0x0003 funder, only if the candidate can make such a key.
        self.suite3 = None
        if re.search(r"0x0003|slh", self.cand_help, re.I):
            sdir = self.work / "keys" / "funder-0x0003"
            for flags in (["--suite", "0x0003"], ["--suite", "3"], ["--suite", "slh-dsa"]):
                try:
                    self.cand.run(["keygen", "--dir", str(sdir), "--index", "901", *flags], timeout=600)
                    _, spk, _ = self.cand.keygen_public(sdir)
                    self.suite3 = {"dir": sdir, "flags": flags, "pubkey_prefix": spk[:8]}
                    allocs.append((lib.sha3_hex(spk), 1_000 * 100_000_000)); names.append("suite3")
                    self.keys["suite3"] = sdir
                    break
                except SoakError as e:
                    shutil.rmtree(sdir, ignore_errors=True)
                    self.suite3_error = str(e)[-300:]
        # Invariance: per round, a TransferV2, a funded validator deposit and a
        # funded delegation signed with TODAY's tools (the baseline binary's CLI)
        # must be included after every gate. One funder per kind, one opening
        # allocation per round (amounts differ by a few sat so outpoints are distinct).
        self.inv_rounds = [] if getattr(self.a, "no_invariance", True) else ["pre-HF1", "post-HF1", "post-HF2", "post-HF3"]
        self.inv_keys: dict[str, tuple[Path, str]] = {}
        for k, (role, idx) in enumerate((("transfer", 910), ("deposit", 911), ("delegate", 912))):
            if not self.inv_rounds:
                break
            d = self.work / "keys" / f"inv-{role}"
            self.base.keygen(d, idx)
            _, pk, _ = self.base.keygen_public(d)
            (d / "pubkey.hex").write_text(pk + "\n")
            self.inv_keys[role] = (d, pk)
            for r_i, r in enumerate(self.inv_rounds):
                sat = (25_010 if role == "deposit" else 200) * 100_000_000 + r_i
                allocs.append((lib.sha3_hex(pk), sat)); names.append(f"inv-{role}-{r}")
        for r in self.inv_rounds:
            jd = self.work / "keys" / f"inv-joiner-{r}"
            self.base.keygen(jd, "auto")
        args = ["genesis", "--keys", ",".join(map(str, keydirs)), "--out", str(self.genesis),
                "--slot-ms", str(self.a.slot_ms), "--start-in", str(self.a.start_in)]
        if self.a.bind_genesis:
            args.append("--bind-genesis")
        for sh, sat in allocs:
            args += ["--alloc", f"{sh}:{sat}"]
        out = self.base.run(args, timeout=600)
        found = lib.ALLOC_RE.findall(out.stdout + out.stderr)
        assert len(found) == len(allocs), out.stdout[-1500:]
        for name, (n_, txid, vout, sat, sh) in zip(names, found):
            self.allocs[name] = {"txid": txid, "vout": int(vout), "sat": int(sat), "script_hash": sh}
        gms, sms = lib.manifest_clock(self.genesis)
        self.clock = lib.Clock(gms, sms)
        self.keydirs = keydirs

    def launch_all(self) -> None:
        self.mesh = lib.RelayMesh(self.total_nodes, self.relay_base(), self.a.port_base + 200)
        self.mesh.start_all()
        for i in range(self.total_nodes):
            upgraded = i != self.obs
            d = self.work / f"node{i}"
            d.mkdir(parents=True, exist_ok=True)
            if upgraded:
                shutil.copy2(self.keydirs[i] / "validator.key", d / "validator.key")
            binary = self.cand.path if upgraded else self.base.path
            cmd = [str(binary), "run", "--data-dir", str(d), "--genesis", str(self.genesis),
                   "--transport", "devnet", "--no-doppelganger-check",
                   "--listen", str(self.mesh_port(i)), "--listen-addr", "127.0.0.1",
                   "--peers", ",".join(self.mesh.peers_for(i)),
                   "--rpc-bind", "127.0.0.1", "--rpc-port", str(self.rpc_port(i)),
                   "--metrics-bind", "127.0.0.1", "--metrics-port", str(self.metrics_port(i))]
            node = lib.Node(name=f"node{i}", slot=i, data_dir=d, rpc_port=self.rpc_port(i),
                            mesh_port=self.mesh_port(i), metrics_port=self.metrics_port(i), cmd=cmd,
                            env=self.env, log_path=d / "run.log", has_key=upgraded)
            self.nodes.append(node)
        for node in self.nodes:
            node.start()
            time.sleep(0.2)
        self.event("launched", nodes=self.total_nodes, observer=self.obs)

    # ── observation ──────────────────────────────────────────────────────
    def sampler(self) -> None:
        while not self.stop_sampler.is_set():
            ws = self.clock.wall_slot()
            for i in range(self.total_nodes):
                try:
                    r = self.rpc(i, "getchaininfo", timeout=2.0)
                    self.samples.append({"t": time.time(), "wall_slot": ws, "node": i, "slot": r["slot"],
                                         "height": r["height"], "head": r["block_id"], "root": r.get("state_root"),
                                         "fin": r["finalized"]["epoch"], "fin_root": r["finalized"]["root"],
                                         "just": r["justified"]["epoch"]})
                except (SoakError, KeyError, TypeError):
                    pass
            self.stop_sampler.wait(2.0)

    def latest(self, i) -> dict | None:
        for s in reversed(self.samples):
            if s["node"] == i:
                return s
        return None

    def window(self, nodes, e_from, e_to) -> list[dict]:
        lo, hi = e_from * SPE, e_to * SPE
        return [s for s in self.samples if s["node"] in nodes and lo <= s["wall_slot"] < hi]

    def wait_epoch(self, epoch: int, slot_in_epoch: int = 0) -> None:
        target = epoch * SPE + slot_in_epoch
        while self.clock.wall_slot() < target:
            time.sleep(0.25)
            for node in self.nodes:
                if node.has_key is not None and node.proc and node.proc.poll() is not None and not getattr(node, "stopped_on_purpose", False):
                    raise SoakError(f"{node.name} exited unexpectedly (rc {node.proc.returncode}); see {node.log_path}")

    # ── stake arithmetic ─────────────────────────────────────────────────
    def read_stakes(self) -> None:
        for v in range(self.n):
            rec = self.rpc(0, "getvalidator", [v])
            self.stakes[v] = int(rec["effective_stake_sat"])

    @staticmethod
    def pick_subset(weights: dict[int, int], target: int, exact_ok=True, prefer_high=True) -> list[int]:
        """Smallest-index-last subset whose weight reaches target (greedy from the top)."""
        order = sorted(weights, reverse=prefer_high)
        chosen, w = [], 0
        for v in order:
            if w >= target:
                break
            if w + weights[v] <= target or not exact_ok:
                chosen.append(v); w += weights[v]
        return chosen

    # ── tx helpers ───────────────────────────────────────────────────────
    def submit(self, i, hex_tx) -> tuple[bool, str]:
        try:
            r = self.rpc(i, "sendrawtransaction", [hex_tx], timeout=10.0)
            return True, json.dumps(r)[:300]
        except RpcError as e:
            return False, f"{e.code}: {e.message} {e.data or ''}"[:500]

    def find_block_by(self, validators: set[int], epoch_lo: int, epoch_hi: int, node=0):
        """Most recent canonical block in [epoch_lo, epoch_hi] proposed by one of `validators`."""
        for slot in range(min(epoch_hi * SPE + SPE - 1, self.clock.wall_slot() - 2), epoch_lo * SPE - 1, -1):
            try:
                b = self.rpc(node, "getblockbyslot", [slot])
            except RpcError:
                continue
            if b and b.get("slot") == slot and b.get("proposer_index") in validators:
                return slot, b["proposer_index"], b["block_id"]
        return None

    def equivocate(self, validator: int, slot: int, *, to: str | None, evidence_out: Path | None) -> dict:
        args = ["devnet-equivocate", "--genesis", str(self.genesis), "--dir", str(self.keydirs[validator]),
                "--data-dir", str(self.work / f"node{validator}"), "--slot", str(slot)]
        if to:
            args += ["--to", to]
        if evidence_out:
            args += ["--evidence-out", str(evidence_out)]
        out = self.cand.run(args, timeout=300).stdout
        ids = dict(re.findall(r"^(original|conflicting) block id:\s+([0-9a-f]{64})", out, re.M))
        txid = re.search(r"evidence transaction id: ([0-9a-f]{64})", out)
        return {"ids": ids, "evidence_txid": txid.group(1) if txid else None, "stdout": out[-400:]}

    def transfer_v2(self, binary: lib.Bin, keydir: Path, alloc: dict, out: Path, extra=()) -> tuple[str | None, str]:
        adm = self.rpc(0, "getvalidatoradmission")
        fee = int(adm["next_base_fee_millisat_per_gas"])
        try:
            proc = binary.run(["transfer-v2", "--genesis", str(self.genesis), "--dir", str(keydir),
                               "--input", f"{alloc['txid']}:{alloc['vout']}:{alloc['sat']}",
                               "--to", lib.sha3_hex("00" * 32), "--base-fee", str(fee), "--tip", "1000",
                               "--epoch", str(self.clock.wall_epoch()), "--out", str(out), *extra], timeout=600)
        except SoakError as e:
            return None, f"build refused: {e}"
        txid = lib.TXID_RE.search(proc.stdout).group(1)
        ok, msg = self.submit(0, out.read_text().strip())
        return (txid if ok else None), msg

    def wait_tx_spent(self, alloc: dict, timeout_slots=SPE * 2) -> bool:
        deadline = self.clock.wall_slot() + timeout_slots
        while self.clock.wall_slot() < deadline:
            try:
                v = self.rpc(0, "gettxout", [alloc["txid"], alloc["vout"]])
                if v and v.get("unspent") is False:
                    return True
            except SoakError:
                pass
            time.sleep(1)
        return False

    # ── scenario ─────────────────────────────────────────────────────────
    def run(self) -> int:
        a = self.a
        self.work.mkdir(mode=0o700, parents=True, exist_ok=False)
        report = {"status": "RUNNING", "args": {k: str(v) for k, v in vars(a).items()}}
        sampler = None
        try:
            self.preflight()
            self.keys_and_genesis()
            report["genesis_sha3"] = lib.sha3_hex(self.genesis.read_bytes().hex())
            self.launch_all()
            sampler = threading.Thread(target=self.sampler, daemon=True)
            sampler.start()
            upgraded = set(range(self.n))

            # e2: stakes, role selection.
            self.wait_epoch(2)
            self.read_stakes()
            total = sum(self.stakes.values())
            # Just under 1/3, so the majority keeps a margin above the 2/3 quorum.
            minority = self.pick_subset(self.stakes, total // 3 - 1)
            majority = sorted(upgraded - set(minority))
            report["roles"] = {"stakes": self.stakes, "partition_minority": minority}
            self.event("roles", stakes=self.stakes, minority=minority,
                       minority_share=sum(self.stakes[v] for v in minority) / total)

            # e3: pre-activation offence, held.
            self.wait_epoch(3, 8)
            hit = self.find_block_by(set(majority), 2, 3)
            pre = {}
            if hit:
                slot, p, bid = hit
                ev = self.work / "evidence-pre-activation.hex"
                pre = self.equivocate(p, slot, to=None, evidence_out=ev)
                pre.update(validator=p, slot=slot, offence_epoch=slot // SPE)
                ok, msg = self.submit(majority[0], ev.read_text().strip())
                pre["submitted_before_gate"] = {"accepted": ok, "reply": msg}
                self.event("pre_activation_offence", **pre)
            self.checks.ok("pre-activation offence evidence captured", bool(pre.get("evidence_txid")), pre)
            if pre.get("submitted_before_gate"):
                self.checks.ok("evidence refused while slashing is not yet active",
                               not pre["submitted_before_gate"]["accepted"], pre["submitted_before_gate"])

            inv_results = []
            if self.inv_rounds:
                self.wait_epoch(a.hf1 - 2, 4)
                inv_results.append(self.invariance_round("pre-HF1"))

            # L2 installed at --l2-epoch (< HF1): claim finality must record
            # nothing before HF1 and the chain's own checkpoint roots after it.
            l2_snaps = {}
            if a.l2_epoch is not None:
                self.wait_epoch(a.hf1 - 1, 16)
                l2_snaps["pre_hf1"] = self.l2_snapshot()
                self.wait_epoch(a.hf1, 24)
                l2_snaps["post_hf1"] = self.l2_snapshot()

            # e10 HF1, e11-e13 partition.
            cut, heal = a.hf1 + 1, a.hf1 + 3
            self.wait_epoch(cut)
            minority_set = set(minority)
            other = set(range(self.total_nodes)) - minority_set
            self.mesh.cut_between(minority_set, other)
            self.event("partition_cut", minority=minority)
            self.wait_epoch(heal)
            self.mesh.heal_between(minority_set, other)
            self.event("partition_heal")
            if self.inv_rounds:
                self.wait_epoch(heal, 12)
                inv_results.append(self.invariance_round("post-HF1"))

            if a.l2_epoch is not None:
                self.wait_epoch(a.hf2, 8)
                l2_snaps["hf2"] = self.l2_snapshot()
                self.check_l2_claim_finality(l2_snaps, report)

            # e15: slashing.
            self.wait_epoch(a.hf2 + 1, 4)
            if pre.get("evidence_txid"):
                ok, msg = self.submit(majority[0], (self.work / "evidence-pre-activation.hex").read_text().strip())
                pre["submitted_after_hf2"] = {"accepted": ok, "reply": msg}
                self.checks.ok("pre-activation offence refused after HF2 (submission)", not ok, pre["submitted_after_hf2"])
            # Inactivity set chosen now so that Q (slashed) stays online.
            q_candidates = set(majority) - {pre.get("validator")}
            hit = self.find_block_by(q_candidates, a.hf2, a.hf2 + 1)
            post = {}
            if hit:
                slot, q, bid = hit
                ev = self.work / "evidence-post-activation.hex"
                try:
                    post = self.equivocate(q, slot, to=f"127.0.0.1:{self.mesh_port(majority[-1])}", evidence_out=ev)
                    post.update(validator=q, slot=slot, offence_epoch=slot // SPE)
                    self.event("post_activation_offence", **post)
                except SoakError as e:
                    # Record and continue: the later phases do not depend on it.
                    post = {"error": str(e)[-600:], "slot": slot, "intended_validator": q}
                    self.event("post_activation_offence_failed", **post)
            self.checks.ok("post-activation offence injected", bool(post.get("ids")), post)

            if self.inv_rounds:
                self.wait_epoch(a.hf2 + 1, 20)
                inv_results.append(self.invariance_round("post-HF2"))

            # e16: 0x0003 spend before HF3 must be refused.
            self.wait_epoch(a.hf2 + 2, 4)
            if post.get("validator") is not None:
                slashed = {}
                for i in sorted(upgraded):
                    try:
                        slashed[i] = self.rpc(i, "getvalidator", [post["validator"]]).get("slashed")
                    except SoakError as e:
                        slashed[i] = str(e)
                if not all(v is True for v in slashed.values()):
                    ok, msg = self.submit(majority[0], (self.work / "evidence-post-activation.hex").read_text().strip())
                    post["explicit_submission"] = {"accepted": ok, "reply": msg}
                    self.event("post_activation_evidence_resubmitted", **post["explicit_submission"])
            if self.suite3:
                txid, msg = self.transfer_v2(self.cand, self.suite3["dir"], self.allocs["suite3"],
                                             self.work / "suite3-pre-hf3.hex")
                spent = self.wait_tx_spent(self.allocs["suite3"], timeout_slots=SPE) if txid else False
                self.checks.ok("0x0003 spend refused before HF3", not spent, {"txid": txid, "reply": msg})

            # e17: slashing verdict.
            self.wait_epoch(a.hf2 + 3)
            if post.get("validator") is not None:
                view = {}
                for i in sorted(upgraded):
                    try:
                        r = self.rpc(i, "getvalidator", [post["validator"]])
                        view[i] = {"slashed": r.get("slashed"), "own": r.get("own_stake_sat"), "state": r.get("state")}
                    except SoakError as e:
                        view[i] = str(e)
                post["view"] = view
                self.checks.ok(f"post-activation offender v{post['validator']} slashed on every upgraded node",
                               all(isinstance(v, dict) and v["slashed"] is True for v in view.values()), view)
            if pre.get("validator") is not None:
                view = {}
                for i in sorted(upgraded):
                    try:
                        view[i] = self.rpc(i, "getvalidator", [pre["validator"]]).get("slashed")
                    except SoakError as e:
                        view[i] = str(e)
                self.checks.ok(f"pre-activation offender v{pre['validator']} NOT slashed",
                               all(v is False for v in view.values()), view)
            report["slashing"] = {"pre": pre, "post": post}

            # e19: HF3 features.
            self.wait_epoch(a.hf3 + 1, 4)
            txid, msg = self.transfer_v2(self.cand, self.keys["classic"], self.allocs["classic"],
                                         self.work / "classic-post-hf3.hex")
            self.checks.ok("control: classic TransferV2 spend included after HF3",
                           bool(txid) and self.wait_tx_spent(self.allocs["classic"]), {"txid": txid, "reply": msg})
            if self.suite3:
                txid, msg = self.transfer_v2(self.cand, self.suite3["dir"], self.allocs["suite3"],
                                             self.work / "suite3-post-hf3.hex")
                self.checks.ok("0x0003 address funded at genesis and spent after HF3",
                               bool(txid) and self.wait_tx_spent(self.allocs["suite3"]), {"txid": txid, "reply": msg})
            else:
                self.checks.add("0x0003 address funded and spent", "SKIP",
                                {"reason": "candidate build has no suite-0x0003 keygen",
                                 "error": getattr(self, "suite3_error", None)})
            self.kes_rotation(report)
            if self.inv_rounds:
                self.wait_epoch(a.hf3 + 1, 20)
                inv_results.append(self.invariance_round("post-HF3"))
            report["invariance"] = inv_results

            # e20-e26 inactivity.
            slashed_v = post.get("validator")
            live = {v: w for v, w in self.stakes.items() if v != slashed_v}
            remaining = sum(live.values())
            offline = self.pick_subset({v: w for v, w in live.items() if v not in (majority[0], self.obs)},
                                       remaining // 3 + 1, exact_ok=False)
            off_share = sum(live[v] for v in offline) / remaining
            stop_e, start_e = a.hf3 + 3, a.hf3 + 9
            self.wait_epoch(stop_e)
            # Snapshot EVERY validator: which online ones count as the reference
            # is decided afterwards, from what each one actually attested.
            before = {v: self.rpc(majority[0], "getvalidator", [v]) for v in range(self.n)}
            for v in offline:
                self.nodes[v].stopped_on_purpose = True
                self.nodes[v].stop()
            self.event("inactivity_start", offline=offline, offline_share=off_share)
            self.wait_epoch(start_e)
            after = {v: self.rpc(majority[0], "getvalidator", [v]) for v in range(self.n)}
            for v in offline:
                self.nodes[v].start()
                self.nodes[v].stopped_on_purpose = False
            self.event("inactivity_end")
            report["inactivity"] = {"offline": offline, "share": off_share, "window": [stop_e, start_e],
                                    "slashed": slashed_v,
                                    "stake_before": {v: (before[v]["own_stake_sat"], before[v]["effective_stake_sat"]) for v in before},
                                    "stake_after": {v: (after[v]["own_stake_sat"], after[v]["effective_stake_sat"]) for v in after}}

            self.wait_epoch(a.stop_epoch)
            if inv_results:
                self.invariance_verdicts(inv_results)
            report["final_live"] = {i: self.latest(i) for i in range(self.total_nodes)}
            self.stop_sampler.set()
            sampler.join(timeout=10)
            for node in self.nodes:
                node.stopped_on_purpose = True
                node.stop()
            if self.mesh:
                self.mesh.close_all()
            self.event("stopped")

            self.evaluate(report, majority, minority, offline, cut, heal, stop_e, start_e)
            self.replay_and_compare(report)
        except BaseException as e:
            report["error"] = repr(e)
            self.checks.add("harness completed", "FAIL", repr(e))
            raise
        finally:
            self.stop_sampler.set()
            for node in self.nodes:
                try:
                    node.stopped_on_purpose = True
                    node.stop()
                except Exception:
                    pass
            if self.mesh:
                try:
                    self.mesh.close_all()
                except Exception:
                    pass
            report["checks"] = self.checks.rows
            report["events"] = self.events
            fails = [c for c in self.checks.rows if c["status"] == "FAIL"]
            report["status"] = "FAIL" if fails else "PASS"
            (self.work / "samples.json").write_text(json.dumps(self.samples) + "\n")
            (self.work / "report.json").write_text(json.dumps(report, indent=2, default=str) + "\n")
            print("=" * 100)
            for c in self.checks.rows:
                print(f"{c['status']:<5} {c['name']}")
            print("=" * 100)
            print(f"VERDICT: {report['status']}  ({sum(c['status']=='PASS' for c in self.checks.rows)} pass, "
                  f"{len(fails)} fail, {sum(c['status']=='SKIP' for c in self.checks.rows)} skip)  report: {self.work/'report.json'}")
        return 1 if report["status"] != "PASS" else 0

    def invariance_round(self, r: str) -> dict:
        """Sign with the baseline (release) binary's CLIs, submit to an upgraded node."""
        res: dict = {"round": r, "epoch": self.clock.wall_epoch()}
        txdir = self.work / "tx"
        txdir.mkdir(exist_ok=True)
        fee = int(self.rpc(0, "getvalidatoradmission")["next_base_fee_millisat_per_gas"])
        epoch = self.clock.wall_epoch()
        via = next(v for v in range(self.n) if self.nodes[v].alive())
        # TransferV2
        d, _ = self.inv_keys["transfer"]
        txid, msg = self.transfer_v2(self.base, d, self.allocs[f"inv-transfer-{r}"], txdir / f"inv-transfer-{r}.hex")
        res["transfer"] = {"accepted": bool(txid), "reply": msg[:200]}
        # Funded validator deposit
        fd, fpk = self.inv_keys["deposit"]
        jd = self.work / "keys" / f"inv-joiner-{r}"
        _, vpk, randao = self.base.keygen_public(jd)
        (jd / "pubkey.hex").write_text(vpk + "\n")
        a = self.allocs[f"inv-deposit-{r}"]
        fsh = lib.sha3_hex(fpk)
        p0, p1, p2 = (txdir / f"inv-deposit-{r}.{k}.hex" for k in range(3))
        try:
            self.base.run(["validator-deposit", "prepare", "--genesis", str(self.genesis),
                           "--funding-pubkey", str(fd / "pubkey.hex"), "--validator-pubkey", str(jd / "pubkey.hex"),
                           "--randao", randao, "--withdrawal", fsh, "--change", fsh,
                           "--stake", str(25_000 * 100_000_000), "--input", f"{a['txid']}:{a['vout']}:{a['sat']}",
                           "--max-base-fee", str(fee * 2 + 100), "--tip", "5", "--expiry", str(epoch + 6),
                           "--commission", "500", "--out", str(p0)], timeout=120)
            self.base.run(["validator-deposit", "sign", "--genesis", str(self.genesis), "--tx", str(p0),
                           "--role", "funding", "--dir", str(fd), "--out", str(p1)], timeout=600)
            self.base.run(["validator-deposit", "sign", "--genesis", str(self.genesis), "--tx", str(p1),
                           "--role", "validator", "--dir", str(jd), "--out", str(p2)], timeout=600)
            ok, msg = self.submit(via, p2.read_text().strip())
        except SoakError as e:
            ok, msg = False, f"tool refused: {e}"
        res["deposit"] = {"accepted": ok, "reply": msg[:200], "validator_pubkey_hash": lib.sha3_hex(vpk)}
        # Funded delegation to a live, unslashed genesis validator
        gd, gpk = self.inv_keys["delegate"]
        target = None
        for v in range(self.n):
            try:
                rec = self.rpc(via, "getvalidator", [v])
            except SoakError:
                continue
            if rec.get("state") == "active" and not rec.get("slashed"):
                target = v
                break
        a = self.allocs[f"inv-delegate-{r}"]
        q0, q1 = (txdir / f"inv-delegate-{r}.{k}.hex" for k in range(2))
        try:
            tpk = self.rpc(via, "getvalidator", [target])["pubkey_hash"]
            self.base.run(["funded-delegation", "prepare-delegate", "--genesis", str(self.genesis),
                           "--pubkey", str(gd / "pubkey.hex"), "--validator-hash", tpk,
                           "--amount", str(100 * 100_000_000), "--input", f"{a['txid']}:{a['vout']}:{a['sat']}",
                           "--change", lib.sha3_hex(gpk), "--max-base-fee", str(fee * 2 + 100), "--tip", "5",
                           "--expiry", str(epoch + 6), "--out", str(q0)], timeout=120)
            info = json.loads(self.base.run(["funded-delegation", "inspect", "--tx", str(q0)], timeout=60).stdout)
            self.base.run(["funded-delegation", "sign", "--genesis", str(self.genesis), "--tx", str(q0),
                           "--dir", str(gd), "--expected-root", info["signing_root"], "--out", str(q1)], timeout=600)
            ok, msg = self.submit(via, q1.read_text().strip())
        except (SoakError, KeyError, ValueError) as e:
            ok, msg = False, f"tool refused: {e}"
        res["delegate"] = {"accepted": ok, "reply": msg[:200], "target": target}
        self.event("invariance_round", **{k: (v if not isinstance(v, dict) else v.get("accepted")) for k, v in res.items()})
        return res

    def invariance_verdicts(self, rounds: list[dict]) -> None:
        via = next(v for v in range(self.n) if self.nodes[v].alive())
        for res in rounds:
            r = res["round"]
            def spent(name):
                a = self.allocs[name]
                try:
                    return self.rpc(via, "gettxout", [a["txid"], a["vout"]]).get("unspent") is False
                except SoakError:
                    return False
            t = spent(f"inv-transfer-{r}")
            d = spent(f"inv-deposit-{r}")
            try:
                known = bool(self.rpc(via, "getvalidatorbykey", [res["deposit"]["validator_pubkey_hash"]]))
            except SoakError:
                known = False
            g = spent(f"inv-delegate-{r}")
            for kind, ok in (("TransferV2", t), ("validator deposit", d and known), ("funded delegation", g)):
                key = {"TransferV2": "transfer", "validator deposit": "deposit", "funded delegation": "delegate"}[kind]
                self.checks.ok(f"invariance {r}: {kind} signed with today's CLI is included",
                               bool(ok), dict(res[key], included=bool(ok), **({"registered": known} if kind == "validator deposit" else {})))

    def l2_snapshot(self) -> dict:
        snap = {"wall_slot": self.clock.wall_slot(), "nodes": {}}
        for i in range(self.total_nodes):
            try:
                r = self.rpc(i, "getl2settlement", timeout=5.0)
            except SoakError as e:
                snap["nodes"][i] = {"error": str(e)[:200]}
                continue
            snap["nodes"][i] = None if r is None else {
                "activated": (r.get("profile") or {}).get("activated"),
                "roots": {int(x["epoch"]): x["root"] for x in r.get("rehearsal_checkpoint_roots", [])}
                if "rehearsal_checkpoint_roots" in r else None}
        return snap

    def own_checkpoint_root(self, epoch: int) -> str | None:
        """The chain's own checkpoint root for `epoch`: the last block strictly
        before the epoch's first slot (the convention attesters vote)."""
        for slot in range(epoch * SPE - 1, max(epoch * SPE - 4 * SPE, 0), -1):
            try:
                b = self.rpc(0, "getblockbyslot", [slot])
            except RpcError:
                continue
            if b and b.get("slot") == slot:
                return b["block_id"]
        return None

    def check_l2_claim_finality(self, snaps: dict, report: dict) -> None:
        a = self.a
        up = list(range(self.n))
        report["l2_claim_finality"] = snaps
        pre, post, late = snaps["pre_hf1"]["nodes"], snaps["post_hf1"]["nodes"], snaps["hf2"]["nodes"]
        installed = {i: bool(v and v.get("activated")) for i, v in pre.items()}
        self.checks.ok(f"L2 installed at e{a.l2_epoch} on every node, the non-upgraded one included",
                       all(installed.values()), installed)
        exposed = all(post.get(i) and post[i].get("roots") is not None for i in up)
        if not exposed:
            self.checks.add("HF1 claim finality records checkpoint roots", "SKIP",
                            {"reason": "candidate getl2settlement has no rehearsal_checkpoint_roots "
                                       "(tree without State::checkpoint_roots, or !expose-l2-checkpoint-roots off)"})
            return
        self.checks.ok("HF1 claim finality: no checkpoint root recorded before HF1",
                       all(pre[i] and pre[i]["roots"] == {} for i in up), {i: pre[i] for i in up})
        roots = {i: {**post[i]["roots"], **late[i]["roots"]} for i in up if late.get(i) and late[i].get("roots") is not None}
        self.checks.ok("HF1 claim finality: roots recorded from HF1 on, at most four kept",
                       all(post[i]["roots"] and min(post[i]["roots"]) >= a.hf1 for i in up)
                       and all(len(late[i]["roots"]) <= 4 for i in up if late.get(i) and late[i].get("roots") is not None),
                       {"post_hf1": {i: post[i]["roots"] for i in up}, "at_hf2": {i: (late.get(i) or {}).get("roots") for i in up}})
        agree = {}
        for e in sorted({e for r in roots.values() for e in r}):
            vals = {r[e] for r in roots.values() if e in r}
            own = self.own_checkpoint_root(e)
            agree[e] = {"distinct_across_nodes": len(vals), "own_root": own, "matches_own": vals == {own}}
        self.checks.ok("HF1 claim finality: every recorded root is the chain's own checkpoint, identical on all nodes",
                       bool(agree) and all(v["matches_own"] for v in agree.values()), agree)

    def kes_rotation(self, report) -> None:
        if not re.search(r"\bkes\b", self.cand_help, re.I):
            self.checks.add("KES rotation", "SKIP", {"reason": "candidate build has no KES command"})
            return
        # The KES CLI does not exist on b4a21fb6; the integration branch defines it.
        # Try the conventional shape and report exactly what happened.
        v = 1
        out = self.work / "kes-rotate.hex"
        try:
            proc = self.cand.run(["kes", "rotate", "--genesis", str(self.genesis), "--dir", str(self.keydirs[v]),
                                  "--epoch", str(self.clock.wall_epoch()), "--out", str(out)], timeout=600)
            ok, msg = self.submit(0, out.read_text().strip())
            self.checks.ok("KES rotation submitted", ok, {"stdout": proc.stdout[-300:], "reply": msg})
        except SoakError as e:
            self.checks.add("KES rotation", "FAIL", {"error": str(e)[-500:]})

    # ── verdicts ─────────────────────────────────────────────────────────
    def evaluate(self, report, majority, minority, offline, cut, heal, stop_e, start_e) -> None:
        a = self.a
        upgraded = list(range(self.n))
        # Panics.
        panics = {n.name: PANIC_RE.findall(n.log_text())[:3] for n in self.nodes}
        self.checks.ok("no node panicked", not any(panics.values()), {k: v for k, v in panics.items() if v})
        # Finality across each boundary (live samples).
        for name, b in (("HF1", a.hf1), ("HF2", a.hf2), ("HF3", a.hf3)):
            first = {}
            for s in self.samples:
                if s["node"] in upgraded and s["fin"] >= b and s["node"] not in first:
                    first[s["node"]] = s["wall_slot"] // SPE
            lag = {k: v - b for k, v in first.items()}
            # FFG finalizes epoch b's checkpoint during b+2 at the earliest;
            # the partition minority may lag around HF1 until the heal.
            prompt = [k for k in majority if lag.get(k, 99) <= 3]
            ok = len(first) == len(upgraded) and len(prompt) == len(majority)
            self.checks.ok(f"finality crossed {name} (e{b}) on every upgraded node (majority within 3 epochs)", ok,
                           {"lag_epochs": lag, "missing": sorted(set(upgraded) - set(first))})
        # Partition.
        mid = self.window(set(minority), cut + 1, heal)
        maj = self.window(set(majority), cut, heal)
        min_fins = {s["fin"] for s in mid}
        maj_gain = (max((s["fin"] for s in maj), default=0) - min((s["fin"] for s in maj), default=0))
        self.checks.ok("partition: minority (~1/3) finality frozen while cut",
                       bool(mid) and max(min_fins) - min(min_fins) <= 1, {"minority_fin_values": sorted(min_fins)})
        self.checks.ok("partition: majority (~2/3) kept finalizing while cut", maj_gain >= 1, {"gain_epochs": maj_gain})
        healed = self.window(set(upgraded), heal + 3, heal + 4)
        last = {}
        for s in healed:
            last[s["node"]] = s["fin"]
        self.checks.ok("partition: all upgraded nodes finalized past the heal within 3 epochs",
                       len(last) == len(upgraded) and min(last.values()) >= heal, last)
        # Inactivity.
        online = [v for v in upgraded if v not in offline]
        during = self.window(set(online), stop_e + 2, start_e)
        fins = sorted({s["fin"] for s in during})
        self.checks.ok("inactivity: finality stalled while > 1/3 stake offline",
                       bool(fins) and fins[-1] - fins[0] <= 1, {"online_fin_values": fins, "offline": offline})
        inact = report.get("inactivity", {})
        # The leak is a ledger subtracted from the bond: effective = own - leaked.
        # own_stake keeps compounding issuance, so the bite is the growth of
        # (own - effective), and an online validator's gap must not grow.
        def gap(snap, v):
            return int(snap[v][0]) - int(snap[v][1])
        # A slashed validator reports null stakes; it has no leak to measure.
        def numeric(snap, v):
            return v in snap and all(x is not None for x in snap[v])
        bites = {v: gap(inact["stake_after"], v) - gap(inact["stake_before"], v) for v in inact["stake_after"]
                 if v != inact.get("slashed") and numeric(inact["stake_after"], v) and numeric(inact["stake_before"], v)}
        self.checks.ok("inactivity: leak bit every offline validator", all(bites.get(v, 0) > 0 for v in offline),
                       {v: bites.get(v) for v in offline})
        # Online reference: only a validator whose OWN node logged an attestation
        # for every epoch in which the leak could charge it ([stop_e-1, start_e])
        # must come out at zero. A node log line is "signed and broadcast", not
        # "included and counted"; that is the strongest claim the harness can
        # make without decoding block bodies. Partial attesters are reported
        # with the epochs they missed, never failed.
        need = set(range(stop_e - 1, start_e + 1))
        online = [v for v in upgraded if v not in offline and v in bites]
        attested = {v: {int(e) for e in re.findall(r"\] attested \(epoch (\d+)", self.nodes[v].log_text())} & need
                    for v in online}
        full = [v for v in online if attested[v] == need]
        partial = {v: {"missed_epochs": sorted(need - attested[v]), "leaked_sat": bites[v]}
                   for v in online if v not in full}
        ev = {"window_epochs": sorted(need), "fully_attesting": {v: bites[v] for v in full},
              "partially_attesting": partial}
        if full:
            self.checks.ok("inactivity: online validators that attested in every leaking epoch were not charged",
                           all(bites[v] == 0 for v in full), ev)
        else:
            self.checks.add("inactivity: online validators that attested in every leaking epoch were not charged",
                            "SKIP", dict(ev, reason="no online validator logged an attestation in every window epoch"))
        end = {}
        for s in self.window(set(upgraded), start_e + 3, a.stop_epoch + 1):
            end[s["node"]] = s["fin"]
        self.checks.ok("inactivity: finality resumed after the validators returned",
                       len(end) == len(upgraded) and min(end.values()) >= start_e, end)

    def replay_and_compare(self, report) -> None:
        procs = []
        try:
            for i in range(self.total_nodes):
                d = self.work / f"replay{i}"
                d.mkdir(mode=0o700)
                src = self.work / f"node{i}"
                for f in ("blocks.log", "blocks.idx"):
                    if (src / f).exists():
                        shutil.copy2(src / f, d / f)
                binary = self.cand.path if i != self.obs else self.base.path
                fh = open(d / "replay.log", "w")
                procs.append((subprocess.Popen(
                    [str(binary), "run", "--data-dir", str(d), "--genesis", str(self.genesis), "--transport", "devnet",
                     "--listen", str(self.replay_mesh(i)), "--listen-addr", "127.0.0.1", "--no-doppelganger-check",
                     "--rpc-bind", "127.0.0.1", "--rpc-port", str(self.replay_rpc(i)),
                     "--metrics-bind", "127.0.0.1", "--metrics-port", str(self.a.port_base + 500 + i),
                     "--replay-from-genesis"], env=self.env, stdout=fh, stderr=subprocess.STDOUT,
                    start_new_session=True), fh))
            infos = {}
            deadline = time.monotonic() + 600
            while time.monotonic() < deadline and len(infos) < self.total_nodes:
                for i in range(self.total_nodes):
                    if i in infos:
                        continue
                    try:
                        infos[i] = lib.rpc(self.replay_rpc(i), "getchaininfo")
                    except SoakError:
                        pass
                time.sleep(1)
            self.checks.ok("every data dir replays from genesis with its own binary", len(infos) == self.total_nodes,
                           {"replayed": sorted(infos)})
            final_live = report.get("final_live", {})
            consistent = {}
            for i, live in final_live.items():
                if not live or i not in infos:
                    consistent[i] = False
                    continue
                try:
                    b = lib.rpc(self.replay_rpc(i), "getblockbyid", [live["head"]])
                    consistent[i] = bool(b)
                except SoakError:
                    consistent[i] = False
            self.checks.ok("replayed chain contains each node's last live head (no state corruption)",
                           all(consistent.values()), consistent)
            # Slot-by-slot canonical comparison.
            top = max((x["slot"] for x in infos.values()), default=0)
            chains = {i: {} for i in infos}
            for i in infos:
                for slot in range(1, top + 1):
                    try:
                        b = lib.rpc(self.replay_rpc(i), "getblockbyslot", [slot])
                    except RpcError:
                        continue
                    except SoakError:
                        continue
                    if b and b.get("slot") == slot:
                        chains[i][slot] = (b["block_id"], b["state_root"])
                        if i == 0:
                            self.proposers[slot] = b.get("proposer_index")
            up = [i for i in infos if i != self.obs]
            fin_slot = min(infos[i]["finalized"]["epoch"] for i in up) * SPE
            diverge = [s for s in range(1, fin_slot + 1) if len({chains[i].get(s) for i in up}) != 1]
            self.checks.ok("upgraded nodes: identical canonical chain up to the common finalized checkpoint",
                           not diverge, {"finalized_slot": fin_slot, "first_divergent_slots": diverge[:5],
                                         "finalized_epochs": {i: infos[i]["finalized"]["epoch"] for i in infos}})
            for name, b in self.boundaries:
                first_slot = next((s for s in range(b * SPE, top + 1) if s in chains[up[0]]), None)
                ok = first_slot is not None and first_slot <= fin_slot
                self.checks.ok(f"{name} boundary block (first slot >= {b * SPE}) is finalized and shared", ok,
                               {"slot": first_slot, "finalized_slot": fin_slot})
            # Non-upgraded observer.
            if self.obs in infos:
                ref = chains[up[0]]
                mine = chains[self.obs]
                # First slot where the upgraded chain has a block the observer
                # does not share — including blocks past the observer's head,
                # which is what a node that stopped at a rejected block shows.
                fork = next((s for s in sorted(ref) if mine.get(s) != ref.get(s)), None)
                obs_fin = infos[self.obs]["finalized"]["epoch"]
                ev = {"fork_slot": fork, "fork_epoch": None if fork is None else fork // SPE,
                      "observer_head_slot": infos[self.obs]["slot"], "observer_finalized_epoch": obs_fin,
                      "hf_armed": self.hf_armed,
                      "observer_rejections": len(re.findall(r"StateRootMismatch|reject ", self.nodes[self.obs].log_text()))}
                report["observer"] = ev
                if self.hf_armed:
                    first_hf = min(e for _, e in self.boundaries) * SPE
                    self.checks.ok("non-upgraded node follows the shared chain until the first HF boundary",
                                   fork is None or fork >= first_hf, ev)
                    self.checks.ok("non-upgraded node forked off (did not follow upgraded blocks to the end)",
                                   fork is not None, ev)
                    self.checks.ok("non-upgraded node never finalized anything the upgraded side did not",
                                   all(ref.get(s) == mine.get(s) for s in mine if s <= obs_fin * SPE), ev)
                else:
                    self.checks.ok("gates-off arm: baseline observer followed the identical chain",
                                   all(ref.get(s) == mine.get(s) for s in range(1, fin_slot + 1)), ev)
        finally:
            for p, fh in procs:
                if p.poll() is None:
                    p.send_signal(signal.SIGTERM)
            for p, fh in procs:
                try:
                    p.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    p.kill()
                fh.close()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--candidate-bin", type=Path, required=True)
    ap.add_argument("--baseline-bin", type=Path, required=True)
    ap.add_argument("--arming", type=Path, help="arm.py report of the candidate build")
    ap.add_argument("--work", type=Path, required=True)
    ap.add_argument("--validators", type=int, default=12)
    ap.add_argument("--slot-ms", type=int, default=1000)
    ap.add_argument("--start-in", type=int, default=20)
    ap.add_argument("--hf1", type=int, default=10)
    ap.add_argument("--hf2", type=int, default=14)
    ap.add_argument("--hf3", type=int, default=18)
    ap.add_argument("--stop-epoch", type=int, default=31)
    ap.add_argument("--port-base", type=int, default=27400)
    ap.add_argument("--bind-genesis", action="store_true", help="BPOSMAN2 manifest (default: the format mainnet launched with)")
    ap.add_argument("--no-invariance", action="store_true",
                    help="skip the deposit/withdrawal invariance rounds (TransferV2, deposit, delegation per gate)")
    ap.add_argument("--l2-epoch", type=int, help="the L2 install epoch both binaries were built with (run.sh --l2-epoch)")
    a = ap.parse_args()
    if not 8 <= a.validators <= 15:
        sys.exit("--validators must be 8..15 (one relay port block of 16 incl. the observer)")
    if not (4 < a.hf1 < a.hf2 < a.hf3 and a.hf3 + 13 <= a.stop_epoch):
        sys.exit("need 4 < hf1 < hf2 < hf3 and stop-epoch >= hf3 + 13")
    if a.l2_epoch is not None and not 0 < a.l2_epoch < a.hf1 - 1:
        sys.exit("--l2-epoch must be before HF1 - 1 (the pre-HF1 snapshot is taken in epoch HF1 - 1)")
    if a.hf2 - a.hf1 < 4 or a.hf3 - a.hf2 < 4:
        sys.exit("leave >= 4 epochs between HF gates (partition / slashing phases live there)")
    return Rehearsal(a).run()


if __name__ == "__main__":
    sys.exit(main())
