#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Live gate crossing of an ARMED release on a throwaway loopback network.

rehearse.py (the HF1/HF2/HF3 scenario) plus what an armed release adds:

  * the release is already armed (78d4921c / fa980367), so the candidate copy
    is rescheduled with literal values (crossing-build.sh writes the conf);
  * every node runs the devnet mesh with `--mesh-security offer`;
  * every validator holds a KES tree (`kes keygen`) from first start; KES
    registration (wire 0x17) is refused before HF3 and sent by every
    validator after it; enforcement must bind at a boundary at or after
    HF3_KES_ENFORCE_EPOCH, after which proposals and votes are KES-signed and
    finality must continue;
  * the suite-0x0003 spend and the HF3 withdrawal-credential rotation (0x18)
    are built with crates/bloch-pos-node/examples/hf3_rehearsal_tool.rs
    (the release CLI cannot build either): both refused before HF3, both
    included after it;
  * the v2 L2 native follower (rebuilt against the same rescheduled native)
    follows node1 for the whole run and must verify every finalized block
    across every gate without halting.

Timeline (defaults, epochs of 32 slots): past flag days e5, L2 installed e7,
HF1 e10 (claim finality + frozen set), own-target votes e16, HF2 e20, HF3 e28
(SLH suite, PQ migration, KES registration), KES enforcement e44, stop e56.
The partition (HF1+1..HF1+3), slashing (HF2+1..HF2+3), inactivity
(HF3+3..HF3+9) and replay phases are rehearse.py's.

Everything binds 127.0.0.1, keys are generated fresh under --work, the
manifest is new. Nothing reads or writes outside --work.
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
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))
import rehearse  # noqa: E402
from rehearse import SPE, Rehearsal  # noqa: E402
import lifecycle_devnet_soak_lib as lib  # noqa: E402
from lifecycle_devnet_soak_lib import RpcError, SoakError  # noqa: E402

KES_ERR = re.compile(r"KES enforcement state unknown|no validator\.kes is loaded|is not v\d+'s KES key in force|"
                     r"does not cover period|is erased|refusing to erase KES periods|no KES key is registered")
REJECT_RE = re.compile(r"(?i)(invalid attestation|attestation rejected|rejected block|reject(?:ed|ing)? (?:block|proposal)|"
                       r"StateRootMismatch|BadSignature|InvalidSignature|KesSignature|bad proposer signature)")


class Crossing(Rehearsal):
    def __init__(self, a):
        super().__init__(a)
        self.tool = lib.Bin(a.tool.resolve(), self.env, self.work / "commands.log")
        self.kes_bind = None
        self.kes_samples: list[dict] = []
        self.extra: dict = {}
        self.follower = None
        self.boundaries = [("HF1", a.hf1), ("HF1 own-target votes", a.own_target), ("HF2", a.hf2), ("HF3", a.hf3)]

    # ── keys: rehearse.keys_and_genesis + suite-0x0003 keys from the tool ─
    def keys_and_genesis(self) -> None:
        keydirs = []
        for i in range(self.n):
            d = self.work / "keys" / f"v{i}"
            self.base.keygen(d, i)
            keydirs.append(d)
        # KES trees before the genesis clock starts (depth 12 takes a while).
        t0 = time.time()
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=len(keydirs)) as pool:
            list(pool.map(lambda d: self.cand.run(["kes", "keygen", "--dir", str(d), "--depth", str(self.a.kes_depth)],
                                                  timeout=3600), keydirs))
        self.extra["kes_keygen_seconds"] = round(time.time() - t0, 1)
        allocs: list[tuple[str, int]] = []
        names: list[str] = []
        fdir = self.work / "keys" / "funder-classic"
        self.base.keygen(fdir, 900)
        _, pk, _ = self.base.keygen_public(fdir)
        allocs.append((lib.sha3_hex(pk), 1_000 * 100_000_000)); names.append("classic")
        self.keys = {"classic": fdir}
        # Suite 0x0003: a funded spend key and a fresh credential key (rotation target).
        sdir = self.work / "keys" / "funder-0x0003"
        out = self.tool.run(["slh-keystore", "--dir", str(sdir), "--index", "901"], timeout=120).stdout
        script = re.search(r"^script ([0-9a-f]{64})", out, re.M).group(1)
        self.suite3 = {"dir": sdir, "flags": ["hf3_rehearsal_tool"], "script": script}
        allocs.append((script, 1_000 * 100_000_000)); names.append("suite3")
        self.keys["suite3"] = sdir
        cdir = self.work / "keys" / "credential-0x0003"
        out = self.tool.run(["slh-keystore", "--dir", str(cdir), "--index", "902"], timeout=120).stdout
        self.cred3 = {"dir": cdir, "script": re.search(r"^script ([0-9a-f]{64})", out, re.M).group(1)}
        self.inv_rounds = [] if self.a.no_invariance else ["pre-HF1", "post-HF1", "post-HF2", "post-HF3"]
        self.inv_keys = {}
        for role, idx in (("transfer", 910), ("deposit", 911), ("delegate", 912)):
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
            self.base.keygen(self.work / "keys" / f"inv-joiner-{r}", "auto")
        # Extra allocations for an attached stack (gate_l2.py): SCRIPT_HASH:SATS.
        for i, spec in enumerate(self.a.extra_alloc):
            sh, sat = spec.split(":")
            allocs.append((sh, int(sat))); names.append(f"extra-{i}")
        args = ["genesis", "--keys", ",".join(map(str, keydirs)), "--out", str(self.genesis),
                "--slot-ms", str(self.a.slot_ms), "--start-in", str(self.a.start_in)]
        if self.a.bind_genesis:
            args.append("--bind-genesis")
        for sh, sat in allocs:
            args += ["--alloc", f"{sh}:{sat}"]
        out = self.base.run(args, timeout=600)
        (self.work / "genesis.out").write_text(out.stdout + out.stderr)
        found = lib.ALLOC_RE.findall(out.stdout + out.stderr)
        assert len(found) == len(allocs), out.stdout[-1500:]
        for name, (n_, txid, vout, sat, sh) in zip(names, found):
            self.allocs[name] = {"txid": txid, "vout": int(vout), "sat": int(sat), "script_hash": sh}
        gms, sms = lib.manifest_clock(self.genesis)
        self.clock = lib.Clock(gms, sms)
        self.keydirs = keydirs

    # ── launch: KES trees, mesh offer, L2 follower ───────────────────────
    def launch_all(self) -> None:
        # MOVE (never copy) each KES tree into its data dir before first start.
        for v in range(self.n):
            d = self.work / f"node{v}"
            d.mkdir(parents=True, exist_ok=True)
            shutil.move(str(self.keydirs[v] / "validator.kes"), str(d / "validator.kes"))
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
                   "--metrics-bind", "127.0.0.1", "--metrics-port", str(self.metrics_port(i)),
                   "--mesh-security", self.a.mesh_security]
            node = lib.Node(name=f"node{i}", slot=i, data_dir=d, rpc_port=self.rpc_port(i),
                            mesh_port=self.mesh_port(i), metrics_port=self.metrics_port(i), cmd=cmd,
                            env=self.env, log_path=d / "run.log", has_key=upgraded)
            self.nodes.append(node)
        for node in self.nodes:
            node.start()
            time.sleep(0.2)
        self.event("launched", nodes=self.total_nodes, observer=self.obs, mesh_security=self.a.mesh_security)
        if self.a.l2_follower and self.a.l2_follower.exists():
            self.start_follower()

    def start_follower(self) -> None:
        domain = lib.sha3_hex(self.genesis.read_bytes().hex())
        d = self.work / "l2-follower"
        d.mkdir(exist_ok=True)
        cmd = [str(self.a.l2_follower), "--manifest", str(self.genesis), "--network-pin", domain,
               "--rpc-port", str(self.rpc_port(1)), "--state", str(d / "state"), "--status", str(d / "status.json"),
               "--poll-seconds", "2"]
        fh = open(d / "follower.log", "ab")
        env = {k: v for k, v in self.env.items() if k in ("PATH", "HOME", "LANG")}
        self.follower = subprocess.Popen(cmd, stdout=fh, stderr=subprocess.STDOUT, env=env, start_new_session=True)
        (d / "pid").write_text(f"{self.follower.pid}\n")
        self.event("l2_follower_started", pid=self.follower.pid, network_pin=domain, rpc_port=self.rpc_port(1))

    def stop_follower(self) -> None:
        if self.follower and self.follower.poll() is None:
            self.follower.send_signal(signal.SIGTERM)
            try:
                self.follower.wait(timeout=20)
            except subprocess.TimeoutExpired:
                self.follower.kill()

    # ── tx helpers ───────────────────────────────────────────────────────
    def transfer_v2(self, binary, keydir: Path, alloc: dict, out: Path, extra=()):
        if keydir != self.suite3["dir"]:
            return super().transfer_v2(binary, keydir, alloc, out, extra)
        adm = self.rpc(0, "getvalidatoradmission")
        fee = int(adm["next_base_fee_millisat_per_gas"])
        try:
            proc = self.tool.run(["slh-transfer", "--dir", str(keydir),
                                  "--input", f"{alloc['txid']}:{alloc['vout']}:{alloc['sat']}",
                                  "--to", lib.sha3_hex("00" * 32), "--base-fee", str(fee), "--tip", "1000",
                                  "--epoch", str(self.clock.wall_epoch()), "--out", str(out)], timeout=600)
        except SoakError as e:
            return None, f"build refused: {e}"
        txid = lib.TXID_RE.search(proc.stdout).group(1)
        ok, msg = self.submit(0, out.read_text().strip())
        self.extra.setdefault("slh_transfers", []).append({"txid": txid, "accepted": ok, "reply": msg[:300],
                                                           "tool": proc.stdout[-300:], "epoch": self.clock.wall_epoch()})
        return (txid if ok else None), msg

    def equivocate(self, validator: int, slot: int, *, to, evidence_out):
        """rehearse.equivocate with the TOOLING binary (consensus-identical to the
        candidate; only devnet_tools.rs differs: check_signed_by judges the block
        under its epoch's signature policy, which the release tool does not do
        after SIG_CANONICAL). The nodes keep running the unpatched candidate."""
        if not self.a.equivocate_bin:
            return super().equivocate(validator, slot, to=to, evidence_out=evidence_out)
        real = self.cand
        self.cand = lib.Bin(self.a.equivocate_bin.resolve(), self.env, self.work / "commands.log")
        try:
            return super().equivocate(validator, slot, to=to, evidence_out=evidence_out)
        finally:
            self.cand = real

    def joiner_index(self) -> int | None:
        jd = self.work / "keys" / "inv-joiner-pre-HF1"
        if not (jd / "pubkey.hex").exists():
            return None
        h = lib.sha3_hex((jd / "pubkey.hex").read_text().strip())
        try:
            r = self.rpc(0, "getvalidatorbykey", [h])
        except SoakError:
            return None
        for k in ("index", "validator", "validator_index"):
            if isinstance(r, dict) and k in r:
                return int(r[k])
        return None

    def rotation(self, tag: str) -> dict:
        v = self.joiner_index()
        res: dict = {"tag": tag, "validator": v, "epoch": self.clock.wall_epoch()}
        if v is None:
            res["error"] = "joiner validator (invariance pre-HF1 deposit) not found"
            return res
        out = self.work / "tx" / f"rotation-{tag}.hex"
        (self.work / "tx").mkdir(exist_ok=True)
        try:
            proc = self.tool.run(["rotate", "--genesis", str(self.genesis), "--auth-dir", str(self.work / "keys" / "inv-deposit"),
                                  "--new-dir", str(self.cred3["dir"]), "--validator", str(v),
                                  "--epoch", str(self.clock.wall_epoch()), "--out", str(out)], timeout=600)
            res["tool"] = proc.stdout[-400:]
            res["txid"] = lib.TXID_RE.search(proc.stdout).group(1)
        except SoakError as e:
            res["error"] = f"tool refused: {e}"[-600:]
            return res
        res["accepted"], res["reply"] = self.submit(0, out.read_text().strip())
        try:
            res["credential_before"] = self.rpc(0, "getvalidator", [v]).get("withdrawal_credentials")
        except SoakError as e:
            res["credential_before"] = str(e)
        return res

    def kes_register(self, v: int, tag: str) -> tuple[bool, str]:
        (self.work / "tx").mkdir(exist_ok=True)
        ok, msg = False, ""
        for attempt in range(3):
            out = self.work / "tx" / f"kes-register-v{v}-{tag}-{attempt}.hex"
            try:
                self.cand.run(["kes", "register", "--dir", str(self.work / f"node{v}"), "--genesis", str(self.genesis),
                               "--out", str(out), "--validator", str(v)], timeout=600)
            except SoakError as e:
                return False, f"build refused: {e}"[:400]
            via = next((i for i in range(self.n) if self.nodes[i].alive()), 0)
            ok, msg = self.submit(via, out.read_text().strip())
            if ok or "out-of-range depth or signature length" not in msg:
                return ok, msg
        return ok, msg

    def getkes(self):
        for j in [v for v in range(self.n) if self.nodes[v].alive()]:
            try:
                return self.rpc(j, "getkes", timeout=5.0)
            except SoakError:
                continue
        return None

    # ── hooks into rehearse.run() ────────────────────────────────────────
    def wait_epoch(self, epoch: int, slot_in_epoch: int = 0) -> None:
        a = self.a
        # Pre-HF3 negatives (once, at HF2+2 slot 8, after rehearse's 0x0003 refusal).
        if not self.extra.get("pre_hf3_done") and a.hf2 + 2 <= self.clock.wall_epoch() < a.hf3 \
                and epoch >= a.hf2 + 3:
            self.extra["pre_hf3_done"] = True
            self.pre_hf3_negatives()
        if self.a.l2_follower and self.follower is None and self.a.l2_follower.exists() \
                and os.access(self.a.l2_follower, os.X_OK):
            # The follower may be built while the network runs; it re-verifies
            # from the pinned genesis when it starts, so a late start is complete.
            time.sleep(2)
            self.start_follower()
        super().wait_epoch(epoch, slot_in_epoch)
        if self.follower and self.follower.poll() is not None and not self.extra.get("follower_exit"):
            self.extra["follower_exit"] = {"rc": self.follower.returncode, "epoch": self.clock.wall_epoch()}
            self.event("l2_follower_exited", **self.extra["follower_exit"])
        st = self.work / "l2-follower" / "status.json"
        if st.exists():
            try:
                j = json.loads(st.read_text())
                tl = self.extra.setdefault("l2_timeline", [])
                row = {"wall_epoch": self.clock.wall_epoch(), "verified_slot": j.get("verified_slot"),
                       "finalized_epoch": j.get("native_finalized_epoch")}
                if not tl or tl[-1]["verified_slot"] != row["verified_slot"]:
                    tl.append(row)
            except (ValueError, OSError):
                pass
        k = self.getkes() if self.clock.wall_epoch() >= a.hf3 else None
        if k:
            self.kes_samples.append({"wall_slot": self.clock.wall_slot(), "epoch": k.get("epoch"), "period": k.get("period"),
                                     "enforced_from": k.get("enforced_from"), "bps": k.get("registered_stake_bps"),
                                     "registered": len(k.get("registered") or [])})

    def pre_hf3_negatives(self) -> None:
        r = self.rotation("pre-hf3")
        self.extra["rotation_pre_hf3"] = r
        self.checks.ok("PQ migration (0x18 credential rotation) refused before HF3",
                       r.get("validator") is not None and r.get("accepted") is False, r)
        ok, msg = self.kes_register(0, "pre-hf3")
        self.extra["kes_register_pre_hf3"] = {"accepted": ok, "reply": msg[:300]}
        self.checks.ok("KES registration (0x17) refused before HF3", not ok, self.extra["kes_register_pre_hf3"])

    def kes_rotation(self, report) -> None:
        """Called by rehearse.run() at HF3+1 slot 4 (after the 0x0003 spend):
        KES registration by every validator and the 0x0018 credential rotation."""
        a = self.a
        # A slashed validator cannot register (check_kes_register, StakingRule):
        # the offender of the slashing phase must be refused, the others accepted.
        slashed = (report.get("slashing") or {}).get("post", {}).get("validator")
        # Static-key fallback: one live validator never registers. It is chosen here so
        # it is not the slashed one and is not in the partition minority or the outage
        # set (both take the highest indices); nodes 0-2 serve the L2 stack.
        self.unregistered = None
        if a.static_fallback:
            self.unregistered = next(v for v in range(3, self.n) if v != slashed)
        regs = {v: self.kes_register(v, "hf3") for v in range(self.n) if v != self.unregistered}
        self.extra["static_fallback_validator"] = self.unregistered
        self.extra["kes_register_hf3"] = {v: {"accepted": r[0], "reply": r[1][:200]} for v, r in regs.items()}
        self.checks.ok("KES registration accepted after HF3 for every validator not slashed",
                       all(r[0] for v, r in regs.items() if v != slashed), self.extra["kes_register_hf3"])
        if slashed is not None:
            self.checks.ok(f"KES registration refused for the slashed validator v{slashed}", not regs[slashed][0],
                           self.extra["kes_register_hf3"][slashed])
        r = self.rotation("post-hf3")
        self.extra["rotation_post_hf3"] = r
        self.checks.ok("PQ migration (0x18 credential rotation) accepted after HF3", r.get("accepted") is True, r)
        # Inclusion: the validator's credential becomes SHA3(new 0x0003 key).
        deadline = self.clock.wall_slot() + 2 * SPE
        cred = None
        while self.clock.wall_slot() < deadline and r.get("accepted"):
            try:
                cred = self.rpc(0, "getvalidator", [r["validator"]]).get("withdrawal_credentials")
            except SoakError:
                cred = None
            if cred == self.cred3["script"]:
                break
            time.sleep(1)
        r["credential_after"] = cred
        self.checks.ok("PQ migration included: validator withdrawal credential = SHA3(suite-0x0003 key)",
                       cred == self.cred3["script"], {"validator": r.get("validator"), "before": r.get("credential_before"),
                                                       "after": cred, "expected": self.cred3["script"]})
        k = self.getkes()
        self.extra["kes_after_registration"] = k and {kk: k.get(kk) for kk in ("epoch", "enforced_from", "registered_stake_bps")}

    # ── extra verdicts ───────────────────────────────────────────────────
    def evaluate(self, report, majority, minority, offline, cut, heal, stop_e, start_e) -> None:
        super().evaluate(report, majority, minority, offline, cut, heal, stop_e, start_e)
        a = self.a
        upgraded = list(range(self.n))
        # Own-target votes and KES bind: finality must cross them too.
        k = self.kes_samples[-1] if self.kes_samples else {}
        bind = k.get("enforced_from")
        self.kes_bind = bind
        self.extra["kes_final_sample"] = k
        self.checks.ok("KES enforcement bound at a boundary at or after HF3_KES_ENFORCE_EPOCH",
                       bind is not None and int(bind) >= a.kes_enforce, {"enforced_from": bind, "kes_enforce": a.kes_enforce,
                                                                         "registered_stake_bps": k.get("bps")})
        gates = [("HF1 own-target votes", a.own_target)]
        if bind is not None:
            gates.append(("KES enforcement", int(bind)))
            self.boundaries.append(("KES enforcement", int(bind)))
            # params.rs: the first boundary at or past the gate with >= 9000 bps decides,
            # and the bind is KES_BIND_DELAY_EPOCHS (2) later.
            self.checks.ok("KES bound exactly at enforce + 2 (first deciding boundary, delay 2) with >= 9000 bps",
                           int(bind) == a.kes_enforce + 2 and (k.get("bps") or 0) >= 9000,
                           {"enforced_from": bind, "kes_enforce": a.kes_enforce, "bps": k.get("bps")})
        handover = a.kes_enforce + a.kes_period_epochs
        if a.stop_epoch > handover:
            gates.append(("KES period 1 handover", handover))
            self.boundaries.append(("KES period 1 handover", handover))
            self.checks.ok(f"KES period 1 reached under enforcement (starts e{handover}, counted from the gate)",
                           k.get("period") == (a.stop_epoch - a.kes_enforce) // a.kes_period_epochs and (k.get("period") or 0) >= 1,
                           {"final_sample": k, "handover": handover})
            evolved = {i: re.findall(r"KES key evolved[^\n]*", self.nodes[i].log_text())[:3] for i in upgraded}
            self.extra["kes_evolved_lines"] = evolved
        for name, b in gates:
            first = {}
            for s in self.samples:
                if s["node"] in upgraded and s["fin"] >= b and s["node"] not in first:
                    first[s["node"]] = s["wall_slot"] // SPE
            lag = {kk: v - b for kk, v in first.items()}
            self.checks.ok(f"finality crossed {name} (e{b}) on every upgraded node",
                           len(first) == len(upgraded) and all(v <= 4 for v in lag.values()),
                           {"lag_epochs": lag, "missing": sorted(set(upgraded) - set(first))})
        # KES errors / forbidden lines / per-slot re-application (fork-choice loop guard).
        kes_err, forbidden, reapply, rejects = {}, {}, {}, {}
        for i in upgraded:
            text = self.nodes[i].log_text()
            kes_err[i] = len(KES_ERR.findall(text))
            hits = lib.forbidden_hits(text)
            if hits:
                forbidden[i] = hits
            counts: dict[int, int] = {}
            for slot, *_ in lib.APPLIED_RE.findall(text):
                counts[int(slot)] = counts.get(int(slot), 0) + 1
            reapply[i] = {"slots_applied_more_than_once": sum(1 for c in counts.values() if c > 1),
                          "max_applications_of_one_slot": max(counts.values(), default=0)}
            rejects[i] = len(REJECT_RE.findall(text))
        self.extra["log_scan"] = {"kes_errors": kes_err, "forbidden": forbidden, "reapply": reapply, "reject_lines": rejects}
        self.checks.ok("no KES signing error on any validator", not any(kes_err.values()), kes_err)
        self.checks.ok("no forbidden log line (latch, refused own block, RANDAO, wrong validator, panic)", not forbidden, forbidden)
        self.checks.ok("no fork-choice loop: no slot applied more than 3 times on any node",
                       all(r["max_applications_of_one_slot"] <= 3 for r in reapply.values()), reapply)
        # Samples: the head never oscillates (same node, head id flipping back to an earlier id).
        flips = {}
        for i in upgraded:
            seq = [s["head"] for s in self.samples if s["node"] == i]
            seen, back = set(), 0
            prev = None
            for h in seq:
                if h != prev and h in seen:
                    back += 1
                seen.add(h)
                prev = h
            flips[i] = back
        self.checks.ok("no head oscillation in live samples (head never returns to an earlier head)",
                       all(v == 0 for v in flips.values()), flips)

    def replay_and_compare(self, report) -> None:
        super().replay_and_compare(report)
        # Proposals per validator in each gate window, from the canonical chain node0 replayed.
        windows = [("pre-HF1", 0, self.a.hf1), ("HF1..own-target", self.a.hf1, self.a.own_target),
                   ("own-target..HF2", self.a.own_target, self.a.hf2), ("HF2..HF3", self.a.hf2, self.a.hf3),
                   ("HF3..KES", self.a.hf3, self.kes_bind or self.a.kes_enforce),
                   ("KES..stop", self.kes_bind or self.a.kes_enforce, self.a.stop_epoch + 1)]
        by_window = {}
        for name, lo, hi in windows:
            props = {}
            for slot, p in self.proposers.items():
                if lo * SPE <= slot < int(hi) * SPE and p is not None:
                    props[p] = props.get(p, 0) + 1
            by_window[name] = {"blocks": sum(props.values()), "slots": (int(hi) - lo) * SPE, "by_proposer": props}
        self.extra["proposals"] = by_window
        kes_window = by_window["KES..stop"]
        slashed = (report.get("slashing") or {}).get("post", {}).get("validator")
        expected = set(range(self.n)) - {slashed}
        handover = self.a.kes_enforce + self.a.kes_period_epochs
        if self.a.stop_epoch > handover:
            props = {}
            for slot, p in self.proposers.items():
                if slot >= handover * SPE and p is not None:
                    props[p] = props.get(p, 0) + 1
            self.extra["proposals"]["period1..stop"] = {"blocks": sum(props.values()), "by_proposer": props}
            self.checks.ok("after the KES period handover every validator not slashed proposed canonical blocks",
                           expected.issubset(set(props)), {"by_proposer": props, "slashed": slashed})
        u = getattr(self, "unregistered", None)
        if u is not None:
            n = sum(1 for s, p in self.proposers.items() if p == u and self.kes_bind and s >= int(self.kes_bind) * SPE)
            attested = {int(e) for e in re.findall(r"\] attested \(epoch (\d+)", self.nodes[u].log_text())}
            after = sorted(e for e in attested if self.kes_bind and e >= int(self.kes_bind))
            self.checks.ok(f"static-key fallback: unregistered v{u} proposes and attests after the bind",
                           n > 0 and bool(after), {"canonical_blocks_after_bind": n, "attested_epochs_after_bind": len(after)})
        self.checks.ok("after KES enforcement every genesis validator not slashed still proposed canonical blocks",
                       expected.issubset(set(kes_window["by_proposer"])) and kes_window["blocks"] > 0,
                       dict(kes_window, slashed=slashed))

    def run(self) -> int:
        try:
            rc = super().run()
        finally:
            self.stop_follower()
            self.l2_verdict()
            rp = self.work / "report.json"
            if rp.exists():
                r = json.loads(rp.read_text())
                r["crossing"] = self.extra
                r["kes_samples"] = self.kes_samples[-50:]
                r["checks"] = self.checks.rows
                fails = [c for c in self.checks.rows if c["status"] == "FAIL"]
                r["status"] = "FAIL" if fails else "PASS"
                rp.write_text(json.dumps(r, indent=2, default=str) + "\n")
                print("=" * 100)
                for c in self.checks.rows:
                    print(f"{c['status']:<5} {c['name']}")
                print(f"FINAL VERDICT: {r['status']} ({sum(c['status']=='PASS' for c in self.checks.rows)} pass, "
                      f"{len(fails)} fail, {sum(c['status']=='SKIP' for c in self.checks.rows)} skip)")
                rc = 1 if fails else 0
        return rc

    def l2_verdict(self) -> None:
        if not self.a.l2_follower:
            return
        d = self.work / "l2-follower"
        log = (d / "follower.log").read_text(errors="replace") if (d / "follower.log").exists() else ""
        status = json.loads((d / "status.json").read_text()) if (d / "status.json").exists() else {}
        n_index = sum(1 for _ in open(d / "state" / "index")) if (d / "state" / "index").exists() else 0
        halted = re.findall(r"halted: .*", log)
        self.extra["l2_follower"] = {"verified_blocks": n_index, "halted": halted[:3],
                                     "status_keys": sorted(status)[:40], "exit": self.extra.get("follower_exit"),
                                     "status_excerpt": json.dumps(status)[:1500]}
        top_gate = max(e for _, e in self.boundaries)
        fin_epoch = status.get("native_finalized_epoch")
        vslot = status.get("verified_slot")
        self.extra["l2_follower"].update({"verified_slot": vslot, "native_finalized_epoch": fin_epoch,
                                          "l2_genesis": status.get("l2_genesis"),
                                          "timeline": self.extra.get("l2_timeline", [])[-80:]})
        self.checks.ok("L2 native follower never halted", not halted and not self.extra.get("follower_exit"),
                       {k: self.extra["l2_follower"][k] for k in ("verified_blocks", "halted", "exit")})
        self.checks.ok("L2 native follower verified finalized blocks past every gate (last gate e%d)" % top_gate,
                       not halted and fin_epoch is not None and int(fin_epoch) > top_gate and vslot is not None
                       and int(vslot) >= (top_gate + 1) * SPE,
                       {"verified_blocks": n_index, "verified_slot": vslot, "follower_finalized_epoch": fin_epoch,
                        "gates": self.boundaries})
        self.checks.ok("L2 genesis installed and finalized in the follower's verified prefix",
                       bool(status.get("l2_genesis") and status["l2_genesis"].get("finalized")), status.get("l2_genesis"))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--candidate-bin", type=Path, required=True)
    ap.add_argument("--baseline-bin", type=Path, required=True)
    ap.add_argument("--tool", type=Path, required=True, help="hf3_rehearsal_tool example binary")
    ap.add_argument("--l2-follower", type=Path, help="bloch-l2-native-follower built against the same rescheduled native")
    ap.add_argument("--equivocate-bin", type=Path,
                    help="bloch-pos built with arm.py !devnet-equivocate-tooling (devnet-equivocate only)")
    ap.add_argument("--arming", type=Path)
    ap.add_argument("--work", type=Path, required=True)
    ap.add_argument("--validators", type=int, default=8)
    ap.add_argument("--slot-ms", type=int, default=1000)
    ap.add_argument("--start-in", type=int, default=30)
    ap.add_argument("--hf1", type=int, default=10)
    ap.add_argument("--own-target", type=int, default=16)
    ap.add_argument("--hf2", type=int, default=20)
    ap.add_argument("--hf3", type=int, default=28)
    ap.add_argument("--kes-enforce", type=int, default=44)
    ap.add_argument("--kes-depth", type=int, default=12)
    ap.add_argument("--stop-epoch", type=int, default=56)
    ap.add_argument("--port-base", type=int, default=27400)
    ap.add_argument("--mesh-security", default="offer", choices=["plain", "offer", "require"])
    ap.add_argument("--l2-epoch", type=int, default=7)
    ap.add_argument("--bind-genesis", action="store_true", default=True)
    ap.add_argument("--no-invariance", action="store_true")
    ap.add_argument("--partition-epochs", type=int, default=2, help="length of the cut after HF1 (default 2)")
    ap.add_argument("--static-fallback", action="store_true", help="one live validator never registers a KES key")
    ap.add_argument("--extra-alloc", action="append", default=[], help="SCRIPT_HASH:SATS genesis allocation")
    ap.add_argument("--kes-period-epochs", type=int, default=90, help="KES_PERIOD_EPOCHS of the build")
    a = ap.parse_args()
    if a.hf1 + 1 + a.partition_epochs + 3 > a.own_target:
        sys.exit("own-target must come at least 3 epochs after the partition heals")
    if not (4 < a.hf1 < a.own_target < a.hf2 < a.hf3 <= a.kes_enforce and a.hf3 + 13 <= a.stop_epoch
            and a.kes_enforce + 8 <= a.stop_epoch):
        sys.exit("need 4 < hf1 < own-target < hf2 < hf3 <= kes-enforce, stop >= hf3+13 and >= kes-enforce+8")
    return Crossing(a).run()


if __name__ == "__main__":
    sys.exit(main())
