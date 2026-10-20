#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""HF3 KES rehearsal on a throwaway loopback devnet (codex/hf3-kes-20261020).

Needs a candidate built by run.sh with `--conf gates.conf --conf kes.conf`
(test-short KES: registration opens e4, enforcement e8, 2-epoch periods,
depth-3 trees = 16-epoch key lifetimes, staggered rotation 1 + index % 2
periods before expiry, a rehearsal-copy clock offset), and the baseline
(non-upgraded) binary for the observer. Same network as rehearse.py: 12
validators with fresh plaintext throwaway keys, loopback relays only, a
new genesis, nothing outside --work.

Scenarios (each reported PASS / FAIL / NOT-EXERCISED with evidence):

  S1  registration window: KES binds only at >= 90% registered stake. 70.8%
      registered before e8, 83.3% at e9 (no bind at either boundary), 95.8%
      at e10 -> binds at a following boundary (getkes.enforced_from).
  S2  v0 never registers and keeps proposing with its static key after bind.
  S3  automatic rotation (KesRotate) before expiry for every registered
      validator, staggered by index parity, over >= 3 full key lifetimes,
      with no KES signing error on undisturbed validators and finality
      continuous.
  S4  v4 is SIGKILLed at its first handover with the on-disk state of a swap
      interrupted between its two renames (validator.kes.retired +
      validator.kes.next, no validator.kes); it must recover at startup and
      sign with the successor.
  S5  v6 is restarted with its clock 3 periods ahead: it must erase no KES
      period (inspect before/after) and sign nothing until the clock is back.
  S6  v7 gets a validator.kes from an unrelated tree: it must refuse to sign
      (and keep running); restoring its own file resumes signing.
  S7  v3 is kept offline past its key's expiry, then re-registers with its
      static key (rescue); the new key starts KES_RESCUE_DELAY_PERIODS after
      inclusion and v3 signs again. A second registration by a validator
      whose key has NOT expired (v9) must be refused.
  S8  after rotation the old tree is gone from disk (validator.kes.retired
      shredded) and is no longer the key in force. Signing with a retained
      old tree is NOT simulated live; run.sh reports the branch's unit tests
      for that (see --unit-tests).
  S9  the non-upgraded observer forks off cleanly at the first KES transition
      (it cannot decode the 0x17 registration) without corrupting state.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
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

REG_EPOCH, ENFORCE_EPOCH, PERIOD_EPOCHS, DEPTH = 4, 8, 2, 3
LIFETIME_EPOCHS = PERIOD_EPOCHS << DEPTH  # 16
KES_ERR = re.compile(r"KES enforcement state unknown|no validator\.kes is loaded|is not v\d+'s KES key in force|"
                     r"does not cover period|is erased|refusing to erase KES periods|no KES key is registered")


def period_of(epoch: int) -> int | None:
    return None if epoch < ENFORCE_EPOCH else (epoch - ENFORCE_EPOCH) // PERIOD_EPOCHS


def first_epoch_of_period(p: int) -> int:
    return ENFORCE_EPOCH + p * PERIOD_EPOCHS


class KesRehearsal(Rehearsal):
    U, LATE, CRASH, JUMP, WRONG, RESCUE, SECOND = 0, (2, 5), 4, 6, 7, 3, 9

    def __init__(self, a):
        super().__init__(a)
        self.boundaries = [("KES registration", REG_EPOCH), ("KES enforcement", ENFORCE_EPOCH)]
        self.kes_samples: list[dict] = []
        self.windows: dict[int, list[tuple[int, int]]] = {}  # validator -> disturbed wall-slot ranges
        self.sres: dict[str, dict] = {}

    # ── helpers ──────────────────────────────────────────────────────────
    def kes(self, *args, timeout=600) -> str:
        return self.cand.run(["kes", *map(str, args)], timeout=timeout).stdout

    def getkes(self, i=None):
        for j in ([i] if i is not None else [v for v in range(self.n) if self.nodes[v].alive()]):
            try:
                return self.rpc(j, "getkes", timeout=5.0)
            except SoakError:
                continue
        return None

    def entry(self, k, v):
        return next((e for e in (k or {}).get("registered", []) if e["validator"] == v), None)

    def register(self, v, data_dir: Path, via: int, tag: str) -> tuple[bool, str]:
        # The hybrid signature's length varies (Falcon); one over
        # ADMISSION_PQ_SIGNATURE_MAX is refused on size alone (observed
        # 2026-10-20: 4596 > 4593). Re-sign (new file) up to 3 times.
        (self.work / "tx").mkdir(exist_ok=True)
        for attempt in range(3):
            out = self.work / "tx" / f"kes-register-v{v}-{tag}-{attempt}.hex"
            try:
                self.kes("register", "--dir", data_dir, "--genesis", self.genesis, "--out", out, "--validator", v)
            except SoakError as e:
                return False, f"build refused: {e}"[:400]
            ok, msg = self.submit(via, out.read_text().strip())
            if ok or "out-of-range depth or signature length" not in msg:
                return ok, msg
            self.event("kes_register_oversized_signature", validator=v, tag=tag, attempt=attempt)
        return ok, msg

    def disturb(self, v, start_slot, end_slot=None):
        self.windows.setdefault(v, []).append((start_slot, end_slot if end_slot is not None else 10**9))

    def close_window(self, v):
        s, _ = self.windows[v][-1]
        self.windows[v][-1] = (s, self.clock.wall_slot())

    def stop_node(self, v):
        self.nodes[v].stopped_on_purpose = True
        return self.nodes[v].stop()

    def start_node(self, v, extra_env=None):
        node = self.nodes[v]
        node.env = dict(self.env, **(extra_env or {}))
        node.start()
        node.stopped_on_purpose = False
        node.env = self.env

    def kes_sampler_tick(self):
        k = self.getkes()
        if k:
            self.kes_samples.append({"wall_slot": self.clock.wall_slot(), "epoch": k.get("epoch"),
                                     "period": k.get("period"), "enforced_from": k.get("enforced_from"),
                                     "bps": k.get("registered_stake_bps"), "registered": k.get("registered")})
        return k

    def wait_epoch(self, epoch: int, slot_in_epoch: int = 0) -> None:
        target = epoch * SPE + slot_in_epoch
        last = 0.0
        while self.clock.wall_slot() < target:
            if time.time() - last > 6:
                self.kes_sampler_tick()
                last = time.time()
            time.sleep(0.25)
            for node in self.nodes:
                if node.proc and node.proc.poll() is not None and not getattr(node, "stopped_on_purpose", False):
                    raise SoakError(f"{node.name} exited unexpectedly (rc {node.proc.returncode}); see {node.log_path}")

    # ── setup: KES trees before launch ──────────────────────────────────
    def launch_all(self) -> None:
        for v in range(self.n):
            if v == self.U:
                continue
            self.kes("keygen", "--dir", self.keydirs[v], "--depth", DEPTH)
            # MOVE (never copy) the tree into the data dir before first start;
            # super().launch_all() then copies validator.key beside it.
            d = self.work / f"node{v}"
            d.mkdir(parents=True, exist_ok=True)
            shutil.move(str(self.keydirs[v] / "validator.kes"), str(d / "validator.kes"))
        super().launch_all()

    # ── scenario ────────────────────────────────────────────────────────
    def run(self) -> int:
        a = self.a
        self.work.mkdir(mode=0o700, parents=True, exist_ok=False)
        report = {"status": "RUNNING", "args": {k: str(v) for k, v in vars(a).items()}}
        sampler = None
        try:
            self.preflight()
            if "kes" not in self.cand_help.lower():
                raise SoakError("candidate has no `kes` command: not an hf3-kes build")
            self.keys_and_genesis()
            self.launch_all()
            import threading
            sampler = threading.Thread(target=self.sampler, daemon=True)
            sampler.start()
            upgraded = set(range(self.n))

            self.wait_epoch(2)
            self.read_stakes()
            total = sum(self.stakes.values())
            early = [v for v in range(self.n) if v != self.U and v not in self.LATE]
            report["stakes"] = self.stakes

            # S1: register 70.8% in the window.
            self.wait_epoch(REG_EPOCH, 4)
            regs = {v: self.register(v, self.work / f"node{v}", v, "early") for v in early}
            self.event("kes_register_early", accepted={v: r[0] for v, r in regs.items()},
                       share=sum(self.stakes[v] for v in early) / total)
            self.checks.ok("S1 early registrations accepted in the window", all(r[0] for r in regs.values()),
                           {v: r[1][:160] for v, r in regs.items() if not r[0]})
            self.wait_epoch(ENFORCE_EPOCH + 1, 8)
            k = self.kes_sampler_tick()
            s1a = {"enforced_from": k and k["enforced_from"], "bps": k and k["registered_stake_bps"]}
            ok, msg = self.register(self.LATE[0], self.work / f"node{self.LATE[0]}", self.LATE[0], "late")
            s1a["late1"] = msg[:160]
            self.wait_epoch(ENFORCE_EPOCH + 2, 16)
            k = self.kes_sampler_tick()
            s1b = {"enforced_from": k and k["enforced_from"], "bps": k and k["registered_stake_bps"]}
            ok2, msg2 = self.register(self.LATE[1], self.work / f"node{self.LATE[1]}", self.LATE[1], "late")
            # KES_BIND_DELAY_EPOCHS (2 on the integration line) after the deciding boundary.
            self.wait_epoch(ENFORCE_EPOCH + 6)
            k = self.kes_sampler_tick()
            bind = k and k["enforced_from"]
            s1c = {"enforced_from": bind, "bps": k and k["registered_stake_bps"], "late2": msg2[:160]}
            self.sres["S1"] = {"after_enforce_epoch_70pct": s1a, "at_83pct": s1b, "at_96pct": s1c}
            self.checks.ok("S1 no bind below 90% registered stake (e9: ~70.8%, e10: ~83.3%)",
                           s1a["enforced_from"] is None and s1b["enforced_from"] is None
                           and (s1a["bps"] or 0) < 9000 and (s1b["bps"] or 0) < 9000, self.sres["S1"])
            self.checks.ok("S1 binds at a boundary once >= 90% is registered", bind is not None and (s1c["bps"] or 0) >= 9000,
                           s1c)
            self.boundaries.append(("KES bind", int(bind) if bind is not None else ENFORCE_EPOCH))

            # S7 (part 1): take v3 offline before its rotation horizon so its key expires.
            self.wait_epoch(18)
            self.stop_node(self.RESCUE)
            self.disturb(self.RESCUE, self.clock.wall_slot())
            self.event("s7_offline", validator=self.RESCUE)

            # S4: crash v4 just before its first handover with the interrupted-swap state.
            s4 = self.crash_mid_swap(self.CRASH, deadline_epoch=26)
            self.sres["S4"] = s4

            # S7 (part 2): v3 expired (period 8 starts at e24). Rescue at e26.
            self.wait_epoch(26)
            self.sres["S7"] = self.rescue(self.RESCUE)

            # S6: wrong validator.kes on v7 (between its rotation windows).
            self.wait_epoch(28)
            self.sres["S6"] = self.wrong_file(self.WRONG)

            # S5: clock jump on v6.
            self.wait_epoch(31)
            self.sres["S5"] = self.clock_jump(self.JUMP)

            self.wait_epoch(a.stop_epoch)
            report["final_live"] = {i: self.latest(i) for i in range(self.total_nodes)}
            self.stop_sampler.set()
            sampler.join(timeout=10)
            for node in self.nodes:
                node.stopped_on_purpose = True
                node.stop()
            if self.mesh:
                self.mesh.close_all()
            self.event("stopped")
            self.replay_and_compare(report)
            self.evaluate_kes(report, bind)
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
            report.update(checks=self.checks.rows, events=self.events, scenarios=self.sres)
            fails = [c for c in self.checks.rows if c["status"] == "FAIL"]
            report["status"] = "FAIL" if fails else "PASS"
            (self.work / "samples.json").write_text(json.dumps(self.samples) + "\n")
            (self.work / "kes-samples.json").write_text(json.dumps(self.kes_samples) + "\n")
            (self.work / "report.json").write_text(json.dumps(report, indent=2, default=str) + "\n")
            print("=" * 100)
            for c in self.checks.rows:
                print(f"{c['status']:<5} {c['name']}")
            print("=" * 100)
            print(f"VERDICT: {report['status']}  ({sum(c['status']=='PASS' for c in self.checks.rows)} pass, "
                  f"{len(fails)} fail, {sum(c['status']=='SKIP' for c in self.checks.rows)} not exercised)  "
                  f"report: {self.work/'report.json'}")
        return 1 if report["status"] != "PASS" else 0

    # ── S4 ───────────────────────────────────────────────────────────────
    def crash_mid_swap(self, v, deadline_epoch) -> dict:
        d = self.work / f"node{v}"
        while self.clock.wall_epoch() < deadline_epoch:
            k = self.kes_sampler_tick()
            e = self.entry(k, v)
            pend = e and e.get("pending_rotation")
            if pend and (d / "validator.kes.next").exists():
                handover_slot = first_epoch_of_period(pend["start_period"]) * SPE
                if self.clock.wall_slot() >= handover_slot - 6:
                    break
            time.sleep(1)
        else:
            self.checks.ok("S4 crash mid file-swap recovers at startup", False,
                           {"reason": f"v{v} had no pending rotation with a sealed successor before e{deadline_epoch}"})
            return {}
        self.nodes[v].proc.kill()  # SIGKILL
        self.nodes[v].stopped_on_purpose = True
        self.nodes[v].stop()
        self.disturb(v, self.clock.wall_slot())
        # The state a crash between promote_next's two renames leaves.
        (d / "validator.kes").rename(d / "validator.kes.retired")
        before = sorted(p.name for p in d.glob("validator.kes*"))
        while self.clock.wall_slot() < handover_slot + 2:
            time.sleep(0.5)
        log_off = self.nodes[v].log_size()
        self.start_node(v)
        self.wait_epoch(self.clock.wall_epoch() + 2)
        self.close_window(v)
        after = sorted(p.name for p in d.glob("validator.kes*"))
        k = self.kes_sampler_tick()
        e = self.entry(k, v)
        text = self.nodes[v].log_text_from(log_off)
        res = {"files_before_restart": before, "files_after": after, "pending_root": pend["root"],
               "in_force_root": e and e["root"], "kes_errors_after_restart": KES_ERR.findall(text)[:5],
               "kes_loaded_lines": re.findall(r"KES key loaded.*", text)[:2]}
        self.checks.ok("S4 crash mid file-swap: recovered at startup, signing with the successor",
                       after == ["validator.kes"] and e is not None and e["root"] == pend["root"]
                       and not res["kes_errors_after_restart"], res)
        return res

    # ── S7 ───────────────────────────────────────────────────────────────
    def rescue(self, v) -> dict:
        d = self.work / f"node{v}"
        k = self.kes_sampler_tick()
        e = self.entry(k, v)
        res = {"entry_before": e, "period": k and k["period"]}
        expired = e is not None and k and k["period"] is not None and k["period"] >= e["end_period"]
        res["expired"] = expired
        aside = self.work / "expired-kes" / f"v{v}"
        aside.mkdir(parents=True, exist_ok=True)
        for f in d.glob("validator.kes*"):
            shutil.move(str(f), str(aside / f.name))
        res["keygen"] = self.kes("keygen", "--dir", d, "--depth", DEPTH).strip()[-200:]
        ok, msg = self.register(v, d, 0, "rescue")
        res["register"] = {"accepted": ok, "reply": msg[:200]}
        self.start_node(v)
        # Negative: a validator whose key has NOT expired cannot re-register.
        tmp = self.work / "second-registration" / f"v{self.SECOND}"
        tmp.mkdir(parents=True, exist_ok=True)
        shutil.copy2(self.work / f"node{self.SECOND}" / "validator.key", tmp / "validator.key")
        self.kes("keygen", "--dir", tmp, "--depth", DEPTH)
        ok2, msg2 = self.register(self.SECOND, tmp, 0, "second")
        res["second_registration_unexpired"] = {"accepted": ok2, "reply": msg2[:200]}
        shutil.rmtree(tmp)
        self.wait_epoch(self.clock.wall_epoch() + 2)
        k = self.kes_sampler_tick()
        e2 = self.entry(k, v)
        res["entry_after"] = e2
        res["inclusion_period_upper_bound"] = k and k["period"]
        self.checks.ok("S7 expired key: static re-registration (rescue) accepted", bool(expired) and ok
                       and e2 is not None and e2["root"] != (e or {}).get("root"), res)
        self.checks.ok("S7 a second registration while the key has not expired is refused (once-only rule)",
                       not ok2 and "already registered" in msg2, res["second_registration_unexpired"])
        # Only a rescue that was applied (new root) has a start period to check.
        res["rescued_start_period"] = e2["start_period"] if e2 and e2["root"] != (e or {}).get("root") else None
        return res

    # ── S6 ───────────────────────────────────────────────────────────────
    def wrong_file(self, v) -> dict:
        d = self.work / f"node{v}"
        hold = self.work / "held-kes" / f"v{v}"
        hold.mkdir(parents=True, exist_ok=True)
        self.stop_node(v)
        self.disturb(v, self.clock.wall_slot())
        for f in d.glob("validator.kes*"):
            shutil.move(str(f), str(hold / f.name))
        tmp = self.work / "unrelated-tree" / f"v{v}"
        tmp.mkdir(parents=True, exist_ok=True)
        shutil.copy2(d / "validator.key", tmp / "validator.key")
        self.kes("keygen", "--dir", tmp, "--depth", DEPTH)
        shutil.move(str(tmp / "validator.kes"), str(d / "validator.kes"))
        shutil.rmtree(tmp)
        off = self.nodes[v].log_size()
        start = self.clock.wall_slot()
        self.start_node(v)
        self.wait_epoch(self.clock.wall_epoch() + 2)
        text = self.nodes[v].log_text_from(off)
        alive = self.nodes[v].alive()
        self.stop_node(v)
        end = self.clock.wall_slot()
        (d / "validator.kes").unlink()
        for f in hold.iterdir():
            shutil.move(str(f), str(d / f.name))
        off2 = self.nodes[v].log_size()
        self.start_node(v)
        self.wait_epoch(self.clock.wall_epoch() + 2)
        self.close_window(v)
        text2 = self.nodes[v].log_text_from(off2)
        res = {"refusals": re.findall(r"[^\n]*is not v\d+'s KES key in force[^\n]*", text)[:2],
               "alive_with_wrong_file": alive, "wrong_window_slots": [start, end],
               "kes_errors_after_restore": KES_ERR.findall(text2)[:5]}
        self.sres_pending_wrong = (v, start, end)
        return res

    # ── S5 ───────────────────────────────────────────────────────────────
    def clock_jump(self, v) -> dict:
        d = self.work / f"node{v}"
        self.stop_node(v)
        self.disturb(v, self.clock.wall_slot())
        before = json.loads(self.kes("inspect", "--dir", d))
        offset_ms = 3 * PERIOD_EPOCHS * SPE * self.a.slot_ms
        off = self.nodes[v].log_size()
        start = self.clock.wall_slot()
        self.start_node(v, {"BLOCH_REHEARSAL_CLOCK_OFFSET_MS": str(offset_ms)})
        self.wait_epoch(self.clock.wall_epoch() + 2)
        text = self.nodes[v].log_text_from(off)
        alive = self.nodes[v].alive()
        self.stop_node(v)
        end = self.clock.wall_slot()
        mid = json.loads(self.kes("inspect", "--dir", d))
        off2 = self.nodes[v].log_size()
        self.start_node(v)
        self.wait_epoch(self.clock.wall_epoch() + 2)
        self.close_window(v)
        text2 = self.nodes[v].log_text_from(off2)
        res = {"offset_ms": offset_ms, "key_period_before": before["period"], "key_period_after_jump": mid["period"],
               "evolved_lines_during_jump": re.findall(r"KES key evolved[^\n]*", text)[:3],
               "refusal_lines": re.findall(r"[^\n]*refusing to erase KES periods[^\n]*", text)[:2],
               "alive_during_jump": alive, "jump_window_slots": [start, end],
               "kes_errors_after_clock_restored": KES_ERR.findall(text2)[:5]}
        self.sres_pending_jump = (v, start, end)
        return res

    # ── verdicts ─────────────────────────────────────────────────────────
    def blocks_by(self, v, lo_slot, hi_slot) -> int:
        return sum(1 for s, p in self.proposers.items() if p == v and lo_slot <= s < hi_slot)

    def evaluate_kes(self, report, bind) -> None:
        stop_slot = self.a.stop_epoch * SPE
        bind_slot = (int(bind) if bind is not None else ENFORCE_EPOCH) * SPE
        # S2: the unregistered validator keeps proposing statically after bind.
        n0 = self.blocks_by(self.U, bind_slot, stop_slot)
        self.checks.ok("S2 unregistered v0 keeps proposing with its static key after bind", n0 > 0,
                       {"v0_blocks_after_bind": n0, "bind_epoch": bind})
        # S6 / S5 verdicts need the replayed proposer map.
        if hasattr(self, "sres_pending_wrong"):
            v, s, e = self.sres_pending_wrong
            r = self.sres["S6"]
            r["blocks_with_wrong_file"] = self.blocks_by(v, s, e)
            r["blocks_after_restore"] = self.blocks_by(v, e, stop_slot)
            self.checks.ok("S6 wrong validator.kes: refuses to sign, keeps running; own file resumes signing",
                           r["blocks_with_wrong_file"] == 0 and bool(r["refusals"]) and r["alive_with_wrong_file"]
                           and r["blocks_after_restore"] > 0 and not r["kes_errors_after_restore"], r)
        if hasattr(self, "sres_pending_jump"):
            v, s, e = self.sres_pending_jump
            r = self.sres["S5"]
            r["blocks_during_jump"] = self.blocks_by(v, s, e)
            r["blocks_after_clock_restored"] = self.blocks_by(v, e, stop_slot)
            self.checks.ok("S5 clock jump: no KES period erased and nothing signed until the clock is back",
                           r["key_period_after_jump"] == r["key_period_before"] and not r["evolved_lines_during_jump"]
                           and r["blocks_during_jump"] == 0 and r["alive_during_jump"]
                           and r["blocks_after_clock_restored"] > 0, r)
            if not r["refusal_lines"]:
                r["note"] = ("the node stops duties while its clock is ahead of the chain head, so the "
                             "BLOCH_KES_ALLOW_PERIOD_JUMP refusal path is not reached live; it is pinned by the "
                             "unit test kes_evolution_refuses_multi_period_jumps_without_confirmation")
        if "S7" in self.sres:
            r = self.sres["S7"]
            sp = r.get("rescued_start_period")
            if sp is not None:
                r["blocks_after_rescued_start"] = self.blocks_by(self.RESCUE, first_epoch_of_period(sp) * SPE, stop_slot)
                self.checks.ok("S7 rescued key starts after the delay and the validator signs again",
                               r["blocks_after_rescued_start"] > 0, {k: r[k] for k in ("rescued_start_period",
                                                                                    "blocks_after_rescued_start")})
        # S3: rotations over >= 3 lifetimes, staggered, no KES errors on undisturbed validators.
        roots: dict[int, list[str]] = {}
        expired_seen: dict[int, int] = {}
        for smp in self.kes_samples:
            for e in smp.get("registered") or []:
                v = e["validator"]
                if not roots.get(v) or roots[v][-1] != e["root"]:
                    roots.setdefault(v, []).append(e["root"])
                if smp.get("period") is not None and e["periods_remaining"] == 0:
                    expired_seen[v] = expired_seen.get(v, 0) + 1
        undisturbed = [v for v in range(self.n) if v != self.U and v not in self.windows]
        submits: dict[int, list[int]] = {}
        errors: dict[int, list[str]] = {}
        for v in range(self.n):
            text = self.nodes[v].log_text()
            submits[v] = [int(p) for p in re.findall(rf"KES rotation for v{v} submitted in period (\d+)", text)]
            if v in undisturbed:
                errs = KES_ERR.findall(text)
                if errs:
                    errors[v] = errs[:3]
        lifetimes = (self.a.stop_epoch - ENFORCE_EPOCH) // LIFETIME_EPOCHS
        ok3 = (lifetimes >= 3 and all(len(roots.get(v, [])) >= lifetimes for v in undisturbed)
               and not any(expired_seen.get(v) for v in undisturbed) and not errors)
        self.checks.ok(f"S3 auto-rotation before expiry for every undisturbed validator over {lifetimes} lifetimes",
                       ok3, {"distinct_roots": {v: len(roots.get(v, [])) for v in range(self.n)},
                             "expired_samples": expired_seen, "kes_errors": errors, "undisturbed": undisturbed})
        first = {v: (s[0] if s else None) for v, s in submits.items() if v in undisturbed}
        even = {first[v] for v in first if v % 2 == 0 and first[v] is not None}
        odd = {first[v] for v in first if v % 2 == 1 and first[v] is not None}
        self.checks.ok("S3 rotation is staggered by index (odd indices submit one period earlier)",
                       bool(even) and bool(odd) and min(even) > min(odd), {"first_submit_period": first})
        # Duties: every undisturbed registered validator proposed in every lifetime window.
        missing = {}
        for v in undisturbed:
            for lt in range(lifetimes):
                lo = (ENFORCE_EPOCH + lt * LIFETIME_EPOCHS) * SPE
                if self.blocks_by(v, lo, lo + LIFETIME_EPOCHS * SPE) == 0:
                    missing.setdefault(v, []).append(lt)
        self.checks.ok("S3 every undisturbed validator proposed in every key lifetime", not missing, missing)
        # Finality continuity after bind (live samples, nodes 0..n-1).
        worst = 0
        for s in self.samples:
            if s["node"] in undisturbed and s["wall_slot"] >= bind_slot + 2 * SPE:
                worst = max(worst, s["wall_slot"] // SPE - s["fin"])
        self.checks.ok("S3 finality continuous after bind (wall epoch - finalized <= 4 on every sample)",
                       worst <= 4, {"worst_lag_epochs": worst})
        # S8 (live part).
        leftovers = {v: sorted(p.name for p in (self.work / f"node{v}").glob("validator.kes.retired"))
                     for v in range(self.n)}
        self.checks.ok("S8 rotated-out trees are shredded from disk (no validator.kes.retired left)",
                       not any(leftovers.values()), {k: v for k, v in leftovers.items() if v})
        self.checks.add("S8 signing/rotating/slashing with a retained old tree", "SKIP",
                        {"reason": "not simulated live; covered by the hf3-kes unit tests listed by run-kes.sh"})
        # S9 is the observer part of replay_and_compare; relabel for the report.
        obs = report.get("observer", {})
        self.checks.ok("S9 non-upgraded node forks off at the first KES transition, not before registration opens",
                       obs.get("fork_slot") is not None and obs["fork_slot"] >= REG_EPOCH * SPE, obs)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--candidate-bin", type=Path, required=True)
    ap.add_argument("--baseline-bin", type=Path, required=True)
    ap.add_argument("--arming", type=Path)
    ap.add_argument("--work", type=Path, required=True)
    ap.add_argument("--validators", type=int, default=12)
    ap.add_argument("--slot-ms", type=int, default=2000)
    ap.add_argument("--start-in", type=int, default=20)
    ap.add_argument("--stop-epoch", type=int, default=58)
    ap.add_argument("--port-base", type=int, default=33400)
    ap.add_argument("--bind-genesis", action="store_true")
    a = ap.parse_args()
    a.hf1, a.hf2, a.hf3 = REG_EPOCH, ENFORCE_EPOCH, ENFORCE_EPOCH + 4  # labels only (Rehearsal needs them)
    if a.validators != 12:
        sys.exit("the KES scenario roles assume 12 validators")
    arming = json.loads(a.arming.read_text()) if a.arming else {}
    lit = arming.get("literal_overrides", {})
    want = {"HF3_KES_EPOCH": REG_EPOCH, "HF3_KES_ENFORCE_EPOCH": ENFORCE_EPOCH, "KES_PERIOD_EPOCHS": PERIOD_EPOCHS,
            "KES_DEFAULT_DEPTH": DEPTH}
    if any(lit.get(k) != v for k, v in want.items()):
        sys.exit(f"candidate must be armed with kes.conf ({want}); arming says {lit}")
    return KesRehearsal(a).run()


if __name__ == "__main__":
    sys.exit(main())
