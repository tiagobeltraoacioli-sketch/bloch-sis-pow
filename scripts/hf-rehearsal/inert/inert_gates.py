#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Exercise the gates that real history leaves inert, on private loopback nets.

Each cell submits a transaction, block or vote the gate must refuse or accept,
just before and just after the gate, on rehearsal builds of 78d4921c. Side
nodes run a build where only one gate moved, so a forked side shows the gate
is a consensus rule. Throwaway keys only; everything binds 127.0.0.1.

  inert_gates.py --net A|B|C1|C2 --bins DIR --work NEW_DIR [--port-base 28300]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lifecycle_devnet_soak_lib as lib  # noqa: E402
from lifecycle_devnet_soak_lib import RpcError, SoakError  # noqa: E402

SPE = 32
HF1, OWN, HF2, HF3, KESE, BIND = 10, 16, 26, 36, 44, 46
BLCH = 100_000_000


class Net:
    def __init__(self, a):
        self.a = a
        self.w = a.work.resolve()
        self.w.mkdir(parents=True, exist_ok=False)
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("BLOCH_")}
        self.env["BLOCH_KEYSTORE_ALLOW_PLAINTEXT"] = "1"
        self.res = open(self.w / "cells.jsonl", "a", buffering=1)
        self.nodes: list[lib.Node] = []
        self.binaries: list[str] = []
        self.allocs: dict = {}
        self.stop = threading.Event()

    def bin(self, name):
        return lib.Bin((self.a.bins / f"bloch-pos-{name}").resolve(), self.env, self.w / "commands.log")

    def cell(self, name, **kw):
        kw.update(cell=name, wall_slot=self.clock.wall_slot() if hasattr(self, "clock") else None,
                  wall_epoch=self.clock.wall_epoch() if hasattr(self, "clock") else None)
        self.res.write(json.dumps(kw, default=str) + "\n")
        print(json.dumps(kw, default=str)[:400], flush=True)

    def rport(self, i): return self.a.port_base + i
    def mport(self, i): return self.a.port_base + 30 + i
    def sport(self, i): return self.a.port_base + 60 + i

    def rpc(self, i, method, params=None, timeout=5.0):
        return lib.rpc(self.rport(i), method, params or [], timeout=timeout)

    def submit(self, i, hex_tx):
        try:
            return True, json.dumps(self.rpc(i, "sendrawtransaction", [hex_tx], timeout=15.0))[:200]
        except RpcError as e:
            return False, f"{e.code}: {e.message} {e.data or ''}"[:400]
        except SoakError as e:
            return False, f"transport: {e}"[:300]

    def wait(self, epoch, slot=0):
        target = epoch * SPE + slot
        while self.clock.wall_slot() < target:
            time.sleep(0.05)

    # ── network ──────────────────────────────────────────────────────────
    def build_net(self, validators: list[str], observers: list[str], kes: set[int], allocs: list[tuple[str, str, int]],
                  extra_keys=()):
        """validators / observers: variant names. allocs: (name, keydir name, sat)."""
        self.n = len(validators)
        self.binaries = validators + observers
        tool = self.bin("tool")
        self.tool = tool
        keydirs = []
        for i in range(self.n):
            d = self.w / "keys" / f"v{i}"
            tool.keygen(d, i)
            keydirs.append(d)
        self.keydirs = keydirs
        cand = self.bin("cand")
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda v: cand.run(["kes", "keygen", "--dir", str(keydirs[v]), "--depth", "8"], timeout=1800), sorted(kes)))
        self.keyinfo = {}
        args = ["genesis", "--keys", ",".join(map(str, keydirs)), "--out", str(self.w / "genesis.bin"),
                "--slot-ms", str(self.a.slot_ms), "--start-in", "20", "--bind-genesis"]
        names = []
        for name, keyname, sat in allocs:
            kd = self.w / "keys" / keyname
            if keyname not in self.keyinfo:
                if keyname.startswith("slh-"):
                    out = tool.run(["gate-probe", "slh-keystore", "--dir", str(kd), "--index", "901"], timeout=120).stdout
                    self.keyinfo[keyname] = re.search(r"^script ([0-9a-f]{64})", out, re.M).group(1)
                else:
                    tool.keygen(kd, 900 + len(self.keyinfo))
                    _, pk, _ = tool.keygen_public(kd)
                    (kd / "pubkey.hex").write_text(pk + "\n")
                    self.keyinfo[keyname] = lib.sha3_hex(pk)
            args += ["--alloc", f"{self.keyinfo[keyname]}:{sat}"]
            names.append(name)
        out = tool.run(args, timeout=600)
        found = lib.ALLOC_RE.findall(out.stdout + out.stderr)
        assert len(found) == len(names), out.stdout[-800:]
        for name, (_, txid, vout, sat, sh) in zip(names, found):
            self.allocs[name] = {"txid": txid, "vout": int(vout), "sat": int(sat), "script_hash": sh}
        gms, sms = lib.manifest_clock(self.w / "genesis.bin")
        self.clock = lib.Clock(gms, sms)
        for i, variant in enumerate(self.binaries):
            d = self.w / f"node{i}"
            d.mkdir(parents=True)
            if i < self.n:
                shutil.copy2(keydirs[i] / "validator.key", d / "validator.key")
                if i in kes:
                    shutil.move(str(keydirs[i] / "validator.kes"), str(d / "validator.kes"))
            peers = ",".join(f"127.0.0.1:{self.sport(j)}" for j in range(len(self.binaries)) if j != i)
            cmd = [str((self.a.bins / f"bloch-pos-{variant}").resolve()), "run", "--data-dir", str(d),
                   "--genesis", str(self.w / "genesis.bin"), "--transport", "devnet", "--no-doppelganger-check",
                   "--listen", str(self.sport(i)), "--listen-addr", "127.0.0.1", "--peers", peers,
                   "--rpc-bind", "127.0.0.1", "--rpc-port", str(self.rport(i)),
                   "--metrics-bind", "127.0.0.1", "--metrics-port", str(self.mport(i))]
            node = lib.Node(name=f"node{i}", slot=i, data_dir=d, rpc_port=self.rport(i), mesh_port=self.sport(i),
                            metrics_port=self.mport(i), cmd=cmd, env=self.env, log_path=d / "run.log", has_key=i < self.n)
            self.nodes.append(node)
            node.start()
            time.sleep(0.1)
        self.cell("launched", binaries=self.binaries)
        threading.Thread(target=self.sampler, daemon=True).start()

    def sampler(self):
        with open(self.w / "samples.jsonl", "a", buffering=1) as fh:
            while not self.stop.is_set():
                ws = self.clock.wall_slot()
                for i in range(len(self.nodes)):
                    try:
                        r = self.rpc(i, "getchaininfo", timeout=2.0)
                        fh.write(json.dumps({"ws": ws, "n": i, "slot": r["slot"], "fin": r["finalized"]["epoch"],
                                             "head": r["block_id"]}) + "\n")
                    except (SoakError, KeyError, TypeError):
                        pass
                self.stop.wait(4.0)

    def block(self, i, slot):
        try:
            b = self.rpc(i, "getblockbyslot", [slot])
            return b if b and b.get("slot") == slot else None
        except SoakError:
            return None

    def find_block(self, pool: set[int], lo_slot, node=1):
        """Newest canonical block at or after lo_slot by one of pool, waiting for one."""
        while True:
            ws = self.clock.wall_slot()
            for s in range(ws - 1, lo_slot - 1, -1):
                b = self.block(node, s)
                if b and b.get("proposer_index") in pool:
                    return s, b["proposer_index"]
            if ws > lo_slot + 3 * SPE:
                return None, None
            time.sleep(0.25)

    def log(self, i):
        return self.nodes[i].log_text()

    def fee(self):
        return int(self.rpc(1, "getvalidatoradmission")["next_base_fee_millisat_per_gas"])

    def probe(self, *args, timeout=300):
        try:
            return True, self.tool.run(["gate-probe", *map(str, args)], timeout=timeout).stdout
        except SoakError as e:
            return False, str(e)[-500:]

    # ── transactions ─────────────────────────────────────────────────────
    def txfile(self, tag):
        (self.w / "tx").mkdir(exist_ok=True)
        return self.w / "tx" / f"{tag}-{int(time.time() * 1000)}.hex"

    def kes_register(self, v, via):
        for _ in range(4):
            out = self.txfile(f"kes-reg-v{v}")
            try:
                self.bin("cand").run(["kes", "register", "--dir", str(self.w / f"node{v}"),
                                      "--genesis", str(self.w / "genesis.bin"), "--out", str(out), "--validator", str(v)], timeout=300)
            except SoakError as e:
                return False, f"build refused: {e}"[-300:], None
            hx = out.read_text().strip()
            ok, msg = self.submit(via, hx)
            if ok or "out-of-range depth or signature length" not in msg:
                return ok, msg, hx
        return ok, msg, hx

    def slh_spend(self, via, price_epoch=None):
        a = self.allocs["slh"]
        out = self.txfile("slh")
        epoch = self.clock.wall_epoch()
        args = ["slh-transfer", "--dir", self.w / "keys" / "slh-spend", "--input", f"{a['txid']}:{a['vout']}:{a['sat']}",
                "--to", lib.sha3_hex("00" * 32), "--base-fee", self.fee(), "--tip", 1000, "--epoch", epoch, "--out", out]
        if price_epoch is not None:
            args += ["--price-epoch", price_epoch]
        ok, o = self.probe(*args)
        if not ok:
            return False, f"build refused: {o}", o
        return (*self.submit(via, out.read_text().strip()), o)

    def rotation(self, validator, via):
        out = self.txfile("rot")
        ok, o = self.probe("rotate", "--genesis", self.w / "genesis.bin", "--auth-dir", self.w / "keys" / "funder",
                           "--new-dir", self.w / "keys" / "slh-cred", "--validator", validator,
                           "--epoch", self.clock.wall_epoch(), "--out", out)
        if not ok:
            return False, f"build refused: {o}", o
        return (*self.submit(via, out.read_text().strip()), o)

    def deposit(self, name, stake_blch, via=1):
        fd = self.w / "keys" / "funder"
        jd = self.w / "keys" / f"joiner-{name}"
        cli = self.bin("cand")
        cli.keygen(jd, "auto")
        _, vpk, randao = cli.keygen_public(jd)
        (jd / "pubkey.hex").write_text(vpk + "\n")
        a = self.allocs[f"dep-{name}"]
        fsh = self.keyinfo["funder"]
        fee = self.fee()
        epoch = self.clock.wall_epoch()
        p = [self.w / "tx" / f"dep-{name}.{k}.hex" for k in range(3)]
        (self.w / "tx").mkdir(exist_ok=True)
        cli.run(["validator-deposit", "prepare", "--genesis", str(self.w / "genesis.bin"), "--funding-pubkey", str(fd / "pubkey.hex"),
                 "--validator-pubkey", str(jd / "pubkey.hex"), "--randao", randao, "--withdrawal", fsh, "--change", fsh,
                 "--stake", str(stake_blch * BLCH), "--input", f"{a['txid']}:{a['vout']}:{a['sat']}",
                 "--max-base-fee", str(fee * 2 + 100), "--tip", "5", "--expiry", str(epoch + 6), "--commission", "500",
                 "--out", str(p[0])], timeout=120)
        cli.run(["validator-deposit", "sign", "--genesis", str(self.w / "genesis.bin"), "--tx", str(p[0]), "--role", "funding",
                 "--dir", str(fd), "--out", str(p[1])], timeout=300)
        cli.run(["validator-deposit", "sign", "--genesis", str(self.w / "genesis.bin"), "--tx", str(p[1]), "--role", "validator",
                 "--dir", str(jd), "--out", str(p[2])], timeout=300)
        ok, msg = self.submit(via, p[2].read_text().strip())
        return ok, msg, lib.sha3_hex(vpk)

    def deposit_retry(self, name, stake_blch):
        """The funding key has a per-slot verification allowance: one try per fresh slot."""
        ok, msg, h = self.deposit(name, stake_blch)
        for _ in range(8):
            if ok or "allowance" not in msg:
                break
            time.sleep(1.2)
            ok, msg = self.submit(1, (self.w / "tx" / f"dep-{name}.2.hex").read_text().strip())
        return ok, msg, h

    def val_by_hash(self, h, via=1):
        try:
            r = self.rpc(via, "getvalidatorbykey", [h])
        except SoakError:
            return None
        for k in ("index", "validator", "validator_index"):
            if isinstance(r, dict) and k in r:
                return int(r[k])
        return None

    # ── forensic helpers ─────────────────────────────────────────────────
    def first_divergence(self, obs, ref, lo_slot, hi_slot):
        """First slot whose block differs between the two nodes, plus the observer's reject lines."""
        for s in range(lo_slot, hi_slot):
            a, b = self.block(obs, s), self.block(ref, s)
            if (a or {}).get("block_id") != (b or {}).get("block_id"):
                lines = [l for l in self.log(obs).splitlines() if re.search(r"(?i)reject|mismatch", l)][:4]
                return {"slot": s, "epoch": s // SPE, "obs_block": (a or {}).get("block_id"), "ref_block": (b or {}).get("block_id"),
                        "ref_txs": (b or {}).get("transactions") if b else None, "obs_reject_lines": lines}
        return None

    def early_blocks(self, v, ref=1):
        """Blocks a side validator built with transactions, and the on-side verdict on each."""
        rows = []
        for m in re.finditer(r"\[slot (\d+)\] proposing block ([0-9a-f]+) \((\d+) attestations, (\d+) txs", self.log(v)):
            slot, bid, _, txs = int(m[1]), m[2], m[3], int(m[4])
            if not txs:
                continue
            ref_b = self.block(ref, slot)
            ref_text = self.log(ref)
            lines = [l for l in ref_text.splitlines() if bid in l][:3]
            rows.append({"slot": slot, "epoch": slot // SPE, "id8": bid, "txs": txs,
                         "adopted_by_on_side": bool(ref_b and ref_b["block_id"].startswith(bid)),
                         "on_side_block_at_slot": (ref_b or {}).get("block_id"), "on_side_lines": lines})
        return rows

    def forms(self, node, lo, hi):
        ok, o = self.probe("sig-forms", "--genesis", self.w / "genesis.bin", "--data-dir", self.w / f"node{node}",
                           "--from-epoch", lo, "--to-epoch", hi, timeout=600)
        return [json.loads(x) for x in o.splitlines() if x.startswith("{")] if ok else o

    def gates_seen(self):
        rows = {}
        for i, b in enumerate(self.binaries):
            try:
                r = self.rpc(i, "getchaininfo")
                rows[f"{i}:{b}"] = r.get("hard_forks") or {k: v for k, v in r.items() if "fork" in k}
            except SoakError as e:
                rows[f"{i}:{b}"] = str(e)
        (self.w / "gates-seen.json").write_text(json.dumps(rows, indent=1))

    def finish(self):
        self.stop.set()
        for n in self.nodes:
            try:
                n.stop()
            except Exception:
                pass
        (self.w / "DONE").write_text(time.strftime("%FT%TZ", time.gmtime()) + "\n")

    # ── net A: transaction gates with side nodes ─────────────────────────
    def run_a(self):
        vals = ["cand"] * 14
        vals[3], vals[6], vals[9] = "kes-early", "slh-early", "pq-early"
        obs = ["growth-late", "slash-late", "kes-late", "slh-late", "pq-late"]
        self.G, self.S, self.KR, self.SL, self.PQ = 14, 15, 16, 17, 18
        allocs = [("slh", "slh-spend", 1000 * BLCH), ("cred", "slh-cred", 1000 * BLCH)]
        for name in ["A0", "A1", "A2", "A3", "B0", "B1", "B2"]:
            allocs.append((f"dep-{name}", "funder", (50_010 * BLCH) + len(allocs)))
        self.build_net(vals, obs, kes={1, 3}, allocs=allocs)
        self.wait(1); self.gates_seen()
        # Growth cap: batch A activates before the gate, batch B would after it.
        self.wait(13, 4)
        self.joiners = {}
        for n in ["A0", "A1", "A2", "A3"]:
            ok, msg, h = self.deposit(n, 50_000)
            self.joiners[n] = h; self.cell("growth_deposit", batch="A", joiner=n, accepted=ok, reply=msg, hash=h)
        self.wait(20, 4)
        for n in ["B0", "B1", "B2"]:
            ok, msg, h = self.deposit(n, 50_000)
            self.joiners[n] = h; self.cell("growth_deposit", batch="B", joiner=n, accepted=ok, reply=msg, hash=h)
        # Slashing v2 evidence admission.
        self.wait(HF2 - 2, 2); self.evidence_round("pre", accused=12)
        self.wait(HF2 - 1, 20); self.evidence_replies("pre-last-epoch")
        self.wait(HF2, 1); self.evidence_replies("post-first-slots")
        self.wait(HF2 + 1, 2); self.evidence_round("post", accused=0)
        # Early proposers: each side validator gets the transaction 3 epochs early.
        self.wait(33, 1)
        ok, msg, _ = self.kes_register(3, 3); self.cell("kes_early_side_admit", accepted=ok, reply=msg)
        ok, msg, _ = self.kes_register(3, 1); self.cell("kes_on_side_refuse_early", accepted=ok, reply=msg)
        ok, msg, o = self.slh_spend(6); self.cell("slh_early_side_admit", accepted=ok, reply=msg)
        ok, msg, o = self.slh_spend(1); self.cell("slh_on_side_refuse_early", accepted=ok, reply=msg)
        jv = self.val_by_hash(self.joiners["A0"])
        self.cell("rotation_target", validator=jv)
        for e in (33, 34, 35):
            if e > 33:
                self.wait(e, 1)
            ok, msg, o = self.rotation(jv, 9); self.cell("pq_early_side_admit", epoch=e, accepted=ok, reply=msg)
        ok, msg, o = self.rotation(jv, 1); self.cell("pq_on_side_refuse_early", accepted=ok, reply=msg)
        # Last slots of e35: refused. First slots of e36: accepted.
        self.wait(HF3 - 1, 18)
        ok, msg, _ = self.kes_register(1, 1); self.cell("kes_last_epoch_before", accepted=ok, reply=msg)
        ok, msg, o = self.slh_spend(1); self.cell("slh_last_epoch_before", accepted=ok, reply=msg)
        ok, msg, o = self.rotation(jv, 1); self.cell("pq_last_epoch_before", accepted=ok, reply=msg)
        self.wait(HF3, 0)
        ok, msg, _ = self.kes_register(1, 1); self.cell("kes_first_slots_after", accepted=ok, reply=msg)
        ok, msg, o = self.slh_spend(1, price_epoch=HF3 - 1); self.cell("slh_underpriced_after", accepted=ok, reply=msg, tool=o[-160:])
        ok, msg, o = self.slh_spend(1); self.cell("slh_first_slots_after", accepted=ok, reply=msg, tool=o[-160:])
        ok, msg, o = self.rotation(jv, 1); self.cell("pq_first_slots_after", accepted=ok, reply=msg)
        t = threading.Thread(target=self.inclusion_watch, args=(jv,), daemon=True); t.start()
        self.wait(HF3 + 3)
        # Growth cap outcome is read at the end, after the window has passed.
        self.wait(self.a.stop_epoch)
        act = {}
        for n, h in self.joiners.items():
            v = self.val_by_hash(h)
            try:
                r = self.rpc(1, "getvalidator", [v]) if v is not None else {}
                act[n] = {"validator": v, "activation_epoch": r.get("activation_epoch"), "state": r.get("state")}
                ro = self.rpc(self.G, "getvalidator", [v]) if v is not None else {}
                act[n]["late_side_activation_epoch"] = ro.get("activation_epoch")
            except SoakError as e:
                act[n] = {"validator": v, "error": str(e)}
        self.cell("growth_activation", activations=act)
        for label, i in (("growth-late", self.G), ("slash-late", self.S), ("kes-late", self.KR), ("slh-late", self.SL), ("pq-late", self.PQ)):
            self.cell("late_side_fork", side=label, divergence=self.first_divergence(i, 1, (HF2 - 2) * SPE, self.clock.wall_slot() - 40))
        for label, v in (("kes-early", 3), ("slh-early", 6), ("pq-early", 9)):
            self.cell("early_side_blocks", side=label, rows=self.early_blocks(v))
        for i in (2, 5):
            ch = self.rpc(i, "getchaininfo")
            self.cell("on_side_final", node=i, slot=ch["slot"], finalized=ch["finalized"]["epoch"], block=ch["block_id"])
        self.finish()

    def inclusion_watch(self, jv):
        got = set()
        a = self.allocs["slh"]
        while not self.stop.is_set() and len(got) < 3:
            try:
                k = self.rpc(1, "getkes")
                if "kes" not in got and any((isinstance(r, dict) and r.get("validator") == 1) or r == 1 for r in (k.get("registered") or [])):
                    got.add("kes"); self.cell("kes_included", getkes={x: k.get(x) for x in ("epoch", "registered_stake_bps")})
                v = self.rpc(1, "gettxout", [a["txid"], a["vout"]])
                if "slh" not in got and v and v.get("unspent") is False:
                    got.add("slh"); self.cell("slh_included", view=v)
                r = self.rpc(1, "getvalidator", [jv])
                if "pq" not in got and r.get("withdrawal_credentials") == self.keyinfo["slh-cred"]:
                    got.add("pq"); self.cell("pq_included", credentials=r.get("withdrawal_credentials"))
            except SoakError:
                pass
            time.sleep(0.5)

    def run_k(self):
        """First slots of the opening epoch, and a suite-0x0003 spend included early by a side proposer."""
        vals = ["cand"] * 6
        vals[3] = "slh-early"
        self.build_net(vals, ["slh-late"], kes={1, 2, 4}, allocs=[("slh", "slh-spend", 1000 * BLCH)])
        self.wait(1); self.gates_seen()
        self.wait(33, 1)
        ok, msg, o = self.slh_spend(3, price_epoch=HF3); self.cell("slh_early_side_admit", accepted=ok, reply=msg, tool=o[-120:])
        ok, msg, o = self.slh_spend(1, price_epoch=HF3); self.cell("slh_on_side_refuse_early", accepted=ok, reply=msg)
        self.wait(HF3, 0)
        head = lambda: self.rpc(1, "getchaininfo")["slot"]
        h0 = head()
        ok, msg, hx = self.kes_register(1, 1); self.cell("kes_opening_try", attempt=0, head_slot=h0, accepted=ok, reply=msg)
        while head() < HF3 * SPE:
            time.sleep(0.05)
        h1 = head()
        ok2, msg2 = self.submit(1, hx); self.cell("kes_opening_same_bytes_after_first_block", head_slot=h1, accepted=ok2, reply=msg2)
        ok3, msg3, _ = self.kes_register(2, 1); self.cell("kes_opening_try", attempt=1, head_slot=h1, accepted=ok3, reply=msg3)
        ok4, msg4, _ = self.kes_register(1, 2); self.cell("kes_opening_fresh_bytes_same_validator", head_slot=head(), accepted=ok4, reply=msg4)
        ok5, msg5, _ = self.kes_register(4, 1); self.cell("kes_opening_try", attempt=2, head_slot=head(), accepted=ok5, reply=msg5)
        self.wait(HF3 + 2)
        k = self.rpc(1, "getkes")
        self.cell("kes_after", registered=k.get("registered"), bps=k.get("registered_stake_bps"))
        self.cell("slh_side_blocks", rows=self.early_blocks(3))
        self.cell("slh_side_fork", divergence=self.first_divergence(3, 1, 32 * SPE, (HF3 + 1) * SPE))
        self.finish()

    def run_l(self):
        """A node that keeps the KES registration gate closed, facing the first 0x17 block."""
        self.build_net(["cand"] * 6, ["kes-late"], kes={1}, allocs=[("ctl", "funder", 1000 * BLCH)])
        self.wait(1); self.gates_seen()
        self.wait(HF3, 4)
        ok, msg, _ = self.kes_register(1, 1); self.cell("kes_accepted", accepted=ok, reply=msg)
        self.wait(HF3 + 1, 8)
        self.cell("kes_after", registered=self.rpc(1, "getkes").get("registered"))
        self.cell("kes_late_fork", divergence=self.first_divergence(6, 1, HF3 * SPE, (HF3 + 1) * SPE))
        self.finish()

    def run_g(self):
        """Growth cap only: a batch that exceeds the budget before the gate, another after it."""
        allocs = [(f"dep-{n}", "funder", (50_010 * BLCH) + i) for i, n in enumerate(["A0", "A1", "A2", "A3", "B0", "B1", "B2"])]
        self.build_net(["cand"] * 14, ["growth-late"], kes=set(), allocs=allocs)
        self.wait(1); self.gates_seen()
        self.wait(13, 4)
        self.joiners = {}
        for n in ["A0", "A1", "A2", "A3"]:
            ok, msg, h = self.deposit_retry(n, 50_000)
            self.joiners[n] = h; self.cell("growth_deposit", batch="A", joiner=n, accepted=ok, reply=msg[:120], hash=h)
        self.wait(20, 4)
        for n in ["B0", "B1", "B2"]:
            ok, msg, h = self.deposit_retry(n, 50_000)
            self.joiners[n] = h; self.cell("growth_deposit", batch="B", joiner=n, accepted=ok, reply=msg[:120], hash=h)
        for e in (24, 26, 28, 30, 36, 44, 47, 48, 49, self.a.stop_epoch):
            self.wait(e, 2)
            self.cell("growth_activation", at_epoch=e, activations=self.activations(14))
        self.cell("late_side_fork", side="growth-late", divergence=self.first_divergence(14, 1, (HF2 - 2) * SPE, self.clock.wall_slot() - 40))
        self.finish()

    def activations(self, late):
        act = {}
        for n, h in self.joiners.items():
            v = self.val_by_hash(h)
            try:
                r = self.rpc(1, "getvalidator", [v]) if v is not None else {}
                ro = self.rpc(late, "getvalidator", [v]) if v is not None else {}
                act[n] = {"validator": v, "on_side": r.get("activation_epoch"), "state": r.get("state"), "late_side": ro.get("activation_epoch")}
            except SoakError as e:
                act[n] = {"validator": v, "error": str(e)[:100]}
        return act

    def bad_evidence(self, slot, slot2, kind, tag):
        out = self.txfile(f"ev-{kind}-{tag}")
        ok, o = self.probe("bad-evidence", "--genesis", self.w / "genesis.bin", "--data-dir", self.w / "node1", "--slot", slot,
                           "--slot2", slot2, "--kind", kind, "--tag", tag, "--out", out)
        return out.read_text().strip() if ok else None

    def evidence_replies(self, label):
        s, p = self.find_block({2, 4, 5, 7, 8, 10, 11, 13}, self.clock.wall_slot() - SPE)
        s2, _ = self.find_block({1}, self.clock.wall_slot() - 2 * SPE)
        tag = self.clock.wall_slot() % 60000
        for kind in ("forged-sig", "no-conflict", "two-signers"):
            hx = self.bad_evidence(s, s2 or s, kind, tag)
            for node, name in ((1, "on-side"), (self.S, "slash-late")):
                ok, msg = self.submit(node, hx)
                self.cell("evidence_reply", phase=label, kind=kind, node=name, accepted=ok, reply=msg)

    def evidence_round(self, label, accused):
        """Forged evidence burst against one validator, then that validator's genuine evidence, in one slot."""
        s, p = self.find_block({accused}, self.clock.wall_slot() - 2 * SPE)
        if s is None:
            self.cell("evidence_round", phase=label, error=f"no recent block by v{accused}"); return
        out = self.txfile(f"ev-genuine-{label}")
        self.bin("tool").run(["devnet-equivocate", "--genesis", str(self.w / "genesis.bin"), "--dir", str(self.keydirs[accused]),
                              "--data-dir", str(self.w / "node1"), "--slot", str(s), "--evidence-out", str(out)], timeout=120)
        genuine = out.read_text().strip()
        forged = [self.bad_evidence(s, s, "forged-sig", 40000 + i + (0 if label == "pre" else 100)) for i in range(8)]
        ws = self.clock.wall_slot()
        while self.clock.wall_slot() == ws:
            time.sleep(0.01)
        start = self.clock.wall_slot()
        replies = [self.submit(1, hx) for hx in forged]
        g = self.submit(1, genuine)
        self.cell("evidence_round", phase=label, accused=accused, same_slot=self.clock.wall_slot() == start,
                  forged_replies=[m[:90] for _, m in replies], limited=sum("allowance" in m for _, m in replies),
                  genuine_accepted=g[0], genuine_reply=g[1])
        if not g[0]:
            time.sleep(1.2)
            g2 = self.submit(1, genuine)
            self.cell("evidence_round_retry", phase=label, accepted=g2[0], reply=g2[1])
        self.wait(self.clock.wall_epoch() + 1, 4)
        try:
            self.cell("evidence_outcome", phase=label, accused=accused, state=self.rpc(1, "getvalidator", [accused]).get("state"))
        except SoakError as e:
            self.cell("evidence_outcome", phase=label, error=str(e))

    # ── net B: signature forms and KES enforcement ───────────────────────
    def forge_block(self, pool, form, lo_slot, cell, target=2):
        s, p = self.find_block(pool, lo_slot)
        if s is None:
            self.cell(cell, error="no block by pool"); return
        rej0 = self.rejects(target)
        ok, o = self.probe("forge-block", "--genesis", self.w / "genesis.bin", "--dir", self.keydirs[p], "--data-dir", self.w / "node1",
                           "--slot", s, "--form", form, "--kes-dir", self.w / f"node{p}", "--to", f"127.0.0.1:{self.sport(target)}")
        time.sleep(2.5)
        m = re.search(r"id8 ([0-9a-f]+)", o) if ok else None
        lines = [l for l in self.log(target).splitlines() if m and m[1] in l][:3]
        self.cell(cell, form=form, slot=s, block_epoch=s // SPE, proposer=p, tool_ok=ok, tool=o[-200:], target_lines=lines,
                  rejected_metric_delta=self.rejects(target) - rej0)

    def rejects(self, i):
        try:
            return lib.metric_value(lib.http_get(self.mport(i), "/metrics"), "bloch_pos_blocks_rejected_total") or 0
        except SoakError:
            return 0

    def forge_vote(self, v, form, cell, target=2):
        n0 = self.log(target).count(f"attestation from v{v} REJECTED")
        ok, o = self.probe("forge-vote", "--genesis", self.w / "genesis.bin", "--dir", self.keydirs[v], "--data-dir", self.w / "node1",
                           "--after-slot", max(0, self.clock.wall_slot() - SPE), "--validator", v, "--form", form,
                           "--kes-dir", self.w / f"node{v}", "--to", f"127.0.0.1:{self.sport(target)}")
        time.sleep(2.5)
        lines = [l for l in self.log(target).splitlines() if f"attestation from v{v} REJECTED" in l]
        self.cell(cell, form=form, validator=v, tool_ok=ok, tool=o[-200:], new_reject_lines=len(lines) - n0, last=lines[-1:] )

    def run_b(self):
        vals = ["cand"] * 8
        obs = ["sig-late", "kese-late"]
        self.build_net(vals, obs, kes={1, 2, 3, 4, 5, 6, 7}, allocs=[("ctl", "funder", 1000 * BLCH)])
        self.keyinfo.setdefault("x", "")
        self.wait(1); self.gates_seen()
        pool = {1, 2, 4, 5, 7}
        # Signature gate, e25 (last epoch before): v2 must be refused, v1 passes authentication.
        self.wait(HF2 - 1, 10)
        self.forge_block(pool, "v2", (HF2 - 1) * SPE, "sig_block_v2_before")
        self.forge_vote(4, "v2", "sig_vote_v2_before")
        self.forge_block({3}, "v1", (HF2 - 1) * SPE, "sig_block_v1_before_CONTROL")
        self.forge_vote(6, "v1", "sig_vote_v1_before_CONTROL")
        self.wait(HF2, 2)
        self.forge_block(pool, "v1", HF2 * SPE, "sig_block_v1_after")
        self.forge_vote(4, "v1", "sig_vote_v1_after")
        self.wait(HF2 + 2)
        self.cell("sig_forms", rows=self.forms(1, HF2 - 2, HF2 + 1))
        self.cell("sig_late_fork", divergence=self.first_divergence(8, 1, (HF2 - 2) * SPE, (HF2 + 2) * SPE))
        self.cell("control_outcome", v3=self.rpc(1, "getvalidator", [3]).get("state"), v6=self.rpc(1, "getvalidator", [6]).get("state"))
        # KES: everyone but v0 and the slashed controls registers.
        self.wait(HF3 + 1, 1)
        for v in sorted(pool):
            ok, msg, _ = self.kes_register(v, 1); self.cell("kes_register", validator=v, accepted=ok, reply=msg)
        self.wait(KESE, 1); self.cell("kes_state", getkes=self.kes_state())
        self.wait(BIND - 1, 8)
        self.cell("kes_state", getkes=self.kes_state())
        self.forge_block(pool, "leaf", (BIND - 1) * SPE, "kes_block_leaf_before_bind")
        self.forge_vote(4, "leaf", "kes_vote_leaf_before_bind")
        self.wait(BIND, 3)
        self.cell("kes_state", getkes=self.kes_state())
        self.forge_block(pool, "v2", BIND * SPE, "kes_block_static_after_bind")
        self.forge_vote(4, "v2", "kes_vote_static_after_bind")
        self.forge_block({0}, "v2", BIND * SPE, "kes_block_static_unregistered_after_bind_SLASHES")
        self.wait(BIND + 3)
        self.cell("kes_forms", rows=self.forms(1, KESE - 1, BIND + 2))
        by = {}
        for s in range(BIND * SPE, (BIND + 3) * SPE):
            b = self.block(1, s)
            if b:
                by[b["proposer_index"]] = by.get(b["proposer_index"], 0) + 1
        self.cell("kes_proposers_after_bind", by_proposer=by)
        self.cell("kese_late_fork", divergence=self.first_divergence(9, 1, (KESE - 1) * SPE, (BIND + 3) * SPE))
        self.finish()

    def kes_state(self):
        k = self.rpc(1, "getkes")
        return {x: k.get(x) for x in ("epoch", "enforced_from", "registered_stake_bps", "activation_epoch")}

    def run_smoke(self):
        allocs = [("slh", "slh-spend", 1000 * BLCH), ("cred", "slh-cred", 1000 * BLCH), ("dep-A0", "funder", 50_010 * BLCH), ("m1", "funder", 200 * BLCH + 1), ("p1", "funder", 200 * BLCH + 2)]
        self.build_net(["cand"] * 6, ["cand"], kes={1, 4}, allocs=allocs)
        self.wait(1); self.gates_seen()
        self.wait(6, 2)
        ok, msg, h = self.deposit("A0", 25_000); self.cell("smoke_deposit", accepted=ok, reply=msg, h=h)
        ok, msg, _ = self.kes_register(1, 1); self.cell("smoke_kes_reg", accepted=ok, reply=msg)
        ok, msg, o = self.slh_spend(1); self.cell("smoke_slh", accepted=ok, reply=msg, o=o[-200:])
        self.marker("m1", 1, "smoke_marker")
        self.plain("p1", 1, "smoke_plain")
        self.S = 6
        self.evidence_replies("smoke")
        self.forge_block({2, 4, 5}, "v2", 5 * SPE, "smoke_block_v2")
        self.forge_vote(4, "v2", "smoke_vote_v2")
        self.forge_block({3}, "v1", 5 * SPE, "smoke_block_v1_control")
        self.forge_vote(5, "v1", "smoke_vote_v1_control")
        self.forge_block({1}, "leaf", 5 * SPE, "smoke_block_leaf")
        self.cell("smoke_forms", rows=self.forms(1, 5, 8))
        self.evidence_round("smoke", accused=0)
        self.cell("smoke_end", v3=self.rpc(1, "getvalidator", [3]).get("state"), v5=self.rpc(1, "getvalidator", [5]).get("state"))
        self.finish()

    # ── nets C: ML-DSA pin (fault-injected pinned verifier) ──────────────
    def marker(self, name, via, cell):
        a = self.allocs[name]
        out = self.txfile(name)
        ok, o = self.probe("marker-transfer", "--dir", self.w / "keys" / "funder", "--input", f"{a['txid']}:{a['vout']}:{a['sat']}",
                           "--to", lib.sha3_hex("00" * 32), "--base-fee", self.fee(), "--tip", 1000,
                           "--epoch", self.clock.wall_epoch(), "--out", out)
        if not ok:
            self.cell(cell, tool_refused=o); return
        ok2, msg = self.submit(via, out.read_text().strip())
        self.cell(cell, marker=True, node=via, accepted=ok2, reply=msg)

    def plain(self, name, via, cell):
        a = self.allocs[name]
        out = self.txfile(name)
        try:
            self.bin("cand").run(["transfer-v2", "--genesis", str(self.w / "genesis.bin"), "--dir", str(self.w / "keys" / "funder"),
                                  "--input", f"{a['txid']}:{a['vout']}:{a['sat']}", "--to", lib.sha3_hex("00" * 32),
                                  "--base-fee", str(self.fee()), "--tip", "1000", "--epoch", str(self.clock.wall_epoch()),
                                  "--out", str(out)], timeout=120)
        except SoakError as e:
            self.cell(cell, tool_refused=str(e)[-300:]); return
        ok, msg = self.submit(via, out.read_text().strip())
        self.cell(cell, marker=False, node=via, accepted=ok, reply=msg)

    def spent(self, name):
        a = self.allocs[name]
        v = self.rpc(1, "gettxout", [a["txid"], a["vout"]])
        return {"unspent": (v or {}).get("unspent"), "view": v}

    def run_c(self, net):
        names = ["m1", "m2", "m3", "m4", "p1", "p2"]
        allocs = [(n, "funder", 200 * BLCH + i) for i, n in enumerate(names)]
        if net == "C1":
            self.build_net(["pinfi-both"] * 6, ["pinfi-pinlate"], kes=set(), allocs=allocs)
            late_side = 6
        else:
            vals = ["pinfi-pinonly"] * 6; vals[3] = "pinfi-nopin"
            self.build_net(vals, [], kes=set(), allocs=allocs)
            late_side = 3
        self.wait(1); self.gates_seen()
        self.wait(HF2 - 1, 8)
        self.marker("m1", 1, "pin_marker_before")
        self.wait(HF2, 0)
        self.marker("m2", 1, "pin_marker_after_first_slots")
        self.plain("p1", 1, "pin_plain_after_control")
        self.marker("m3", late_side, "pin_marker_after_on_late_side")
        self.wait(HF2 + 3)
        self.cell("pin_spent", m1=self.spent("m1"), m2=self.spent("m2"), m3=self.spent("m3"), p1=self.spent("p1"))
        refused = {i: [l for l in self.log(i).splitlines() if "REFUSED OWN BLOCK" in l or "StateRootMismatch" in l or re.search(r"reject [0-9a-f]+ at slot", l)][:6]
                   for i in range(len(self.nodes))}
        self.cell("pin_refusal_lines", lines=refused)
        self.cell("pin_side_blocks", rows=self.early_blocks(late_side))
        self.cell("pin_side_fork", divergence=self.first_divergence(late_side, 1, (HF2 - 1) * SPE, (HF2 + 2) * SPE))
        self.finish()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--net", required=True, choices=["A", "B", "C1", "C2", "G", "K", "L", "smoke"])
    ap.add_argument("--bins", type=Path, required=True)
    ap.add_argument("--work", type=Path, required=True)
    ap.add_argument("--port-base", type=int, default=28300)
    ap.add_argument("--slot-ms", type=int, default=1000)
    ap.add_argument("--stop-epoch", type=int, default=52)
    a = ap.parse_args()
    a.bins = a.bins.resolve()
    n = Net(a)
    try:
        {"smoke": n.run_smoke, "L": n.run_l, "K": n.run_k, "G": n.run_g, "A": n.run_a, "B": n.run_b, "C1": lambda: n.run_c("C1"), "C2": lambda: n.run_c("C2")}[a.net]()
    except BaseException as e:
        n.cell("DRIVER_ERROR", error=repr(e))
        raise
    finally:
        n.finish()


if __name__ == "__main__":
    sys.exit(main())
