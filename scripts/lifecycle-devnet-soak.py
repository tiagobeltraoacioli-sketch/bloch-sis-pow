#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""VAD-04: the ADR-041 validator lifecycle across real `bloch-pos` processes.

Builds a DISPOSABLE armed copy of this tree (never the checkout; constants per
vad04-design.md D2, `git diff --quiet` on the checkout asserted at the end),
drives five real node processes over the devnet TCP transport through
harness-owned relays, and puts one funded validator through the whole
lifecycle by RPC and CLI only — deposit, activation, duties, restart, a
partition longer than ACTIVATION_DELAY_EPOCHS with a second registration
submitted on both halves, heal, exit, an equivocation prosecuted by an
observer, the withdrawal and the spend of the payout — with eight more
funded candidates registering under load. The verdict is CONVERGED /
DIVERGED / NO-DATA over every node's log plus RPC snapshots at every phase
boundary; NO-DATA is a failure.

Usage
  scripts/lifecycle-devnet-soak.py [--arm full|control|unarmed-control]
      [--work DIR] [--reuse-build] [--keep] [--slot-ms 500]
      [--timeout-minutes 60] [--port-base 17610] [--split-epochs 9]
      [--observer-epoch 10] [--load 8]

  --arm full             the split arm: relays between {v0,v1,observer} and
                         {v2,joiner} are cut for --split-epochs (> 8).
  --arm control          same lifecycle, relays never cut. Run it: a harness
                         that can only print DIVERGED is not measuring anything.
  --arm unarmed-control  the SHIPPING tree (no rewrite): boot + one deposit,
                         which must be refused at the RPC door with
                         `funded validator admission is not active`.

Outputs, under --work (kept on failure or with --keep): copy/ (armed tree +
binary), node<i>/ joiner/ observer/ (data dirs, run.log, pid), tx/ (every
transaction file), commands.log, report.json (one record per phase),
verdict.json (every check with PASS/FAIL and its evidence). Exit 0 only when
every check passed. The overall timeout covers the run, not the build.

Ports (all loopback, from --port-base B): rpc B+i, metrics B+1000+i, mesh
B+2000+i, relay(i,j) B+3000+16*i+j, for roster slots i,j in 0..4
(0..2 genesis validators, 3 joiner, 4 observer).

What a passing run proves
  * With the five ADR-041 gates armed, a funded PQ deposit prepared and signed
    offline is admitted, included, finalized and activated ≥ 8 epochs later
    and only after finality passed its epoch — on separate processes with
    separate data directories over the real transport, including a node that
    learned the registration from history (the joiner boots after inclusion)
    and a fresh observer that synced under the genesis anchor.
  * The joiner proposes and attests, survives a restart after ≥ 2 RANDAO
    reveals (journal and identity intact, no peer sees an equivocation) and
    proposes again.
  * A live partition longer than ACTIVATION_DELAY_EPOCHS freezes finality on
    BOTH halves (measured, and required: 600k vs 625k of 1.225M), heads
    diverge, PIDs never change, and after the heal every node reconverges and
    finality resumes; a registration submitted on both halves during the
    split activates only after finality passed its epoch.
  * ExitV2 lands at the signed epoch; a proposer equivocation sent to the
    observer is prosecuted on every node (5% loss, exit_epoch shortened to
    the slash epoch + 1, withdrawable_epoch unchanged, whistleblower credited
    to the including proposer); the node auto-cranks the withdrawal at
    withdrawable_epoch (the manual crank is a duplicate); the payout is spent
    by the credential holder and every node agrees on every UTXO fact.
  * Eight independently funded candidates registering in one epoch activate
    at ≤ 4 per epoch and all reach `active`.

What it does NOT prove
  * Anything about the shipping binary's consensus: the copy is armed at
    epoch 0 with EXIT/WITHDRAWAL delays of 4/64 and the epoch-800/1400/2700
    rules active from genesis. The unarmed-control arm proves only that the
    SHIPPING binary refuses the deposit.
  * Automatic RANDAO renewal, unless run with `--randao-chain 256`: at the
    shipping chain length nothing exhausts in a run this long. (The 2026-09-11
    run with 256 did observe one renewal included over the real transport —
    generation 1 on every node — before the second exhaustion stalled a
    partition half; the in-process rehearsal covers renewal deterministically.)
  * Attester-offence slashing (only proposer equivocation is exercised), the
    per-source mempool quota (8 candidates have 8 funders), the correlation
    penalty, delegation, the libp2p transport, or a partition under real
    network conditions (loopback relays only).
  * The whistleblower reward exactly: issuance also lands on the including
    proposer's `own_stake_sat` at the same boundary, so the check is a lower
    bound (delta ≥ loss/32) with every validator's delta recorded.
  * Timings are a 500 ms slot; nothing here measures mainnet pacing.

Every `bloch-pos` command line and output format the harness relies on —
including the three devnet subcommands `genesis --alloc`, `transfer-v2` and
`devnet-equivocate` from `crates/bloch-pos-node/src/devnet_tools.rs` — is
isolated in `lifecycle_devnet_soak_lib.Bin`, one method each, with the source
line it was read from; correct a drift there, nowhere else.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lifecycle_devnet_soak_lib as lib  # noqa: E402
from lifecycle_devnet_soak_lib import SoakError, RpcError, as_int  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
TOOLCHAIN = Path("crates/bloch-pos-node/rust-toolchain.toml")
N_GENESIS, JOINER, OBSERVER, N_SLOTS = 3, 3, 4, 5
SIDE_A, SIDE_B = {0, 1, 4}, {2, 3}  # vad04-design.md D4: 600k vs 625k of 1.225M
SPE = lib.SLOTS_PER_EPOCH
BLOCH = lib.SAT_PER_BLOCH
MIN_STAKE_SAT = 25_000 * BLOCH  # staking.rs:97; verified against getvalidatoradmission at boot
ALLOC_SAT = MIN_STAKE_SAT + 1 * BLOCH  # stake + fees + change ≥ 1,000 sat (vad04-synthesis.md §2)
VALIDATOR_NOT_FOUND, SLOT_EMPTY = -32001, -32007  # rpc.rs:150, :163


@dataclass
class Key:
    name: str
    dir: Path
    index: str
    pubkey: str
    randao: str
    pub_file: Path

    @property
    def script_hash(self) -> str:  # SHA3-256 of the enveloped pubkey = pubkey_hash = script_hash
        return lib.sha3_hex(self.pubkey)


class Harness:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.work = Path(args.work).resolve() if args.work else Path(tempfile.mkdtemp(prefix="lifecycle-devnet-soak-"))
        self.work.mkdir(parents=True, exist_ok=True)
        self.env = dict(os.environ, BLOCH_KEYSTORE_ALLOW_PLAINTEXT="1")
        self.env.pop("BLOCH_RPC_HOST_ALLOWLIST", None)
        self.report: list[dict] = []
        self.checks: list[dict] = []
        self.nodes: dict[str, lib.Node] = {}
        self.keys: dict[str, Key] = {}
        self.mesh: lib.RelayMesh | None = None
        self.clock: lib.Clock | None = None
        self.bin: lib.Bin | None = None
        self.manifest = self.work / "genesis.blg"
        self.delays: dict[str, int] = {}
        self.tracked: list[dict] = []  # UTXO facts every node must agree on
        self.finality_samples: list[tuple[str, int, int]] = []  # (node, wall_epoch, finalized.epoch)
        self.split_window: tuple[int, int] | None = None
        self.deadline_mono: float | None = None
        self.armed = args.arm != "unarmed-control"

    # ── plumbing ────────────────────────────────────────────────────────────
    def log(self, message: str) -> None:
        stamp = dt.datetime.now(dt.timezone.utc).strftime("%H:%M:%S")
        where = f"e{self.clock.wall_epoch()}/s{self.clock.slot_in_epoch():02d}" if self.clock else "e-/s--"
        print(f"[{stamp} {where}] {message}", flush=True)

    def check(self, name: str, ok: bool, evidence) -> bool:
        self.checks.append({"name": name, "ok": bool(ok), "evidence": evidence,
                            "wall_epoch": self.clock.wall_epoch() if self.clock else None})
        self.log(f"{'PASS' if ok else 'FAIL'}  {name}  {lib.jdump(evidence)[:400]}")
        return bool(ok)

    def record(self, phase: str, **fields) -> None:
        entry = {"phase": phase, "at": dt.datetime.now(dt.timezone.utc).isoformat(),
                 "wall_epoch": self.clock.wall_epoch() if self.clock else None, **fields}
        self.report.append(entry)
        tmp = self.work / "report.json.tmp"
        tmp.write_text(json.dumps(self.report, indent=1, default=str))
        tmp.replace(self.work / "report.json")

    def check_timeout(self) -> None:
        if self.deadline_mono is not None and time.monotonic() > self.deadline_mono:
            raise SoakError(f"overall timeout of {self.args.timeout_minutes} minutes exceeded")

    def check_alive(self) -> None:
        dead = [f"{n.name}(pid {n.pid}, rc {n.proc.returncode})" for n in self.nodes.values()
                if n.proc is not None and not n.alive()]
        if dead:
            raise SoakError(f"node process exited on its own: {', '.join(dead)} — see run.log")

    def port(self, kind: str, slot: int) -> int:
        base = self.args.port_base
        return {"rpc": base, "metrics": base + 1000, "mesh": base + 2000}[kind] + slot

    def rpc(self, node: lib.Node, method: str, params: list | None = None):
        return lib.rpc(node.rpc_port, method, params)

    def rpc_all(self, method: str, params: list | None = None, nodes=None) -> dict:
        return {n.name: self.rpc(n, method, params) for n in (nodes or self.live_nodes())}

    def live_nodes(self) -> list[lib.Node]:
        return [n for n in self.nodes.values() if n.proc is not None]

    def node_at(self, slot: int) -> lib.Node:
        return next(n for n in self.nodes.values() if n.slot == slot)

    def poll(self, what: str, probe, *, epochs: float, every: float = 1.0):
        """probe() -> (done, observed). Deadline in epochs; fails loudly with
        the last observation. A node that exits fails the poll at once."""
        deadline_epoch = self.clock.wall_epoch() + epochs
        last = None
        while True:
            self.check_timeout()
            self.check_alive()
            try:
                done, last = probe()
            except lib.RpcTransportError as e:
                done, last = False, {"transport_error": str(e)}
            if done:
                return last
            if self.clock.wall_epoch() > deadline_epoch:
                raise SoakError(f"{what}: not observed within {epochs} epochs (deadline epoch "
                                f"{deadline_epoch}); last observed: {lib.jdump(last)[:1500]}")
            self.clock.sleep_slots(every)

    def validator(self, node: lib.Node, pkh: str) -> dict | None:
        try:
            return self.rpc(node, "getvalidatorbykey", [pkh])
        except RpcError as e:
            if e.code == VALIDATOR_NOT_FOUND:
                return None
            raise

    def block_at(self, node: lib.Node, slot: int) -> dict | None:
        try:
            return self.rpc(node, "getblockbyslot", [slot])
        except RpcError as e:
            if e.code == SLOT_EMPTY:
                return None
            raise

    def track(self, label: str, txid: str, vout: int, **expect) -> None:
        self.tracked.append({"label": label, "txid": txid, "vout": vout, "expect": expect})

    # ── phase 1: copy + arm + build ─────────────────────────────────────────
    def phase_build(self) -> None:
        copy, bin_path, arm_file = self.work / "copy", self.work / "copy" / "bloch-pos", self.work / "copy" / "ARM"
        pin = re.search(r'^channel\s*=\s*"([^"]+)"', (ROOT / TOOLCHAIN).read_text(), re.M)
        if not pin:
            raise SoakError(f"cannot read the toolchain pin from {TOOLCHAIN}")
        changes: list[dict] = []
        if self.args.reuse_build and bin_path.exists():
            if arm_file.read_text().strip() != self.args.arm.split("-")[0]:
                raise SoakError(f"--reuse-build: {bin_path} was built for arm `{arm_file.read_text().strip()}`")
            self.log(f"reusing {bin_path}")
            built = "reused"
        else:
            if copy.exists():
                shutil.rmtree(copy)
            copy.mkdir(parents=True)
            if self.armed:
                lib.copy_tree(ROOT, copy)
                sources = {f: (copy / f).read_text() for f in (lib.PARAMS, lib.STAKING)}
                armed_constants = list(lib.ARMED_CONSTANTS)
                if self.args.randao_chain != lib.RANDAO_CHAIN_LENGTH_SHIPPING:
                    # Opt-in only: see the note beside ARMED_CONSTANTS in the lib.
                    armed_constants.append((lib.PARAMS, "RANDAO_CHAIN_LENGTH", "u32", str(self.args.randao_chain)))
                rewritten, changes = lib.rewrite_constants(sources, armed_constants)
                for f, text in rewritten.items():
                    (copy / f).write_text(text)
                src_tree, target = copy, ROOT / "target" / "lifecycle-devnet-soak"
            else:
                src_tree, target = ROOT, ROOT / "target"  # the shipping tree, its own target
            self.log(f"building in {src_tree} with CARGO_TARGET_DIR={target} (log: {self.work / 'build.log'})")
            shutil.copy2(lib.cargo_build(src_tree, target, pin.group(1), self.env, self.work / "build.log",
                                         self.args.build_timeout_minutes * 60), bin_path)
            arm_file.write_text("unarmed\n" if not self.armed else "full\n" if self.args.arm == "full" else "control\n")
            built = str(target)
        self.bin = lib.Bin(bin_path, self.env, self.work / "commands.log")
        version, buildinfo, selfcheck = self.bin.version(), self.bin.buildinfo(), self.bin.selfcheck()
        self.check("build: selfcheck passed", "self-check passed" in selfcheck, selfcheck)
        self.record("build", arm=self.args.arm, binary=str(bin_path), built=built, toolchain=pin.group(1),
                    version=version, buildinfo=buildinfo, constants=changes)

    # ── phase 2: keys + manifest ────────────────────────────────────────────
    def keygen(self, name: str, directory: Path, index: int | str) -> Key:
        self.bin.keygen(directory, index)
        idx, pubkey, randao = self.bin.keygen_public(directory)
        pub_file = self.work / "keys" / f"{name}.pub.hex"
        pub_file.parent.mkdir(parents=True, exist_ok=True)
        pub_file.write_text(pubkey + "\n")
        key = Key(name, directory, idx, pubkey, randao, pub_file)
        self.keys[name] = key
        return key

    def phase_keys_manifest(self) -> None:
        for i in range(N_GENESIS):
            self.keygen(f"node{i}", self.work / f"node{i}", i)
        self.keygen("joiner", self.work / "joiner", "auto")
        self.keygen("funder", self.work / "keys" / "funder", "auto")
        funders = ["funder"]
        if self.armed:
            self.keygen("split-cand", self.work / "keys" / "split-cand", "auto")
            self.keygen("split-funder", self.work / "keys" / "split-funder", "auto")
            self.keygen("dest", self.work / "keys" / "dest", "auto")
            funders.append("split-funder")
            for k in range(self.args.load):
                self.keygen(f"load{k}", self.work / "keys" / f"load{k}", "auto")
                self.keygen(f"load{k}-funder", self.work / "keys" / f"load{k}-funder", "auto")
                funders.append(f"load{k}-funder")
        allocs = [(self.keys[f].script_hash, ALLOC_SAT) for f in funders]
        self.manifest.unlink(missing_ok=True)
        allocations = self.bin.genesis([self.work / f"node{i}" for i in range(N_GENESIS)], self.manifest,
                                       self.args.slot_ms, self.args.start_in, allocs)
        by_hash = {a["script_hash"]: a for a in allocations}
        missing = [f for f in funders if self.keys[f].script_hash not in by_hash]
        if missing:
            raise SoakError(f"genesis printed no allocation for {missing}")
        genesis_ms, slot_ms = lib.manifest_clock(self.manifest)
        self.clock = lib.Clock(genesis_ms, slot_ms)
        self.check("manifest: genesis_time is in the future at write and slot_ms matches",
                   genesis_ms > lib.Clock.now_ms() and slot_ms == self.args.slot_ms,
                   {"genesis_time_ms": genesis_ms, "now_ms": lib.Clock.now_ms(), "slot_ms": slot_ms})
        self.record("keys_manifest", keys={k: {"dir": str(v.dir), "index": v.index, "script_hash": v.script_hash}
                                            for k, v in self.keys.items()},
                    allocations=allocations, genesis_time_ms=genesis_ms, slot_ms=slot_ms)

    # ── phase 3: relays + boot ──────────────────────────────────────────────
    def make_node(self, name: str, slot: int, data_dir: Path, has_key: bool) -> lib.Node:
        cmd = [str(self.bin.path), "run", "--data-dir", str(data_dir), "--genesis", str(self.manifest),
               "--transport", "devnet", "--listen", str(self.port("mesh", slot)), "--listen-addr", "127.0.0.1",
               "--peers", ",".join(self.mesh.peers_for(slot)), "--rpc-bind", "127.0.0.1",
               "--rpc-port", str(self.port("rpc", slot)), "--metrics-bind", "127.0.0.1",
               "--metrics-port", str(self.port("metrics", slot)), "--no-doppelganger-check"]
        node = lib.Node(name, slot, data_dir, self.port("rpc", slot), self.port("mesh", slot),
                        self.port("metrics", slot), cmd, self.env, data_dir / "run.log", has_key)
        self.nodes[name] = node
        return node

    def wait_synced(self, node: lib.Node, *, epochs: float) -> None:
        def probe():
            behind, info = self.chain_field(node, "behind_by_slots")
            return behind <= 2, {"behind_by_slots": behind, "slot": info["slot"]}
        self.poll(f"{node.name} synced (behind_by_slots ≤ 2)", probe, epochs=epochs)

    def wait_epoch(self, what: str, target: int, *, every: float = 1.0) -> None:
        self.poll(f"{what} (epoch {target})", lambda: (self.clock.wall_epoch() >= target, self.clock.wall_epoch()),
                  epochs=max(target - self.clock.wall_epoch(), 0) + 2, every=every)

    def wait_ready(self, nodes: list[lib.Node], epochs: float = 3) -> dict:
        def probe():
            infos = {}
            for n in nodes:
                try:
                    infos[n.name] = self.rpc(n, "getchaininfo")
                except lib.RpcTransportError as e:
                    infos[n.name] = {"transport_error": str(e)}
            return all("block_id" in i for i in infos.values()), infos
        return self.poll("getchaininfo answers on " + ",".join(n.name for n in nodes), probe, epochs=epochs, every=0.5)

    def phase_relays_boot(self) -> None:
        self.mesh = lib.RelayMesh(N_SLOTS, self.args.port_base + 3000, self.port("mesh", 0))
        self.mesh.start_all()
        for i in range(N_GENESIS):
            node = self.make_node(f"node{i}", i, self.work / f"node{i}", True)
            self.log(f"boot {node.name} pid {node.start()} rpc :{node.rpc_port} mesh :{node.mesh_port}")
        booted_before_genesis = lib.Clock.now_ms() < self.clock.genesis_ms
        infos = self.wait_ready(self.live_nodes())
        rpc_wall = {k: v.get("wall_slot") for k, v in infos.items()}
        have_field = all(isinstance(w, int) for w in rpc_wall.values())
        self.check("boot: getchaininfo.wall_slot agrees with the manifest clock (±1 slot)",
                   have_field and all(abs(w - self.clock.wall_slot()) <= 1 for w in rpc_wall.values()),
                   {"rpc_wall_slot": rpc_wall, "clock_wall_slot": self.clock.wall_slot(),
                    "source": "getchaininfo.wall_slot" if have_field else "manifest genesis_time_ms/slot_ms (fallback)"})
        admission = self.rpc_all("getvalidatoradmission")
        first = next(iter(admission.values()))
        self.check("boot: getvalidatoradmission.active on every node matches the arm",
                   all(a["active"] is self.armed for a in admission.values()),
                   {k: {"active": v["active"], "activation_epoch": v["activation_epoch"]} for k, v in admission.items()})
        self.check("boot: network_domain identical on every node and non-null",
                   first["network_domain"] and len({a["network_domain"] for a in admission.values()}) == 1,
                   {k: v["network_domain"] for k, v in admission.items()})
        self.check("boot: minimum_stake_sat matches the harness allocation arithmetic",
                   as_int(first["minimum_stake_sat"]) == MIN_STAKE_SAT, first["minimum_stake_sat"])
        self.delays = {k: as_int(first[k]) for k in ("activation_delay_epochs", "exit_delay_epochs",
                                                     "withdrawal_delay_epochs", "maximum_activations_per_epoch")}
        if self.armed:
            self.check("boot: compiled delays are the armed ones (8/4/64)",
                       (self.delays["activation_delay_epochs"], self.delays["exit_delay_epochs"],
                        self.delays["withdrawal_delay_epochs"]) == (8, 4, 64), self.delays)
        builds = self.rpc_all("getbuildinfo")
        self.check("boot: getbuildinfo identical on every node", len({lib.jdump(b) for b in builds.values()}) == 1,
                   {k: v.get("source_digest") for k, v in builds.items()})
        self.record("relays_boot", pids={n.name: n.pids for n in self.live_nodes()},
                    booted_before_genesis=booted_before_genesis, admission=first, delays=self.delays,
                    relays={f"{i}->{j}": r.listen_port for (i, j), r in self.mesh.relays.items()})

    # ── lifecycle building blocks ───────────────────────────────────────────
    def deposit(self, tag: str, cand: Key, funder: Key, submit_to: list[lib.Node], *, expiry_epochs: int = 40) -> dict:
        utxos = self.rpc(submit_to[0], "getutxos", [funder.script_hash, 10])["utxos"]
        if not utxos:
            raise SoakError(f"{tag}: funder {funder.name} ({funder.script_hash}) has no spendable output")
        u = utxos[0]
        inp = (u["txid"], as_int(u["vout"]), as_int(u["value_sat"]))
        epoch = self.clock.wall_epoch()
        txdir = self.work / "tx"
        txdir.mkdir(exist_ok=True)
        p0, p1, p2 = (txdir / f"{tag}.deposit.{k}.hex" for k in range(3))
        for p in (p0, p1, p2):
            p.unlink(missing_ok=True)  # the CLI uses create_new
        self.bin.deposit_prepare(self.manifest, funder.pub_file, cand.pub_file, cand.randao, funder.script_hash,
                                 funder.script_hash, MIN_STAKE_SAT, [inp], max_base_fee=100, tip=5,
                                 expiry_epoch=epoch + expiry_epochs, commission_bps=500, out=p0)
        self.bin.deposit_sign(self.manifest, p0, "funding", funder.dir, p1)
        self.bin.deposit_sign(self.manifest, p1, "validator", cand.dir, p2)
        txid, _ = self.bin.deposit_inspect(p2)
        raw = lib.read_hex_file(p2)
        submits = {}
        for n in submit_to:
            try:
                submits[n.name] = self.rpc(n, "sendrawtransaction", [raw])
            except RpcError as e:
                submits[n.name] = {"error": e.as_dict()}
        rec = {"tag": tag, "candidate": cand.name, "pkh": cand.script_hash, "funder": funder.script_hash,
               "txid": txid, "input": inp, "submitted_epoch": epoch, "submits": submits, "raw": raw}
        self.log(f"{tag}: deposit {txid[:16]} submitted at epoch {epoch}: "
                 f"{ {k: v.get('status', v.get('error', {}).get('message')) for k, v in submits.items()} }")
        return rec

    def wait_included(self, dep: dict, node: lib.Node, *, epochs: float = 4) -> None:
        """Poll gettxstatus to `included`; record the including block's epoch
        (head or head-1..3 with tx_count ≥ 1 — polls run every slot) and the
        finalized epoch at that moment."""
        def probe():
            status = self.rpc(node, "gettxstatus", [dep["txid"]])["status"]
            return status in ("included", "justified", "finalized"), {"status": status}
        self.poll(f"{dep['tag']}: gettxstatus included", probe, epochs=epochs)
        info = self.rpc(node, "getchaininfo")
        including = None
        for slot in range(as_int(info["slot"]), as_int(info["slot"]) - 4, -1):
            block = self.block_at(node, slot)
            if block and as_int(block["tx_count"]) >= 1:
                including = block
                break
        dep["including_block"] = {k: including.get(k) for k in ("slot", "epoch", "proposer_index", "tx_count")} if including else None
        dep["dep_epoch"] = as_int(including["epoch"]) if including else as_int(info["epoch"])
        dep["finalized_at_deposit"] = as_int(info["finalized"]["epoch"])
        dep["included_seen_epoch"] = self.clock.wall_epoch()

    def wait_finalized(self, dep: dict, node: lib.Node, *, epochs: float = 10) -> None:
        def probe():
            status = self.rpc(node, "gettxstatus", [dep["txid"]])["status"]
            return status == "finalized", {"status": status, "finalized": self.rpc(node, "getchaininfo")["finalized"]}
        self.poll(f"{dep['tag']}: gettxstatus finalized", probe, epochs=epochs)

    def wait_activation(self, dep: dict, node: lib.Node, *, floor_finalized: int, epochs: float = 16) -> dict:
        seen = {"fin_gt_dep_epoch": None}

        def probe():
            v = self.validator(node, dep["pkh"])
            fin = as_int(self.rpc(node, "getchaininfo")["finalized"]["epoch"])
            if fin > dep["dep_epoch"] and seen["fin_gt_dep_epoch"] is None:
                seen["fin_gt_dep_epoch"] = self.clock.wall_epoch()
            return v is not None and v.get("activation_epoch") is not None, v
        v = self.poll(f"{dep['tag']}: activation_epoch assigned", probe, epochs=epochs)
        a, delay = as_int(v["activation_epoch"]), self.delays["activation_delay_epochs"]
        assigned_at = self.clock.wall_epoch()
        self.check(f"{dep['tag']}: activation_epoch ≥ dep_epoch + delay and > finalized-at-deposit",
                   a >= dep["dep_epoch"] + delay and a > floor_finalized,
                   {"activation_epoch": a, "dep_epoch": dep["dep_epoch"], "delay": delay, "floor_finalized": floor_finalized})
        self.check(f"{dep['tag']}: finality passed dep_epoch before the assignment was observed",
                   seen["fin_gt_dep_epoch"] is not None and seen["fin_gt_dep_epoch"] <= assigned_at,
                   {"finality_passed_at": seen["fin_gt_dep_epoch"], "assigned_seen_at": assigned_at})
        return self.poll(f"{dep['tag']}: state active", lambda: self.state_is(node, dep["pkh"], "active"),
                         epochs=max(a - self.clock.wall_epoch(), 0) + 3)

    def state_is(self, node: lib.Node, pkh: str, state: str) -> tuple[bool, dict | None]:
        v = self.validator(node, pkh)
        return v is not None and v.get("state") == state, v

    def every_node_sees(self, pkh: str, predicate) -> tuple[bool, dict]:
        """getvalidatorbykey on every live node; done when `predicate` holds on all."""
        views = self.rpc_all("getvalidatorbykey", [pkh])
        return all(predicate(v) for v in views.values()), views

    def chain_field(self, node: lib.Node, *path: str) -> tuple[int, dict]:
        """(integer at getchaininfo[path...], the whole reply)."""
        info = self.rpc(node, "getchaininfo")
        value = info
        for key in path:
            value = value[key]
        return as_int(value), info

    def snapshot(self, label: str, nodes: list[lib.Node] | None = None, *, compare: bool = True) -> dict:
        """Phase-boundary RPC snapshot. Nodes at the same slot must agree on
        block_id/state_root/finalized/justified; if they cannot be caught at
        one slot within a slot of retries, the per-slot log map up to the
        lowest head decides instead."""
        nodes = nodes or self.live_nodes()
        infos: dict[str, dict] = {}
        for _ in range(4):
            infos = {n.name: self.rpc(n, "getchaininfo") for n in nodes}
            if len({as_int(i["slot"]) for i in infos.values()}) == 1:
                break
            self.clock.sleep_slots(0.25)
        keep = ("slot", "height", "block_id", "state_root", "finalized", "justified", "blocks_known",
                "behind_by_slots", "validators", "mempool")
        rec = {"label": label, "wall_epoch": self.clock.wall_epoch(),
               "nodes": {k: {f: v.get(f) for f in keep} | {"peers_devnet": v.get("transport", {}).get("peers", {}).get("devnet")}
                         for k, v in infos.items()}}
        for name, info in infos.items():
            self.finality_samples.append((name, self.clock.wall_epoch(), as_int(info["finalized"]["epoch"])))
        if compare:
            slots = {as_int(i["slot"]) for i in infos.values()}
            if len(slots) == 1:
                views = {k: (v["block_id"], v["state_root"], lib.jdump(v["finalized"]), lib.jdump(v["justified"])) for k, v in infos.items()}
                self.check(f"{label}: heads/state/finality equal on {len(nodes)} nodes at slot {slots.pop()}",
                           len(set(views.values())) == 1, {k: [v[0][:12], v[1][:12], v[2]] for k, v in views.items()})
            else:
                low = min(slots)
                maps = {n.name: {s: v for s, v in lib.parse_applied(n.log_text()).items() if s <= low} for n in nodes}
                cv = lib.chain_verdict(maps)
                self.check(f"{label}: nodes unaligned ({sorted(slots)}); log map up to slot {low} CONVERGED", cv.ok, cv.as_dict())
            self.check(f"{label}: behind_by_slots ≤ 2 on every node",
                       all(as_int(i["behind_by_slots"]) <= 2 for i in infos.values()),
                       {k: v["behind_by_slots"] for k, v in infos.items()})
        return rec

    def registry_equal(self, label: str) -> None:
        nodes = self.live_nodes()
        for _ in range(3):
            lists = self.rpc_all("getvalidators", nodes=nodes)
            norm = {k: lib.jdump(sorted(v, key=lambda r: as_int(r["index"]))) for k, v in lists.items()}
            if len(set(norm.values())) == 1:
                break
            self.clock.sleep_slots(0.34)
        self.check(f"{label}: getvalidators identical on every node", len(set(norm.values())) == 1,
                   {k: [f"{r['index']}:{r['status']}" for r in sorted(v, key=lambda r: as_int(r["index"]))] for k, v in lists.items()})
        count = as_int(self.rpc(nodes[0], "getvalidatorcount")["total"])
        fields = ("index", "pubkey_hash", "state", "own_stake_sat", "slashed", "activation_epoch", "exit_epoch",
                  "withdrawable_epoch", "withdrawal_credentials", "funded", "randao_reveals_used")
        full = {n.name: lib.jdump([{f: self.rpc(n, "getvalidator", [i]).get(f) for f in fields} for i in range(count)]) for n in nodes}
        self.check(f"{label}: getvalidator lifecycle fields identical for all {count} indexes", len(set(full.values())) == 1,
                   {"count": count, "distinct_views": len(set(full.values()))})

    def utxo_facts_equal(self, label: str) -> None:
        nodes = self.live_nodes()
        results = {}
        for t in self.tracked:
            views = {n.name: self.rpc(n, "gettxout", [t["txid"], t["vout"]]) for n in nodes}
            same = len({lib.jdump({k: v[k] for k in ("unspent", "utxo")}) for v in views.values()}) == 1
            v0 = next(iter(views.values()))
            expect_ok = lib.outpoint_matches(v0, t["expect"])
            results[t["label"]] = {"same_on_all": same, "as_expected": expect_ok, "view": {k: v0[k] for k in ("unspent", "utxo")}}
        self.check(f"{label}: {len(self.tracked)} tracked outpoints identical on every node and as expected",
                   all(r["same_on_all"] and r["as_expected"] for r in results.values()), results)

    # ── the lifecycle (vad04-design.md D5) ──────────────────────────────────
    def step_wait_finality(self) -> None:
        v0 = self.node_at(0)

        def probe():
            fin, info = self.chain_field(v0, "finalized", "epoch")
            return fin >= 1, info["finalized"]
        self.poll("finalized.epoch ≥ 1 on node0", probe, epochs=6)
        info = self.rpc(v0, "getchaininfo")
        self.check("step1: chain is producing (height > 0, blocks_known > 0)", as_int(info["height"]) > 0 and as_int(info["blocks_known"]) > 0,
                   {"height": info["height"], "blocks_known": info["blocks_known"]})
        self.record("step1_finality", snapshot=self.snapshot("step1"))

    def step_deposit(self) -> dict:
        v0 = self.node_at(0)
        dep = self.deposit("joiner", self.keys["joiner"], self.keys["funder"], [v0])
        self.check("step2: deposit accepted at the door", dep["submits"]["node0"].get("accepted") is True, dep["submits"])
        self.wait_included(dep, v0)
        v = self.validator(v0, dep["pkh"])
        self.check("step2: registered as queued/funded with the funder credential and index = last+1",
                   v is not None and v["state"] == "queued" and v["funded"] is True and v["withdrawal_credentials"] == dep["funder"]
                   and as_int(v["index"]) == N_GENESIS and as_int(v["randao_reveals_used"]) == 0, v)
        self.track("joiner deposit change", dep["txid"], 0, unspent=True, script_hash=dep["funder"])
        self.check("step2: funder input spent", not any(u["txid"] == dep["input"][0] for u in self.rpc(v0, "getutxos", [dep["funder"], 10])["utxos"]), dep["input"])
        counts = self.rpc_all("getvalidatorcount")
        self.check("step2: getvalidatorcount +1 on every node", all(as_int(c["total"]) == N_GENESIS + 1 for c in counts.values()), counts)
        self.record("step2_deposit", deposit={k: v for k, v in dep.items() if k != "raw"})
        return dep

    def step_boot_joiner(self, dep: dict) -> None:
        joiner = self.make_node("joiner", JOINER, self.work / "joiner", True)
        self.log(f"boot joiner pid {joiner.start()} (after the deposit was included: late join of its own registration)")
        self.wait_ready([joiner])
        self.wait_synced(joiner, epochs=3)
        text = joiner.log_text()
        self.check("step3: joiner boot log says its key is unregistered or queued (no restart needed)",
                   "is unregistered or queued" in text or "registered and its key matches" in text,
                   [l for l in text.splitlines() if "validator key" in l or "registered" in l][:3])
        self.record("step3_joiner_boot", pid=joiner.pids, snapshot=self.snapshot("step3"))

    def step_activation(self, dep: dict) -> None:
        self.wait_finalized(dep, self.node_at(0))
        v = self.wait_activation(dep, self.node_at(0), floor_finalized=dep["finalized_at_deposit"])
        dep["index"], dep["activation_epoch"] = as_int(v["index"]), as_int(v["activation_epoch"])
        active = self.rpc_all("getchaininfo")
        self.check("step4: validators.active == 4 on every node", all(as_int(i["validators"]["active"]) == N_GENESIS + 1 for i in active.values()),
                   {k: i["validators"] for k, i in active.items()})
        self.record("step4_activation", validator=v, snapshot=self.snapshot("step4"))

    def maybe_start_observer(self) -> None:
        if "observer" in self.nodes or self.clock.wall_epoch() < self.args.observer_epoch:
            return
        ws_limit = self.delays["withdrawal_delay_epochs"] - self.delays["exit_delay_epochs"]
        self.check("observer: fresh late join happens before wall epoch W − X", self.clock.wall_epoch() < ws_limit,
                   {"wall_epoch": self.clock.wall_epoch(), "W-X": ws_limit})
        data_dir = self.work / "observer"
        if data_dir.exists():
            raise SoakError("observer data dir already exists; it must be empty at start")
        observer = self.make_node("observer", OBSERVER, data_dir, False)
        self.log(f"boot observer pid {observer.start()} with an EMPTY data dir")
        self.wait_ready([observer])
        self.wait_synced(observer, epochs=4)
        text = observer.log_text()
        # A fresh data dir has nothing to replay: the node prints no
        # `replayed N blocks` line at all (measured 2026-09-11, observer/run.log)
        # and announces itself with `fresh node: syncing under the genesis
        # anchor (age A of P epochs)`. A `replayed` line here would mean the
        # dir was NOT empty — the copied-data-dir trap — so its absence, or a
        # count of 0, is the required evidence together with the anchor line.
        replayed = lib.REPLAYED_RE.search(text)
        fresh = "fresh node: syncing under the genesis anchor" in text
        self.check("observer: nothing to replay (empty dir) and synced under the genesis anchor",
                   (replayed is None or replayed.group(1) == "0") and fresh,
                   {"replayed": replayed.group(0) if replayed else None, "fresh_anchor_line": fresh})
        self.registry_equal("observer")
        self.record("observer_join", pid=observer.pids, snapshot=self.snapshot("observer"))

    def step_duties(self, dep: dict) -> None:
        joiner, idx = self.nodes["joiner"], dep["index"]
        others = [n for n in self.live_nodes() if n.name != "joiner"]

        def probe():
            proposed = [int(s) for s, _ in lib.PROPOSING_RE.findall(joiner.log_text())]
            applied_by = {n.name: [s for s, v in lib.parse_applied(n.log_text()).items() if v[2] == idx] for n in others}
            attested = len(lib.ATTESTED_RE.findall(joiner.log_text()))
            reveals = as_int((self.validator(others[0], dep["pkh"]) or {}).get("randao_reveals_used", 0))
            landed = sorted(set().union(*applied_by.values()))
            obs = {"proposed": proposed[-3:], "landed": landed[-3:], "attested_lines": attested, "reveals": reveals}
            return bool(landed) and attested >= 1 and reveals >= 1 and sum(1 for v in applied_by.values() if v) >= 2, obs
        obs = self.poll("step5: joiner proposed (landed on ≥ 2 peers), attested, reveals ≥ 1", probe, epochs=14)
        slot = obs["landed"][-1]
        block = self.block_at(others[0], slot)
        self.check("step5: getblockbyslot.proposer_index == joiner", block is not None and as_int(block["proposer_index"]) == idx,
                   {"slot": slot, "block": block and {k: block[k] for k in ("proposer_index", "attestation_count", "tx_count")}})
        # Attestations are packed once per epoch: measured 2026-09-11, every
        # block of an epoch carries attestation_count 0 except the first few
        # slots of the NEXT epoch, one vote per block (slots 544-547 and
        # 576-579 carried one each with four validators). So the evidence
        # that the joiner votes is the per-epoch TOTAL rising from N_GENESIS
        # to N_GENESIS + 1 after activation — with the epoch before
        # activation as the control at N_GENESIS. RPC lists no attesters
        # (block JSON has only attestation_count), which is why this is a
        # sum and the joiner's own `attested` lines are the other half.
        activation = as_int((self.validator(others[0], dep["pkh"]) or {}).get("activation_epoch", 0))

        def epoch_votes(epoch: int) -> int:
            return sum(as_int(b["attestation_count"]) for s in range(epoch * lib.SLOTS_PER_EPOCH, (epoch + 1) * lib.SLOTS_PER_EPOCH)
                       if (b := self.block_at(others[0], s)))
        # Votes for epoch E land in the first blocks of E + 1, so E's total is
        # complete once the wall clock is at E + 2. The joiner's first landed
        # block can come in its activation epoch itself (measured 2026-09-11:
        # activation 11, proposal at e11/s24), so wait for the first full
        # post-activation epoch (activation + 1) to be fully on chain before
        # counting, instead of counting whatever slot // 32 - 2 happens to be.
        after = activation + 1
        self.poll(f"step5: epoch {after}'s attestations are fully on chain (wall epoch ≥ {after + 2})",
                  lambda: (self.clock.wall_epoch() >= after + 2, {"wall_epoch": self.clock.wall_epoch()}), epochs=4)
        votes_after = epoch_votes(after)
        votes_before = epoch_votes(activation - 2) if activation >= 2 else -1
        self.check("step5: per-epoch attestation total is N_GENESIS + 1 after activation (control: N_GENESIS before)",
                   votes_after >= N_GENESIS + 1 and 0 <= votes_before <= N_GENESIS,
                   {"activation_epoch": activation, "epoch_after": after, "votes_after": votes_after,
                    "epoch_before": activation - 2, "votes_before": votes_before})
        self.record("step5_duties", **obs, block=block, votes_after=votes_after, votes_before=votes_before)

    def step_restart(self, dep: dict) -> None:
        joiner, idx, v0 = self.nodes["joiner"], dep["index"], self.node_at(0)

        def reveals_at_least(n: int):
            v = self.validator(v0, dep["pkh"]) or {}
            return as_int(v.get("randao_reveals_used", 0)) >= n, v
        self.poll("step6: randao_reveals_used ≥ 2", lambda: reveals_at_least(2), epochs=16)
        before = self.validator(v0, dep["pkh"])
        old_pid, old_size = joiner.pid, joiner.log_size()
        outcome = joiner.stop()
        self.log(f"joiner pid {old_pid} stopped: {outcome}; relaunching the identical command line")
        self.check("step6: SIGTERM stopped the joiner cleanly", outcome.startswith("terminated"), outcome)
        joiner.start()
        self.wait_ready([joiner])
        # The RPC answers before the boot replay finishes writing its
        # summary (measured 2026-09-11: `replayed 603 blocks …` and the
        # identity line landed after the first successful getchaininfo), so
        # the log is polled for both lines instead of read once.

        def boot_lines():
            text = joiner.log_text_from(old_size)
            replayed = lib.REPLAYED_RE.search(text)
            ok = replayed is not None and int(replayed.group(1)) > 0 and "registered and its key matches" in text
            return ok, {"replayed": replayed.group(0) if replayed else None, "pid": joiner.pids}
        self.poll("step6: restart replayed > 0 blocks and re-resolved an Active identity", boot_lines, epochs=2)
        self.check("step6: slashing_protection.bin retained", (joiner.data_dir / "slashing_protection.bin").exists(), str(joiner.data_dir))
        target = as_int(before["randao_reveals_used"]) + 1
        after = self.poll(f"step6: proposes again after restart (reveals ≥ {target})", lambda: reveals_at_least(target), epochs=14)
        evidence_lines = [l for n in self.live_nodes() for l in n.log_text().splitlines() if f"slashing evidence against v{idx}" in l]
        self.check("step6: identity unchanged, not slashed, no peer reported an equivocation",
                   after["pubkey_hash"] == before["pubkey_hash"] and after["slashed"] is False and not evidence_lines,
                   {"pubkey_hash": after["pubkey_hash"][:16], "slashed": after["slashed"], "evidence_lines": evidence_lines[:2]})
        self.record("step6_restart", pids=joiner.pids, reveals_before=before["randao_reveals_used"], reveals_after=after["randao_reveals_used"])

    def step_partition(self) -> dict | None:
        nodes = self.live_nodes()
        a_nodes, b_nodes = [n for n in nodes if n.slot in SIDE_A], [n for n in nodes if n.slot in SIDE_B]
        pre = self.snapshot("split-pre")
        pids = {n.name: n.pid for n in nodes}
        sizes = {n.name: n.log_size() for n in nodes}
        f0 = {k: as_int(v["finalized"]["epoch"]) for k, v in pre["nodes"].items()}
        peers_before = {k: v["peers_devnet"] for k, v in pre["nodes"].items()}
        split_dep = None
        # Cut at the top of an epoch so no attestation of the split's first
        # epoch was exchanged before the cut; sample once per epoch after that.
        self.poll("step7: top of an epoch (slot_in_epoch ≤ 2)", lambda: (self.clock.slot_in_epoch() <= 2, self.clock.slot_in_epoch()), epochs=2, every=0.5)
        start = self.clock.wall_epoch()
        if self.args.arm == "full":
            pairs = self.mesh.cut_between(SIDE_A, SIDE_B)
            self.split_window = (start, start + self.args.split_epochs)
            self.log(f"SPLIT at epoch {start}: cut {len(pairs)} relays between {sorted(SIDE_A)} and {sorted(SIDE_B)} for {self.args.split_epochs} epochs")
        else:
            self.log(f"control arm: no cut; observing {self.args.split_epochs} epochs of mesh instead")
        samples: list[dict] = []
        for k in range(1, self.args.split_epochs + 1):
            self.wait_epoch("step7: next split sample", start + k)
            sa = self.snapshot(f"split+{k}A", a_nodes, compare=False)
            sb = self.snapshot(f"split+{k}B", b_nodes, compare=False)
            heads_a, heads_b = {v["block_id"] for v in sa["nodes"].values()}, {v["block_id"] for v in sb["nodes"].values()}
            fins = {n: as_int(v["finalized"]["epoch"]) for s in (sa, sb) for n, v in s["nodes"].items()}
            sample = {"wall_epoch": self.clock.wall_epoch(), "heads_a": sorted(heads_a), "heads_b": sorted(heads_b), "finalized": fins,
                      "peers": {n: v["peers_devnet"] for s in (sa, sb) for n, v in s["nodes"].items()}}
            if split_dep is None and self.armed:
                split_dep = self.deposit("split", self.keys["split-cand"], self.keys["split-funder"], [self.node_at(0), self.node_at(2)])
                split_dep["finalized_at_deposit"] = max(fins.values())
                split_dep["status_during_split"] = []
            if split_dep is not None:  # where and when each half included it
                statuses = {n.name: self.rpc(n, "gettxstatus", [split_dep["txid"]])["status"] for n in (self.node_at(0), self.node_at(2))}
                for name, status in statuses.items():
                    if status in ("included", "justified", "finalized") and "dep_epoch" not in split_dep:
                        split_dep["dep_epoch"] = as_int(self.rpc(self.nodes[name], "getchaininfo")["epoch"])
                        split_dep["included_on"] = name
                split_dep["status_during_split"].append({"epoch": self.clock.wall_epoch(), **statuses})
                sample["split_deposit"] = statuses
            samples.append(sample)
            self.log(f"split sample {k}: A={[h[:8] for h in heads_a]} B={[h[:8] for h in heads_b]} finalized={fins}")
        if self.args.arm == "full":
            self.check("step7: peers.devnet dropped on every node during the split",
                       all(all(s["peers"][n] is not None and s["peers"][n] < peers_before[n] for n in peers_before) for s in samples[1:]),
                       {"before": peers_before, "during": [s["peers"] for s in samples[1:3]]})
            self.check("step7: finality FROZEN on both halves from the first post-cut sample to the heal (required, not tolerated)",
                       len(samples) >= 3 and all(s["finalized"] == samples[0]["finalized"] for s in samples[1:]),
                       {"pre_split": f0, "samples": [s["finalized"] for s in samples]})
            self.check("step7: heads DIVERGED between the halves (no shared head) at every post-cut sample",
                       all(not (set(s["heads_a"]) & set(s["heads_b"])) for s in samples[1:]),
                       [{"a": [h[:8] for h in s["heads_a"]], "b": [h[:8] for h in s["heads_b"]]} for s in samples])
            for side, half in (("A", a_nodes), ("B", b_nodes)):
                heads = samples[-1]["heads_" + side.lower()]
                agreed = len(heads) == 1 or lib.chain_verdict({n.name: lib.parse_applied(n.log_text()) for n in half}).ok
                self.check(f"step7: half {side} agreed internally at the last sample", agreed, {"heads": [h[:8] for h in heads]})
            pairs = self.mesh.heal_between(SIDE_A, SIDE_B)
            self.split_window = (start, self.clock.wall_epoch())
            self.log(f"HEAL at epoch {self.clock.wall_epoch()}: reopened {len(pairs)} relays")
        else:
            self.check("step7(control): finality kept advancing on every node with no cut",
                       all(v > f0[n] for n, v in samples[-1]["finalized"].items()), {"f0": f0, "last": samples[-1]["finalized"]})
        conv = self.poll("step7: heads reconverged on every node", self.converged_probe, epochs=10)
        self.poll("step7: finality resumed on every node", lambda: (all(as_int(i["finalized"]["epoch"]) > f0[k] for k, i in self.rpc_all("getchaininfo").items()),
                                                                     {k: i["finalized"] for k, i in self.rpc_all("getchaininfo").items()}), epochs=10)
        self.check("step7: PIDs unchanged across split/heal", {n.name: n.pid for n in self.live_nodes()} == pids, pids)
        replays = {n.name: len(lib.REPLAYED_RE.findall(n.log_text_from(sizes[n.name]))) for n in nodes}
        self.check("step7: no node replayed (restarted) inside the phase", not any(replays.values()), replays)
        post = self.snapshot("split-post")
        self.registry_equal("split-post")
        self.record("step7_partition", window=self.split_window, f0=f0, samples=samples, converged=conv, post=post,
                    split_deposit=split_dep and {k: v for k, v in split_dep.items() if k != "raw"})
        return split_dep

    def converged_probe(self):
        infos = self.rpc_all("getchaininfo")
        slots = {as_int(i["slot"]) for i in infos.values()}
        heads = {i["block_id"] for i in infos.values()}
        behind = max(as_int(i["behind_by_slots"]) for i in infos.values())
        obs = {k: [i["slot"], i["block_id"][:8], i["behind_by_slots"]] for k, i in infos.items()}
        return len(slots) == 1 and len(heads) == 1 and behind <= 2, obs

    def step_split_deposit(self, dep: dict) -> None:
        """After the heal: the registration submitted on both halves must be
        on the converged chain (re-submitted once if the winning branch
        orphaned it — recorded, not hidden) and activate only after finality
        passed its epoch, which was frozen while it was included."""
        v0, v2 = self.node_at(0), self.node_at(2)
        statuses = {n.name: self.rpc(n, "gettxstatus", [dep["txid"]])["status"] for n in (v0, v2)}
        self.check("step7b: split registration was included on at least one half during the split",
                   "dep_epoch" in dep, {"during": dep.get("status_during_split", [])[-3:], "after_heal": statuses})
        if all(s == "unknown" for s in statuses.values()):
            resub = {}
            for n in (v0, v2):
                try:
                    resub[n.name] = self.rpc(n, "sendrawtransaction", [dep["raw"]])
                except RpcError as e:
                    resub[n.name] = {"error": e.as_dict()}
            dep["resubmitted_after_heal"] = resub
            dep.pop("dep_epoch", None)
            self.log(f"split deposit unknown after heal (orphaned branch); resubmitted: {resub}")
        if "dep_epoch" not in dep:
            self.wait_included(dep, v2)
        self.wait_finalized(dep, v2, epochs=12)
        v = self.wait_activation(dep, v2, floor_finalized=dep["finalized_at_deposit"], epochs=16)
        idxs = {n.name: as_int(self.validator(n, dep["pkh"])["index"]) for n in self.live_nodes()}
        self.check("step7b: split registration converged to one index on every node", len(set(idxs.values())) == 1, idxs)
        self.track("split deposit change", dep["txid"], 0, unspent=True, script_hash=dep["funder"])
        self.record("step7b_split_deposit", deposit={k: v for k, v in dep.items() if k != "raw"}, validator=v)

    def step_exit(self, dep: dict) -> dict:
        joiner, v0 = self.nodes["joiner"], self.node_at(0)
        for attempt in range(2):
            self.poll("step8: early in an epoch (slot_in_epoch ≤ 20)", lambda: (self.clock.slot_in_epoch() <= 20, self.clock.slot_in_epoch()), epochs=2, every=0.5)
            epoch = self.clock.wall_epoch()
            out = self.work / "tx" / f"exit.e{epoch}.hex"
            out.unlink(missing_ok=True)
            txid = self.bin.lifecycle_exit(joiner.data_dir, epoch, out)
            try:
                submit = self.rpc(joiner, "sendrawtransaction", [lib.read_hex_file(out)])
                break
            except RpcError as e:
                submit = {"error": e.as_dict()}
                self.log(f"exit for epoch {epoch} refused ({e.message}); {'retrying next epoch' if attempt == 0 else 'giving up'}")
                self.wait_epoch("step8: next epoch", epoch + 1)
        self.check("step8: ExitV2 accepted at the door", isinstance(submit, dict) and submit.get("accepted") is True, submit)
        x, w = self.delays["exit_delay_epochs"], self.delays["withdrawal_delay_epochs"]
        v = self.poll("step8: state exiting", lambda: self.state_is(v0, dep["pkh"], "exiting"), epochs=3)
        self.check("step8: exit_epoch == E + X and withdrawable_epoch == E + X + W",
                   as_int(v["exit_epoch"]) == epoch + x and as_int(v["withdrawable_epoch"]) == epoch + x + w,
                   {"E": epoch, "exit_epoch": v["exit_epoch"], "withdrawable_epoch": v["withdrawable_epoch"]})
        rec = {"epoch": epoch, "txid": txid, "exit_epoch": as_int(v["exit_epoch"]), "withdrawable_epoch": as_int(v["withdrawable_epoch"])}
        self.record("step8_exit", **rec, submit=submit)
        return rec

    def step_equivocation(self, dep: dict, exit_rec: dict) -> dict:
        joiner, observer, idx = self.nodes["joiner"], self.nodes["observer"], dep["index"]
        v0 = self.node_at(0)
        floor_slot = self.clock.wall_slot()

        def fresh_proposal():
            slots = [s for s, v in lib.parse_applied(observer.log_text()).items() if v[2] == idx and s >= floor_slot]
            return bool(slots), {"slots": slots[-3:]}
        slot = self.poll("step9: a joiner proposal applied by the observer while exiting", fresh_proposal,
                         epochs=max(exit_rec["exit_epoch"] - self.clock.wall_epoch(), 1) + 1)["slots"][-1]
        before = {i: self.rpc(v0, "getvalidator", [i]) for i in range(as_int(self.rpc(v0, "getvalidatorcount")["total"]))}
        obs_metric_before = lib.metric_value(lib.http_get(observer.metrics_port, "/metrics"), "bloch_pos_equivocations_observed_total")
        # The tool reads the joiner's live data dir lock-free (devnet_tools.rs:548) and
        # refuses any block the joiner's keystore did not sign.
        forged = self.bin.devnet_equivocate(self.manifest, joiner.data_dir, joiner.data_dir, slot, f"127.0.0.1:{observer.mesh_port}")
        self.log(f"devnet-equivocate on slot {slot} → observer :{observer.mesh_port}: original {str(forged['original'])[:12]} "
                 f"conflicting {str(forged['conflicting'])[:12]}")
        self.check("step9: the tool printed two distinct block ids", forged["original"] and forged["conflicting"]
                   and forged["original"] != forged["conflicting"], {k: forged[k] for k in ("original", "conflicting")})
        line = f"slashing evidence against v{idx} admitted and broadcast"
        self.poll("step9: observer admitted and broadcast the evidence", lambda: (line in observer.log_text(), {"line": line}), epochs=2, every=0.5)
        after_metric = lib.metric_value(lib.http_get(observer.metrics_port, "/metrics"), "bloch_pos_equivocations_observed_total")
        self.check("step9: observer equivocations_observed_total +1", obs_metric_before is not None and after_metric == obs_metric_before + 1,
                   {"before": obs_metric_before, "after": after_metric})
        v = self.poll("step9: slashed == true on every node", lambda: self.every_node_sees(dep["pkh"], lambda x: x["slashed"] is True), epochs=4)
        including = None
        for s in range(slot + 1, self.clock.wall_slot() + 1):
            block = self.block_at(v0, s)
            if block and as_int(block["tx_count"]) >= 1:
                including = block
                break
        self.check("step9: the evidence's including block was found (tx_count ≥ 1 after the proposal)", including is not None, including)
        slash_epoch = as_int(including["epoch"]) if including else self.clock.wall_epoch()
        prev = before[idx]
        loss = as_int(prev["own_stake_sat"]) // 20
        v0v = v["node0"]
        self.check("step9: state slashed, own_stake −5%, exit_epoch = min(prev, e+1), withdrawable UNCHANGED",
                   v0v["state"] == "slashed" and as_int(v0v["own_stake_sat"]) == as_int(prev["own_stake_sat"]) - loss
                   and as_int(v0v["exit_epoch"]) == min(as_int(prev["exit_epoch"]), slash_epoch + 1)
                   and as_int(v0v["withdrawable_epoch"]) == as_int(prev["withdrawable_epoch"]),
                   {"prev": {k: prev[k] for k in ("own_stake_sat", "exit_epoch", "withdrawable_epoch")},
                    "now": {k: v0v[k] for k in ("state", "own_stake_sat", "exit_epoch", "withdrawable_epoch")}, "slash_epoch": slash_epoch})
        self.check("step9: identical slashed record on every node", len({lib.jdump({k: x[k] for k in ("state", "own_stake_sat", "exit_epoch", "withdrawable_epoch", "slashed")}) for x in v.values()}) == 1,
                   {k: x["state"] for k, x in v.items()})
        proposer = as_int(including["proposer_index"]) if including else None
        self.wait_epoch("step9: boundary after the slash (whistleblower settles)", slash_epoch + 1)
        self.clock.sleep_slots(1)  # let the boundary block land
        deltas = {i: as_int(self.rpc(v0, "getvalidator", [i])["own_stake_sat"]) - as_int(before[i]["own_stake_sat"]) for i in before}
        self.check("step9: including proposer's own_stake_sat rose by ≥ loss/32 (issuance lands at the same boundary: lower bound)",
                   proposer is not None and deltas.get(proposer, 0) >= loss // 32, {"proposer": proposer, "loss": loss, "reward_floor": loss // 32, "deltas": deltas})
        not_submitted = [l for n in self.live_nodes() for l in n.log_text().splitlines() if "not submitted:" in l]
        self.check("step9: no node logged `not submitted:`", not not_submitted, not_submitted[:3])
        rec = {"slot": slot, "forged": forged, "including_block": including, "slash_epoch": slash_epoch, "loss": loss, "proposer": proposer,
               "deltas": deltas, "post_slash_stake": as_int(v0v["own_stake_sat"]), "withdrawable_epoch": as_int(v0v["withdrawable_epoch"])}
        self.record("step9_equivocation", **rec)
        return rec

    def step_load(self) -> list[dict]:
        v0 = self.node_at(0)
        # Start at the top of an epoch: eight prepare/sign/sign/inspect rounds
        # must all be submitted inside one epoch (16 s at 500 ms slots).
        self.poll("step12: top of an epoch", lambda: (self.clock.slot_in_epoch() <= 1, self.clock.slot_in_epoch()), epochs=2, every=0.5)
        start, t0 = self.clock.wall_epoch(), time.monotonic()
        deps = [self.deposit(f"load{k}", self.keys[f"load{k}"], self.keys[f"load{k}-funder"], [v0], expiry_epochs=60) for k in range(self.args.load)]
        self.check("step12: all load deposits accepted, submitted within one epoch",
                   all(d["submits"]["node0"].get("accepted") is True for d in deps) and self.clock.wall_epoch() == start,
                   {"start": start, "end": self.clock.wall_epoch(), "seconds": round(time.monotonic() - t0, 1),
                    "statuses": [d["submits"]["node0"].get("status", "error") for d in deps]})
        for d in deps:
            self.wait_included(d, v0)
            self.track(f"{d['tag']} change", d["txid"], 0, unspent=True, script_hash=d["funder"])
        for d in deps:
            self.wait_finalized(d, v0, epochs=12)
        cap = self.delays["maximum_activations_per_epoch"]
        acts = {}
        for d in deps:
            def assigned(pkh=d["pkh"]):
                x = self.validator(v0, pkh)
                return x is not None and x.get("activation_epoch") is not None, x
            v = self.poll(f"{d['tag']}: activation assigned", assigned, epochs=self.args.load // cap + 12)
            acts[d["tag"]] = as_int(v["activation_epoch"])
        per_epoch: dict[int, int] = {}
        for a in acts.values():
            per_epoch[a] = per_epoch.get(a, 0) + 1
        self.check(f"step12: activations ≤ {cap} per epoch and ≥ dep_epoch + delay", all(c <= cap for c in per_epoch.values())
                   and all(acts[d["tag"]] >= d["dep_epoch"] + self.delays["activation_delay_epochs"] for d in deps), {"activation_epochs": acts, "per_epoch": per_epoch})
        last = max(acts.values())
        self.poll("step12: all load candidates active on node0", lambda: (all((self.validator(v0, d["pkh"]) or {}).get("state") == "active" for d in deps), acts),
                  epochs=max(last - self.clock.wall_epoch(), 0) + 3)
        self.registry_equal("step12")
        self.record("step12_load", activation_epochs=acts, deposits=[{k: v for k, v in d.items() if k != "raw"} for d in deps])
        return deps

    def step_withdrawal(self, dep: dict, slash: dict) -> dict:
        joiner, v0, idx = self.nodes["joiner"], self.node_at(0), dep["index"]
        we = slash["withdrawable_epoch"]
        written_off_before = as_int(self.rpc(v0, "getvalidatoradmission")["written_off_sat"])
        pre = self.validator(v0, dep["pkh"]) or {}
        self.check("step10: before the crank, withdrawal_payout_sat == post-slash own_stake_sat (funded: unbacked 0)",
                   as_int(pre.get("withdrawal_payout_sat", -1)) == slash["post_slash_stake"] == as_int(pre.get("own_stake_sat", -2))
                   and as_int(pre.get("unbacked_principal_sat", -1)) == 0,
                   {k: pre.get(k) for k in ("withdrawal_payout_sat", "own_stake_sat", "unbacked_principal_sat", "state")})
        out = self.work / "tx" / "withdraw.hex"
        out.unlink(missing_ok=True)
        wtxid = self.bin.lifecycle_withdraw(idx, out)
        raw = lib.read_hex_file(out)
        while self.clock.wall_epoch() + 8 < we:  # the lock: a snapshot every 8 epochs keeps finality measured
            target = self.clock.wall_epoch() + 8
            self.wait_epoch("step10: withdrawal lock", target)
            self.snapshot(f"lock@{target}")
        self.wait_epoch(f"step10: withdrawable_epoch", we, every=0.25)
        self.clock.sleep_slots(0.75)  # the auto-crank runs at the top of the slot loop, before attest
        try:
            manual = self.rpc(joiner, "sendrawtransaction", [raw])
        except RpcError as e:
            manual = {"error": e.as_dict(), "state_at_refusal": (self.validator(joiner, dep["pkh"]) or {}).get("state")}
        v = self.poll("step10: state withdrawn on every node", lambda: self.every_node_sees(dep["pkh"], lambda x: x["state"] == "withdrawn"), epochs=4)
        auto_first = manual.get("status") == "duplicate" or (manual.get("error") and manual.get("state_at_refusal") == "withdrawn")
        self.check("step10: the node auto-cranked the withdrawal (manual crank was a duplicate)", auto_first, manual)
        v0v = v["node0"]
        payout = slash["post_slash_stake"]
        written_off_after = as_int(self.rpc(v0, "getvalidatoradmission")["written_off_sat"])
        self.check("step10: own_stake_sat 0 after the crank and written_off_sat unchanged (nothing written off)",
                   as_int(v0v["own_stake_sat"]) == 0 and written_off_after == written_off_before,
                   {"own_stake_sat": v0v["own_stake_sat"], "written_off": [written_off_before, written_off_after]})
        txout = self.rpc_all("gettxout", [wtxid, 0])
        self.check("step10: payout at (withdraw txid, 0) with value == residue and script_hash == credential on every node",
                   all(t["unspent"] is True and as_int(t["utxo"]["value_sat"]) == payout and t["utxo"]["script_hash"] == dep["funder"] for t in txout.values()),
                   {k: t["utxo"] for k, t in txout.items()})
        listed = any(u["txid"] == wtxid for u in self.rpc(v0, "getutxos", [dep["funder"], 20])["utxos"])
        deferred = [l for l in joiner.log_text().splitlines() if f"validator lifecycle action for v{idx} deferred" in l]
        self.check("step10: funder's getutxos lists the payout; no deferred-crank loop in the joiner log", listed and len(deferred) <= 2, {"listed": listed, "deferred": deferred[:3]})
        self.track("withdrawal payout", wtxid, 0, unspent=True, value_sat=payout, script_hash=dep["funder"])
        rec = {"txid": wtxid, "payout_sat": payout, "manual": manual}
        self.record("step10_withdrawal", **rec)
        return rec

    def step_spend(self, dep: dict, wd: dict) -> None:
        v0, dest = self.node_at(0), self.keys["dest"].script_hash
        # The fee is priced at the INCLUDING block's base fee: build with the
        # next base fee and submit at once; one rebuild if the fee moved meanwhile.
        for attempt in range(2):
            base_fee = as_int(self.rpc(v0, "getvalidatoradmission")["next_base_fee_millisat_per_gas"])
            out = self.work / "tx" / f"spend.{attempt}.hex"
            out.unlink(missing_ok=True)
            stxid = self.bin.transfer_v2(self.manifest, self.keys["funder"].dir, [(wd["txid"], 0, wd["payout_sat"])], dest,
                                         base_fee, 5, self.clock.wall_epoch(), out)
            try:
                submit = self.rpc(v0, "sendrawtransaction", [lib.read_hex_file(out)])
                break
            except RpcError as e:
                submit = {"error": e.as_dict(), "base_fee": base_fee}
                self.log(f"transfer-v2 refused ({e.message}); {'rebuilding with a fresh base fee' if attempt == 0 else 'giving up'}")
        self.check("step11: transfer-v2 accepted at the door", submit.get("accepted") is True and submit.get("kind") == "transfer_v2", submit)
        def spent_and_present():
            olds = self.rpc_all("gettxout", [wd["txid"], 0])
            news = self.rpc_all("gettxout", [stxid, 0])
            ok = all(o["unspent"] is False for o in olds.values()) and all(
                t["unspent"] is True and t["utxo"]["script_hash"] == dest for t in news.values())
            return ok, {k: [olds[k]["unspent"], news[k]["unspent"]] for k in news}
        self.poll("step11: old outpoint gone and new outpoint present on every node", spent_and_present, epochs=4)
        new = self.rpc(v0, "gettxout", [stxid, 0])["utxo"]
        balance = self.rpc(v0, "getbalance", [dest])
        value = as_int(new["value_sat"])
        self.check("step11: output value == payout − fee (> 0) and getbalance[dest].balance_sat agrees",
                   0 < value < wd["payout_sat"] and as_int(balance["balance_sat"]) == value,
                   {"value_sat": value, "fee_sat": wd["payout_sat"] - value, "balance": balance})
        self.tracked = [t for t in self.tracked if t["label"] != "withdrawal payout"]
        self.track("withdrawal payout (spent)", wd["txid"], 0, unspent=False)
        self.track("spend output", stxid, 0, unspent=True, script_hash=dest, value_sat=value)
        self.record("step11_spend", txid=stxid, value_sat=value, base_fee=base_fee, submit=submit)

    def phase_lifecycle(self) -> None:
        self.step_wait_finality()
        dep = self.step_deposit()
        self.step_boot_joiner(dep)
        self.step_activation(dep)
        self.maybe_start_observer()
        self.step_duties(dep)
        self.maybe_start_observer()
        self.step_restart(dep)
        self.maybe_start_observer()
        if "observer" not in self.nodes:  # epoch 10 already passed inside the polls above
            self.args.observer_epoch = self.clock.wall_epoch()
            self.maybe_start_observer()
        split_dep = self.step_partition()
        exit_rec = self.step_exit(dep)
        slash = self.step_equivocation(dep, exit_rec)
        if split_dep is not None:
            self.step_split_deposit(split_dep)
        self.step_load()  # runs inside the 64-epoch withdrawal lock, not after it
        wd = self.step_withdrawal(dep, slash)
        self.step_spend(dep, wd)
        self.record("lifecycle_done", snapshot=self.snapshot("final"))

    def phase_unarmed_control(self) -> None:
        self.step_wait_finality()
        dep = self.deposit("unarmed", self.keys["joiner"], self.keys["funder"], [self.node_at(0)])
        err = dep["submits"]["node0"].get("error") or {}
        self.check("unarmed-control: the SHIPPING binary refused the deposit at the RPC door with `not active`",
                   "not active" in str(err.get("message", "")), dep["submits"])
        self.check("unarmed-control: getvalidatoradmission.activation_epoch is null",
                   self.rpc(self.node_at(0), "getvalidatoradmission")["activation_epoch"] is None, None)
        self.record("unarmed_control", deposit={k: v for k, v in dep.items() if k != "raw"}, snapshot=self.snapshot("unarmed"))

    # ── verdict ─────────────────────────────────────────────────────────────
    def phase_verdict(self) -> None:
        nodes = self.live_nodes()
        maps = {n.name: lib.parse_applied(n.log_text()) for n in nodes}
        cv = lib.chain_verdict(maps)
        self.check(f"verdict: per-slot chain map {cv.status} over {cv.nodes} nodes / {cv.common_slots} shared slots", cv.ok, cv.as_dict())
        proposers = {v[2] for m in maps.values() for v in m.values()}
        self.check("verdict: proposer set over the run ⊇ every genesis index", set(range(N_GENESIS)) <= proposers, sorted(proposers))
        forbidden = {n.name: lib.forbidden_hits(n.log_text()) for n in nodes}
        self.check("verdict: no forbidden log line on any node", not any(forbidden.values()), {k: v for k, v in forbidden.items() if v})
        self.check("verdict: every node process alive until the harness stops it", all(n.alive() for n in nodes), {n.name: n.pid for n in nodes})
        self.check("verdict: finality progression (non-decreasing, frozen only inside the split window, rising outside)", *self.finality_progress())
        if self.armed and len(nodes) > 1:
            self.registry_equal("verdict")
            self.utxo_facts_equal("verdict")
            admission = self.rpc_all("getvalidatoradmission")
            self.check("verdict: admission active and one network_domain on every node",
                       all(a["active"] for a in admission.values()) and len({a["network_domain"] for a in admission.values()}) == 1,
                       {k: a["network_domain"][:16] for k, a in admission.items()})
        diff = subprocess.run(["git", "diff", "--quiet", "--", lib.PARAMS, lib.STAKING], cwd=ROOT)
        self.check("verdict: checkout params.rs/staking.rs untouched (git diff --quiet)", diff.returncode == 0, diff.returncode)

    def finality_progress(self) -> tuple[bool, dict]:
        return lib.finality_progress(self.finality_samples, self.split_window)

    # ── cleanup and main ────────────────────────────────────────────────────
    def cleanup(self) -> None:
        outcomes = {n.name: n.stop() for n in self.nodes.values()}
        if self.mesh:
            self.mesh.close_all()
        if outcomes:
            self.log(f"stopped nodes: {outcomes}")
        self.record("cleanup", stopped=outcomes)

    def write_verdict(self, ok: bool, error: str | None) -> None:
        failed = [c for c in self.checks if not c["ok"]]
        print("\n" + lib.check_table(self.checks))
        print(f"arm={self.args.arm} checks={len(self.checks)} failed={len(failed)} error={error!r} → {'PASS' if ok else 'FAIL'}")
        print(f"work dir: {self.work}")
        (self.work / "verdict.json").write_text(json.dumps(
            {"ok": ok, "arm": self.args.arm, "error": error, "checks": self.checks, "split_window": self.split_window,
             "work": str(self.work)}, indent=1, default=str))

    def run(self) -> int:
        error = None
        try:
            self.phase_build()
            self.phase_keys_manifest()
            self.deadline_mono = time.monotonic() + self.args.timeout_minutes * 60
            self.phase_relays_boot()
            if self.armed:
                self.phase_lifecycle()
            else:
                self.phase_unarmed_control()
        except (SoakError, subprocess.SubprocessError, OSError, KeyboardInterrupt) as e:
            error = f"{type(e).__name__}: {e}"
            self.log(f"ABORT: {error}")
            self.record("abort", error=error)
        finally:
            try:
                if self.nodes and self.clock:
                    self.phase_verdict()
            except (SoakError, OSError) as e:
                error = error or f"verdict: {e}"
                self.log(f"verdict aborted: {e}")
            self.cleanup()
        ok = error is None and all(c["ok"] for c in self.checks) and bool(self.checks)
        self.write_verdict(ok, error)
        if ok and not self.args.keep:
            shutil.rmtree(self.work, ignore_errors=True)
        return 0 if ok else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--work", help="work directory (default: a fresh mkdtemp)")
    parser.add_argument("--reuse-build", action="store_true", help="skip copy+build if <work>/copy/bloch-pos exists")
    parser.add_argument("--slot-ms", type=int, default=500)
    parser.add_argument("--arm", choices=["full", "control", "unarmed-control"], default="full")
    parser.add_argument("--keep", action="store_true", help="keep the work dir on success too")
    parser.add_argument("--timeout-minutes", type=int, default=60, help="overall run budget after the build")
    parser.add_argument("--build-timeout-minutes", type=int, default=45)
    parser.add_argument("--port-base", type=int, default=17610)
    parser.add_argument("--split-epochs", type=int, default=9, help="must exceed ACTIVATION_DELAY_EPOCHS (8)")
    parser.add_argument("--allow-short-split", action="store_true",
                        help="experiment only: permit --split-epochs <= 8 (e.g. 3, below INACTIVITY_LEAK_THRESHOLD_EPOCHS = 4) "
                             "to discriminate WHY a long partition does not heal; such a run does not discharge VAD-04")
    parser.add_argument("--observer-epoch", type=int, default=10, help="fresh late join at this wall epoch (< W − X = 60)")
    parser.add_argument("--start-in", type=int, default=20, help="genesis --start-in seconds")
    parser.add_argument("--load", type=int, default=8, help="independently funded load candidates")
    parser.add_argument("--randao-chain", type=int, default=lib.RANDAO_CHAIN_LENGTH_SHIPPING,
                        help="RANDAO_CHAIN_LENGTH in the armed copy (default: the shipping 8192, i.e. unchanged; "
                             "256 reproduces the automatic-renewal observation of 2026-09-11 but stalls a partition "
                             "half whose only proposer has spent its chain)")
    args = parser.parse_args()
    if args.split_epochs <= 8 and not args.allow_short_split:
        parser.error("--split-epochs must exceed ACTIVATION_DELAY_EPOCHS (8); pass --allow-short-split for a "
                     "partition-length experiment, which the verdict then labels as such")
    if not 1 <= args.load <= 32:
        parser.error("--load must be 1..32 (idle active stake must stay < 1/3)")
    harness = Harness(args)

    def on_sigterm(*_) -> None:
        raise KeyboardInterrupt("SIGTERM")
    signal.signal(signal.SIGTERM, on_sigterm)
    return harness.run()


if __name__ == "__main__":
    sys.exit(main())
