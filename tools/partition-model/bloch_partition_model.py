"""Fast partition model of Bloch L1 finality (FFG + inactivity leak), for wide
parameter sweeps.  Port of an epoch-granularity partition simulator to
Bloch's exact rules.  DEV TOOLING ONLY (scripts/hf-verify/run-all.sh).

Research tool, not a consensus reference.  The epoch fold below is a line-by-line
port of `FinalityState::process_epoch`
(crates/bloch-pos-committee/src/finality.rs:331-618, release lineage dd287b6c);
everything around it (who votes where, heal, fork choice) is a model.

    python3 tools/partition-model/bloch_partition_model.py sweep  [--jobs N] [--out results.json]
            [--quick] [--variants TODAY,BOTH] [--hf-from EPOCH] [--gate eth_paced_from=N ...]
    python3 tools/partition-model/bloch_partition_model.py table  results.json
    python3 tools/partition-model/test_bloch_partition_model.py -v

Rules ported (file:line in crates/bloch-pos-committee/src at dd287b6c):

  quorum      3*w >= 2*total, total > 0                         finality.rs:466
  source      vote counts iff source == current justified,     finality.rs:433-445
              source.epoch < target.epoch
  equivocator two different votes for one target epoch: the    finality.rs:403-430
              validator counts for NO target (and is absent)
  tally       by target ROOT, no ancestry check                finality.rs:448-454
  finality    link (s -> t), t.epoch == s.epoch + 1 and         finality.rs:492-497
              s.epoch > finalized.epoch finalizes s
  denominator leak-adjusted total; from LEAK_RECOVERY_ACTIVATION  finality.rs:365-391
              _EPOCH (2880, params.rs:1277) floored at
              MIN_QUORUM_DENOMINATOR 1/2 (params.rs:330-332) of
              the unleaked total
  leak        since = epoch - finalized.epoch (post-vote);       finality.rs:505-541
              leaking iff since > 4 (params.rs:154); every
              member without a valid vote and stake > 0 loses
              max(stake*t // Q, 1), t = since - 4, capped at its
              stake; Q = 64 below epoch 5700, 2_684_355 from it
              (params.rs:162, 194, 206, 209-218)
  recovery    from epoch 2880: leaked -= max(leaked // 16, 1)   finality.rs:548-611
              (params.rs:293) for every member, except absent
              members while leaking
  roster      denominator base = duty roster = registry stake    transition.rs:2718,
              with the genesis-cohort cap (cohort 0..63, cap      genesis_cohort.rs:75-190
              bps 10000 - 6667*e/32872, closed form
              others*bps/(10000-bps), pro rata); the C-R2-2
              combined cap is unarmed (params.rs:1437 = MAX)
  proposer    21e382a1 liveness floor: a fully leaked roster      transition.rs:2755-2772
              still has a proposer, so every live branch is
              modelled as producing >= 1 block per epoch that
              carries its votes (the best case for liveness).

Variants (one flag each; BOTH = all three):

  TODAY     the rules above.
  CLAIM     native claim finality (NATIVE_CLAIM_FINALITY_ACTIVATION_EPOCH):
            finality unchanged; an L2 claim releases only where the finalized
            ROOT is the chain's own checkpoint at that epoch.  Changes the
            payout metric only.
  P2A       own-chain target: a vote counts (quorum AND presence) only if its
            target root is this chain's own checkpoint root at that epoch, so
            a branch can no longer justify the other branch's checkpoint from
            gossiped votes.  This is the model's definition; check it against
            the HF1 own-target rule with the Rust harness.
  P1A       frozen no-leak finality set (PoCI-like): numerator and denominator
            read the UNLEAKED duty-roster weights frozen at the last finalized
            checkpoint's epoch; the leak ledger still accrues but no longer
            touches the quorum.
  BOTH      CLAIM + P2A + P1A.

Every variant flag binds from `Rules.active_from` (default 0 = from the
partition start; `--hf-from EPOCH` overrides it for the sweep), and the
inherited flag days in `Gates` can be overridden with `--gate`.

Network model (at epoch granularity):
  - One checkpoint per epoch per live branch.  A partition starting at S forks
    one branch per side; checkpoints from epoch S on are branch-specific.
  - Every online member of a side votes (branch current_justified -> the
    branch's checkpoint) and the vote is included in that epoch.
  - `cross` = [(i, j)]: side i's votes are also gossiped into side j's blocks
    (blocks do not cross).  With it a branch can finalize the other side's
    checkpoint (the split-claim reproduction in l2_settlement_tests).
  - Heal at H: if two branches hold conflicting finalized checkpoints the
    split is permanent (node finality latch, bloch-pos-node engine.rs:4830-4870
    refuses a reorg below its finalized height).  Otherwise every node adopts
    the branch with the highest (finalized epoch, justified epoch, online
    stake) and votes there from H on.
  - Offline validators cast no vote anywhere for [from, to).
"""
from __future__ import annotations

import argparse
import copy
import itertools
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
SNAPSHOT = HERE / "fleet_snapshot.json"

# ── Constants (crates/bloch-pos-committee/src, dd287b6c) ─────────────────────
INACTIVITY_LEAK_THRESHOLD_EPOCHS = 4          # params.rs:154
INACTIVITY_LEAK_QUOTIENT = 64                 # params.rs:162
INACTIVITY_LEAK_QUOTIENT_ETH_PACED = 2_684_355  # params.rs:194
ETH_PACED_LEAK_ACTIVATION_EPOCH = 5_700       # params.rs:206
INACTIVITY_LEAK_RECOVERY_QUOTIENT = 16        # params.rs:293
MIN_QUORUM_DENOMINATOR_NUM = 1                # params.rs:330
MIN_QUORUM_DENOMINATOR_DEN = 2                # params.rs:332
LEAK_RECOVERY_ACTIVATION_EPOCH = 2_880        # params.rs:1277
SLOTS_PER_EPOCH = 32                          # params.rs:34
SLOT_DURATION_SECS = 30                       # params.rs:73
EPOCHS_PER_DAY = 24 * 3600 // (SLOTS_PER_EPOCH * SLOT_DURATION_SECS)  # 90
SLOTS_PER_YEAR = 1_051_920                    # tokenomics_v4.rs:302
EPOCHS_PER_YEAR = SLOTS_PER_YEAR // SLOTS_PER_EPOCH  # genesis_cohort.rs:55
COHORT_CAP_START_BPS = 10_000                 # genesis_cohort.rs:58
COHORT_CAP_FLOOR_BPS = 3_333                  # genesis_cohort.rs:61


@dataclass(frozen=True)
class Gates:
    """Which flag days are open.  `mainnet()` is the release; the others are the
    switches the Rust tests use (finality.rs tests_hook, params::rehearsal)."""
    eth_paced_from: int = ETH_PACED_LEAK_ACTIVATION_EPOCH
    floor_from: int | None = LEAK_RECOVERY_ACTIVATION_EPOCH  # None: never
    recovery_from: int | None = LEAK_RECOVERY_ACTIVATION_EPOCH

    def quotient(self, epoch: int) -> int:  # params.rs:209-218
        return INACTIVITY_LEAK_QUOTIENT_ETH_PACED if epoch >= self.eth_paced_from else INACTIVITY_LEAK_QUOTIENT

    def floor(self, epoch: int) -> bool:
        return self.floor_from is not None and epoch >= self.floor_from

    def recovery(self, epoch: int) -> bool:
        return self.recovery_from is not None and epoch >= self.recovery_from


MAINNET = Gates()
LEGACY = Gates(eth_paced_from=1 << 62, floor_from=None, recovery_from=None)   # legacy_arithmetic(true)
GATES_OPEN = Gates(eth_paced_from=1 << 62, floor_from=0, recovery_from=0)     # rehearsal::gates_open_guard
ETH_REHEARSAL = Gates(eth_paced_from=0)                                        # eth_paced_leak_rehearsal::open


@dataclass(frozen=True)
class Rules:
    name: str
    claim_fix: bool = False
    own_target: bool = False
    frozen_noleak: bool = False
    active_from: int = 0  # absolute epoch from which the flags above bind

    def claim(self, epoch: int) -> bool:
        return self.claim_fix and epoch >= self.active_from

    def own(self, epoch: int) -> bool:
        return self.own_target and epoch >= self.active_from

    def frozen(self, epoch: int) -> bool:
        return self.frozen_noleak and epoch >= self.active_from


TODAY = Rules("TODAY")
CLAIM = Rules("CLAIM", claim_fix=True)
P2A = Rules("P2A", own_target=True)
P1A = Rules("P1A", frozen_noleak=True)
BOTH = Rules("BOTH", claim_fix=True, own_target=True, frozen_noleak=True)
VARIANTS = (TODAY, CLAIM, P2A, P1A, BOTH)


# ── Roster ───────────────────────────────────────────────────────────────────

def cohort_cap_bps(epoch: int) -> int:  # genesis_cohort.rs:75-81
    if epoch >= EPOCHS_PER_YEAR:
        return COHORT_CAP_FLOOR_BPS
    span = COHORT_CAP_START_BPS - COHORT_CAP_FLOOR_BPS
    return COHORT_CAP_START_BPS - span * epoch // EPOCHS_PER_YEAR


class Roster:
    """Duty-roster weights per epoch: registry stake with the cohort cap."""

    def __init__(self, indices: list[int], stake: list[int], cohort: set[int] | None = None):
        self.indices = list(indices)
        self.raw = np.array(stake, dtype=np.int64)
        self.cohort_mask = np.array([i in (cohort or set()) for i in indices], dtype=bool)
        self._cache: dict[int, np.ndarray] = {}

    def __len__(self) -> int:
        return len(self.indices)

    def at(self, epoch: int) -> np.ndarray:
        if not self.cohort_mask.any():
            return self.raw
        bps = cohort_cap_bps(epoch)
        got = self._cache.get(bps)
        if got is not None:
            return got
        total = int(self.raw.sum())
        cohort = int(self.raw[self.cohort_mask].sum())
        others = total - cohort
        out = self.raw
        # genesis_cohort.rs:111-127 (NotTapering / Deferred leave it alone),
        # 161-190 (closed form, truncating pro rata).
        if bps < 10_000 and others > 0:
            cap = others * bps // (10_000 - bps)
            if cohort > cap:
                out = self.raw.copy()
                for k in np.nonzero(self.cohort_mask)[0]:
                    out[k] = int(self.raw[k]) * cap // cohort
        self._cache[bps] = out
        return out


# ── The fold: FinalityState::process_epoch ───────────────────────────────────

NO_VOTE = -1


@dataclass
class Votes:
    """At most one admitted vote per validator, plus the equivocator mask
    (finality.rs:403-430).  Roots are interned ints; NO_VOTE = absent."""
    src_e: np.ndarray
    src_r: np.ndarray
    tgt_r: np.ndarray
    equiv: np.ndarray

    @staticmethod
    def empty(n: int) -> "Votes":
        return Votes(np.full(n, NO_VOTE, np.int64), np.full(n, NO_VOTE, np.int64),
                     np.full(n, NO_VOTE, np.int64), np.zeros(n, bool))

    def add(self, mask: np.ndarray, src_e: int, src_r: int, tgt_r: int) -> None:
        clash = mask & (self.tgt_r != NO_VOTE) & ((self.tgt_r != tgt_r) | (self.src_r != src_r) | (self.src_e != src_e))
        self.equiv |= clash
        fresh = mask & (self.tgt_r == NO_VOTE)
        self.src_e[fresh] = src_e
        self.src_r[fresh] = src_r
        self.tgt_r[fresh] = tgt_r

    def add_from(self, other: "Votes", mask: np.ndarray) -> None:
        m = mask & (other.tgt_r != NO_VOTE)
        clash = m & (self.tgt_r != NO_VOTE) & ((self.tgt_r != other.tgt_r) | (self.src_r != other.src_r)
                                               | (self.src_e != other.src_e))
        self.equiv |= clash | (m & other.equiv)
        fresh = m & (self.tgt_r == NO_VOTE)
        self.src_e[fresh] = other.src_e[fresh]
        self.src_r[fresh] = other.src_r[fresh]
        self.tgt_r[fresh] = other.tgt_r[fresh]


@dataclass
class Finality:
    """Port of FinalityState (finality.rs:169-186).  Checkpoints are
    (epoch, root id) tuples."""
    justified: dict[int, int]
    cj: tuple[int, int]
    fin: tuple[int, int]
    leaked: np.ndarray
    next_epoch: int
    frozen: np.ndarray | None = None  # P1A only: weights frozen at fin.epoch

    @staticmethod
    def new(genesis: tuple[int, int], n: int) -> "Finality":  # finality.rs:192-202
        return Finality({genesis[0]: genesis[1]}, genesis, genesis, np.zeros(n, np.int64), genesis[0] + 1)

    def copy(self) -> "Finality":
        return Finality(dict(self.justified), self.cj, self.fin, self.leaked.copy(), self.next_epoch,
                        None if self.frozen is None else self.frozen.copy())

    def process_epoch(self, epoch: int, roster: Roster, votes: Votes, gates: Gates, rules: Rules,
                      own_root: int | None = None) -> tuple[tuple[int, int] | None, tuple[int, int] | None]:
        if epoch != self.next_epoch:
            raise ValueError(f"OutOfOrderEpoch got {epoch} expected {self.next_epoch}")
        self.next_epoch += 1
        eff = roster.at(epoch)
        stake = np.maximum(eff - self.leaked, 0)  # saturating_sub, finality.rs:343-347
        unleaked_total = int(eff.sum())
        leak_adjusted = int(stake.sum())
        if gates.floor(epoch):  # finality.rs:377-391
            total = max(leak_adjusted, unleaked_total * MIN_QUORUM_DENOMINATOR_NUM // MIN_QUORUM_DENOMINATOR_DEN)
        else:
            total = leak_adjusted
        weight = stake
        if rules.frozen(epoch):
            if self.frozen is None:
                self.frozen = roster.at(self.fin[0]).copy()
            weight = self.frozen
            total = int(self.frozen.sum())

        src_e, src_r = self.cj
        valid = ((votes.tgt_r != NO_VOTE) & ~votes.equiv & (votes.src_e == src_e) & (votes.src_r == src_r))
        if not src_e < epoch:
            valid[:] = False
        if rules.own(epoch):
            valid &= votes.tgt_r == own_root

        justified_now = None
        if valid.any():
            roots = np.unique(votes.tgt_r[valid])
            for r in roots:  # BTreeMap order; at most one can reach 2/3
                w = int(weight[valid & (votes.tgt_r == r)].sum())
                if total > 0 and 3 * w >= 2 * total:
                    justified_now = (epoch, int(r))
                    break
        finalized_now = None
        if justified_now is not None:  # finality.rs:476-498
            self.justified[epoch] = justified_now[1]
            if epoch > self.cj[0]:
                self.cj = justified_now
            if src_e + 1 == epoch and src_e > self.fin[0]:
                self.fin = (src_e, src_r)
                finalized_now = self.fin
                if rules.frozen(epoch):
                    self.frozen = roster.at(self.fin[0]).copy()

        since = epoch - self.fin[0]  # finality.rs:505-541
        leaking = since > INACTIVITY_LEAK_THRESHOLD_EPOCHS
        if leaking:
            t = since - INACTIVITY_LEAK_THRESHOLD_EPOCHS
            q = gates.quotient(epoch)
            absent = ~valid & (stake > 0)
            if absent.any():
                s = stake[absent]
                bite = (s // q) * t + ((s % q) * t) // q  # == s*t//q without int64 overflow
                bite = np.minimum(np.maximum(bite, 1), s)
                self.leaked[absent] += bite
        if gates.recovery(epoch):  # finality.rs:548-611
            m = (valid if leaking else np.ones(len(valid), bool)) & (self.leaked > 0)
            if m.any():
                lk = self.leaked[m]
                back = np.minimum(np.maximum(lk // INACTIVITY_LEAK_RECOVERY_QUOTIENT, 1), lk)
                self.leaked[m] = lk - back
        return justified_now, finalized_now


# ── Branches and the world ───────────────────────────────────────────────────

class Roots:
    def __init__(self) -> None:
        self.ids: dict[tuple[str, int], int] = {}
        self.of: list[tuple[str, int]] = []

    def get(self, label: str, epoch: int) -> int:
        k = (label, epoch)
        r = self.ids.get(k)
        if r is None:
            r = len(self.of)
            self.ids[k] = r
            self.of.append(k)
        return r


@dataclass
class Branch:
    label: str
    parent: "Branch | None"
    fork_epoch: int
    members: np.ndarray
    fs: Finality
    first_new_fin: int | None = None  # epoch at which a checkpoint >= start was first finalized here
    alive: bool = True

    def own_label(self, epoch: int) -> str:
        b = self
        while b.parent is not None and epoch < b.fork_epoch:
            b = b.parent
        return b.label


@dataclass
class Scenario:
    name: str
    sides: list[list[str]] | None  # groups per side; None: one chain
    start: int
    heal: int | None = None
    offline: dict[str, tuple[int, int]] = field(default_factory=dict)  # group -> [from, to)
    cross: list[tuple[int, int]] = field(default_factory=list)
    end: int | None = None
    byz: list[str] = field(default_factory=list)  # groups that vote on every side


@dataclass
class Fleet:
    roster: Roster
    groups: dict[str, np.ndarray]  # group -> mask

    @staticmethod
    def load(path: Path = SNAPSHOT) -> "Fleet":
        snap = json.loads(path.read_text())
        idx = [v["index"] for v in snap["validators"]]
        stake = [v["stake_sat"] for v in snap["validators"]]
        roster = Roster(idx, stake, set(snap["genesis_cohort"]))
        pos = {i: k for k, i in enumerate(idx)}
        groups = {}
        for g, members in snap["hosts"].items():
            m = np.zeros(len(idx), bool)
            for i in members:
                m[pos[i]] = True
            groups[g.split("-")[0]] = m
        cover = sum(m.astype(int) for m in groups.values())
        assert (cover == 1).all(), "every active validator in exactly one group"
        return Fleet(roster, groups)

    def mask(self, names: list[str]) -> np.ndarray:
        m = np.zeros(len(self.roster), bool)
        for g in names:
            m |= self.groups[g]
        return m

    def share(self, names: list[str], epoch: int) -> float:
        w = self.roster.at(epoch)
        return float(w[self.mask(names)].sum()) / float(w.sum())


class World:
    def __init__(self, fleet: Fleet, sc: Scenario, rules: Rules, gates: Gates = MAINNET):
        self.fleet, self.sc, self.rules, self.gates = fleet, sc, rules, gates
        self.n = len(fleet.roster)
        self.roots = Roots()
        g = sc.start - 1
        main = Branch("M", None, 0, np.ones(self.n, bool), Finality.new((g, self.roots.get("M", g)), self.n))
        self.branches = [main]
        self.dead: list[Branch] = []
        self.epoch = sc.start  # next epoch to run
        self.conflict: int | None = None
        self.foreign: int | None = None   # a branch finalized a root not on its own chain
        self.split = False
        self.healed_at: int | None = None
        self.offline_mask_cache: dict[int, np.ndarray] = {}
        self.byz = fleet.mask(sc.byz) if sc.byz else np.zeros(self.n, bool)

    def copy(self) -> "World":
        w = copy.copy(self)
        mp = {}
        for b in self.branches + self.dead:
            mp[id(b)] = Branch(b.label, None, b.fork_epoch, b.members.copy(), b.fs.copy(), b.first_new_fin, b.alive)
        for b in self.branches + self.dead:
            if b.parent is not None:
                mp[id(b)].parent = mp[id(b.parent)]
        w.branches = [mp[id(b)] for b in self.branches]
        w.dead = [mp[id(b)] for b in self.dead]
        r = Roots()
        r.ids, r.of = dict(self.roots.ids), list(self.roots.of)
        w.roots = r
        return w

    # ── topology
    def own_root(self, b: Branch, epoch: int) -> int:
        return self.roots.get(b.own_label(epoch), epoch)

    def on_chain(self, b: Branch, cp: tuple[int, int]) -> bool:
        return self.own_root(b, cp[0]) == cp[1]

    def minted_by(self, root: int) -> Branch:
        label = self.roots.of[root][0]
        for b in self.branches + self.dead:
            if b.label == label:
                return b
        raise KeyError(label)

    def conflicting(self, a: tuple[int, int], c: tuple[int, int]) -> bool:
        lo, hi = (a, c) if a[0] <= c[0] else (c, a)
        return not self.on_chain(self.minted_by(hi[1]), lo)

    def offline(self, epoch: int) -> np.ndarray:
        m = self.offline_mask_cache.get(epoch)
        if m is None:
            m = np.zeros(self.n, bool)
            for g, (lo, hi) in self.sc.offline.items():
                if lo <= epoch < hi:
                    m |= self.fleet.groups[g]
            self.offline_mask_cache[epoch] = m
        return m

    def partition(self) -> None:
        main = self.branches[0]
        out = []
        for k, side in enumerate(self.sc.sides):
            members = self.fleet.mask(side) | self.byz
            out.append(Branch(chr(ord("A") + k), main, self.sc.start, members, main.fs.copy()))
        main.alive = False
        self.dead.append(main)
        self.branches = out

    def heal_now(self) -> None:
        if self.conflict is not None:
            self.split = True  # finality latch: nobody reorgs below its own finality
            return
        online = ~self.offline(self.epoch)
        stake = self.fleet.roster.at(self.epoch)
        win = max(self.branches, key=lambda b: (b.fs.fin[0], b.fs.cj[0], int(stake[b.members & online].sum()),
                                               -ord(b.label[0])))
        for b in self.branches:
            if b is not win:
                win.members |= b.members
                b.alive = False
                self.dead.append(b)
        self.branches = [win]
        self.healed_at = self.epoch

    # ── one epoch
    def step(self) -> None:
        e = self.epoch
        if self.sc.sides is not None and e == self.sc.start:
            self.partition()
        if self.sc.heal is not None and e == self.sc.heal and len(self.branches) > 1 and self.healed_at is None:
            self.heal_now()
        off = self.offline(e)
        own = []
        for b in self.branches:
            v = Votes.empty(self.n)
            v.add(b.members & ~off, b.fs.cj[0], b.fs.cj[1], self.own_root(b, e))
            own.append(v)
        incl = [copy.deepcopy(v) for v in own] if self.sc.cross and len(self.branches) > 1 else own
        if len(self.branches) > 1:
            for i, j in self.sc.cross:
                incl[j].add_from(own[i], self.fleet.mask(self.sc.sides[i]) & ~self.byz)
        for b, v in zip(self.branches, incl):
            _, fin = b.fs.process_epoch(e, self.fleet.roster, v, self.gates, self.rules, self.own_root(b, e))
            if fin is not None and fin[0] >= self.sc.start and b.first_new_fin is None:
                b.first_new_fin = e
            if fin is not None and self.foreign is None and not self.on_chain(b, fin):
                self.foreign = e
        if self.conflict is None:
            fins = [b.fs.fin for b in self.branches + self.dead]
            for a, c in itertools.combinations(fins, 2):
                if self.conflicting(a, c):
                    self.conflict = e
                    break
        self.epoch += 1

    def run_to(self, end: int) -> None:
        while self.epoch < end:
            self.step()

    # ── metrics
    def metrics(self) -> dict:
        S = self.sc.start
        stake0 = self.fleet.roster.at(S)
        live = self.branches
        heavy = max(live, key=lambda b: int(stake0[b.members].sum()))

        def halt(b: Branch) -> int | None:
            return None if b.first_new_fin is None else b.first_new_fin - S - 1

        halts = [halt(b) for b in live]
        halt_all = None if any(h is None for h in halts) else max(halts)
        double_pay = self.conflict
        if self.foreign is not None and not self.rules.claim(self.foreign):
            double_pay = self.foreign if double_pay is None else min(double_pay, self.foreign)
        rel = lambda x: None if x is None else x - S  # noqa: E731
        return {
            "conflict": rel(self.conflict),
            "foreign": rel(self.foreign),
            "double_pay": rel(double_pay),
            "split": self.split or (len(live) > 1 and self.conflict is not None),
            "halt_major": halt(heavy),
            "halt_all": halt_all,
            "end": self.epoch - S,
        }


def run(fleet: Fleet, sc: Scenario, rules: Rules, gates: Gates = MAINNET) -> dict:
    end = sc.end if sc.end is not None else (sc.heal or sc.start) + 30
    w = World(fleet, sc, rules, gates)
    w.run_to(end)
    return w.metrics()


def run_heals(fleet: Fleet, sc: Scenario, rules: Rules, heals: list[int | None], post: int = 30,
              horizon: int | None = None, gates: Gates = MAINNET) -> dict:
    """One long run with no heal; at each heal epoch, a copy is healed and run
    `post` more epochs.  Equivalent to separate runs (the run with heal H equals
    the never-heal run up to H), at a fraction of the cost.  `None` = never."""
    horizon = horizon or max(h for h in heals if h is not None) + post
    w = World(fleet, sc, rules, gates)
    out = {}
    pending = sorted(h for h in heals if h is not None)
    while w.epoch < horizon:
        while pending and w.epoch == pending[0]:
            h = pending.pop(0)
            c = w.copy()
            c.sc = Scenario(sc.name, sc.sides, sc.start, h, dict(sc.offline), list(sc.cross), None, list(sc.byz))
            c.run_to(h + post)
            out[h] = c.metrics()
        w.step()
    if None in heals:
        out[None] = w.metrics()
    return out


# ── Sweeps ───────────────────────────────────────────────────────────────────

START = 6017  # first epoch after the snapshot (chain tip 6016)
DAYS = [0.25, 1, 3, 7, 14, 21, 30, 45, 60, 90]
HORIZON_DAYS = 120


def set_partitions(items: list[str], k: int):
    if k == 1:
        yield [list(items)]
        return
    if len(items) < k:
        return
    first, rest = items[0], items[1:]
    for p in set_partitions(rest, k - 1):
        yield [[first]] + p
    for p in set_partitions(rest, k):
        for i in range(len(p)):
            yield p[:i] + [[first] + p[i]] + p[i + 1:]


def jobs() -> list[dict]:
    fleet = Fleet.load()
    names = list(fleet.groups)
    out = []
    for k in (2, 3):
        for p in set_partitions(names, k):
            p = sorted((sorted(s) for s in p), key=lambda s: -fleet.share(s, START))
            out.append({"kind": f"split{k}", "sides": p, "cross": []})
            if k == 2:
                out.append({"kind": "split2+gossip", "sides": p, "cross": [(0, 1)]})  # heavy side's votes reach light side
                out.append({"kind": "split2+gossip2", "sides": p, "cross": [(0, 1), (1, 0)]})  # votes cross both ways
    for r in range(1, len(names)):
        for off in itertools.combinations(names, r):
            out.append({"kind": "offline", "offline": list(off)})
    return out


def resolve_variants(names: list[str] | None, hf_from: int | None) -> tuple[Rules, ...]:
    by = {v.name: v for v in VARIANTS}
    out = [by[n] for n in names] if names else list(VARIANTS)
    if hf_from is not None:
        out = [Rules(v.name, v.claim_fix, v.own_target, v.frozen_noleak, hf_from) for v in out]
    return tuple(out)


def run_job(job: dict) -> list[dict]:
    fleet = Fleet.load()
    days = job.get("days_list", DAYS)
    heals = [START + int(d * EPOCHS_PER_DAY) for d in days]
    horizon = START + job.get("horizon_days", HORIZON_DAYS) * EPOCHS_PER_DAY
    gates = Gates(**job.get("gates", {}))
    rows = []
    for rules in resolve_variants(job.get("variants"), job.get("hf_from")):
        if job["kind"] == "offline":
            # Offline until H, back from H: emulate with a single long run per H
            # (the snapshot trick needs the group back online at H).
            res = {}
            for d, h in zip(days + [None], heals + [None]):
                sc = Scenario("off", None, START, None, {g: (START, h if h else 1 << 62) for g in job["offline"]},
                              end=(h + 30) if h else horizon)
                res[h] = run(fleet, sc, rules, gates)
        else:
            sc = Scenario("split", job["sides"], START, None, cross=[tuple(c) for c in job["cross"]])
            res = run_heals(fleet, sc, rules, heals + [None], horizon=horizon, gates=gates)
        meta = {k: v for k, v in job.items() if k not in ("days_list", "horizon_days", "gates", "variants", "hf_from")}
        for d, h in zip(days + [None], heals + [None]):
            m = res[h]
            rows.append({**meta, "variant": rules.name, "days": d, **m,
                         "shares": [round(fleet.share(s, START), 4) for s in job.get("sides", [])]
                         if job["kind"] != "offline" else [round(fleet.share(job["offline"], START), 4)]})
    return rows


QUICK_DAYS = [3, 30]
QUICK_HORIZON_DAYS = 60


def sweep(n_jobs: int, out: Path, quick: bool = False, variants: list[str] | None = None,
          hf_from: int | None = None, gates: dict | None = None) -> None:
    from multiprocessing import Pool
    days = QUICK_DAYS if quick else DAYS
    horizon_days = QUICK_HORIZON_DAYS if quick else HORIZON_DAYS
    extra = {"days_list": days, "horizon_days": horizon_days, "gates": gates or {}, "variants": variants,
             "hf_from": hf_from}
    js = [{**j, **extra} for j in jobs()]
    with Pool(n_jobs) as pool:
        rows = [r for rs in pool.imap_unordered(run_job, js, chunksize=1) for r in rs]
    rows.sort(key=lambda r: (r["kind"], json.dumps(r.get("sides") or r.get("offline")), r["variant"],
                             r["days"] if r["days"] is not None else 1e9))
    out.write_text(json.dumps({"start": START, "days": days, "horizon_days": horizon_days,
                               "variants": [v.name for v in resolve_variants(variants, hf_from)],
                               "hf_from": hf_from, "gates": gates or {}, "rows": rows}, indent=0))
    print(f"wrote {len(rows)} rows to {out}")


def counts(path: Path) -> str:
    """One `HFV-MODEL` line per (class, variant): host groupings with
    conflicting finality / a double-paid claim, over every heal time."""
    data = json.loads(path.read_text())
    out = []
    for kind in ("split2", "split2+gossip", "split2+gossip2", "split3", "offline"):
        for v in data["variants"]:
            sub = [r for r in data["rows"] if r["kind"] == kind and r["variant"] == v]
            if not sub:
                continue
            c = sum(r["conflict"] is not None for r in sub)
            dp = sum(r["double_pay"] is not None for r in sub)
            fo = sum(r["foreign"] is not None for r in sub)
            out.append(f"HFV-MODEL class={kind} variant={v} runs={len(sub)} conflicting_finality={c} "
                       f"double_pay={dp} foreign_finality={fo}")
    return "\n".join(out)


def fmt_epochs(xs: list[int]) -> str:
    if not xs:
        return "-"
    xs = sorted(xs)
    return f"{xs[0]}/{xs[len(xs) // 2]}"


def table(path: Path) -> str:
    data = json.loads(path.read_text())
    rows = data["rows"]
    lines = []
    for kind in ("split2", "split2+gossip", "split2+gossip2", "split3", "offline"):
        sub = [r for r in rows if r["kind"] == kind]
        if not sub:
            continue
        n = len({json.dumps(r.get("sides") or r.get("offline")) for r in sub})
        lines.append(f"\n## {kind}  ({n} host groupings; heal after D days; never = {data['horizon_days']} d run)")
        lines.append("| variant | D (days) | P(conflicting finality) | epochs to conflict min/med | P(double pay) "
                     "| P(foreign fin) | halt heavy side med/max (ep) | P(halt heavy > D) |")
        lines.append("|---|---|---|---|---|---|---|---|")
        for v in data["variants"]:
            for d in data["days"] + [None]:
                rs = [r for r in sub if r["variant"] == v and r["days"] == d]
                if not rs:
                    continue
                c = [r["conflict"] for r in rs if r["conflict"] is not None]
                dp = sum(r["double_pay"] is not None for r in rs)
                fo = sum(r["foreign"] is not None for r in rs)
                hs = [r["halt_major"] for r in rs]
                span = r_end = rs[0]["end"]
                hv = sorted(h if h is not None else r_end for h in hs)
                long_halt = sum((h is None) or (d is not None and h > d * EPOCHS_PER_DAY) for h in hs)
                lines.append(f"| {v} | {'never' if d is None else d} | {len(c)}/{len(rs)} | {fmt_epochs(c)} "
                             f"| {dp}/{len(rs)} | {fo}/{len(rs)} | {hv[len(hv) // 2]}/{hv[-1]}"
                             f"{'+' if any(h is None for h in hs) else ''} | {long_halt}/{len(rs)} |")
                del span
    return "\n".join(lines)


def summary(path: Path) -> str:
    """One row per (scenario class, variant): share of host groupings with
    conflicting finality (and with a double-paid L2 claim) by partition length,
    epochs from partition start to the first conflict, and the heavy side's
    finality halt if the partition never heals."""
    data = json.loads(path.read_text())
    rows = data["rows"]
    cols = [3, 7, 14, 21, 30, 60, None]
    head = " | ".join("never" if d is None else f"{d}d" for d in cols)
    out = [f"| class | variant | conflicting finality, heal after: {head} | double pay, never | "
           "epochs to conflict min/med | halt heavy side, never: med/max epochs |",
           "|---|---|" + "---|" * (len(cols) + 3)]
    for kind in ("split2", "split2+gossip", "split2+gossip2", "split3", "offline"):
        for v in data["variants"]:
            sub = [r for r in rows if r["kind"] == kind and r["variant"] == v]
            if not sub:
                continue
            cells = []
            for d in cols:
                rs = [r for r in sub if r["days"] == d]
                cells.append(f"{sum(r['conflict'] is not None for r in rs)}/{len(rs)}")
            nv = [r for r in sub if r["days"] is None]
            dp = f"{sum(r['double_pay'] is not None for r in nv)}/{len(nv)}"
            c = [r["conflict"] for r in nv if r["conflict"] is not None]
            hv = sorted(r["halt_major"] if r["halt_major"] is not None else 10**9 for r in nv)
            show = lambda x: "inf" if x >= 10**9 else str(x)  # noqa: E731
            out.append(f"| {kind} | {v} | " + " | ".join(cells) + f" | {dp} | {fmt_epochs(c)} | "
                       f"{show(hv[len(hv) // 2])}/{show(hv[-1])} |")
    return "\n".join(out)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    sp = ap.add_subparsers(dest="cmd", required=True)
    s = sp.add_parser("sweep")
    s.add_argument("--jobs", type=int, default=8)
    s.add_argument("--out", type=Path, default=HERE / "results.json")
    s.add_argument("--quick", action="store_true", help=f"heal after {QUICK_DAYS} d or never ({QUICK_HORIZON_DAYS} d run)")
    s.add_argument("--variants", type=lambda x: x.split(","), default=None)
    s.add_argument("--hf-from", type=int, default=None, help="absolute epoch from which variant flags bind")
    s.add_argument("--gate", action="append", default=[], metavar="FIELD=EPOCH|none",
                   help="override a Gates field: eth_paced_from, floor_from, recovery_from")
    c = sp.add_parser("counts")
    c.add_argument("path", type=Path, nargs="?", default=HERE / "results.json")
    t = sp.add_parser("table")
    t.add_argument("path", type=Path, nargs="?", default=HERE / "results.json")
    u = sp.add_parser("summary")
    u.add_argument("path", type=Path, nargs="?", default=HERE / "results.json")
    a = ap.parse_args(argv)
    if a.cmd == "sweep":
        gates = {}
        for g in a.gate:
            k, v = g.split("=", 1)
            if k not in Gates.__dataclass_fields__:
                ap.error(f"unknown gate {k}")
            gates[k] = None if v == "none" else int(v)
        sweep(a.jobs, a.out, a.quick, a.variants, a.hf_from, gates)
    elif a.cmd == "counts":
        print(counts(a.path))
    elif a.cmd == "summary":
        print(summary(a.path))
    else:
        print(table(a.path))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
