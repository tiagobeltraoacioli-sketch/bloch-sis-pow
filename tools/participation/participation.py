#!/usr/bin/env python3
"""Read-only participation report for the owner's Genesis-4 validators.

What it measures, per own validator, over the last N complete epochs:

* attestation duties (one per epoch: the committee the epoch partition seats
  the validator in) versus attestations actually included on the canonical
  chain, with inclusion distance (inclusion slot - attested slot);
* block proposals: produced, versus expected (slots x stake share);
* breakdowns by slot-in-epoch and by host;
* issuance forfeited by missed attestation credit, in BLCH/day.

Data sources (all read-only, nothing is signed or submitted):

* JSON-RPC (``getchaininfo``, ``getblockbyslot``, ``getvalidators``,
  ``getvalidator``) for the canonical header of every slot and the registry.
  The RPC does not expose block bodies, so
* attestation identities come from a **copy of a node's blocks.log tail**
  (``--block-log``; frame = u32 LE length || envelope, codec.rs). Every block
  taken from it must match the RPC's canonical ``block_id`` for its slot, so a
  stale or forked log cannot leak in silently. Fetch it read-only, e.g.

      ssh ubuntu@HOST 'tail -c 170000000 /home/ubuntu/g4/n00/blocks.log' > tail.bin

Consensus rules mirrored here (bloch-pos-committee, release in force):

* committee partition: ``committees::epoch_committees`` (SHAKE256 Fisher-Yates
  over the sorted active index set, role 0x03), seeded by the boundary mix at
  the close of epoch E-1 (``seed_for_epoch``; the ancestry-seed gate is not
  active, so look-ahead is 0);
* proposer: ``schedule::proposer`` is a stake-weighted draw ``v mod total``
  over the leak-adjusted roster of that epoch. Any change in total stake
  reshuffles every draw, and per-epoch historical stakes are not queryable,
  so the scheduled proposer of a past EMPTY slot cannot be recomputed. The
  report instead gives expected proposals (slots x current stake share)
  against produced; a large positive deficit is a missing proposer;
* credit: an attestation counts for epoch E only if it is included in a
  canonical block of epoch E (transition step 8 rejects any other epoch);
  rewards v1 pays ``epoch_issuance * stake / total_stake`` per credited epoch
  (``rewards::distribute`` with max_credits 1).
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import glob
import hashlib
import json
import os
import struct
import sys
import time
import urllib.request
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

# ── consensus constants (bloch-pos-committee/src/params.rs, tokenomics_v4.rs) ──
SLOTS_PER_EPOCH = 32
SLOT_SECS = 30
SLOTS_PER_DAY = 86400 // SLOT_SECS
DS_SORTITION = b"BLCH4:SORTIT\x00\x00\x00\x00"
DS_BLOCK = b"BLCH4:BLOCK\x00\x00\x00\x00\x00"
ROLE_PARTITION = 0x03
U128_MAX = (1 << 128) - 1
VERSION_G4 = 0xB10C0005
HEADER_LEN = 304
SAT_PER_BLCH = 100_000_000
INITIAL_ANNUAL_SAT = 434_965_169_252_191_762
SLOTS_PER_YEAR = 1_051_920
EMISSION_YEARS = 40


def epoch_of(slot: int) -> int:
    return slot // SLOTS_PER_EPOCH


# ── XOF / sortition ─────────────────────────────────────────────────────────
class Xof:
    """Sequential reader over SHAKE256(prefix) — sha3's ``XofReader``."""

    def __init__(self, prefix: bytes):
        self._prefix = prefix
        self._buf = b""
        self._pos = 0

    def read(self, n: int) -> bytes:
        need = self._pos + n
        if need > len(self._buf):
            size = max(need, 2 * len(self._buf), 1024)
            self._buf = hashlib.shake_256(self._prefix).digest(size)
        out = self._buf[self._pos:need]
        self._pos = need
        return out

    def u128(self) -> int:
        return int.from_bytes(self.read(16), "little")


def epoch_committees(mix: bytes, epoch: int, indices: Iterable[int]) -> List[List[int]]:
    """``committees::epoch_committees_uncached`` — membership by index set only."""
    eligible = sorted(set(indices))
    if not eligible:
        return [[] for _ in range(SLOTS_PER_EPOCH)]
    xof = Xof(DS_SORTITION + mix + struct.pack("<Q", epoch) + bytes([ROLE_PARTITION]))
    n = len(eligible)
    for i in range(n - 1, 0, -1):
        bound = i + 1
        limit = (U128_MAX // bound) * bound
        while True:
            v = xof.u128()
            if v < limit:
                j = v % bound
                break
        eligible[i], eligible[j] = eligible[j], eligible[i]
    base, extra = divmod(n, SLOTS_PER_EPOCH)
    out, pos = [], 0
    for s in range(SLOTS_PER_EPOCH):
        take = base + (1 if s < extra else 0)
        out.append(sorted(eligible[pos:pos + take]))
        pos += take
    return out


def slot_issuance_sat(slot: int) -> int:
    """``tokenomics_v4::validator_reward_decay_sat``."""
    if slot >= EMISSION_YEARS * SLOTS_PER_YEAR:
        return 0
    annual = INITIAL_ANNUAL_SAT
    for _ in range(slot // SLOTS_PER_YEAR):
        annual = annual * 9 // 10
    return annual // SLOTS_PER_YEAR


def epoch_issuance_sat(epoch: int) -> int:
    first = epoch * SLOTS_PER_EPOCH
    return sum(slot_issuance_sat(s) for s in range(first, first + SLOTS_PER_EPOCH))


# ── block log decoding (bloch-pos-node/src/codec.rs) ────────────────────────
@dataclass
class Att:
    slot: int
    target_epoch: int
    validator: int


@dataclass
class Block:
    block_id: str
    slot: int
    proposer: int
    randao_mix: bytes
    atts: List[Att] = field(default_factory=list)


class DecodeError(Exception):
    pass


def _u32(buf: bytes, o: int) -> int:
    if o + 4 > len(buf):
        raise DecodeError("short u32")
    return struct.unpack_from("<I", buf, o)[0]


def decode_envelope(buf: bytes) -> Block:
    if len(buf) < HEADER_LEN:
        raise DecodeError("short header")
    hdr = buf[:HEADER_LEN]
    if struct.unpack_from("<I", hdr, 0)[0] != VERSION_G4:
        raise DecodeError("bad version")
    slot = struct.unpack_from("<Q", hdr, 100)[0]
    prop = struct.unpack_from("<I", hdr, 108)[0]
    mix = hdr[144:176]
    bid = hashlib.sha3_256(DS_BLOCK + hdr).hexdigest()
    o = HEADER_LEN
    o += 4 + _u32(buf, o)  # proposer_sig
    natt = _u32(buf, o)
    o += 4
    if natt > 4096:
        raise DecodeError("too many attestations")
    atts = []
    for _ in range(natt):
        if o + 124 > len(buf):
            raise DecodeError("short attestation")
        a_slot = struct.unpack_from("<Q", buf, o)[0]
        tgt = struct.unpack_from("<Q", buf, o + 80)[0]
        val = struct.unpack_from("<I", buf, o + 120)[0]
        o += 124
        o += 4 + _u32(buf, o)  # signature
        atts.append(Att(a_slot, tgt, val))
    ntx = _u32(buf, o)
    o += 4
    if ntx > 65536:
        raise DecodeError("too many transactions")
    for _ in range(ntx):
        o += 4 + _u32(buf, o)
    if o != len(buf):
        raise DecodeError("trailing bytes")
    return Block(bid, slot, prop, mix, atts)


def _frame_at(data: bytes, off: int) -> Optional[Tuple[Block, int]]:
    if off + 8 > len(data):
        return None
    n = struct.unpack_from("<I", data, off)[0]
    if n < HEADER_LEN or off + 4 + n > len(data):
        return None
    try:
        return decode_envelope(data[off + 4: off + 4 + n]), off + 4 + n
    except DecodeError:
        return None


def parse_log_tail(data: bytes) -> List[Block]:
    """Decode every whole frame of a blocks.log tail that may start mid-frame.

    Resynchronises on the first offset whose frame decodes exactly AND is
    followed by another decodable frame (or the end), then walks frames.
    A truncated trailing frame is dropped, as the node's own replay does.
    """
    magic = struct.pack("<I", VERSION_G4)
    start = None
    pos = 0
    while True:
        hit = data.find(magic, pos + 4)
        if hit < 0:
            return []
        off = hit - 4
        first = _frame_at(data, off)
        if first is not None:
            nxt = first[1]
            if nxt + 8 > len(data) or _frame_at(data, nxt) is not None:
                start = off
                break
        pos = hit - 3
    blocks, off = [], start
    while True:
        got = _frame_at(data, off)
        if got is None:
            break
        blocks.append(got[0])
        off = got[1]
    return blocks


# ── RPC ─────────────────────────────────────────────────────────────────────
class Rpc:
    def __init__(self, url: str, timeout: float = 30.0, retries: int = 4):
        self.url, self.timeout, self.retries = url, timeout, retries

    def call(self, method: str, params: Sequence = ()) -> dict:
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": list(params)}).encode()
        last = None
        for attempt in range(self.retries):
            try:
                req = urllib.request.Request(
                    self.url, body,
                    {"content-type": "application/json", "user-agent": "bloch-participation/1"})
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    return json.loads(r.read())
            except Exception as e:  # network hiccup: back off and retry
                last = e
                time.sleep(0.5 * (attempt + 1))
        raise RuntimeError(f"{self.url} {method}{list(params)}: {last}")

    def result(self, method: str, params: Sequence = ()):
        r = self.call(method, params)
        if "error" in r:
            raise RuntimeError(f"{method}: {r['error']}")
        return r["result"]


def fetch_headers(rpc: Rpc, slots: Sequence[int], workers: int = 16) -> Dict[int, Optional[dict]]:
    """slot -> canonical header json, or None for an empty (missed) slot."""

    def one(s):
        r = rpc.call("getblockbyslot", [s])
        if "result" in r:
            return s, r["result"]
        msg = r.get("error", {}).get("message", "")
        if "no canonical block" in msg:
            return s, None
        raise RuntimeError(f"getblockbyslot {s}: {r.get('error')}")

    out = {}
    with cf.ThreadPoolExecutor(workers) as ex:
        for s, h in ex.map(one, slots):
            out[s] = h
    return out


# ── host map (remote-scan TSVs) ─────────────────────────────────────────────
def unit_index(unit: str) -> Optional[int]:
    if unit == "bloch-funded-64":
        return 64
    if unit.startswith("bloch-n") and unit[7:].isdigit() and len(unit) == 9:
        return int(unit[7:])
    return None


def host_map(tsv_paths: Iterable[str]) -> Dict[int, str]:
    running: Dict[int, List[str]] = defaultdict(list)
    stopped: Dict[int, List[str]] = defaultdict(list)
    for p in tsv_paths:
        with open(p) as f:
            for line in f:
                c = line.rstrip("\n").split("\t")
                if len(c) < 6 or c[0] != "UNIT":
                    continue
                idx = unit_index(c[2])
                if idx is None:
                    continue
                (running if c[5] == "active/running" else stopped)[idx].append(c[1])
    out = {}
    for idx in set(running) | set(stopped):
        if running.get(idx):
            out[idx] = "+".join(sorted(set(running[idx])))
        elif any(s for s in stopped.get(idx, [])):
            out[idx] = "stopped"
    return out


# ── analysis ────────────────────────────────────────────────────────────────
@dataclass
class ValidatorInfo:
    index: int
    stake: int
    activation: int
    exit: Optional[int]
    slashed: bool


def active_at(v: ValidatorInfo, epoch: int) -> bool:
    return v.activation <= epoch and (v.exit is None or epoch < v.exit) and not v.slashed


def boundary_mixes(blocks_by_slot: Dict[int, Block], epochs: Iterable[int]) -> Dict[int, bytes]:
    """Mix at the close of each epoch = mix of its last canonical block."""
    out, last = {}, None
    for s in sorted(blocks_by_slot):
        e = epoch_of(s)
        out[e] = blocks_by_slot[s].randao_mix
    for e in sorted(epochs):
        if e in out:
            last = out[e]
        elif last is not None:
            out[e] = last
    return out


def analyse(
    epochs: Sequence[int],
    canonical: Dict[int, Optional[str]],
    blocks: Dict[int, Block],
    validators: Dict[int, ValidatorInfo],
    own: Sequence[int],
    hosts: Dict[int, str],
) -> dict:
    """Pure core: duties vs inclusions, proposals, rewards. See module doc."""
    own_set = set(own)
    stakes = {i: v.stake for i, v in validators.items() if v.stake > 0 and not v.slashed}
    total_stake = sum(stakes.values())
    mixes = boundary_mixes(blocks, [e - 1 for e in epochs] + list(epochs))

    per = {i: defaultdict(int) for i in own}
    dist = {i: [] for i in own}
    by_sie = {k: defaultdict(int) for k in range(SLOTS_PER_EPOCH)}
    check = defaultdict(int)
    lost_sat = defaultdict(int)

    for e in epochs:
        seed = mixes.get(e - 1)
        if seed is None:
            check["epochs_without_seed"] += 1
            continue
        act = [i for i, v in validators.items() if active_at(v, e)]
        comm = epoch_committees(seed, e, act)
        seat = {i: k for k, c in enumerate(comm) for i in c}
        first = e * SLOTS_PER_EPOCH
        # inclusions in canonical blocks of THIS epoch (the only ones credited)
        included: Dict[int, Tuple[int, int]] = {}
        for s in range(first, first + SLOTS_PER_EPOCH):
            b = blocks.get(s)
            if canonical.get(s) is None:
                continue
            if b is None:
                check["canonical_blocks_without_body"] += 1
                continue
            for a in b.atts:
                if epoch_of(a.slot) != e:
                    check["atts_wrong_epoch"] += 1
                    continue
                check["atts_seen"] += 1
                if seat.get(a.validator) == a.slot % SLOTS_PER_EPOCH:
                    check["atts_in_computed_committee"] += 1
                d = s - a.slot
                if a.validator not in included or d < included[a.validator][1]:
                    included[a.validator] = (a.slot, d)
        issuance = epoch_issuance_sat(e)
        for i in own:
            if i not in seat:
                continue
            k = seat[i]
            per[i]["duties"] += 1
            by_sie[k]["duties"] += 1
            if i in included:
                per[i]["included"] += 1
                by_sie[k]["included"] += 1
                dist[i].append(included[i][1])
                by_sie[k]["dist_sum"] += included[i][1]
            else:
                per[i]["missed"] += 1
                by_sie[k]["missed"] += 1
                if total_stake:
                    lost_sat[i] += issuance * stakes.get(i, 0) // total_stake
        # proposals: who produced, and which slots stayed empty
        for s in range(first, first + SLOTS_PER_EPOCH):
            if canonical.get(s) is None:
                check["empty_slots"] += 1
                by_sie[s % SLOTS_PER_EPOCH]["empty_slots"] += 1
                continue
            check["filled_slots"] += 1
            b = blocks.get(s)
            if b is not None and b.proposer in own_set:
                per[b.proposer]["proposed"] += 1

    n_epochs = len(epochs)
    n_slots = n_epochs * SLOTS_PER_EPOCH
    days = n_epochs * SLOTS_PER_EPOCH / SLOTS_PER_DAY
    rows = []
    for i in own:
        p = per[i]
        d = dist[i]
        rows.append({
            "validator": i,
            "name": "funded-64" if i == 64 else f"n{i:02d}",
            "host": hosts.get(i, "?"),
            "stake_blch": stakes.get(i, 0) / SAT_PER_BLCH,
            "duties": p["duties"],
            "included": p["included"],
            "missed": p["missed"],
            "rate": p["included"] / p["duties"] if p["duties"] else None,
            "dist_mean": sum(d) / len(d) if d else None,
            "dist_max": max(d) if d else None,
            "proposed": p["proposed"],
            # Expected = slots x stake share (the draw is stake-weighted);
            # positive deficit = proposals this validator most likely missed.
            "proposals_expected": n_slots * stakes.get(i, 0) / total_stake if total_stake else 0.0,
            "proposal_deficit": (n_slots * stakes.get(i, 0) / total_stake if total_stake else 0.0) - p["proposed"],
            "lost_blch_per_day": lost_sat[i] / SAT_PER_BLCH / days if days else 0.0,
        })
    hosts_agg: Dict[str, dict] = defaultdict(lambda: defaultdict(float))
    for r in rows:
        h = hosts_agg[r["host"]]
        h["validators"] += 1
        for k in ("duties", "included", "missed", "proposed", "proposals_expected", "lost_blch_per_day"):
            h[k] += r[k]
    sie = []
    for k in range(SLOTS_PER_EPOCH):
        b = by_sie[k]
        sie.append({
            "slot_in_epoch": k,
            "duties": b["duties"],
            "included": b["included"],
            "missed": b["missed"],
            "rate": b["included"] / b["duties"] if b["duties"] else None,
            "dist_mean": b["dist_sum"] / b["included"] if b["included"] else None,
            "empty_slots_all": b["empty_slots"],
        })
    tot = {k: sum(r[k] for r in rows) for k in ("duties", "included", "missed", "proposed", "proposals_expected", "lost_blch_per_day")}
    tot["rate"] = tot["included"] / tot["duties"] if tot["duties"] else None
    return {
        "epochs": [epochs[0], epochs[-1]] if epochs else [],
        "days": days,
        "epoch_issuance_blch": epoch_issuance_sat(epochs[-1]) / SAT_PER_BLCH if epochs else 0,
        "checks": dict(check),
        "totals": tot,
        "validators": rows,
        "hosts": {h: dict(v) for h, v in sorted(hosts_agg.items())},
        "slot_in_epoch": sie,
    }


# ── CLI ─────────────────────────────────────────────────────────────────────
def parse_range(spec: str) -> List[int]:
    out = []
    for part in spec.split(","):
        if "-" in part:
            a, b = part.split("-")
            out.extend(range(int(a), int(b) + 1))
        elif part:
            out.append(int(part))
    return out


def load_validators(rpc: Rpc, workers: int = 16) -> Dict[int, ValidatorInfo]:
    lst = rpc.result("getvalidators")
    idxs = [v["index"] for v in lst]
    with cf.ThreadPoolExecutor(workers) as ex:
        details = list(ex.map(lambda i: rpc.result("getvalidator", [i]), idxs))
    out = {}
    for v, d in zip(lst, details):
        eff = v.get("effective_stake_sat")
        out[v["index"]] = ValidatorInfo(
            index=v["index"],
            stake=int(eff) if eff is not None else 0,
            activation=d["activation_epoch"] if d.get("activation_epoch") is not None else 1 << 62,
            exit=d.get("exit_epoch"),
            slashed=bool(d.get("slashed")),
        )
    return out


def corroborate(urls: Sequence[str], sample_slots: Sequence[int]) -> dict:
    res = {}
    base = None
    for u in urls:
        try:
            h = fetch_headers(Rpc(u, timeout=20, retries=2), sample_slots, workers=8)
            ids = {s: (x or {}).get("block_id") for s, x in h.items()}
        except Exception as e:  # report, do not fail the whole run
            res[u] = f"unreachable: {e}"
            continue
        if base is None:
            base = ids
            res[u] = "reference"
        else:
            agree = sum(1 for s in sample_slots if ids.get(s) == base.get(s))
            res[u] = f"{agree}/{len(sample_slots)} slots agree"
    return res


def render(rep: dict) -> str:
    L = []
    t = rep["totals"]
    L.append(f"epochs {rep['epochs'][0]}..{rep['epochs'][1]} ({rep['days']:.2f} days), "
             f"epoch issuance {rep['epoch_issuance_blch']:,.0f} BLCH")
    L.append("checks: " + ", ".join(f"{k}={v}" for k, v in sorted(rep["checks"].items())))
    L.append(f"own: duties {t['duties']} included {t['included']} missed {t['missed']} "
             f"rate {100 * (t['rate'] or 0):.2f}%  proposed {t['proposed']} "
             f"expected {t['proposals_expected']:.0f}  lost {t['lost_blch_per_day']:,.0f} BLCH/day")
    L.append("")
    L.append(f"{'val':>9} {'host':>16} {'stake':>12} {'duty':>5} {'incl':>5} {'miss':>5} {'rate%':>6} "
             f"{'dist':>5} {'dmax':>4} {'prop':>4} {'pexp':>6} {'lost/day':>10}")
    for r in rep["validators"]:
        L.append(f"{r['name']:>9} {r['host']:>16} {r['stake_blch']:>12,.0f} {r['duties']:>5} {r['included']:>5} "
                 f"{r['missed']:>5} {100 * (r['rate'] or 0):>6.1f} "
                 f"{(r['dist_mean'] or 0):>5.2f} {(r['dist_max'] or 0):>4} {r['proposed']:>4} "
                 f"{r['proposals_expected']:>6.1f} {r['lost_blch_per_day']:>10,.0f}")
    L.append("")
    L.append(f"{'host':>16} {'vals':>4} {'duty':>6} {'miss':>5} {'rate%':>6} {'prop':>5} {'pexp':>6} {'lost/day':>10}")
    for h, a in rep["hosts"].items():
        rate = a["included"] / a["duties"] if a["duties"] else 0
        L.append(f"{h:>16} {int(a['validators']):>4} {int(a['duties']):>6} {int(a['missed']):>5} "
                 f"{100 * rate:>6.1f} {int(a['proposed']):>5} {a['proposals_expected']:>6.0f} {a['lost_blch_per_day']:>10,.0f}")
    L.append("")
    L.append(f"{'sie':>3} {'duty':>5} {'miss':>5} {'rate%':>6} {'dist':>5} {'empty':>5}")
    for r in rep["slot_in_epoch"]:
        L.append(f"{r['slot_in_epoch']:>3} {r['duties']:>5} {r['missed']:>5} {100 * (r['rate'] or 0):>6.1f} "
                 f"{(r['dist_mean'] or 0):>5.2f} {r['empty_slots_all']:>5}")
    return "\n".join(L)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--rpc", default="http://127.0.0.1:8080")
    ap.add_argument("--witness", action="append", default=[],
                    help="extra RPC URLs to cross-check canonical block ids on a slot sample")
    ap.add_argument("--block-log", required=True, help="local copy of a blocks.log tail")
    ap.add_argument("--epochs", type=int, default=200)
    ap.add_argument("--own", default="0-64")
    ap.add_argument("--scan-dir", help="directory of remote-scan TSVs (host map)")
    ap.add_argument("--json", help="write the full report as JSON here")
    ap.add_argument("--workers", type=int, default=16)
    a = ap.parse_args(argv)

    rpc = Rpc(a.rpc)
    info = rpc.result("getchaininfo")
    head_epoch = info["epoch"]
    with open(a.block_log, "rb") as f:
        blocks_list = parse_log_tail(f.read())
    if not blocks_list:
        print("block log: no decodable frame", file=sys.stderr)
        return 2
    log_lo, log_hi = blocks_list[0].slot, blocks_list[-1].slot
    last = min(head_epoch - 1, epoch_of(log_hi + 1) - 1)  # complete epochs only
    first = max(last - a.epochs + 1, epoch_of(log_lo) + 2)
    epochs = list(range(first, last + 1))
    slots = list(range((first - 1) * SLOTS_PER_EPOCH, (last + 1) * SLOTS_PER_EPOCH))
    print(f"head epoch {head_epoch}; log slots {log_lo}..{log_hi}; window epochs {first}..{last}",
          file=sys.stderr)

    headers = fetch_headers(rpc, slots, a.workers)
    canonical = {s: (h["block_id"] if h else None) for s, h in headers.items()}
    by_slot = {b.slot: b for b in blocks_list}
    blocks, mismatched = {}, 0
    for s, bid in canonical.items():
        b = by_slot.get(s)
        if bid is None or b is None:
            continue
        if b.block_id == bid:
            blocks[s] = b
        else:
            mismatched += 1
    validators = load_validators(rpc, a.workers)
    hosts = host_map(sorted(glob.glob(os.path.join(a.scan_dir, "*.tsv")))) if a.scan_dir else {}
    rep = analyse(epochs, canonical, blocks, validators, parse_range(a.own), hosts)
    rep["checks"]["log_blocks_not_canonical"] = mismatched
    if a.witness:
        sample_slots = slots[:: max(1, len(slots) // 64)]
        rep["corroboration"] = corroborate([a.rpc] + a.witness, sample_slots)
    print(render(rep))
    if "corroboration" in rep:
        print("\ncorroboration: " + json.dumps(rep["corroboration"]))
    if a.json:
        with open(a.json, "w") as f:
            json.dump(rep, f, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
