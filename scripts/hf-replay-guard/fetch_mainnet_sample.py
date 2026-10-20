#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Fetch a read-only sample of finalized mainnet block headers over public RPC.

Writes one JSON object per line (ascending slot) with exactly the twelve
BlockHeaderV4 fields plus the block id the network reports. The replay guard
re-encodes each header with the code under test and checks the id, so a
branch that changes header encoding, id hashing or version handling at any
sampled slot is caught. Nothing is written to the network: getblockbyslot and
getchaininfo only.

usage: fetch_mainnet_sample.py <out.jsonl> [--rpc URL] [--recent N] [--boundary SLOT]
"""
import argparse
import concurrent.futures as cf
import json
import sys
import time
import urllib.request

FIELDS = ("block_id", "version", "parent", "state_root", "body_root", "slot",
          "proposer_index", "randao_reveal", "randao_mix", "justified_root",
          "finalized_root", "attestation_root", "coherence_root")


def call(rpc, method, params, tries=6):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    delay = 1.0
    for attempt in range(tries):
        try:
            req = urllib.request.Request(rpc, data=body, headers={
                "content-type": "application/json", "user-agent": "bloch-hf-replay-guard/1"})
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.loads(r.read())
        except Exception as exc:  # network hiccup: back off and retry
            if attempt == tries - 1:
                raise RuntimeError(f"{method}{params}: {exc}")
            time.sleep(delay)
            delay *= 2


def fetch(rpc, slot):
    resp = call(rpc, "getblockbyslot", [slot])
    res = resp.get("result")
    if not res or res.get("slot") != slot:
        return None  # empty slot
    if res.get("finalized") is not True:
        return None
    return {k: res[k] for k in FIELDS}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--rpc", default="https://blochl1.com/g4rpc")
    ap.add_argument("--recent", type=int, default=2600, help="recent finalized slots to scan")
    ap.add_argument("--boundary", type=int, default=187200, help="boundary slot to cover")
    ap.add_argument("--boundary-span", type=int, default=160)
    ap.add_argument("--workers", type=int, default=6)
    a = ap.parse_args()

    info = call(a.rpc, "getchaininfo", [])["result"]
    fin_epoch = info["finalized"]["epoch"]
    spe = info["slots_per_epoch"]
    top = fin_epoch * spe  # first slot of the finalized epoch: everything below is final
    slots = set(range(a.boundary - a.boundary_span, a.boundary + a.boundary_span + 1))
    slots |= set(range(top - a.recent, top))
    slots = sorted(slots)
    print(f"finalized epoch {fin_epoch}; scanning {len(slots)} slots "
          f"({slots[0]}..{slots[-1]}) from {a.rpc}", file=sys.stderr)
    out = []
    with cf.ThreadPoolExecutor(a.workers) as ex:
        for blk in ex.map(lambda s: fetch(a.rpc, s), slots):
            if blk:
                out.append(blk)
    out.sort(key=lambda b: b["slot"])
    with open(a.out, "w") as f:
        for b in out:
            f.write(json.dumps(b, sort_keys=True) + "\n")
    have = {b["slot"] for b in out}
    print(f"wrote {len(out)} finalized blocks; boundary slot {a.boundary} "
          f"{'PRESENT' if a.boundary in have else 'ABSENT'}", file=sys.stderr)
    if a.boundary not in have:
        sys.exit(3)


if __name__ == "__main__":
    main()
