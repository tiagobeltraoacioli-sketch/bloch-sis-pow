#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Verdict for scripts/devnet-fratura.sh.

Reads each node's persisted blocks.log — the node's own canonical chain, the
same artifact `Store::blocks_after` serves peers from — and reports, per node:
its height, its head, and the first slot at which the nodes stopped agreeing.

Reading the LOG rather than the RPC is the point: the RPC crosses the single
consensus thread, and whether observation perturbs the thing observed is one
of the questions this harness exists to answer.
"""
import hashlib, os, sys, collections

DS_BLOCK = b"BLCH4:BLOCK\0\0\0\0\0"
HDR = 304

def frames(path):
    out = []
    with open(path, "rb") as f:
        data = f.read()
    i = 0
    while i + 4 <= len(data):
        n = int.from_bytes(data[i:i+4], "little"); i += 4
        if i + n > len(data) or n < HDR:
            break
        p = data[i:i+n]; i += n
        h = p[:HDR]
        bid = hashlib.sha3_256(DS_BLOCK + h).digest()
        out.append(dict(
            slot=int.from_bytes(h[100:108], "little"),
            proposer=int.from_bytes(h[108:112], "little"),
            parent=h[4:36].hex()[:8],
            state_root=h[36:68].hex()[:8],
            bid=bid.hex()[:8],
            full=bid.hex(),
            parent_full=h[4:36].hex(),
        ))
    return out

def main(workdir):
    nodes = sorted(d for d in os.listdir(workdir) if d.startswith("node"))
    chains = {}
    for nd in nodes:
        p = os.path.join(workdir, nd, "blocks.log")
        chains[nd] = frames(p) if os.path.exists(p) else []

    print("node      height  head_slot  head_id   last_root  proposers(applied)")
    for nd in nodes:
        c = chains[nd]
        pc = collections.Counter(b["proposer"] for b in c)
        head = c[-1] if c else None
        print(f"{nd:9} {len(c):6}  {head['slot'] if head else '-':>9}  "
              f"{head['bid'] if head else '-':8}  {head['state_root'] if head else '-':9}  "
              f"{dict(sorted(pc.items()))}")

    # Is every node's log a prefix-compatible view of one chain?
    print()
    ref = nodes[0]
    for nd in nodes[1:]:
        a, b = chains[ref], chains[nd]
        n = min(len(a), len(b))
        div = next((i for i in range(n) if a[i]["full"] != b[i]["full"]), None)
        if div is None:
            print(f"{ref} vs {nd}: AGREE over {n} common blocks (one is a prefix of the other)")
        else:
            print(f"{ref} vs {nd}: DIVERGE at block index {div} — "
                  f"{ref} slot {a[div]['slot']} id {a[div]['bid']} (prop v{a[div]['proposer']}), "
                  f"{nd} slot {b[div]['slot']} id {b[div]['bid']} (prop v{b[div]['proposer']}); "
                  f"common ancestor slot {a[div-1]['slot'] if div else 0}")

    # Per-slot cross-check: which slots does each node hold, and do the ids match?
    bysl = {nd: {b["slot"]: b["full"] for b in chains[nd]} for nd in nodes}
    allsl = sorted(set().union(*[set(v) for v in bysl.values()])) if bysl else []
    conflicts = [s for s in allsl if len({bysl[nd][s] for nd in nodes if s in bysl[nd]}) > 1]
    missing = {nd: [s for s in allsl if s not in bysl[nd]] for nd in nodes}
    print()
    print(f"slots held by at least one node: {len(allsl)} (max slot {allsl[-1] if allsl else '-'})")
    print(f"slots where two nodes hold DIFFERENT blocks: {len(conflicts)}"
          + (f" — first at slot {conflicts[0]}" if conflicts else ""))
    for nd in nodes:
        m = missing[nd]
        print(f"  {nd}: missing {len(m)} of those slots"
              + (f", first {m[0]}, last {m[-1]}" if m else ""))

    # Log-side signals.
    print()
    for nd in nodes:
        logs = [f for f in os.listdir(os.path.join(workdir, nd)) if f.endswith(".log")]
        txt = "".join(open(os.path.join(workdir, nd, f), errors="replace").read() for f in logs)
        def c(s): return txt.count(s)
        print(f"  {nd}: applied={c('] applied ')} REORG={c('REORG:')} "
              f"reject={c('reject ')} refused-own={c('REFUSED OWN BLOCK')} "
              f"justified={c('*** JUSTIFIED')} finalized={c('*** FINALIZED')} "
              f"att-rejected={c('attestation from v')}")

if __name__ == "__main__":
    main(sys.argv[1])
