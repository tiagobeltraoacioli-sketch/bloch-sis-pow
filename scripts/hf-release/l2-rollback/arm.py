#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Arm the L2 program rollback for an EMERGENCY release. Deterministic: the same
inputs on the same tree always give the same diff. Writes nothing but the four
source files below and the manifest; it never builds, signs or publishes.

  params.rs        L2_PROGRAM_ROLLBACK_EPOCH = R   (and L2_NEXT_PROGRAM_EPOCH = S,
                   which must equal what the shipped swap release has, or be
                   u64::MAX in a candidate tree that is armed for a rehearsal)
  l2_settlement.rs ROLLBACK_HEAD_RESET = Some(..) only with --head-reset;
                   PROGRAM_NEXT_FINAL must already be true (or --candidate-pins,
                   which is for qualification builds and refuses --release)
  hard_forks.rs    both L2 gates join RELEASE_ARMABLE

usage:
  arm.py --tree DIR --swap-epoch S --rollback-epoch R --publish-epoch P
         [--head-reset reset.json] [--min-lead 270] [--candidate-pins] [--manifest out.json]

reset.json: {"number": N, "commitment": "<64 hex>", "statement": "<hex>" | null}
(number 0 = L2 genesis: commitment all zero, statement null).
"""
import argparse, hashlib, json, re, sys
from pathlib import Path

P = 'crates/bloch-pos-committee/src/params.rs'
L = 'crates/bloch-pos-committee/src/l2_settlement.rs'
H = 'crates/bloch-pos-committee/src/hard_forks.rs'
MAX = 'u64::MAX'
KES_ENFORCE_MIN = 8620 + 90  # hard_forks::l2_program_schedule_coherent


def die(msg):
    sys.exit(f'arm.py: REFUSED: {msg}')


def one(text, pattern, what):
    m = list(re.finditer(pattern, text, re.M))
    if len(m) != 1:
        die(f'{what}: expected exactly one match, found {len(m)}')
    return m[0]


def main():
    a = argparse.ArgumentParser()
    a.add_argument('--tree', required=True, type=Path)
    a.add_argument('--swap-epoch', required=True, type=int)
    a.add_argument('--rollback-epoch', required=True, type=int)
    a.add_argument('--publish-epoch', required=True, type=int, help='current mainnet epoch when the release is published')
    a.add_argument('--min-lead', type=int, default=270, help='epochs from publication to the rollback gate (3 days)')
    a.add_argument('--head-reset', type=Path)
    a.add_argument('--candidate-pins', action='store_true', help='QUALIFICATION ONLY: allow PROGRAM_NEXT_FINAL=false (the build will then refuse to compile outside rehearsal features)')
    a.add_argument('--manifest', type=Path)
    o = a.parse_args()
    S, R = o.swap_epoch, o.rollback_epoch
    if not (S > KES_ENFORCE_MIN):
        die(f'swap epoch {S} must be > {KES_ENFORCE_MIN}')
    if not (R > S):
        die(f'rollback epoch {R} must be after the swap epoch {S}')
    lead = R - o.publish_epoch
    if lead < o.min_lead:
        die(f'lead {lead} epochs < minimum {o.min_lead}: a shorter lead risks a split (pass a lower --min-lead only on an owner decision)')

    p, l, h = (o.tree / x for x in (P, L, H))
    pt, lt, ht = p.read_text(), l.read_text(), h.read_text()

    m = one(pt, r'^pub const L2_NEXT_PROGRAM_EPOCH: u64 = ([0-9_]+|u64::MAX);$', 'L2_NEXT_PROGRAM_EPOCH')
    cur = m.group(1).replace('_', '')
    if cur not in (MAX, str(S)):
        die(f'tree swap epoch is {cur}, not {S}: build on the shipped swap release')
    if cur == MAX and not o.candidate_pins:
        die('tree has no armed swap: an emergency release builds on the shipped swap release (or pass --candidate-pins for a rehearsal)')
    pt = pt[:m.start(1)] + str(S) + pt[m.end(1):]
    m = one(pt, r'^pub const L2_PROGRAM_ROLLBACK_EPOCH: u64 = (u64::MAX);$', 'L2_PROGRAM_ROLLBACK_EPOCH (must be inert before arming)')
    pt = pt[:m.start(1)] + str(R) + pt[m.end(1):]

    m = one(lt, r'^    pub const PROGRAM_NEXT_FINAL: bool = (true|false);$', 'PROGRAM_NEXT_FINAL')
    final = m.group(1) == 'true'
    if not final and not o.candidate_pins:
        die('PROGRAM_NEXT_FINAL is false: the tree carries candidate pins')
    m = one(lt, r'^    pub const ROLLBACK_HEAD_RESET: Option<HeadReset> = (None);$', 'ROLLBACK_HEAD_RESET (must be None before arming)')
    reset = None
    if o.head_reset:
        reset = json.loads(o.head_reset.read_text())
        n, c, st = int(reset['number']), reset['commitment'].lower(), reset.get('statement')
        if not re.fullmatch(r'[0-9a-f]{64}', c):
            die('commitment must be 64 hex')
        if n == 0:
            if c != '0' * 64 or st is not None:
                die('number 0 (L2 genesis) needs a zero commitment and no statement')
            st_rs = 'None'
        else:
            if not st or not re.fullmatch(r'([0-9a-f]{2})+', st.lower()) or len(st) != 2 * 766:
                die('statement must be the 766-byte V3 statement as hex')
            st_rs = f'Some("{st.lower()}")'
        body = ', '.join(f'0x{c[i:i+2]}' for i in range(0, 64, 2))
        rs = f'Some(HeadReset {{ number: {n}, commitment: [{body}], statement: {st_rs} }})'
        lt = lt[:m.start(1)] + rs + lt[m.end(1):]

    m = one(ht, r'^pub const RELEASE_ARMABLE: &\[&str\] = &\[\n((?:    "params::[A-Z0-9_]+",\n)+)\];$', 'RELEASE_ARMABLE')
    names = m.group(1)
    add = ''.join(f'    "params::{g}",\n' for g in ('L2_NEXT_PROGRAM_EPOCH', 'L2_PROGRAM_ROLLBACK_EPOCH') if f'"params::{g}"' not in names)
    ht = ht[:m.end(1)] + add + ht[m.end(1):]

    p.write_text(pt); l.write_text(lt); h.write_text(ht)
    man = {
        'kind': 'l2-program-rollback' if final else 'l2-program-rollback-QUALIFICATION-ONLY',
        'swap_epoch': S, 'rollback_epoch': R, 'publish_epoch': o.publish_epoch, 'lead_epochs': lead,
        'head_reset': reset, 'program_next_final': final,
        'files_sha256': {x: hashlib.sha256((o.tree / x).read_bytes()).hexdigest() for x in (P, L, H)},
    }
    out = json.dumps(man, indent=1, sort_keys=True)
    if o.manifest:
        o.manifest.write_text(out + '\n')
    print(out)


if __name__ == '__main__':
    main()
