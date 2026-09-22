#!/usr/bin/env python3
"""Explicit scenario model, not a production restart SLA.

c(k) = base + growth*k is the assumed execution cost of historical block k.
Full replay sums c(0)..c(N-1); cached restart sums only the bounded tail, but
retains per-block log/index I/O and a supplied state-load cost. Coefficients
must come from representative host measurements or be labelled assumptions.
"""
import argparse
import json
import math


def project(blocks, base, growth, overhead, metadata, state_load, tail):
    full = overhead + metadata * blocks + base * blocks + growth * blocks * (blocks - 1) / 2
    tail = min(tail, blocks)
    cached = overhead + metadata * blocks + state_load + base * tail + growth * tail * (2 * blocks - tail - 1) / 2
    return {"blocks": blocks, "tail_blocks": tail, "full_replay_seconds": full, "cached_restart_seconds": cached}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--blocks', required=True, type=int)
    p.add_argument('--base-seconds-per-block', required=True, type=float)
    p.add_argument('--growth-seconds-per-block', type=float, default=0)
    p.add_argument('--daily-blocks', type=int, default=2880, help='2880 is a slot-derived upper bound, not measured production')
    p.add_argument('--days', type=int, nargs='+', default=[0, 30, 90, 180, 365])
    p.add_argument('--startup-overhead-seconds', type=float, default=0)
    p.add_argument('--metadata-seconds-per-block', type=float, default=0)
    p.add_argument('--state-load-seconds', type=float, default=0)
    p.add_argument('--tail-blocks', type=int, default=31)
    p.add_argument('--rto-seconds', required=True, type=float)
    a = p.parse_args()
    values = [a.blocks, a.base_seconds_per_block, a.growth_seconds_per_block, a.daily_blocks,
              a.startup_overhead_seconds, a.metadata_seconds_per_block, a.state_load_seconds,
              a.tail_blocks, a.rto_seconds, *a.days]
    if any(not math.isfinite(x) or x < 0 for x in values):
        p.error('all model inputs must be finite and non-negative')
    rows = []
    for day in a.days:
        row = project(a.blocks + day * a.daily_blocks, a.base_seconds_per_block,
                      a.growth_seconds_per_block, a.startup_overhead_seconds,
                      a.metadata_seconds_per_block, a.state_load_seconds, a.tail_blocks)
        row.update(day=day, full_exceeds_rto=row['full_replay_seconds'] > a.rto_seconds,
                   cache_exceeds_rto=row['cached_restart_seconds'] > a.rto_seconds)
        rows.append(row)
    print(json.dumps({'kind': 'assumption_based_scenario_not_a_measurement',
                      'inputs': vars(a), 'projections': rows}, indent=2))


if __name__ == '__main__':
    main()
