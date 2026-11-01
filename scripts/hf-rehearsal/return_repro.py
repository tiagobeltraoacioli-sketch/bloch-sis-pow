#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Do validators stopped together rejoin while the rest keeps finalizing? (private loopback, throwaway keys)

  return_repro.py --bin B --work W --port-base P [--offline 3,6,7] [--out-at 12] [--back-at 18] [--stop 30] [--slot-ms 1000]
                  [--stagger-slots 0]

Writes W/verdict.json: for each node the finalized epoch and head at the end, parked-block metrics and the
blocks each returned node applied from validators that stayed online.
"""
import argparse
import json
import re
import shutil
import sys
import threading
import time
import urllib.request
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))
import rehearse  # noqa: E402
from rehearse import SPE, Rehearsal  # noqa: E402
import lifecycle_devnet_soak_lib as lib  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument('--bin', type=Path, required=True)
ap.add_argument('--work', type=Path, required=True)
ap.add_argument('--port-base', type=int, required=True)
ap.add_argument('--offline', default='3,6,7')
ap.add_argument('--out-at', type=int, default=12)
ap.add_argument('--back-at', type=int, default=18)
ap.add_argument('--stop', type=int, default=30)
ap.add_argument('--slot-ms', type=int, default=1000)
ap.add_argument('--stagger-slots', type=int, default=0)
ap.add_argument('--mesh', default='offer')
ap.add_argument('--validators', type=int, default=8)
ap.add_argument('--register-at', type=int, help='every validator registers a KES key in this epoch')
ap.add_argument('--kes-depth', type=int, default=8)
ap.add_argument('--heal-at', type=int, help='restart one returned node, then (5 epochs later) all of them')
ap.add_argument('--doppelganger', action='store_true', help='leave doppelganger protection on, as a production node does')
ap.add_argument('--wipe-at', type=int, help='stop the group, delete its chain data (keys and slashing protection stay), restart')
ap.add_argument('--no-stop', action='store_true', help='the group is never stopped: only --hold-cut/--partition isolate it')
ap.add_argument('--hold-cut', type=int, default=0, help='seconds after the restart during which returned nodes reach only each other')
ap.add_argument('--partition', help='FROM,TO: cut the --offline set from the rest in these epochs')
a = ap.parse_args()
off = [int(x) for x in a.offline.split(',')]
ns = SimpleNamespace(work=a.work, validators=a.validators, candidate_bin=a.bin, baseline_bin=a.bin, arming=None, hf1=1, hf2=2, hf3=3,
                     slot_ms=a.slot_ms, start_in=20, bind_genesis=True, no_invariance=True, port_base=a.port_base)


class R(Rehearsal):
    def launch_all(self):
        if a.register_at is not None:
            for v in range(self.n):
                self.cand.run(['kes', 'keygen', '--dir', str(self.keydirs[v]), '--depth', str(a.kes_depth)], timeout=900)
                d = self.work / f'node{v}'
                d.mkdir(parents=True, exist_ok=True)
                shutil.move(str(self.keydirs[v] / 'validator.kes'), str(d / 'validator.kes'))
        self.mesh = lib.RelayMesh(self.total_nodes, self.relay_base(), self.a.port_base + 200)
        self.mesh.start_all()
        for i in range(self.total_nodes):
            d = self.work / f'node{i}'
            d.mkdir(parents=True, exist_ok=True)
            if i != self.obs:
                shutil.copy2(self.keydirs[i] / 'validator.key', d / 'validator.key')
            cmd = [str(self.cand.path), 'run', '--data-dir', str(d), '--genesis', str(self.genesis), '--transport', 'devnet',
                   *([] if a.doppelganger else ['--no-doppelganger-check']), '--listen', str(self.mesh_port(i)), '--listen-addr', '127.0.0.1',
                   '--peers', ','.join(self.mesh.peers_for(i)), '--rpc-bind', '127.0.0.1', '--rpc-port', str(self.rpc_port(i)),
                   '--metrics-bind', '127.0.0.1', '--metrics-port', str(self.metrics_port(i)), '--mesh-security', a.mesh]
            self.nodes.append(lib.Node(name=f'node{i}', slot=i, data_dir=d, rpc_port=self.rpc_port(i), mesh_port=self.mesh_port(i),
                                       metrics_port=self.metrics_port(i), cmd=cmd, env=self.env, log_path=d / 'run.log', has_key=i != self.obs))
        for n in self.nodes:
            n.start()
            time.sleep(0.2)


r = R(ns)
r.work.mkdir(mode=0o700, parents=True, exist_ok=False)
out = {'args': vars(a).copy(), 'phases': []}
out['args'] = {k: str(v) for k, v in vars(a).items()}
try:
    r.preflight()
    r.keys_and_genesis()
    r.launch_all()
    threading.Thread(target=r.sampler, daemon=True).start()
    r.wait_epoch(2)
    r.read_stakes()
    total = sum(r.stakes.values())
    out['offline_share'] = sum(r.stakes[v] for v in off) / total
    if a.partition:
        lo, hi = (int(x) for x in a.partition.split(','))
        others = set(range(r.total_nodes)) - set(off)
        r.wait_epoch(lo)
        r.mesh.cut_between(set(off), others)
        r.wait_epoch(hi)
        r.mesh.heal_between(set(off), others)
    if a.register_at is not None:
        r.wait_epoch(a.register_at, 4)
        regs = {}
        (r.work / 'tx').mkdir(exist_ok=True)
        for v in range(r.n):
            for attempt in range(3):
                f = r.work / 'tx' / f'kes-{v}-{attempt}.hex'
                r.cand.run(['kes', 'register', '--dir', str(r.work / f'node{v}'), '--genesis', str(r.genesis), '--out', str(f), '--validator', str(v)], timeout=600)
                ok, msg = r.submit(0, f.read_text().strip())
                if ok or 'out-of-range depth or signature length' not in msg:
                    break
            regs[v] = ok
        out['kes_registered'] = regs
    r.wait_epoch(a.out_at)
    if not a.no_stop:
        for v in off:
            r.nodes[v].stopped_on_purpose = True
            r.nodes[v].stop()
    r.wait_epoch(a.back_at)
    out['before_return'] = {i: r.latest(i)['fin'] for i in (0, 1)}
    others = set(range(r.total_nodes)) - set(off)
    if a.hold_cut:
        r.mesh.cut_between(set(off), others)
    for k, v in enumerate([] if a.no_stop else off):
        if k and a.stagger_slots:
            time.sleep(a.stagger_slots * a.slot_ms / 1000)
        r.nodes[v].start()
        r.nodes[v].stopped_on_purpose = False

    if a.hold_cut:
        time.sleep(a.hold_cut)
        r.mesh.heal_between(set(off), others)
        out['hold_cut_healed_at'] = r.clock.wall_epoch()

    def metrics(i):
        try:
            text = urllib.request.urlopen(f'http://127.0.0.1:{r.metrics_port(i)}/metrics', timeout=4).read().decode()
            return [ln for ln in text.splitlines() if not ln.startswith('#') and re.search(r'park|orphan|peer|sync', ln)]
        except Exception as e:  # noqa: BLE001
            return [str(e)]
    def full_metrics(i):
        try:
            return urllib.request.urlopen(f'http://127.0.0.1:{r.metrics_port(i)}/metrics', timeout=4).read().decode()
        except Exception as e:  # noqa: BLE001
            return str(e)
    def probe(tag):
        try:
            probe_inner(tag)
        except Exception as e:  # noqa: BLE001
            with (r.work / 'probes.jsonl').open('a') as fh:
                fh.write(json.dumps({'tag': tag, 'error': str(e)[:200]}) + '\n')

    def probe_inner(tag):
        online0 = next(i for i in range(r.n) if i not in off)
        info = {i: r.rpc(i, 'getchaininfo', timeout=5.0) for i in (online0, off[0])}
        has = {}
        try:
            has['returned_has_online_head'] = bool(r.rpc(off[0], 'getblockbyid', [info[online0]['block_id']], timeout=5.0))
        except Exception as e:  # noqa: BLE001
            has['returned_has_online_head'] = str(e)[:120]
        try:
            has['online_has_returned_head'] = bool(r.rpc(online0, 'getblockbyid', [info[off[0]]['block_id']], timeout=5.0))
        except Exception as e:  # noqa: BLE001
            has['online_has_returned_head'] = str(e)[:120]
        with (r.work / 'probes.jsonl').open('a') as fh:
            fh.write(json.dumps({'tag': tag, 'epoch': r.clock.wall_epoch(), 'online': {k: info[online0].get(k) for k in ('slot', 'height', 'finalized', 'justified', 'block_id')},
                                 'returned': {k: info[off[0]].get(k) for k in ('slot', 'height', 'finalized', 'justified', 'block_id')}, **has}) + '\n')
        (r.work / f'metrics-{tag}-returned.txt').write_text(full_metrics(off[0]))
        (r.work / f'metrics-{tag}-online.txt').write_text(full_metrics(online0))
    time.sleep(6)
    probe('back')
    marks = sorted({a.back_at + 2, a.back_at + 5, a.stop - 1} | ({a.heal_at - 1, a.heal_at + 4, a.heal_at + 9} if a.heal_at else set())
                   | ({a.wipe_at, a.wipe_at + 3, a.wipe_at + 8} if a.wipe_at else set()))
    for e in marks:
        r.wait_epoch(e)
        probe(f'e{e}')
        if a.wipe_at and e == a.wipe_at:
            for v in off:
                r.nodes[v].stopped_on_purpose = True
                r.nodes[v].stop()
                d = r.work / f'node{v}'
                for f in d.iterdir():
                    if f.name.startswith(('blocks.', 'state.cache', 'meta.', 'ws_latest')):
                        f.unlink()
            time.sleep(2)
            for v in off:
                r.nodes[v].start()
                r.nodes[v].stopped_on_purpose = False
            out['wiped_at'] = r.clock.wall_epoch()
        if a.heal_at and e == a.heal_at - 1:
            r.nodes[off[0]].stop(); time.sleep(2); r.nodes[off[0]].start()
            out['heal_one_at'] = r.clock.wall_epoch()
        if a.heal_at and e == a.heal_at + 4:
            for v in off:
                r.nodes[v].stop()
            time.sleep(2)
            for v in off:
                r.nodes[v].start()
            out['heal_all_at'] = r.clock.wall_epoch()
        out['phases'].append({'epoch': e, 'nodes': {i: {'fin': (r.latest(i) or {}).get('fin'), 'head': (r.latest(i) or {}).get('head', '')[:10]}
                                                    for i in range(a.validators)},
                              'metrics_returned': metrics(off[0]), 'metrics_online': metrics(0)})
        (r.work / 'verdict.json').write_text(json.dumps(out, indent=1))
    applied = {}
    for v in off:
        t = r.nodes[v].log_text()
        i = t.rfind('state-cache: restored')
        i = i if i >= 0 else t.rfind('JSON-RPC listening')
        pv = re.findall(r'applied [0-9a-f]+ by v(\d+)', t[i:])
        applied[v] = {'from_online': sum(int(p) not in off for p in pv), 'from_returned': sum(int(p) in off for p in pv)}
    last = out['phases'][-1]['nodes']
    online = [i for i in range(a.validators) if i not in off]
    joined = all(abs(last[v]['fin'] - last[online[0]]['fin']) <= 2 for v in off)
    out.update(applied=applied, verdict='REJOINED' if joined else 'SPLIT')
finally:
    r.stop_sampler.set()
    for n in r.nodes:
        n.stopped_on_purpose = True
        try:
            n.stop()
        except Exception:  # noqa: BLE001
            pass
    if r.mesh:
        r.mesh.close_all()
    (r.work / 'verdict.json').write_text(json.dumps(out, indent=1))
print(out.get('verdict'), json.dumps(out.get('applied')))
