#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Real L2 settlements across the gates of a crossing.py network (REHEARSAL ONLY, loopback, throwaway keys).

Attaches the settlement stack to a running crossing.py --work directory: follower, settled RPC, settler
with real Groth16 under PROVING.lock, three attestor agents (unmodified Agent.cycle / Agent.rebuild_check,
dry run, each with its own follower), and a traffic loop (deposits, L2 transfers, small and large
withdrawals, claims). After each gate it requires a settlement, a consumed deposit, a claim and a
`reconstruct` from L1 data that matches the finalized settlements, then writes a verdict.

  gate_l2.py prep                 keystores; prints the crossing.py --extra-alloc arguments
  gate_l2.py watch                the whole run; final marker RUN/VERDICT.json
  gate_l2.py agent I              one attestor agent loop (spawned by watch)

Env: GL_ROOT (scratch root), GL_WORK (crossing --work), GL_OUT (binaries), GL_SRC (L2 source),
GL_GATES ("HF1:45,..."), GL_L2_EPOCH, GL_STOP_EPOCH, GL_PORT_BASE, GL_LARGE_AT ("0,165").
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time
import urllib.request

R = Path(os.environ['GL_ROOT'])
WORK = Path(os.environ['GL_WORK'])
OUT = Path(os.environ['GL_OUT'])
SRC = Path(os.environ['GL_SRC'])
RUN = R / 'l2run'
GATES = [(g.split(':')[0], int(g.split(':')[1])) for g in os.environ.get('GL_GATES', '').split(',') if g]
L2_EPOCH = int(os.environ.get('GL_L2_EPOCH', 7))
STOP = int(os.environ.get('GL_STOP_EPOCH', 300))
BASE = int(os.environ.get('GL_PORT_BASE', 28000))
LARGE_AT = [int(x) for x in os.environ.get('GL_LARGE_AT', '0').split(',') if x != '']
RPC = [BASE + i for i in range(3)]
L2_RPC = BASE + 1900
BIN = OUT / 'bloch-pos-candidate-REHEARSAL-ONLY'
PRODUCE = OUT / 'bloch-l2-produce-dev-REHEARSAL-ONLY'
FOLLOWER = OUT / 'bloch-l2-native-follower-REHEARSAL-ONLY'
SETTLED = R / 'stack/bloch-l2-settled-rpc'
PROVER = R / 'stack/bloch-evm-sp1-settlement-v3'
GUARDED = R / 'stack/bloch-evm-sp1-settlement-v3-locked'
ELF = R / 'stack/settlement_v3_mainnet'
KEYS = R / 'keys/attestors'
ATTESTORS = KEYS / 'attestors.set'
PASS = R / 'wallets/keystore.passphrase'
LOCK = R.parent / 'PROVING.lock'
GENESIS = WORK / 'genesis.bin'
SLOTS = 32
SIGNERS = (0, 2, 4)
DOMAIN = '1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733'
L2_GENESIS = '632e45ae778da371a88dc1ae430193aa77eabb67a11de18e84fea7d20d11f468'
L2_GENESIS_STATE = '2ad7e807ac2ea14e2f423572fcb9e0f168de4cb26b5bbbd2711caf34cb05c05d'
NET_ARGS = ['--rules', 'mainnet', '--domain', DOMAIN, '--genesis-time', '1786656679']
PROGRAM = {
    'domain': DOMAIN,
    'configuration': '8ec1c804e67190434fdf72b723103d26938797e90e1b652d366a1b053e3d8f2b',
    'elf_keccak': '6e4c844007cbea4c5a3686f44cfb3b91362c146f3e87199a5229d619fae5c073',
    'vkey_koalabear': '389cfbde2516711668008cf00222398c6b2a3852266ca79c4ec42c5a6b39ac0e',
    'vkey_bn254': '007139f7bc9459c45b40046780222398cd65470a499b29e72762162d6b39ac0e',
    'proof_policy_v3': '154869964f89b4a5536f169ad6a4b17d0455ecace0891521356c554e32e5747d',
}
GNARK = 'ghcr.io/succinctlabs/sp1-gnark@sha256:e1a1cd62838b561ca301f9b2c26475c4a92bfe0e2c916e9bba213062e1548c4d'
EVENTS = RUN / 'gate_l2.jsonl'
BLCH = 10**8


def log(event, **f):
    line = json.dumps({'time': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'event': event, **f}, default=str)
    print(line, flush=True)
    if RUN.exists():
        with EVENTS.open('a') as fh:
            fh.write(line + '\n')


def env(**extra):
    return {'PATH': '/usr/bin:/bin', 'HOME': str(R / 'home'), 'BLOCH_KEYSTORE_PASSPHRASE_FILE': str(PASS), **extra}


class Refused(Exception):
    pass


def run(argv, **kw):
    done = subprocess.run([str(a) for a in argv], env=env(), capture_output=True, text=True, **kw)
    if done.returncode:
        raise Refused(f'{Path(str(argv[0])).name} {argv[1] if len(argv) > 1 else ""}: {done.stderr.strip()[-1500:]}')
    return done.stdout


def produce(*args, tries=5):
    for _ in range(tries):
        done = subprocess.run([str(PRODUCE), *map(str, args), *NET_ARGS], capture_output=True, text=True)
        if done.returncode == 0:
            return json.loads(done.stdout)
        time.sleep(3)
    raise Refused(f'produce {args[0]}: {done.stderr.strip()[-1500:]}')


def rpc(method, params=(), port=RPC[0], timeout=15):
    req = urllib.request.Request(f'http://127.0.0.1:{port}', headers={'Content-Type': 'application/json'},
                                 data=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': list(params)}).encode())
    with urllib.request.urlopen(req, timeout=timeout) as r:
        body = json.loads(r.read())
    if 'error' in body:
        raise Refused(f'{method}: {body["error"]}')
    return body['result']


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def clock():
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    import lifecycle_devnet_soak_lib as lib
    return lib.manifest_clock(GENESIS)


def network():
    return hashlib.sha3_256(GENESIS.read_bytes()).hexdigest()


def prep():
    (R / 'wallets').mkdir(mode=0o700, parents=True, exist_ok=True)
    (R / 'home/tmp').mkdir(parents=True, exist_ok=True)
    if not PASS.exists():
        PASS.write_text(os.urandom(32).hex() + '\n')
        PASS.chmod(0o600)
    allocs = {}
    for name, sats in (('wallet', 5_000 * BLCH), ('da', 100 * BLCH)):
        d = R / 'wallets' / name
        if not d.exists():
            d.mkdir(mode=0o700)
            run([BIN, 'keygen', '--dir', d, '--index', 0])
        pk = bytes.fromhex(run([BIN, 'keygen-public', '--dir', d]).split('\t')[1].strip())
        (R / 'wallets' / f'{name}.pubkey.hex').write_text(pk.hex() + '\n')
        allocs[name] = (hashlib.sha3_256(pk).hexdigest(), sats)
    (R / 'wallets/scripts.json').write_text(json.dumps({k: v[0] for k, v in allocs.items()}))
    print(' '.join(f'--extra-alloc {s}:{n}' for s, n in allocs.values()))


class Stack:
    def __init__(self):
        self.scripts = json.loads((R / 'wallets/scripts.json').read_text())
        self.gms, self.sms = clock()
        self.net = network()
        self.rule = f'1:{self.gms // 1000}:{self.sms}'
        self.st = {'accepted': [], 'claims': [], 'deposits': [], 'consumed': [], 'reconstruct': {}, 'halts': [],
                   'large': [], 'errors': 0, 'traffic': 0}
        self.acc_seen = 0
        self.cons_seen = 0
        self.expect_nonce = 0
        self.large_done = set()
        self.last_traffic = 0.0
        self.last_claim = 0.0
        self.claim_tried = set()
        self.pids = {}

    def epoch(self):
        return int((time.time() * 1000 - self.gms) // self.sms) // SLOTS

    def spawn(self, name, argv, extra=None):
        fh = (RUN / f'{name}.log').open('a')
        p = subprocess.Popen([str(a) for a in argv], env=env(**(extra or {})), stdout=fh, stderr=subprocess.STDOUT,
                             stdin=subprocess.DEVNULL, start_new_session=True, cwd=RUN)
        (RUN / f'{name}.pid').write_text(f'{p.pid}\n')
        self.pids[name] = p
        log('spawned', name=name, pid=p.pid)

    def follower(self, name, port):
        self.spawn(name, [FOLLOWER, '--manifest', GENESIS, '--network-pin', self.net, '--rpc-port', port,
                          '--state', RUN / name, '--status', RUN / f'{name}-status.json', '--poll-seconds', 5])

    def l2init(self):
        GUARDED.write_text(f"""#!/bin/bash
REAL={PROVER}
case " $* " in *" prove-groth16 "*) ;; *) exec "$REAL" "$@";; esac
echo "prover: waiting for {LOCK} $(date -u +%T)" >&2
export XDG_RUNTIME_DIR=/run/user/$(id -u)
exec /usr/bin/flock {LOCK} /usr/bin/systemd-run --user --scope -q -p MemoryMax=64G /usr/bin/nice -n 10 "$REAL" "$@"
""")
        GUARDED.chmod(0o755)
        identity = json.loads(run([PROVER, '--mainnet', 'identity', ELF]))
        bad = {k: identity.get(k) for k, v in PROGRAM.items() if identity.get(k) != v}
        if bad or identity.get('chain_id') != 700770:
            raise SystemExit(f'prover identity differs from the pinned PROGRAM: {bad}')
        db = RUN / 'canonical'
        produce('init', '--target', db)
        head = produce('head', '--target', db)
        if head['hash'] != L2_GENESIS or head['state_root'] != L2_GENESIS_STATE:
            raise SystemExit(f'L2 genesis differs from the pin: {head}')
        cfg = b''.join(bytes.fromhex(PROGRAM[k]) for k in ('domain', 'configuration', 'elf_keccak', 'vkey_koalabear', 'vkey_bn254'))
        cfg += bytes.fromhex(PROGRAM['proof_policy_v3']) + (700770).to_bytes(8, 'little') + bytes.fromhex(L2_GENESIS) + bytes.fromhex(L2_GENESIS_STATE)
        (RUN / 'l2-config.bin').write_bytes(cfg)
        (RUN / 'txpool').mkdir(exist_ok=True)
        log('l2-genesis', head=head, identity=identity)

    def start(self):
        self.l2init()
        self.follower('follower', RPC[1])
        for i in SIGNERS:
            self.follower(f'attestor{i}-follower', RPC[1 + SIGNERS.index(i) % 2])
        self.spawn('settled-rpc', [SETTLED, '--data-dir', RUN / 'canonical', '--view-dir', RUN / 'rpc-view',
                                   '--finality-status', RUN / 'follower-status.json', '--network', self.net,
                                   '--port', L2_RPC, '--poll-ms', 2000, *NET_ARGS, '--txpool', RUN / 'txpool'])
        config = {
            'network': self.net, 'network_kind': 'mainnet-rehearsal', 'chain_id': 700770, 'network_args': NET_ARGS,
            'l2_genesis': L2_GENESIS, 'rpc_ports': RPC, 'produce': str(PRODUCE), 'l2_db': str(RUN / 'canonical'),
            'workdir': str(RUN / 'work'), 'home': str(R / 'home'), 'prover_path': '/usr/bin:/bin',
            'prover': str(GUARDED), 'prover_sha256': sha(GUARDED), 'guest': str(ELF), 'guest_sha256': sha(ELF),
            'l2_config': str(RUN / 'l2-config.bin'), 'l2_config_sha256': sha(RUN / 'l2-config.bin'),
            'gnark_image': GNARK, 'prover_threads': 24, 'timestamp_rule': self.rule,
            'acceptance_timeout_seconds': 900, 'idle_seconds': 10, 'max_consecutive_failures': 100,
            'user_transactions': True, 'txpool_dir': str(RUN / 'txpool'),
            'max_block_gas': 15_000_000, 'max_block_bytes': 114_688, 'max_block_txs': 256,
            'da': {'signer': str(BIN), 'signer_sha256': sha(BIN), 'genesis': str(GENESIS),
                   'funding_pubkey': str(R / 'wallets/da.pubkey.hex'), 'keystore_dir': str(R / 'wallets/da'),
                   'passphrase_file': str(PASS), 'tip_millisat_per_gas': 0, 'inclusion_timeout_seconds': 300},
        }
        (RUN / 'work').mkdir(exist_ok=True)
        (RUN / 'settler.json').write_text(json.dumps(config, indent=2) + '\n')
        self.spawn('settler', ['/usr/bin/python3', '-u', SRC / 'deployment/devnet/settler_v3.py'],
                   {'BLOCH_SETTLER_CONFIG': str(RUN / 'settler.json')})
        for name in ('alice', 'bob'):
            key = RUN / f'{name}.l2.key'
            fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.write(fd, (os.urandom(32).hex() + '\n').encode())
            os.close(fd)
            self.st[f'addr_{name}'] = produce('address', '--key', key)['address']
        for i in SIGNERS:
            self.spawn(f'agent{i}', ['/usr/bin/python3', '-u', Path(__file__).resolve(), 'agent', i],
                       {k: os.environ[k] for k in os.environ if k.startswith('GL_')})

    def wallet_input(self):
        utxos = rpc('getutxos', [self.scripts['wallet'], 64]).get('utxos', [])
        u = max(utxos, key=lambda u: int(u['value_sat']))
        return f"{u['txid']}:{u['vout']}:{u['value_sat']}"

    def base_fee(self):
        return str(rpc('getchaininfo')['next_base_fee_millisat_per_gas'])

    def deposit(self, name, sats):
        n = rpc('getl2settlement')['inbox']['count']
        stamp = f'{time.time():.0f}'
        unsigned, signed = RUN / f'deposit-{stamp}-u.hex', RUN / f'deposit-{stamp}.hex'
        run([BIN, 'l2-deposit', 'prepare', '--genesis', GENESIS, '--funding-pubkey', R / 'wallets/wallet.pubkey.hex',
             '--input', self.wallet_input(), '--amount', sats, '--recipient', self.st[f'addr_{name}'],
             '--base-fee', self.base_fee(), '--tip', '0', '--out', unsigned])
        run([BIN, 'l2-deposit', 'sign', '--genesis', GENESIS, '--tx', unsigned, '--dir', R / 'wallets/wallet', '--out', signed])
        rpc('sendrawtransaction', [signed.read_text().strip()])
        for _ in range(60):
            time.sleep(2)
            if rpc('getl2settlement')['inbox']['count'] != n:
                self.st['deposits'].append({'epoch': self.epoch(), 'sats': sats, 'to': name, 'index': n})
                log('deposit', epoch=self.epoch(), sats=sats, to=name, index=n)
                return
        log('deposit-not-included', index=n)

    def traffic(self, large):
        db = RUN / 'canonical'
        addr = self.st['addr_alice']
        nonce = produce('account', '--target', db, '--address', addr)['nonce']
        if nonce < self.expect_nonce:
            return
        wallet = self.scripts['wallet']
        plan = [['--to', '00' * 19 + '55', '--value-wei', str(10**15)], ['--withdraw-to', wallet, '--sats', str(BLCH)]]
        if large:
            plan.append(['--withdraw-to', wallet, '--sats', str(100 * BLCH)])
        out = []
        for i, a in enumerate(plan):
            staged = RUN / f'tx-{time.time():.0f}-{i}.tx'
            produce('sign-tx', '--key', RUN / 'alice.l2.key', '--nonce', nonce + i, *a, '--out', staged)
            raw = staged.read_text().strip()
            raw = raw if raw.startswith('0x') else '0x' + raw
            out.append(rpc('eth_sendRawTransaction', [raw], port=L2_RPC))
        self.expect_nonce = nonce + len(plan)
        self.st['traffic'] += 1
        log('l2-txs', epoch=self.epoch(), nonce=nonce, large=large, hashes=out)

    def attest(self, index, record):
        d = RUN / f'attest-{record["root"][:12]}'
        d.mkdir(exist_ok=True)
        for i in SIGNERS:
            rebuilt = RUN / f'attest-rebuild-{i}'
            shutil.rmtree(rebuilt, ignore_errors=True)
            produce('reconstruct', '--target', rebuilt, '--l1-follower', RUN / f'attestor{i}-follower', '--timestamp-rule', self.rule)
            proof = d / f'attestor{i}-proof.json'
            proof.write_text(json.dumps(produce('withdrawal-proof', '--target', rebuilt, '--index', index, '--number', record['l2_number'],
                                                '--root', record['root'], '--count', record['count'])) + '\n')
            run([BIN, 'l2-claim', 'attest', '--genesis', GENESIS, '--proof', proof, '--attestors', ATTESTORS,
                 '--signer-index', i, '--key', KEYS / f'attestor-{i}.sk', '--out', d / f'attestor-{i}.partial'])
            shutil.rmtree(rebuilt, ignore_errors=True)
        return sorted(d.glob('*.partial'))

    def claim(self, index, kind, record, partials=()):
        db = RUN / 'canonical'
        proof = RUN / f'claim-{index}-proof.json'
        proof.write_text(json.dumps(produce('withdrawal-proof', '--target', db, '--index', index, '--number', record['l2_number'],
                                            '--root', record['root'], '--count', record['count'])) + '\n')
        extra = []
        if partials:
            extra = ['--attestors', ATTESTORS]
            for f in partials:
                extra += ['--attestation', f]
        unsigned, signed = RUN / f'claim-{index}-u.hex', RUN / f'claim-{index}.hex'
        run([BIN, 'l2-claim', 'prepare', '--genesis', GENESIS, '--funding-pubkey', R / 'wallets/wallet.pubkey.hex',
             '--input', self.wallet_input(), '--proof', proof, '--base-fee', self.base_fee(), '--tip', '0', *extra, '--out', unsigned])
        run([BIN, 'l2-claim', 'sign', '--genesis', GENESIS, '--tx', unsigned, '--dir', R / 'wallets/wallet', '--out', signed])
        before = int(rpc('getl2settlement')['inbox']['escrow_sat'])
        rpc('sendrawtransaction', [signed.read_text().strip()])
        for _ in range(60):
            time.sleep(2)
            v = rpc('getl2settlement')
            if int(v['inbox']['escrow_sat']) != before:
                row = {'index': index, 'kind': kind, 'epoch': self.epoch(), 'escrow_before': before, 'escrow_after': v['inbox']['escrow_sat'],
                       'conserved': v['withdrawals'].get('escrow_conserved'), 'record_number': record['l2_number']}
                self.st['claims'].append(row)
                log('claimed', **row)
                return True
        log('claim-not-included', index=index, kind=kind)
        return False

    def claims(self):
        sys.path.insert(0, str(SRC / 'deployment/mainnet/attestor'))
        import attestor_lib as alib
        w = rpc('getl2settlement')['withdrawals']
        large_sat = int(w['large_claim_sat'])
        small = w.get('claimable')
        large = w.get('claimable_large')
        db = RUN / 'canonical'
        if large and time.time() - self.last_claim > 20:
            for i in range(large['count']):
                if alib.claimed(w['claimed'], i) or i in self.claim_tried:
                    continue
                leaf = produce('withdrawal-proof', '--target', db, '--index', i, '--number', large['l2_number'],
                               '--root', large['root'], '--count', large['count'])['withdrawal']
                if leaf['sats'] < large_sat:
                    continue
                self.claim_tried.add(i)
                parts = self.attest(i, large)
                self.st['large'].append({'index': i, 'epoch': self.epoch(), 'root': large['root'], 'partials': len(parts)})
                self.last_claim = time.time()
                self.claim(i, 'claimable_large', large, parts)
                return
        if small and time.time() - self.last_claim > 240:
            for i in range(small['count']):
                if alib.claimed(w['claimed'], i) or i in self.claim_tried:
                    continue
                leaf = produce('withdrawal-proof', '--target', db, '--index', i, '--number', small['l2_number'],
                               '--root', small['root'], '--count', small['count'])['withdrawal']
                if leaf['sats'] >= large_sat:
                    continue
                self.claim_tried.add(i)
                self.last_claim = time.time()
                self.claim(i, 'claimable', small)
                return

    def observe(self):
        v = rpc('getl2settlement')
        ep = self.epoch()
        info = rpc('getchaininfo')
        acc = v.get('accepted') or {}
        number = None
        try:
            head = produce('head', '--target', RUN / 'canonical')
            number = head['number']
        except Refused:
            pass
        status = json.loads((RUN / 'follower-status.json').read_text()) if (RUN / 'follower-status.json').exists() else {}
        fins = status.get('finalized_settlements') or []
        n_accepted = int(acc.get('number', 0) or 0) if isinstance(acc, dict) else 0
        # settler log is authoritative for accepted blocks; its numbers are collected in the verdict.
        cons = int(v['inbox']['consumed'])
        if cons != self.cons_seen:
            self.st['consumed'].append({'epoch': ep, 'consumed': cons})
            self.cons_seen = cons
        views = {}
        for p in RPC:
            try:
                x = rpc('getl2settlement', port=p)
                views[p] = hashlib.sha256(json.dumps({k: x.get(k) for k in ('accepted', 'inbox')}, sort_keys=True).encode()).hexdigest()[:12]
            except Exception as e:  # noqa: BLE001
                views[p] = str(e)[:60]
        snap = {'epoch': ep, 'chain_height': info.get('height'), 'native_height': v.get('native_height'),
                'finalized_epoch': info['finalized']['epoch'], 'l2_head': number, 'follower_finalized_epoch': status.get('native_finalized_epoch'),
                'finalized_settlements': len(fins), 'inbox': v['inbox'], 'distinct_views': len(set(views.values())), 'n': n_accepted}
        with (RUN / 'snapshots.jsonl').open('a') as fh:
            fh.write(json.dumps(snap) + '\n')
        return snap, status

    def rebuild_after(self, name, gate, status):
        """Reconstruct from L1 data once a settlement past the gate is finalized on the own replay."""
        if name in self.st['reconstruct']:
            return
        fins = status.get('finalized_settlements') or []
        past = [s for s in fins if s['native_slot'] >= gate * SLOTS]
        if not past:
            return
        target = RUN / f'reconstruct-{name}'
        shutil.rmtree(target, ignore_errors=True)
        t0 = time.time()
        try:
            rep = produce('reconstruct', '--target', target, '--l1-follower', RUN / 'follower', '--timestamp-rule', self.rule)
        except Refused as e:
            self.st['reconstruct'][name] = {'ok': False, 'epoch': self.epoch(), 'error': str(e)[-800:]}
            log('reconstruct-failed', gate=name, error=str(e)[-800:])
            return
        blocks = {b['number']: b for b in rep['blocks']}
        fin_bad = [s['l2_number'] for s in fins if s['l2_number'] not in blocks or
                   (blocks[s['l2_number']]['hash'], blocks[s['l2_number']]['state_root']) != (s['l2_hash'], s['l2_state_root'])]
        rpc_bad = []
        for n, b in blocks.items():
            try:
                got = rpc('eth_getBlockByNumber', [hex(n), False], port=L2_RPC)
                if got and got.get('hash', '').removeprefix('0x') != b['hash']:
                    rpc_bad.append(n)
            except Exception:  # noqa: BLE001
                pass
        row = {'ok': not fin_bad and not rpc_bad, 'epoch': self.epoch(), 'seconds': round(time.time() - t0, 1), 'blocks': len(blocks),
               'settled': rep.get('settled'), 'native_blocks': rep.get('native_blocks'),
               'deposits_rebuilt': sum(int(b.get('deposits', 0) or 0) for b in rep['blocks']),
               'finalized_compared': len(fins), 'finalized_mismatch': fin_bad, 'rpc_mismatch': rpc_bad,
               'first_settlement_past_gate': past[0]['l2_number']}
        self.st['reconstruct'][name] = row
        log('reconstruct', gate=name, **row)
        shutil.rmtree(target, ignore_errors=True)

    def health(self):
        for name, p in self.pids.items():
            rc = p.poll()
            if rc is not None and not any(h['name'] == name for h in self.st['halts']):
                self.st['halts'].append({'name': name, 'rc': rc, 'epoch': self.epoch()})
                log('process-exited', name=name, rc=rc, epoch=self.epoch())

    def watch(self):
        while self.epoch() < L2_EPOCH + 1:
            time.sleep(1)
        self.start()
        self.deposit('alice', 3_000 * BLCH)
        self.deposit('bob', 50 * BLCH)
        while self.epoch() < STOP - 3:
            try:
                self.health()
                snap, status = self.observe()
                ep = snap['epoch']
                if time.time() - self.last_traffic > 300 and (snap['l2_head'] or 0) >= 1:
                    want_large = any(ep >= at and at not in self.large_done for at in LARGE_AT)
                    self.deposit('bob' if self.st['traffic'] % 2 else 'alice', 2 * BLCH)
                    self.traffic(want_large)
                    if want_large:
                        self.large_done.update(at for at in LARGE_AT if ep >= at)
                    self.last_traffic = time.time()
                self.claims()
                for name, gate in GATES:
                    if ep >= gate:
                        self.rebuild_after(name, gate, status)
                (RUN / 'progress.json').write_text(json.dumps({**self.st, 'snap': snap}, indent=1, default=str))
            except Exception as e:  # noqa: BLE001
                self.st['errors'] += 1
                log('step-error', epoch=self.epoch(), error=repr(e)[-600:])
            except SystemExit as e:
                self.st['errors'] += 1
                log('step-exit', error=str(e)[-600:])
            time.sleep(15)
        self.verdict()

    def settler_events(self):
        rows = []
        for line in (RUN / 'settler.log').read_text(errors='replace').splitlines():
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if e.get('event') in ('accepted', 'halt', 'retry', 'prover-failed'):
                rows.append(e)
        return rows

    def verdict(self):
        import calendar
        evs = self.settler_events()
        def ep_of(t):
            secs = calendar.timegm(time.strptime(t, '%Y-%m-%dT%H:%M:%SZ'))
            return int((secs * 1000 - self.gms) // self.sms) // SLOTS
        accepted = [dict(number=e['number'], epoch=ep_of(e['time'])) for e in evs if e['event'] == 'accepted']
        halts = [e for e in evs if e['event'] == 'halt']
        status = json.loads((RUN / 'follower-status.json').read_text())
        for name, gate in GATES:
            self.rebuild_after(name, gate, status)
        agent_halts = {}
        agent_ok = {}
        for i in SIGNERS:
            text = (RUN / f'agent{i}.log').read_text(errors='replace') if (RUN / f'agent{i}.log').exists() else ''
            agent_halts[i] = [line[:400] for line in text.splitlines() if '"agent-halt"' in line]
            agent_ok[i] = text.count('rebuild-check-ok')
        follower_halts = {}
        for name in ['follower'] + [f'attestor{i}-follower' for i in SIGNERS]:
            text = (RUN / f'{name}.log').read_text(errors='replace')
            follower_halts[name] = [line[:400] for line in text.splitlines() if 'halted' in line][:3]
        gates = {}
        names = [g for g in GATES]
        for k, (name, gate) in enumerate(names):
            nxt = names[k + 1][1] if k + 1 < len(names) else 10**9
            gates[name] = {
                'epoch': gate,
                'settlements_after': sum(1 for a in accepted if a['epoch'] >= gate),
                'settlements_before_next_gate': sum(1 for a in accepted if gate <= a['epoch'] < nxt),
                'deposits_consumed_after': sum(1 for c in self.st['consumed'] if c['epoch'] >= gate),
                'claims_after': sum(1 for c in self.st['claims'] if c['epoch'] >= gate),
                'claims_before_next_gate': [c['index'] for c in self.st['claims'] if gate <= c['epoch'] < nxt],
                'large_claims_after': [c['index'] for c in self.st['claims'] if c['epoch'] >= gate and c['kind'] == 'claimable_large'],
                'reconstruct': self.st['reconstruct'].get(name),
            }
            g = gates[name]
            g['pass'] = bool(g['settlements_before_next_gate'] and g['deposits_consumed_after'] and g['claims_before_next_gate']
                             and g['reconstruct'] and g['reconstruct'].get('ok'))
        final = RUN / 'final-rebuild'
        shutil.rmtree(final, ignore_errors=True)
        v = rpc('getl2settlement')
        conserved = v['withdrawals'].get('escrow_conserved')
        no_halt = not halts and not any(agent_halts.values()) and not any(follower_halts.values()) and not self.st['halts']
        ok = all(g['pass'] for g in gates.values()) and no_halt and conserved is True
        doc = {'verdict': 'PASS' if ok else 'FAIL', 'gates': gates, 'accepted': len(accepted), 'accepted_detail': accepted,
               'settler_halts': halts, 'settler_retries': sum(1 for e in evs if e['event'] == 'retry'),
               'prover_failures': sum(1 for e in evs if e['event'] == 'prover-failed'),
               'agent_halts': agent_halts, 'agent_rebuild_checks_ok': agent_ok, 'follower_halts': follower_halts,
               'process_exits': self.st['halts'], 'escrow_conserved': conserved, 'claims': self.st['claims'], 'large': self.st['large'],
               'deposits': self.st['deposits'], 'step_errors': self.st['errors'], 'offset': json.loads(
                   (RUN / 'snapshots.jsonl').read_text().splitlines()[-1])}
        (RUN / 'VERDICT.json').write_text(json.dumps(doc, indent=1, default=str) + '\n')
        log('verdict', verdict=doc['verdict'])
        for pidf in RUN.glob('*.pid'):
            try:
                os.killpg(int(pidf.read_text()), signal.SIGTERM)
            except (ProcessLookupError, ValueError):
                pass


def agent(index):
    """The UNMODIFIED Agent.cycle and Agent.rebuild_check with this net's identity (dry run: never signs)."""
    kit = SRC / 'deployment/mainnet/attestor'
    sys.path.insert(0, str(kit))
    import attestor_agent as a
    import attestor_lib as alib
    gms, sms = clock()
    v = rpc('getl2settlement')
    threshold, keys = alib.read_set(str(ATTESTORS))
    pins = alib.Pins(700770, network(), v['genesis'], alib.set_hash(threshold, keys), sha(GENESIS), L2_GENESIS,
                     NET_ARGS, f'1:{gms // 1000}:{sms}', int(v['withdrawals']['large_claim_sat']))
    state = RUN / f'agent{index}-state'
    cfg = {'signer_index': index, 'bloch_pos': str(BIN), 'bloch_pos_sha256': sha(BIN), 'produce': str(PRODUCE), 'produce_sha256': sha(PRODUCE),
           'follower': str(FOLLOWER), 'follower_sha256': sha(FOLLOWER), 'manifest': str(GENESIS), 'attestors': str(ATTESTORS), 'sealed_key': 'unused-dry-run',
           'follower_status': str(RUN / f'attestor{index}-follower-status.json'), 'follower_native': str(RUN / f'attestor{index}-follower'),
           'state_dir': str(state), 'rpc_urls': [f'http://127.0.0.1:{p}' for p in RPC], 'pause_file': str(state / 'PAUSE'),
           'approvals_file': str(state / 'approvals.txt')}
    ag = a.Agent(cfg, pins=pins, dry_run=True)
    ag.check_identity(key='none')
    last = 0.0
    while True:
        try:
            if time.time() - last > 300:
                ag.rebuild_check()
                last = time.time()
            ag.cycle()
        except a.Skip as e:
            a.log('agent-skip', reason=str(e)[:300])
        except a.Halt as e:
            a.log('agent-halt', reason=str(e)[:800])
            raise SystemExit(3)
        time.sleep(30)


if __name__ == '__main__':
    cmd = sys.argv[1]
    if cmd == 'prep':
        prep()
    elif cmd == 'agent':
        agent(int(sys.argv[2]))
    elif cmd == 'watch':
        RUN.mkdir(mode=0o700, exist_ok=True)
        while not GENESIS.exists():
            time.sleep(1)
        time.sleep(2)
        Stack().watch()
