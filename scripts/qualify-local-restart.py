#!/usr/bin/env python3
"""Local devnet process test. Generates disposable keys; never connects to mainnet."""
import argparse
import hashlib
import platform
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def qualify(binary, output):
    env = dict(os.environ, BLOCH_KEYSTORE_ALLOW_PLAINTEXT='1')
    for key in ['BLOCH_REPLAY_FROM_GENESIS', 'BLOCH_REQUIRE_STATE_CACHE', 'BLOCH_MAX_REPLAY_BLOCKS']:
        env.pop(key, None)
    records = []
    with tempfile.TemporaryDirectory(prefix='bloch-restart-qualification-') as temp:
        root = Path(temp)
        producer = root / 'producer'
        manifest = root / 'genesis.blg'
        def command(*args, timeout=40):
            return subprocess.run([binary, *map(str, args)], env=env, capture_output=True, text=True, timeout=timeout, check=True)
        command('keygen', '--dir', producer, '--index', '0')
        command('genesis', '--keys', producer, '--out', manifest, '--slot-ms', '500', '--start-in', '2')
        command('run', '--data-dir', producer, '--genesis', manifest,
                '--listen', free_port(), '--rpc-port', 'off', '--stop-at-slot', '40', '--no-doppelganger-check', timeout=65)
        assert (producer / 'state.cache').exists(), 'producer did not create its periodic cache'
        observer = root / 'observer'
        observer.mkdir()
        for name in ['blocks.log', 'blocks.idx', 'meta.bin', 'state.cache', 'state.cache.previous']:
            if (producer / name).exists():
                shutil.copy2(producer / name, observer / name)
        assert not (observer / 'validator.key').exists()
        def run_read(label, flags):
            port = free_port()
            log = root / (label + '.log')
            start = time.monotonic()
            with log.open('w') as f:
                process = subprocess.Popen([binary, 'run', '--data-dir', str(observer), '--genesis', str(manifest),
                    '--listen', str(free_port()), '--rpc-port', str(port), *flags], env=env, stdout=f, stderr=f)
                try:
                    deadline = start + 40
                    while time.monotonic() < deadline:
                        if process.poll() is not None:
                            raise AssertionError(log.read_text())
                        try:
                            request = urllib.request.Request(f'http://127.0.0.1:{port}/',
                                data=json.dumps({'jsonrpc':'2.0','id':1,'method':'getchaininfo','params':[]}).encode(),
                                headers={'Content-Type':'application/json'})
                            with urllib.request.urlopen(request, timeout=1) as response:
                                info = json.load(response)['result']
                            break
                        except (OSError, ValueError, KeyError):
                            time.sleep(0.05)
                    else:
                        raise AssertionError('RPC not ready: ' + log.read_text())
                    elapsed = time.monotonic() - start
                finally:
                    process.kill()  # SIGKILL: subsequent boot must use durable data only.
                    process.wait(timeout=5)
            text = log.read_text()
            records.append({'case':label,'rpc_ready_seconds':elapsed,'slot':info['slot'],'height':info['height'],
                'state_root':info['state_root'], 'recovery_log':[s for s in text.splitlines() if s.startswith(('recovery:', 'state-cache:'))]})
            return info, text
        cached, text = run_read('cache_and_tail', ['--require-state-cache'])
        assert 'mode=local-cache' in text
        second, text = run_read('restart_after_sigkill', ['--require-state-cache', '--max-replay-blocks', '0'])
        assert 'replayed_blocks=0' in text
        full, text = run_read('full_replay_reference', ['--replay-from-genesis'])
        assert 'mode=full-replay' in text
        for field in ['slot', 'height', 'state_root', 'block_id']:
            assert cached[field] == second[field] == full[field], field
        (observer / 'state.cache').write_bytes(b'torn-cache')
        restored, text = run_read('previous_generation', ['--require-state-cache'])
        assert 'file=state.cache.previous' in text
        assert restored['state_root'] == full['state_root']
        for name in ['state.cache', 'state.cache.previous']:
            (observer / name).write_bytes(b'corrupt')
        rejected = subprocess.run([binary, 'run', '--data-dir', str(observer), '--genesis', str(manifest),
            '--listen', str(free_port()), '--rpc-port', 'off', '--require-state-cache'], env=env,
            capture_output=True, text=True, timeout=10)
        assert rejected.returncode != 0, 'strict mode accepted corrupt caches'
        records.append({'case':'both_caches_corrupt', 'strict_mode_refused': True})
    result = {'kind':'local_devnet_process_qualification_not_mainnet_sla', 'binary':binary, 'binary_sha256':hashlib.sha256(Path(binary).read_bytes()).hexdigest(), 'buildinfo':json.loads(subprocess.check_output([binary, 'buildinfo'], env=env, text=True)), 'platform':platform.platform(), 'rpc_poll_interval_seconds':0.05, 'filesystem_cache':'uncontrolled', 'cases':records}
    Path(output).write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    qualify(str(Path(args.binary).resolve()), args.output)
