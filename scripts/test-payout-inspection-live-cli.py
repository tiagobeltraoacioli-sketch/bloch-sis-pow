#!/usr/bin/env python3
"""Exercise the settlement helper with a real offline CLI and disposable sealed keys."""
import hashlib
import importlib.util
import os
import pathlib
import subprocess
import sys
import tempfile

root = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('payout', root / 'verify-validator-payout.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
binary = pathlib.Path(sys.argv[1]).resolve()
with tempfile.TemporaryDirectory(prefix='bloch-payout-integration-') as directory:
    d = pathlib.Path(directory)
    env = os.environ.copy()
    env.pop('BLOCH_KEYSTORE_PASSPHRASE_FILE', None)
    env.pop('BLOCH_KEYSTORE_ALLOW_PLAINTEXT', None)
    env['BLOCH_KEYSTORE_PASSPHRASE'] = 'disposable payout integration test only'
    def run(*args):
        return subprocess.check_output([str(binary), *map(str, args)], env=env, text=True, stderr=subprocess.PIPE)
    keys = d/'keys'
    run('keygen', '--dir', keys, '--index', 'auto')
    assert (keys/'validator.key').read_bytes().startswith(b'BPOSKEY2')
    pub = bytes.fromhex(run('keygen-public', '--dir', keys).split('\t')[1])
    (d/'public.hex').write_text(pub.hex())
    destination = '82'*32
    common = ['--validator', '71', '--input-value', '2500000000000',
              '--withdrawal-script', hashlib.sha3_256(pub).hexdigest(),
              '--destination', destination, '--base-fee', '10', '--epoch', '5000', '--max-fee', '1000000']
    draft = d/'draft.hex'; signed = d/'signed.hex'
    prepared = run('validator-payout', 'prepare', *common, '--pubkey', d/'public.hex', '--tip', '5', '--out', draft)
    fields = dict(line.split(': ', 1) for line in prepared.splitlines() if ': ' in line)
    run('validator-payout', 'sign', *common, '--tx', draft, '--dir', keys,
        '--expected-root', fields['Signing root'], '--out', signed)
    withdrawal = fields['Payout input'].split(':')[0]
    spend = fields['Transaction id']; amount = int(fields['Output value (sat)'])
    report = m.inspect_signed(binary, signed, common, withdrawal, spend, destination, amount)
    assert report['signed_file_sha256'] == hashlib.sha256(signed.read_bytes()).hexdigest()
    for candidate, txid, dest, value in [(draft, spend, destination, amount),
                                        (signed, '00'*32, destination, amount),
                                        (signed, spend, '00'*32, amount),
                                        (signed, spend, destination, amount+1)]:
        try:
            m.inspect_signed(binary, candidate, common, withdrawal, txid, dest, value)
        except ValueError:
            pass
        else:
            raise AssertionError('Invalid intent was accepted')
    (d/'invalid.hex').write_text('06abcd')
    try:
        m.inspect_signed(binary, d/'invalid.hex', common, withdrawal, spend, destination, amount)
    except ValueError:
        pass
    else:
        raise AssertionError('Malformed transaction was accepted')
print('Real CLI integration passed: signed payout accepted; unsigned, wrong ID/destination/value and malformed transaction refused. No RPC used.')
