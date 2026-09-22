#!/usr/bin/env python3
"""Validate a public test-deposit record offline; no keys, RPC or transaction submission."""
import hashlib
import json
import pathlib
import re
import sys

DOMAIN = 'f47d3e498ff978e34471dafff5f94fe139fc3ff489b1a00f469c030258311966'
FIELDS = {'network_domain', 'funding_pubkey', 'validator_pubkey', 'randao_commitment',
          'withdrawal_script', 'change_script', 'stake_sat', 'fee_cap_sat', 'inputs'}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def hash32(value):
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value), 'Expected lowercase hex32.')
    return value


def amount(value):
    require(isinstance(value, str) and re.fullmatch('[1-9][0-9]{0,19}', value), 'Amounts must be positive decimal strings.')
    number = int(value)
    require(number <= 2**64-1, 'Amount exceeds u64.')
    return number


def public_key(value):
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{7498}', value), 'Expected 3749-byte suite-enveloped public key.')
    raw = bytes.fromhex(value)
    require(raw[:4] == bytes.fromhex('b10c0100'), 'Expected suite-1 public key envelope.')
    return hashlib.sha3_256(raw).hexdigest()


def validate(record):
    require(isinstance(record, dict) and set(record) == FIELDS, 'Unexpected or missing record fields; use the public-only template.')
    require(record['network_domain'] == DOMAIN, 'Wrong network domain.')
    funding = public_key(record['funding_pubkey'])
    validator = public_key(record['validator_pubkey'])
    for name in ('randao_commitment', 'withdrawal_script', 'change_script'):
        hash32(record[name])
        require(record[name] != '00'*32, 'Zero commitment or script is not a usable test record.')
    stake = amount(record['stake_sat']); fee = amount(record['fee_cap_sat'])
    require(stake >= 2500000000000, 'Stake must cover the 25000 BLCH admission minimum.')
    inputs = record['inputs']
    require(isinstance(inputs, list) and 1 <= len(inputs) <= 128, 'Expected 1 to 128 funding inputs.')
    seen = set(); total = 0
    for item in inputs:
        require(isinstance(item, dict) and set(item) == {'txid', 'vout', 'value_sat', 'script_hash'}, 'Unexpected or missing input fields.')
        txid = hash32(item['txid'])
        require(type(item['vout']) is int and 0 <= item['vout'] <= 2**32-1, 'Invalid output index.')
        outpoint = (txid, item['vout'])
        require(outpoint not in seen, 'Duplicate funding outpoint.')
        seen.add(outpoint)
        require(item['script_hash'] == funding, 'Funding script does not match the full public-key SHA3-256.')
        total += amount(item['value_sat'])
    require(total <= 2**64-1, 'Total funding exceeds u64.')
    require(total >= stake + fee, 'Observed funding does not cover stake plus the approved fee cap.')
    return {'status': 'public-record-structurally-valid', 'funding_script': funding,
            'validator_pubkey_hash': validator, 'input_count': len(inputs), 'total_input_sat': str(total),
            'stake_sat': str(stake), 'fee_cap_sat': str(fee),
            'limitations': 'No public key cryptography, UTXO existence, ownership, maturity, registry uniqueness or mainnet admission was verified. This is not authorization to sign or submit.'}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate JSON field.')
        result[key] = value
    return result


if __name__ == '__main__':
    try:
        require(len(sys.argv) == 2, 'Usage: check-admission-public-record.py public-record.json')
        with pathlib.Path(sys.argv[1]).open('rb') as source:
            raw = source.read(131073)
        require(len(raw) <= 131072, 'Public record exceeds 128 KiB.')
        result = validate(json.loads(raw, object_pairs_hook=unique_object))
        result['record_file_sha256'] = hashlib.sha256(raw).hexdigest()
        print(json.dumps(result, indent=2))
    except (ValueError, OSError, TypeError, KeyError) as error:
        print('Record refused: ' + str(error), file=sys.stderr)
        sys.exit(1)
