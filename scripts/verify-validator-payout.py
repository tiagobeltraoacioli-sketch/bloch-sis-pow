#!/usr/bin/env python3
"""Collect bounded, read-only payout settlement observations from two local RPC tunnels."""
import argparse
import datetime
import json
import re
import sys
import time
import urllib.parse
import urllib.request

DOMAIN = 'f47d3e498ff978e34471dafff5f94fe139fc3ff489b1a00f469c030258311966'


class ObservationMoved(ValueError):
    """A valid observation crossed a head boundary and may be retried."""


def require(condition, message):
    if not condition:
        raise ValueError(message)


def hex32(value):
    require(isinstance(value, str) and re.fullmatch('[0-9a-fA-F]{64}', value), 'Expected a 32-byte hex identifier.')
    return value.lower()


def endpoint(value):
    u = urllib.parse.urlsplit(value)
    require(u.scheme == 'http' and u.hostname in ('localhost', '127.0.0.1', '::1')
            and not u.username and not u.password and not u.query and not u.fragment,
            'Use a loopback HTTP RPC, with an SSH tunnel for each remote node.')
    return value


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('RPC redirects are refused.')


class RPC:
    def __init__(self, url):
        self.url = endpoint(url)
        self.client = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        self.sequence = 0

    def __call__(self, method, params):
        self.sequence += 1
        request = urllib.request.Request(self.url, data=json.dumps({
            'jsonrpc': '2.0', 'id': self.sequence, 'method': method, 'params': params
        }).encode(), headers={'Content-Type': 'application/json'})
        with self.client.open(request, timeout=15) as response:
            raw = response.read(1048577)
        require(len(raw) <= 1048576, 'RPC response exceeds one MiB.')
        body = json.loads(raw)
        require(isinstance(body, dict) and type(body.get('id')) is int and body['id'] == self.sequence
                and body.get('jsonrpc') == '2.0' and 'error' not in body
                and 'result' in body, 'Invalid or failed JSON-RPC response.')
        return body['result']


def snapshot(rpc, withdrawal, spend, destination, amount):
    admission = rpc('getvalidatoradmission', [])
    require(admission.get('network_domain') == DOMAIN, 'Wrong network domain.')
    before = rpc('getchaininfo', [])
    old_status = rpc('gettxstatus', [withdrawal])
    status = rpc('gettxstatus', [spend])
    old = rpc('gettxout', [withdrawal, 0])
    new = rpc('gettxout', [spend, 0])
    after = rpc('getchaininfo', [])
    for field in ('block_id', 'state_root', 'slot', 'finalized'):
        require(field in before and field in after, 'Missing chain observation field.')
        if before[field] != after[field]:
            raise ObservationMoved('Node advanced during observation; retry.')
    hex32(before['block_id'])
    hex32(before['state_root'])
    require(type(before['slot']) is int and before['slot'] >= 0, 'Invalid head slot.')
    require(isinstance(before['finalized'], dict), 'Missing finalized checkpoint.')
    hex32(before['finalized']['root'])
    require(type(before['finalized']['epoch']) is int and before['finalized']['epoch'] >= 0,
            'Invalid finalized epoch.')
    require(old_status == {'status': 'finalized'}, 'Withdrawal is not reported finalized.')
    require(status == {'status': 'finalized'}, 'Payout spend is not reported finalized.')
    for output, txid in ((old, withdrawal), (new, spend)):
        require(output.get('txid') == txid and type(output.get('vout')) is int
                and output['vout'] == 0 and type(output.get('at_slot')) is int
                and output['at_slot'] == before['slot'], 'Output observation does not match requested outpoint and head.')
    require(old.get('unspent') is False and old.get('utxo') is None, 'Withdrawal output is still present or malformed.')
    require(new.get('unspent') is True and isinstance(new.get('utxo'), dict), 'Destination output is absent or already spent.')
    utxo = new['utxo']
    require(utxo.get('txid') == spend and type(utxo.get('vout')) is int and utxo['vout'] == 0
            and utxo.get('script_hash') == destination and utxo.get('value_sat') == str(amount),
            'Destination output differs from the approved transaction, destination or amount.')
    return {'head': {k: before[k] for k in ('block_id', 'state_root', 'slot', 'finalized')},
            'withdrawal_status': old_status, 'spend_status': status, 'withdrawal_output': old, 'destination_output': new}


def verify(first, second, withdrawal, spend, destination, amount):
    require(withdrawal != spend, 'Withdrawal and spend IDs must differ.')
    require(type(amount) is int and 1000 <= amount <= 2**64 - 1, 'Expected output amount must be between 1000 and u64::MAX satoshis.')
    observations = [snapshot(r, withdrawal, spend, destination, amount) for r in (first, second)]
    if observations[0]['head'] != observations[1]['head']:
        raise ObservationMoved('Nodes disagree or were observed at different heads; retry.')
    require(observations[0] == observations[1], 'Nodes disagree at the same head.')
    return {'status': 'matching-rpc-settlement-observations', 'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'network_domain': DOMAIN, 'observations': observations,
            'limitations': 'RPC observations are not cryptographic proofs. Verify that the signed transaction spends this withdrawal; retain its inspected intent. Distinct endpoints do not prove independent node operators. No transaction was submitted.'}


def observe(first, second, withdrawal, spend, destination, amount, attempts=3, pause=time.sleep):
    require(type(attempts) is int and 1 <= attempts <= 5, 'Attempts must be between 1 and 5.')
    for attempt in range(1, attempts + 1):
        try:
            result = verify(first, second, withdrawal, spend, destination, amount)
            result['attempts_used'] = attempt
            return result
        except ObservationMoved:
            if attempt == attempts:
                raise
            pause(1)
    raise AssertionError('Unreachable attempt count.')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--rpc-a', required=True, type=endpoint)
    p.add_argument('--rpc-b', required=True, type=endpoint)
    p.add_argument('--withdrawal-txid', required=True, type=hex32)
    p.add_argument('--spend-txid', required=True, type=hex32)
    p.add_argument('--destination', required=True, type=hex32)
    p.add_argument('--value-sat', required=True, type=int)
    p.add_argument('--attempts', type=int, default=3, choices=range(1, 6),
                   help='Retry moving or differing heads only (default: 3, one second apart).')
    a = p.parse_args()
    require(a.rpc_a != a.rpc_b, 'Supply two separately configured node endpoints.')
    result = observe(RPC(a.rpc_a), RPC(a.rpc_b), a.withdrawal_txid, a.spend_txid, a.destination, a.value_sat, a.attempts)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, AttributeError) as error:
        print('Not verified: ' + str(error), file=sys.stderr)
        sys.exit(1)
