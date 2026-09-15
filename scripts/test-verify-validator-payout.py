#!/usr/bin/env python3
"""Test settlement observations without keys, network access or transactions."""
import copy
import importlib.util
import io
import json
import pathlib
import unittest

spec = importlib.util.spec_from_file_location('payout', pathlib.Path(__file__).with_name('verify-validator-payout.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
W, S, D = '11'*32, '22'*32, '33'*32


class Node:
    def __init__(self):
        self.head = {'block_id': '44'*32, 'state_root': '55'*32, 'slot': 96000,
                     'finalized': {'epoch': 2998, 'root': '66'*32}}
        self.domain = m.DOMAIN
        self.status = {W: {'status': 'finalized'}, S: {'status': 'finalized'}}
        self.outputs = {
            W: {'txid': W, 'vout': 0, 'unspent': False, 'utxo': None, 'at_slot': 96000},
            S: {'txid': S, 'vout': 0, 'unspent': True, 'at_slot': 96000,
                'utxo': {'txid': S, 'vout': 0, 'script_hash': D, 'value_sat': '1000'}}}
        self.calls = []
        self.advance = False

    def __call__(self, method, params):
        self.calls.append(method)
        if method == 'getvalidatoradmission':
            return {'network_domain': self.domain}
        if method == 'getchaininfo':
            h = copy.deepcopy(self.head)
            if self.advance and self.calls.count(method) == 2:
                h['block_id'] = '77'*32
            return h
        if method == 'gettxstatus':
            return self.status[params[0]]
        if method == 'gettxout':
            return self.outputs[params[0]]
        raise AssertionError('Unexpected RPC: '+method)


class VerificationTests(unittest.TestCase):
    def verify(self, a=None, b=None):
        return m.verify(a or Node(), b or Node(), W, S, D, 1000)

    def test_matching_finalized_observations_use_only_reads(self):
        a, b = Node(), Node()
        self.assertEqual(self.verify(a, b)['status'], 'matching-rpc-settlement-observations')
        self.assertEqual(set(a.calls), {'getvalidatoradmission', 'getchaininfo', 'gettxstatus', 'gettxout'})

    def test_pending_unknown_and_absent_withdrawal_do_not_pass(self):
        for tx in (W, S):
            for status in ('pending', 'included', 'justified', 'unknown'):
                with self.subTest(tx=tx, status=status):
                    n = Node(); n.status[tx] = {'status': status}
                    with self.assertRaises(ValueError): self.verify(n)

    def test_wrong_network_or_different_or_moving_heads_fail(self):
        for mutation in ('network', 'head', 'moving'):
            n = Node()
            if mutation == 'network': n.domain = '00'*32
            if mutation == 'head': n.head['state_root'] = '99'*32
            if mutation == 'moving': n.advance = True
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): self.verify(n)

    def test_output_substitutions_and_stale_observations_fail(self):
        for field, value in [('txid', W), ('vout', 1), ('script_hash', W), ('value_sat', '999'), ('value_sat', 1000)]:
            n = Node(); n.outputs[S]['utxo'][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError): self.verify(n)
        for field, value in [('at_slot', 95999), ('txid', W), ('vout', True), ('unspent', False)]:
            n = Node(); n.outputs[S][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): self.verify(n)
        n = Node(); n.outputs[W]['unspent'] = True
        with self.assertRaises(ValueError): self.verify(n)

    def test_rpc_rejects_html_errors_wrong_ids_and_oversized_responses(self):
        class Client:
            def __init__(self, raw): self.raw = raw
            def open(self, request, timeout): return io.BytesIO(self.raw)
        for raw in (b'<html>unavailable</html>', b'x'*1048577,
                    json.dumps({'jsonrpc': '2.0', 'id': 2, 'result': {}}).encode(),
                    json.dumps({'jsonrpc': '2.0', 'id': 1, 'error': {'code': -32601}}).encode()):
            rpc = m.RPC('http://127.0.0.1:16400/')
            rpc.client = Client(raw)
            with self.subTest(raw=raw[:60]), self.assertRaises(ValueError):
                rpc('getchaininfo', [])
        rpc = m.RPC('http://127.0.0.1:16400/')
        rpc.client = Client(json.dumps({'jsonrpc': '2.0', 'id': 1, 'result': {'slot': 1}}).encode())
        self.assertEqual(rpc('getchaininfo', []), {'slot': 1})
        with self.assertRaises(ValueError):
            m.NoRedirect().redirect_request(None, None, 302, '', {}, 'http://example.com/')

    def test_moving_head_retries_then_records_successful_attempt(self):
        a = Node(); a.advance = True
        pauses = []
        result = m.observe(a, Node(), W, S, D, 1000, pause=pauses.append)
        self.assertEqual(result['attempts_used'], 2)
        self.assertEqual(pauses, [1])

    def test_persistent_head_disagreement_stops_at_bound(self):
        a = Node(); a.head['state_root'] = '99'*32
        pauses = []
        with self.assertRaises(m.ObservationMoved):
            m.observe(a, Node(), W, S, D, 1000, attempts=3, pause=pauses.append)
        self.assertEqual(pauses, [1, 1])
        self.assertEqual(a.calls.count('getchaininfo'), 6)

    def test_semantic_failures_and_missing_fields_do_not_retry(self):
        for failure in ('network', 'amount', 'missing', 'pending'):
            a = Node(); pauses = []
            if failure == 'network': a.domain = '00'*32
            if failure == 'amount': a.outputs[S]['utxo']['value_sat'] = '999'
            if failure == 'missing': del a.head['state_root']
            if failure == 'pending': a.status[S] = {'status': 'pending'}
            with self.subTest(failure=failure), self.assertRaises(ValueError):
                m.observe(a, Node(), W, S, D, 1000, pause=pauses.append)
            self.assertEqual(pauses, [])


    def test_input_bounds_and_nonlocal_endpoints_fail(self):
        for url in ('https://127.0.0.1/', 'http://example.com/', 'http://user@localhost/', 'http://localhost/?token=x'):
            with self.subTest(url=url), self.assertRaises(ValueError): m.endpoint(url)
        for amount in (999, -1, True, 2**64):
            with self.subTest(amount=amount), self.assertRaises(ValueError): m.verify(Node(), Node(), W, S, D, amount)
        with self.assertRaises(ValueError): m.verify(Node(), Node(), W, W, D, 1000)


if __name__ == '__main__':
    unittest.main()
