#!/usr/bin/env python3
"""Synthetic structural checks; no real keys or funds."""
import importlib.util
import json
import pathlib
import unittest
spec = importlib.util.spec_from_file_location('record', pathlib.Path(__file__).with_name('check-admission-public-record.py'))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


def fixture():
    key = 'b10c0100' + '11'*3745
    return {'network_domain': m.DOMAIN, 'funding_pubkey': key, 'validator_pubkey': key,
            'randao_commitment': '22'*32, 'withdrawal_script': '33'*32, 'change_script': '44'*32,
            'stake_sat': '2500000000000', 'fee_cap_sat': '1000000',
            'inputs': [{'txid': '55'*32, 'vout': 0, 'value_sat': '2500001000000', 'script_hash': m.public_key(key)}]}


class Tests(unittest.TestCase):
    def test_structural_record(self):
        self.assertEqual(m.validate(fixture())['input_count'], 1)

    def test_invalid_network_amount_keys_and_unknown_fields(self):
        for key, value in [('network_domain', '00'*32), ('stake_sat', '2499999999999'), ('fee_cap_sat', 1),
                           ('funding_pubkey', '00'), ('randao_commitment', '00'*32), ('password', 'refuse')]:
            record = fixture(); record[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): m.validate(record)

    def test_duplicate_unfunded_wrong_script_and_boolean_index(self):
        for kind in ('duplicate', 'insufficient', 'script', 'index'):
            record = fixture()
            if kind == 'duplicate': record['inputs'] *= 2
            if kind == 'insufficient': record['inputs'][0]['value_sat'] = '2500000000000'
            if kind == 'script': record['inputs'][0]['script_hash'] = '00'*32
            if kind == 'index': record['inputs'][0]['vout'] = True
            with self.subTest(kind=kind), self.assertRaises(ValueError): m.validate(record)

    def test_duplicate_json_fields(self):
        with self.assertRaises(ValueError): json.loads('{"a":1,"a":2}', object_pairs_hook=m.unique_object)


if __name__ == '__main__': unittest.main()
