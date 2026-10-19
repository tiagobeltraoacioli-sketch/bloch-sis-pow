#!/usr/bin/env python3
"""Tests for participation.py — run: python3 -m unittest test_participation"""
import hashlib
import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import participation as P  # noqa: E402


def header(slot, proposer, mix):
    h = struct.pack("<I", P.VERSION_G4) + b"\x01" * 96 + struct.pack("<QI", slot, proposer)
    h += b"\x02" * 32 + mix + b"\x03" * 128
    assert len(h) == P.HEADER_LEN
    return h


def envelope(slot, proposer, mix, atts=(), txs=()):
    out = header(slot, proposer, mix)
    out += struct.pack("<I", 5) + b"psig!"
    out += struct.pack("<I", len(atts))
    for a_slot, validator in atts:
        e = a_slot // P.SLOTS_PER_EPOCH
        out += struct.pack("<Q", a_slot) + b"\x04" * 32 + struct.pack("<Q", e - 1) + b"\x05" * 32
        out += struct.pack("<Q", e) + b"\x06" * 32 + struct.pack("<I", validator)
        out += struct.pack("<I", 3) + b"sig"
    out += struct.pack("<I", len(txs))
    for t in txs:
        out += struct.pack("<I", len(t)) + t
    return out


def frame(env):
    return struct.pack("<I", len(env)) + env


class Sortition(unittest.TestCase):
    def test_partition_matches_rust_known_answer(self):
        # Produced by bloch_pos_committee::committees::epoch_committees at
        # dd287b6c with mix=[7;32], epoch=3, indices 0..10.
        got = P.epoch_committees(bytes([7] * 32), 3, range(10))
        want = [[5], [4], [9], [6], [3], [1], [8], [7], [2], [0]] + [[]] * 22
        self.assertEqual(got, want)

    def test_partition_covers_every_index_once_and_balances(self):
        idx = list(range(0, 300, 3))
        c = P.epoch_committees(hashlib.sha3_256(b"x").digest(), 6000, idx)
        self.assertEqual(len(c), P.SLOTS_PER_EPOCH)
        flat = [i for x in c for i in x]
        self.assertEqual(sorted(flat), idx)
        sizes = [len(x) for x in c]
        self.assertLessEqual(max(sizes) - min(sizes), 1)
        self.assertEqual(sizes, sorted(sizes, reverse=True))  # larger chunks first

    def test_partition_ignores_input_order(self):
        mix = bytes(range(32))
        self.assertEqual(P.epoch_committees(mix, 9, [5, 1, 9, 3]),
                         P.epoch_committees(mix, 9, [9, 3, 5, 1, 1]))

    def test_issuance_year0_and_decay(self):
        self.assertEqual(P.slot_issuance_sat(0), P.INITIAL_ANNUAL_SAT // P.SLOTS_PER_YEAR)
        self.assertEqual(P.slot_issuance_sat(P.SLOTS_PER_YEAR),
                         (P.INITIAL_ANNUAL_SAT * 9 // 10) // P.SLOTS_PER_YEAR)
        self.assertEqual(P.slot_issuance_sat(40 * P.SLOTS_PER_YEAR), 0)
        self.assertEqual(P.epoch_issuance_sat(5), 32 * P.slot_issuance_sat(160))


class Codec(unittest.TestCase):
    def test_decode_envelope_fields_and_block_id(self):
        mix = b"\x09" * 32
        env = envelope(100, 7, mix, atts=[(99, 3), (100, 4)], txs=[b"abc"])
        b = P.decode_envelope(env)
        self.assertEqual((b.slot, b.proposer, b.randao_mix), (100, 7, mix))
        self.assertEqual([(a.slot, a.validator, a.target_epoch) for a in b.atts], [(99, 3, 3), (100, 4, 3)])
        self.assertEqual(b.block_id, hashlib.sha3_256(P.DS_BLOCK + env[:P.HEADER_LEN]).hexdigest())

    def test_decode_rejects_trailing_bytes(self):
        with self.assertRaises(P.DecodeError):
            P.decode_envelope(envelope(1, 0, b"\0" * 32) + b"x")

    def test_tail_resyncs_mid_frame_and_drops_truncated_trailer(self):
        frames = [frame(envelope(s, s % 5, bytes([s % 256]) * 32, atts=[(s - 1, s % 7)])) for s in range(110, 116)]
        blob = b"".join(frames)
        cut = blob[len(frames[0]) // 2:]  # starts inside frame 0
        cut = cut[:-10]  # last frame truncated
        got = P.parse_log_tail(cut)
        self.assertEqual([b.slot for b in got], [111, 112, 113, 114])


class Analysis(unittest.TestCase):
    def build(self):
        """Two epochs (10, 11) of 8 validators; seed epoch 9 has one block."""
        vals = {i: P.ValidatorInfo(i, 100 * (i + 1), 0, None, False) for i in range(8)}
        blocks, canonical = {}, {}

        def put(slot, prop, atts):
            env = envelope(slot, prop, hashlib.sha3_256(b"m%d" % slot).digest(), atts=atts)
            b = P.decode_envelope(env)
            blocks[slot], canonical[slot] = b, b.block_id

        put(9 * 32 + 31, 0, [])
        mixes = {9: blocks[9 * 32 + 31].randao_mix}
        e10 = P.epoch_committees(mixes[9], 10, range(8))
        seat10 = {v: k for k, c in enumerate(e10) for v in c}
        for s in range(320, 352):
            canonical.setdefault(s, None)
        # epoch 10: everyone attests in their own slot except validator 2
        # (missing) and validator 5 (attests late, in epoch 11: not credited).
        for v, k in seat10.items():
            if v in (2, 5):
                continue
            slot = 320 + k
            prev = blocks.get(slot)
            atts = [(a.slot, a.validator) for a in prev.atts] if prev else []
            put(slot, 1, atts + [(slot, v)])
        put(320 + 31, 1, [(a.slot, a.validator) for a in blocks[351].atts] if 351 in blocks else [])
        mixes[10] = blocks[351].randao_mix
        e11 = P.epoch_committees(mixes[10], 11, range(8))
        seat11 = {v: k for k, c in enumerate(e11) for v in c}
        for s in range(352, 384):
            canonical.setdefault(s, None)
        late = 320 + seat10[5]
        put(352, 0, [(late, 5)])  # wrong epoch: must not count
        atts11 = [(352 + seat11[v], v) for v in range(8)]
        put(383, 6, atts11[:])  # everyone in epoch 11, included at the last slot
        return vals, blocks, canonical, seat10, seat11

    def test_duties_credit_distance_and_loss(self):
        vals, blocks, canonical, seat10, seat11 = self.build()
        rep = P.analyse([10, 11], canonical, blocks, vals, list(range(8)), {0: "hA", 1: "hB"})
        rows = {r["validator"]: r for r in rep["validators"]}
        self.assertEqual(rep["checks"]["atts_wrong_epoch"], 1)
        self.assertEqual(rep["checks"]["atts_in_computed_committee"], rep["checks"]["atts_seen"])
        for v in range(8):
            self.assertEqual(rows[v]["duties"], 2)
        self.assertEqual(rows[2]["missed"], 1)
        self.assertEqual(rows[5]["missed"], 1)
        self.assertEqual(rows[0]["missed"], 0)
        self.assertEqual(rows[3]["dist_max"], 31 - seat11[3])
        total = sum(v.stake for v in vals.values())
        lost = P.epoch_issuance_sat(10) * vals[2].stake // total
        self.assertAlmostEqual(rows[2]["lost_blch_per_day"], lost / P.SAT_PER_BLCH / rep["days"])
        self.assertEqual(rows[0]["host"], "hA")
        self.assertEqual(rows[7]["host"], "?")
        self.assertEqual(rep["totals"]["missed"], 2)
        sie = rep["slot_in_epoch"]
        self.assertEqual(sum(x["duties"] for x in sie), 16)
        self.assertEqual(sum(x["missed"] for x in sie), 2)
        self.assertGreaterEqual(sie[seat10[2]]["missed"], 1)
        self.assertGreaterEqual(sie[seat10[5]]["missed"], 1)

    def test_proposals_counted_and_expected_by_stake_share(self):
        vals, blocks, canonical, _, _ = self.build()
        rep = P.analyse([10, 11], canonical, blocks, vals, list(range(8)), {})
        rows = {r["validator"]: r for r in rep["validators"]}
        produced = sum(1 for s, b in blocks.items() if 320 <= s < 384 and b.proposer == 1)
        self.assertEqual(rows[1]["proposed"], produced)
        total = sum(v.stake for v in vals.values())
        self.assertAlmostEqual(rows[7]["proposals_expected"], 64 * vals[7].stake / total)
        self.assertEqual(rep["checks"]["empty_slots"] + rep["checks"]["filled_slots"], 64)


class HostMap(unittest.TestCase):
    def test_running_wins_and_stopped_reported(self):
        rows = [
            "UNIT\th1\tbloch-n01\tloaded\tenabled\tactive/running\t1\t-",
            "UNIT\th2\tbloch-n01\tmasked\tmasked\tinactive/dead\t0\t/dev/null",
            "UNIT\th2\tbloch-n58\tloaded\tdisabled\tinactive/dead\t0\t-",
            "UNIT\th3\tbloch-funded-64\tloaded\tenabled\tactive/running\t9\t-",
            "UNIT\th3\tbloch-expansion@\tloaded\tstatic\tinactive/dead\t0\t-",
            "KEYDIR\th3\t/x\t0",
        ]
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "a.tsv")
            with open(p, "w") as f:
                f.write("\n".join(rows) + "\n")
            got = P.host_map([p])
        self.assertEqual(got, {1: "h1", 58: "stopped", 64: "h3"})

    def test_parse_range(self):
        self.assertEqual(P.parse_range("0-3,7,9-10"), [0, 1, 2, 3, 7, 9, 10])


if __name__ == "__main__":
    unittest.main()
