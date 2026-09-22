#!/usr/bin/env python3

import copy
import importlib.util
import pathlib
import unittest


SCRIPT = pathlib.Path(__file__).with_name("verify-lg01-provenance.py")
SPEC = importlib.util.spec_from_file_location("lg01", SCRIPT)
lg01 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lg01)


def digest(character):
    return character * 64


def node(number, height=39_917):
    tip = digest("a")
    block = None
    if height == 39_918:
        tip = digest("b")
        block = {
            "hash": tip,
            "selected": True,
            "coinbase_total_sat": 840_000_000_060,
            "tx_count": 2,
        }
    return {
        "node_id": f"archive-{number}",
        "archive_identity_sha256": digest(str(number)),
        "capture_utc": "2026-09-18T12:00:00Z",
        "selected_tip_height_at_snapshot": height,
        "selected_tip_hash_at_snapshot": tip,
        "max_stored_height": 39_918,
        "snapshot": {
            "rows": lg01.EXPECTED_ROWS,
            "total_sat": lg01.EXPECTED_TOTAL_SAT,
            "uncompressed_sha256": lg01.EXPECTED_SHA256,
            "sha3_256": lg01.EXPECTED_SHA3,
            "set_root": lg01.EXPECTED_SET_ROOT,
        },
        "raw_evidence_sha256": {
            "daginfo": digest("c"),
            "tip_meta": digest("d"),
            "carryover_verification": digest("e"),
            "block_lookup": digest("f"),
        },
        "block_39918": block,
    }


def bundle(height=39_917):
    return {"schema": lg01.SCHEMA, "nodes": [node(1, height), node(2, height)]}


class ProvenanceClassifierTest(unittest.TestCase):
    def test_classifies_short_selected_chain(self):
        evidence = bundle()
        evidence["nodes"][0]["block_39918"] = {
            "hash": digest("b"), "selected": False,
            "coinbase_total_sat": lg01.SUBSIDY_SAT, "tx_count": 1,
        }
        self.assertEqual(lg01.classify(evidence), "LABEL_OR_STALE_SNAPSHOT")

    def test_classifies_selected_block_with_missing_effects(self):
        self.assertEqual(lg01.classify(bundle(39_918)), "SELECTED_BLOCK_EFFECTS_MISSING")

    def test_requires_two_distinct_archives(self):
        evidence = bundle()
        evidence["nodes"] = evidence["nodes"][:1]
        with self.assertRaisesRegex(lg01.EvidenceError, "at least two"):
            lg01.classify(evidence)
        evidence = bundle()
        evidence["nodes"][1]["archive_identity_sha256"] = evidence["nodes"][0]["archive_identity_sha256"]
        with self.assertRaisesRegex(lg01.EvidenceError, "archive identities"):
            lg01.classify(evidence)

    def test_rejects_artifact_mismatch_and_bool_as_integer(self):
        evidence = bundle()
        evidence["nodes"][0]["snapshot"]["total_sat"] -= 1
        with self.assertRaisesRegex(lg01.EvidenceError, "pinned carryover"):
            lg01.classify(evidence)
        evidence = bundle()
        evidence["nodes"][0]["snapshot"]["rows"] = True
        with self.assertRaisesRegex(lg01.EvidenceError, "non-negative integer"):
            lg01.classify(evidence)

    def test_rejects_disagreeing_tips(self):
        evidence = bundle()
        evidence["nodes"][1]["selected_tip_hash_at_snapshot"] = digest("9")
        with self.assertRaisesRegex(lg01.EvidenceError, "disagree on the selected tip"):
            lg01.classify(evidence)

    def test_rejects_impossible_stored_height(self):
        evidence = bundle(39_918)
        evidence["nodes"][0]["max_stored_height"] = 39_917
        with self.assertRaisesRegex(lg01.EvidenceError, "below the selected tip"):
            lg01.classify(evidence)

    def test_rejects_selected_block_inconsistent_with_tip(self):
        evidence = bundle(39_918)
        evidence["nodes"][0]["block_39918"]["hash"] = digest("8")
        with self.assertRaisesRegex(lg01.EvidenceError, "does not equal"):
            lg01.classify(evidence)

    def test_rejects_underclaimed_terminal_coinbase(self):
        evidence = bundle(39_918)
        evidence["nodes"][0]["block_39918"]["coinbase_total_sat"] = lg01.SUBSIDY_SAT - 1
        with self.assertRaisesRegex(lg01.EvidenceError, "full scheduled subsidy"):
            lg01.classify(evidence)

    def test_rejects_unknown_fields(self):
        evidence = bundle()
        evidence["nodes"][0]["selected_tip_height"] = 39_917
        with self.assertRaisesRegex(lg01.EvidenceError, "wrong fields"):
            lg01.classify(evidence)


if __name__ == "__main__":
    unittest.main()
