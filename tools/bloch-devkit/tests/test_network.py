import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

root = Path(__file__).parents[1]
spec = importlib.util.spec_from_file_location("bloch_network", root / "bloch_network.py")
network = importlib.util.module_from_spec(spec)
spec.loader.exec_module(network)
BLOCK = json.loads((root / "tests/fixtures/checkpoint-49151.json").read_text())["result"]
NOW = network.GENESIS_TIME + (1538 * 32 + 2) * 30


class Source:
    def __init__(self):
        self.block = copy.deepcopy(BLOCK)
        self.view = {"slot": 1538 * 32 + 2, "wall_slot": 1538 * 32 + 2,
                     "behind_by_slots": 0, "slots_per_epoch": 32, "epoch": 1538,
                     "finalized": {"epoch": 1536, "root": BLOCK["block_id"]},
                     "corroboration": {"corroborated": True, "witnesses": 8}}

    def __call__(self, method, params):
        return copy.deepcopy(self.view if method == "getchaininfo" else self.block)


class NetworkTests(unittest.TestCase):
    def test_live_block_hash_known_answer(self):
        self.assertEqual(network.verify_header(BLOCK), network.PIN["block_id"])
        bad = copy.deepcopy(BLOCK)
        bad["state_root"] = "00" * 32
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            network.verify_header(bad)

    def test_sync_and_restart_keep_source_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "checkpoint.json"
            first = network.sync(path, Source(), NOW)
            second = network.sync(path, Source(), NOW + 1)
            self.assertEqual(first["block"], second["block"])
            self.assertFalse(second["capabilities"]["execution_settled"])
            self.assertEqual(json.loads(path.read_text()), second)

    def test_failed_sync_keeps_previous_file_byte_identical(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "checkpoint.json"
            network.sync(path, Source(), NOW)
            original = path.read_bytes()
            bad = Source()
            bad.view["corroboration"]["corroborated"] = False
            with self.assertRaisesRegex(ValueError, "corroboration"):
                network.sync(path, bad, NOW)
            self.assertEqual(original, path.read_bytes())

    def test_stale_clock_and_unsynced_node_rejected(self):
        for field, value in [("wall_slot", 1), ("slot", 1), ("behind_by_slots", 99)]:
            bad = Source()
            bad.view[field] = value
            with self.assertRaises(ValueError):
                network.collect(call=bad, now=NOW)

    def test_checkpoint_change_during_read_rejected(self):
        source = Source()
        reads = 0
        def changing(method, params):
            nonlocal reads
            result = source(method, params)
            if method == "getchaininfo":
                reads += 1
                if reads == 2:
                    result["finalized"]["epoch"] += 1
            return result
        with self.assertRaisesRegex(ValueError, "changed during"):
            network.collect(call=changing, now=NOW)

    def test_foreign_persisted_network_rejected(self):
        previous = network.collect(call=Source(), now=NOW)
        previous["genesis_root"] = "00" * 32
        with self.assertRaisesRegex(ValueError, "another network"):
            network.collect(previous, Source(), NOW)

    def test_finalized_regression_rejected(self):
        previous = network.collect(call=Source(), now=NOW)
        regressed = Source()
        regressed.view["finalized"]["epoch"] -= 1
        with self.assertRaisesRegex(ValueError, "regression"):
            network.collect(previous, regressed, NOW)

    def test_hash_types_and_duplicate_fields_rejected(self):
        for value in ("00", "0x" + "00" * 32, None, 1):
            with self.assertRaises(ValueError):
                network.hash_bytes(value)
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            network.decode(b'{"result":1,"result":2}')


if __name__ == "__main__":
    unittest.main()
