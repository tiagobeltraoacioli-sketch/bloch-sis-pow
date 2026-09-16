import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("native_source_process_lab", ROOT / "native-source-process-lab.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class DepositBinding(unittest.TestCase):
    def setUp(self):
        fixture = json.loads((ROOT / "fixtures/native-source-local-deposit.json").read_text())
        self.source, self.receipt = fixture["source"], fixture["receipt"]

    def test_actual_local_deposit(self):
        MODULE.validate_deposit(self.source, self.receipt)

    def test_compact_substitution_refused(self):
        for field, value in [("event_index", "0"), ("deposit_nonce", "1"), ("amount", "101"), ("deposit_sender", "0x" + "12" * 20), ("pq_recipient_hash", "0x" + "12" * 32), ("native_domain", "0x" + "12" * 32)]:
            with self.subTest(field=field):
                source = dict(self.source, **{field: value})
                with self.assertRaises(AssertionError):
                    MODULE.validate_deposit(source, self.receipt)

    def test_log_tamper_removed_wrong_emitter_and_transfer_refused(self):
        for index, field, value in [(1, "removed", True), (1, "address", self.source["token"]), (1, "data", "0x" + "00" * 128), (0, "data", "0x" + "00" * 32)]:
            with self.subTest(index=index, field=field):
                receipt = copy.deepcopy(self.receipt)
                receipt["logs"][index][field] = value
                with self.assertRaises(AssertionError):
                    MODULE.validate_deposit(self.source, receipt)


if __name__ == "__main__":
    unittest.main()
