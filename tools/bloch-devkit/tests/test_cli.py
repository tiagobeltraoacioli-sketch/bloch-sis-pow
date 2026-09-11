import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("bloch_dev", Path(__file__).parents[1] / "bloch_dev.py")
kit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kit)


class DevKitTests(unittest.TestCase):
    def test_init_does_not_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "project"
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(kit.main(["init", "evm", str(project)]), 0)
                original = (project / "bloch-dev.json").read_bytes()
                self.assertEqual(kit.main(["init", "svm", str(project)]), 1)
            self.assertEqual((project / "bloch-dev.json").read_bytes(), original)

    def test_wrong_chain_is_rejected_before_export(self):
        with patch.object(kit, "rpc", return_value="0x1"):
            with self.assertRaisesRegex(ValueError, "identity"):
                kit.observe({"vm": "evm", "port": 8545, "chain_id": 31337})

    def test_export_tamper_and_overwrite_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "record.json"
            with patch.object(kit, "observe", return_value={"block": {"hash": "abc"}}), contextlib.redirect_stdout(io.StringIO()):
                kit.export_observation({"vm": "evm"}, output)
                kit.verify_artifact(output)
                with self.assertRaises(FileExistsError):
                    kit.export_observation({"vm": "evm"}, output)
            record = json.loads(output.read_text())
            record["payload"]["observation"]["block"]["hash"] = "forged"
            output.write_text(json.dumps(record))
            with self.assertRaisesRegex(ValueError, "mismatch"):
                kit.verify_artifact(output)

    def test_duplicate_json_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "duplicate.json"
            path.write_text('{"payload":{},"payload":{}}')
            with self.assertRaisesRegex(ValueError, "Duplicate"):
                kit.verify_artifact(path)

    def test_svm_never_labels_block_hash_as_state_root(self):
        with patch.object(kit, "rpc", side_effect=["genesis", 100, {"blockhash": "hash"}]) as rpc:
            result = kit.observe({"vm": "svm", "port": 8899})
            self.assertEqual(result["slot"], 100)
            self.assertNotIn("stateRoot", result)
            self.assertEqual(rpc.call_args.args[2][1]["commitment"], "finalized")

    def test_unavailable_finalized_svm_block(self):
        with patch.object(kit, "rpc", side_effect=["genesis", 0, None]):
            with self.assertRaisesRegex(ValueError, "unavailable"):
                kit.observe({"vm": "svm", "port": 8899})

    def test_runtime_commands_persist_and_bind_locally(self):
        with patch.object(kit, "runtime", return_value="/runtime"):
            evm = kit.command({"vm": "evm", "port": 8545}, Path("/project"))
            svm = kit.command({"vm": "svm", "port": 8899}, Path("/project"))
        self.assertIn("127.0.0.1", evm)
        self.assertIn("--state", evm)
        self.assertIn("127.0.0.1", svm)
        self.assertNotIn("--reset", svm)


if __name__ == "__main__":
    unittest.main()
