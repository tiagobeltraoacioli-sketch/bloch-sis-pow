#!/usr/bin/env python3
"""Regression fixtures for the partition harness's embedded RPC report."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("devnet-particao.sh").read_text()
REPORT = SCRIPT.split('python3 - "$WORKDIR" "$tag" "$N" <<\'PY\'\n', 1)[1].split("\nPY\n", 1)[0]


class ReportTests(unittest.TestCase):
    def report(self, heads, height=1, proposals=True, roots=None, stopped=None):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "rpc").mkdir()
            for index, head in enumerate(heads):
                if head is None:
                    continue
                node = root / f"node{index}"
                node.mkdir()
                log = f"[slot 1] proposing block {head}\n[slot 1] applied {head}\n"
                if stopped is not None and stopped[index] is not None:
                    log += f"STOP at slot 10: head slot 9, 9 blocks, state root {stopped[index]}\n"
                (node / "test.log").write_text(log if proposals else "")
                result = {
                    "block_id": head, "height": height, "slot": height,
                    "finalized": {"epoch": 0, "root": "00"},
                    "justified": {"epoch": 0}, "blocks_known": height,
                    "behind_by_slots": 0,
                    "state_root": roots[index] if roots is not None else "a" * 64,
                }
                (root / "rpc" / f"test.node{index}.json").write_text(
                    json.dumps({"result": result}))
            return subprocess.run(
                [sys.executable, "-c", REPORT, temp, "test", str(len(heads))],
                capture_output=True, text=True)

    def test_no_samples_fail(self):
        self.assertNotEqual(self.report([None, None]).returncode, 0)

    def test_partial_agreement_fails(self):
        self.assertNotEqual(self.report(["abcd", None]).returncode, 0)

    def test_idle_genesis_agreement_fails(self):
        self.assertNotEqual(self.report(["abcd", "abcd"], height=0).returncode, 0)

    def test_phase_without_proposals_fails(self):
        self.assertNotEqual(self.report(["abcd", "abcd"], proposals=False).returncode, 0)

    def test_divergence_fails(self):
        self.assertNotEqual(self.report(["abcd", "dcba"]).returncode, 0)

    def test_missing_state_root_fails(self):
        self.assertNotEqual(self.report(["abcd", "abcd"], roots=[None, None]).returncode, 0)

    def test_same_block_with_conflicting_states_fails(self):
        self.assertNotEqual(self.report(["abcd", "abcd"], roots=["a" * 64, "b" * 64]).returncode, 0)

    def test_complete_progressing_agreement_passes(self):
        result = self.report(["abcd", "abcd"])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("CONVERGED", result.stdout)

    def test_moving_samples_can_agree_at_shutdown(self):
        result = self.report(["abcd", "dcba"], stopped=["a" * 64, "a" * 64])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("CONVERGED terminal", result.stdout)

    def test_conflicting_terminal_states_fail(self):
        self.assertNotEqual(self.report(["abcd", "abcd"], stopped=["a" * 64, "b" * 64]).returncode, 0)

    def test_missing_terminal_state_fails(self):
        self.assertNotEqual(self.report(["abcd", "abcd"], stopped=["a" * 64, None]).returncode, 0)

    def test_terminal_agreement_cannot_hide_same_block_state_conflict(self):
        self.assertNotEqual(self.report(["abcd", "abcd"], roots=["a" * 64, "b" * 64],
                                       stopped=["c" * 64, "c" * 64]).returncode, 0)


if __name__ == "__main__":
    unittest.main()
