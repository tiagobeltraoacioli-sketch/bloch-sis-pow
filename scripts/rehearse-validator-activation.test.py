#!/usr/bin/env python3
"""Fail-closed checks for disposable activation source rewriting."""
import importlib.util
from pathlib import Path
import re
import unittest

PATH = Path(__file__).with_name("rehearse-validator-activation.py")
spec = importlib.util.spec_from_file_location("activation", PATH)
activation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(activation)
SOURCE = (activation.ROOT / activation.PARAMS).read_text()


class RewriteTests(unittest.TestCase):
    def test_only_the_declared_gates_change(self):
        changed = activation.rewrite_params(SOURCE, 4)
        before = SOURCE.splitlines()
        after = changed.splitlines()
        self.assertEqual(len(before), len(after))
        edits = [(a, b) for a, b in zip(before, after) if a != b]
        self.assertEqual(len(edits), 9)
        for name in activation.CURRENT:
            self.assertIn(f"pub const {name}_ACTIVATION_EPOCH: u64 = 1;", changed)
        for name in activation.LIFECYCLE:
            self.assertIn(f"pub const {name}_ACTIVATION_EPOCH: u64 = 4;", changed)
        for name in re.findall(r"^pub const ([A-Z0-9_]+)_ACTIVATION_EPOCH: u64 = u64::MAX;$", SOURCE, re.M):
            if name not in activation.LIFECYCLE:
                self.assertIn(f"pub const {name}_ACTIVATION_EPOCH: u64 = u64::MAX;", changed)

    def test_unknown_finite_gate_fails(self):
        with self.assertRaises(ValueError):
            activation.rewrite_params(SOURCE + "\npub const EXTRA_ACTIVATION_EPOCH: u64 = 3;\n", 4)

    def test_unexpected_lifecycle_schedule_fails(self):
        with self.assertRaises(ValueError):
            activation.rewrite_params(SOURCE.replace(
                "pub const EXIT_AUTH_ACTIVATION_EPOCH: u64 = 2_884;",
                "pub const EXIT_AUTH_ACTIVATION_EPOCH: u64 = 20;"), 4)

    def test_invalid_boundary_fails(self):
        for epoch in (-1, 0, 1, 17, 2**64 - 1):
            with self.subTest(epoch=epoch), self.assertRaises(ValueError):
                activation.rewrite_params(SOURCE, epoch)


if __name__ == "__main__":
    unittest.main()
