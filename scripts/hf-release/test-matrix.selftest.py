#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Regression: an allowed legacy assertion cannot hide a killed qualification."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("matrix", Path(__file__).with_name("test-matrix.py"))
matrix = importlib.util.module_from_spec(spec)
spec.loader.exec_module(matrix)

GOOD = "test example::ok ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n"
BAD = ("test example::failure ... FAILED\n"
       "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out\n"
       "error: test failed, to rerun pass `-p bloch --lib`\n")


class VerdictTests(unittest.TestCase):
    def test_clean_suite(self):
        self.assertEqual(matrix.assess(GOOD, 0)["status"], "PASS")

    def test_failure_is_blocking_by_default(self):
        self.assertEqual(matrix.assess(BAD, 101)["status"], "FAIL")

    def test_explicit_allowance_is_only_a_warning(self):
        self.assertEqual(matrix.assess(BAD, 101, ["bloch"])["status"], "WARN")
        self.assertEqual(matrix.assess(BAD, 101, allow_tests=["failure"])["status"], "WARN")

    def test_killed_container_never_becomes_allowed_warning(self):
        for rc in (-9, 137, 143, 125):
            self.assertEqual(matrix.assess(BAD, rc, ["bloch"])["status"], "FAIL")

    def test_missing_or_inconsistent_summaries_fail(self):
        for log in ("", BAD.replace("1 failed", "2 failed"), BAD.replace("FAILED. 0 passed", "missing")):
            self.assertEqual(matrix.assess(log, 101, ["bloch"])["status"], "FAIL")
        self.assertEqual(matrix.assess("", 0)["status"], "FAIL")

    def test_build_or_process_failure_cannot_hide_behind_allowed_test(self):
        for error in ("error[E0425]: missing name", "error: could not compile `bloch`",
                      "process didn't exit successfully (signal: 9, SIGKILL)"):
            self.assertEqual(matrix.assess(BAD + error, 101, ["bloch"])["status"], "FAIL")

    def test_non_allowed_package_and_zero_exit_with_failure_fail(self):
        self.assertEqual(matrix.assess(BAD.replace("-p bloch", "-p bloch-pos-node"), 101, ["bloch"])["status"], "FAIL")
        self.assertEqual(matrix.assess(BAD, 0, ["bloch"])["status"], "FAIL")


if __name__ == "__main__":
    unittest.main()
