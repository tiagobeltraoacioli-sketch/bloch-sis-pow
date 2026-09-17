#!/usr/bin/env python3
"""Audit regressions: a failed or unrelated build cannot certify a crate."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).with_name('hardened-clippy-score.py')

class ScoringTests(unittest.TestCase):
    def score(self, records):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'log.json'
            path.write_text('\n'.join(json.dumps(r) if isinstance(r, dict) else r for r in records))
            return subprocess.run([sys.executable, str(SCRIPT), '--pkg', 'target', '--panics', '1', '--arith', '0', '--other', '0', str(path)], capture_output=True, text=True).returncode

    def artifact(self, package='target'):
        return {'reason':'compiler-artifact', 'package_id':f'path+file:///workspace#{package}@1.0.0'}

    def message(self, package='target', code='clippy::unwrap_used', level='error'):
        return {'reason':'compiler-message', 'package_id':f'path+file:///workspace#{package}@1.0.0', 'message': {'message':'test diagnostic', 'code':{'code':code}, 'level':level, 'spans':[]}}

    def test_real_cargo_path_identity_with_version_only_fragment(self):
        record = {'reason':'compiler-artifact', 'package_id':'path+file:///workspace/crates/target#0.1.0-mainnet'}
        self.assertEqual(self.score([record, {'reason':'build-finished','success':True}]), 0)
        record['package_id'] = 'path+file:///workspace/target/other#0.1.0-mainnet'
        self.assertEqual(self.score([record, {'reason':'build-finished','success':True}]), 2)
        record['package_id'] = 'path+file:///workspace/target#other@0.1.0'
        self.assertEqual(self.score([record, {'reason':'build-finished','success':True}]), 2)

    def test_failed_build_without_diagnostics_is_void(self):
        self.assertEqual(self.score([self.artifact(), {'reason':'build-finished','success':False}]), 2)

    def test_requested_package_must_actually_run(self):
        self.assertEqual(self.score([self.artifact('other'), {'reason':'build-finished','success':True}]), 2)

    def test_dependency_findings_cannot_spend_target_baseline(self):
        self.assertEqual(self.score([self.artifact(), self.message('other'), {'reason':'build-finished','success':False}]), 2)

    def test_dependency_warning_is_not_a_target_finding(self):
        self.assertEqual(self.score([self.artifact(), self.message('other','clippy::arithmetic_side_effects','warning'), {'reason':'build-finished','success':True}]), 0)

    def test_known_target_deny_lint_can_match_accepted_baseline(self):
        self.assertEqual(self.score([self.message(), {'reason':'build-finished','success':False}]), 0)

    def test_clean_target_artifact_is_valid(self):
        self.assertEqual(self.score([self.artifact(), {'reason':'build-finished','success':True}]), 0)

    def test_malformed_diagnostics_are_not_ignored(self):
        self.assertEqual(self.score([self.artifact(), '{malformed', {'reason':'build-finished','success':True}]), 2)

    def test_cargo_failure_cannot_hide_behind_an_accepted_lint(self):
        self.assertEqual(self.score([self.message(), 'error: failed to run custom build command', {'reason':'build-finished','success':False}]), 2)

if __name__ == '__main__':
    unittest.main()
