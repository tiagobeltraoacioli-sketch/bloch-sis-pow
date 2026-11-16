#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Regression (review R308-10): an armed gate is seen however its value is written.

qualify.sh asked whether an L2 program gate is armed by matching a plain decimal literal. A gate armed through
another constant, a hex literal, a suffixed literal or an expression was read as not armed, and the refusal that
makes the operator name the shipped release as --base-commit did not fire. `hf-gates.py status` evaluates the
value; qualify.sh treats everything but `inert` (evaluated to u64::MAX) and `missing` as armed.

Needs git and python3 only: python3 -I scripts/hf-release/hf-gates.selftest.py
"""
import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

KIT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("gates", KIT / "hf-gates.py")
gates = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gates)

MAX = (1 << 64) - 1
DEFS = {
    "HF3_KES_ENFORCE_EPOCH": ["8_620"],
    "L2_NEXT_PROGRAM_EPOCH": ["u64::MAX"],
    "TWICE": ["1", "2"],
}


class Evaluate(unittest.TestCase):
    def check(self, text, want):
        self.assertEqual(gates.evaluate(text, DEFS), want, text)

    def test_literals(self):
        self.check("9000", 9000)
        self.check("9_000", 9000)
        self.check("9_000u64", 9000)
        self.check("9_000_u64", 9000)
        self.check("0x2328", 9000)
        self.check("u64::MAX", MAX)
        self.check("18_446_744_073_709_551_615", MAX)
        self.check("0xFFFF_FFFF_FFFF_FFFF", MAX)

    def test_names_and_arithmetic(self):
        self.check("HF3_KES_ENFORCE_EPOCH", 8620)
        self.check("params::HF3_KES_ENFORCE_EPOCH", 8620)
        self.check("crate::params::HF3_KES_ENFORCE_EPOCH + 380", 9000)
        self.check("(HF3_KES_ENFORCE_EPOCH + 380) as u64", 9000)
        self.check("2 * (4_000 + 500)", 9000)
        self.check("L2_NEXT_PROGRAM_EPOCH", MAX)
        self.check("u64::MAX - 0", MAX)

    def test_what_it_cannot_tell_is_none_never_inert(self):
        for text in ("u64::MAX - 1 + 2", "epoch_for(9000)", "1 << 13", "TWICE", "UNKNOWN_NAME", "other::CONST",
                     "9000 as u32", "", "9000 9000", "(9000", "1 / 0", "0 - 1"):
            self.check(text, None)


class Status(unittest.TestCase):
    """The `status` subcommand on a throwaway repository, and qualify.sh's reading of it."""

    FORMS = {
        "u64::MAX": "inert",
        "18_446_744_073_709_551_615": "inert",
        "9_000": "scheduled:9000",
        "0x2328": "scheduled:9000",
        "9_000u64": "scheduled:9000",
        "HF3_KES_ENFORCE_EPOCH + 380": "scheduled:9000",
        "SWAP_AT": "scheduled:9000",
        "epoch_for(9_000)": "alias:epoch_for(9_000)",
    }

    def run_git(self, repo, *args):
        env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@invalid", GIT_COMMITTER_NAME="t",
                   GIT_COMMITTER_EMAIL="t@invalid")
        return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True,
                              env=env).stdout.strip()

    def status_of(self, repo, commit, name):
        out = subprocess.run(["python3", "-I", str(KIT / "hf-gates.py"), "status", "--repo", str(repo),
                              "--commit", commit, "--gate", name], check=True, capture_output=True, text=True).stdout
        return out.strip().split("\t")[1]

    def test_every_way_of_writing_an_armed_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            self.run_git(repo, "init", "-q")
            params = repo / "crates" / "bloch-pos-committee" / "src" / "params.rs"
            params.parent.mkdir(parents=True)
            for value, want in self.FORMS.items():
                params.write_text("pub const HF3_KES_ENFORCE_EPOCH: u64 = 8_620;\n"
                                  "pub const SWAP_AT: u64 = 9_000;\n"
                                  f"pub const L2_NEXT_PROGRAM_EPOCH: u64 = {value};\n"
                                  "pub const L2_FORCED_INCLUSION_EPOCH: u64 = L2_NEXT_PROGRAM_EPOCH;\n")
                self.run_git(repo, "add", "-A")
                self.run_git(repo, "commit", "-qm", value, "--allow-empty")
                commit = self.run_git(repo, "rev-parse", "HEAD")
                self.assertEqual(self.status_of(repo, commit, "L2_NEXT_PROGRAM_EPOCH"), want, value)
                # A gate that follows another one is armed exactly when that one is.
                follower = self.status_of(repo, commit, "L2_FORCED_INCLUSION_EPOCH")
                if want.startswith("alias:"):
                    self.assertEqual(follower, "alias:L2_NEXT_PROGRAM_EPOCH", value)
                else:
                    self.assertEqual(follower, want, value)
                self.assertEqual(self.status_of(repo, commit, "L2_PROGRAM_ROLLBACK_EPOCH"), "missing")

    def test_qualify_reads_everything_but_inert_and_missing_as_armed(self):
        text = (KIT / "qualify.sh").read_text()
        body = text[text.index("l2_gate_armed() {"):]
        body = body[:body.index("\n}\n")]
        self.assertIn('status --repo "$REPO" --commit "$COMMIT" --gate "$1"', body)
        self.assertIn("case \"$st\" in inert|missing) return 1 ;; *) return 0 ;; esac", body)
        self.assertNotIn("sed -n", body)


if __name__ == "__main__":
    unittest.main()
