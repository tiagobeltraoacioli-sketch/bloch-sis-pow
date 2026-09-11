#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Prove `arm-lifecycle-epoch.py` refuses every wrong arming and accepts the right one.

A tool that edits consensus constants earns trust the way the other guards
in this directory do: by being driven, in both directions, against a
synthetic tree it cannot mistake for the real one. This builds a minimal
repository in a temporary directory — a params.rs with the six constants and
`SLOTS_PER_EPOCH`, a manifest with the BPOSMAN magic and a genesis clock, a
runbook with the `LIFECYCLE_EPOCH` line, the two files that hold the
retire-on-arm tripwires, and a stub comment guard — and asserts:

  refused : an epoch in the past; an epoch with too little lead; arming an
            already-armed tree; `--verify` on a tree whose runbook disagrees
            with params.rs, whose five constants differ, whose tripwires
            survive arming, or whose comment guard fails;
  accepted: the plan for an admissible epoch; `--write` of it (constants and
            runbook both flipped, DEPOSIT untouched); `--verify` of the
            unarmed tree and of the armed tree once the tripwires are gone.

`--rehearse` needs git and cargo and is exercised by running it on the real
tree, not here.

Run: python3 scripts/arm-lifecycle-epoch.selftest.py
Exit 0 = the tool behaves as documented on all cases.
"""
from __future__ import annotations

import datetime as dt
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

TOOL = Path(__file__).resolve().with_name("arm-lifecycle-epoch.py")
GATES = ["FUNDED_VALIDATOR_ADMISSION", "EXIT_AUTH", "WITHDRAWAL", "SLASHING_EVIDENCE", "RANDAO_RECOMMIT"]
SLOT_MS = 30_000
SLOTS = 32


def params(values: dict[str, str]) -> str:
    lines = [f"pub const SLOTS_PER_EPOCH: u64 = {SLOTS};", "pub const DEPOSIT_ACTIVATION_EPOCH: u64 = u64::MAX;"]
    lines += [f"pub const {g}_ACTIVATION_EPOCH: u64 = {values.get(g, 'u64::MAX')};" for g in GATES]
    return "\n".join(lines) + "\n"


def build_tree(root: Path, *, genesis_epochs_ago: int, armed: str | None = None, tripwires: bool = True) -> None:
    now_ms = int(dt.datetime.now(dt.timezone.utc).timestamp() * 1000)
    genesis_ms = now_ms - genesis_epochs_ago * SLOT_MS * SLOTS
    (root / "genesis").mkdir(parents=True)
    (root / "genesis/mainnet.manifest").write_bytes(b"BPOSMAN1" + struct.pack("<QQ", genesis_ms, SLOT_MS) + b"\0" * 8)
    committee = root / "crates/bloch-pos-committee/src"
    committee.mkdir(parents=True)
    (committee / "params.rs").write_text(params({g: armed for g in GATES} if armed else {}))
    (committee / "transition.rs").write_text(
        "".join(f"    fn {n}_gate_is_inert() {{}}\n" for n in ["exit_auth", "slashing_evidence", "randao_recommit", "withdrawal"])
        if tripwires else "// retired\n"
    )
    node = root / "crates/bloch-pos-node"
    (node / "tests").mkdir(parents=True)
    (node / "tests/slashing_backed_finality_claims.rs").write_text(
        "fn the_activation_constant_exists_in_one_place_and_is_not_armed() {}\n" if tripwires else "// retired\n"
    )
    (node / "rust-toolchain.toml").write_text('[toolchain]\nchannel = "1.94.1"\n')
    (root / "deploy").mkdir()
    (root / "deploy/FLAG-DAY-LIFECYCLE.md").write_text(
        "# runbook\n\n```\nLIFECYCLE_EPOCH = %s\n```\n" % (armed or "unarmed")
    )
    (root / "scripts").mkdir()
    (root / "scripts/check-comment-constants.py").write_text("import sys\nsys.exit(0)\n")


def run(root: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(TOOL), "--root", str(root), *args],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )


def expect(label: str, proc: subprocess.CompletedProcess, code: int, *needles: str) -> None:
    ok = proc.returncode == code and all(n in proc.stdout for n in needles)
    print(f"{'ok  ' if ok else 'FAIL'} {label}")
    if not ok:
        print(f"     exit {proc.returncode}, wanted {code}; wanted text {needles}\n{proc.stdout}")
        raise SystemExit(1)


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="arm-lifecycle-selftest-") as temp:
        base = Path(temp)

        # Chain at ~epoch 2536 (as on 2026-09-11), unarmed, tripwires present.
        t = base / "unarmed"
        build_tree(t, genesis_epochs_ago=2536)
        expect("plan: admissible epoch", run(t, "--epoch", "3400"), 0, "lead", "-> 3400")
        expect("plan: epoch in the past refused", run(t, "--epoch", "2000"), 1, "not strictly in the future")
        expect("plan: short lead refused", run(t, "--epoch", "2600"), 1, "minimum is 540")
        expect("plan: short lead accepted when passed explicitly",
               run(t, "--epoch", "2600", "--min-lead-epochs", "10"), 0, "-> 2600")
        expect("verify: unarmed tree is consistent", run(t, "--verify"), 0, "unarmed", "consistent")
        expect("verify: --epoch on an unarmed tree mismatches", run(t, "--verify", "--epoch", "3400"), 1, "armed at None")

        expect("write: past epoch refused, tree untouched", run(t, "--write", "--epoch", "2000"), 1, "refusing to arm")
        assert "u64::MAX" in (t / "crates/bloch-pos-committee/src/params.rs").read_text()
        expect("write: arms constants and runbook", run(t, "--write", "--epoch", "3400"), 0, "armed: five constants = 3400")
        src = (t / "crates/bloch-pos-committee/src/params.rs").read_text()
        assert all(f"pub const {g}_ACTIVATION_EPOCH: u64 = 3400;" in src for g in GATES), src
        assert "pub const DEPOSIT_ACTIVATION_EPOCH: u64 = u64::MAX;" in src, "DEPOSIT moved"
        assert "LIFECYCLE_EPOCH = 3400" in (t / "deploy/FLAG-DAY-LIFECYCLE.md").read_text()
        print("ok   write: DEPOSIT pinned, runbook line flipped")
        expect("write: second arming refused", run(t, "--write", "--epoch", "3500"), 1, "already")
        expect("verify: armed tree with surviving tripwires fails",
               run(t, "--verify"), 1, "VERIFY FAILED", "exit_auth_gate_is_inert", "is_not_armed")

        # Armed cleanly: constants, runbook and retired tripwires agree.
        a = base / "armed"
        build_tree(a, genesis_epochs_ago=2536, armed="3400", tripwires=False)
        expect("verify: armed tree without tripwires is consistent", run(a, "--verify"), 0, "armed at epoch 3400", "consistent")
        expect("verify: armed tree matches --epoch", run(a, "--verify", "--epoch", "3400"), 0, "consistent")
        expect("verify: armed tree at another --epoch fails", run(a, "--verify", "--epoch", "3300"), 1, "armed at 3400")
        expect("write: already-armed tree refused", run(a, "--epoch", "3500", "--write"), 1, "already")

        # Runbook disagrees with params.rs.
        rb = a / "deploy/FLAG-DAY-LIFECYCLE.md"
        rb.write_text(rb.read_text().replace("LIFECYCLE_EPOCH = 3400", "LIFECYCLE_EPOCH = unarmed"))
        expect("verify: runbook/params disagreement fails", run(a, "--verify"), 1, "records LIFECYCLE_EPOCH = unarmed")
        rb.write_text(rb.read_text().replace("LIFECYCLE_EPOCH = unarmed", "LIFECYCLE_EPOCH = 3400"))

        # Five constants differ (the compile-time assert would also refuse this).
        p = a / "crates/bloch-pos-committee/src/params.rs"
        p.write_text(p.read_text().replace("WITHDRAWAL_ACTIVATION_EPOCH: u64 = 3400", "WITHDRAWAL_ACTIVATION_EPOCH: u64 = 3401"))
        expect("verify: differing constants fail", run(a, "--verify"), 1, "constants differ")
        p.write_text(p.read_text().replace("WITHDRAWAL_ACTIVATION_EPOCH: u64 = 3401", "WITHDRAWAL_ACTIVATION_EPOCH: u64 = 3400"))

        # DEPOSIT moved off u64::MAX.
        p.write_text(p.read_text().replace("DEPOSIT_ACTIVATION_EPOCH: u64 = u64::MAX", "DEPOSIT_ACTIVATION_EPOCH: u64 = 3400"))
        expect("verify: DEPOSIT off u64::MAX fails", run(a, "--verify"), 1, "DEPOSIT_ACTIVATION_EPOCH moved")
        p.write_text(p.read_text().replace("DEPOSIT_ACTIVATION_EPOCH: u64 = 3400", "DEPOSIT_ACTIVATION_EPOCH: u64 = u64::MAX"))

        # Comment guard red on a lifecycle constant: verify fails and names it.
        (a / "scripts/check-comment-constants.py").write_text(
            "import sys\nprint('  FAIL crates/x.rs:7')\nprint('        the comment says  WITHDRAWAL_ACTIVATION_EPOCH is u64::MAX')\n"
            "print('        the code says     WITHDRAWAL_ACTIVATION_EPOCH = 3400')\nsys.exit(1)\n"
        )
        expect("verify: stale lifecycle comment fails", run(a, "--verify"), 1,
               "comment claims about lifecycle constants are stale", "crates/x.rs:7")
        # Comment guard red on something unrelated: reported, not fatal.
        (a / "scripts/check-comment-constants.py").write_text(
            "import sys\nprint('  FAIL crates/y.rs:9')\nprint('        the comment says  MAX_THINGS is 64')\n"
            "print('        the code says     MAX_THINGS = 128')\nsys.exit(1)\n"
        )
        expect("verify: unrelated stale comment is a note, not a failure", run(a, "--verify"), 0,
               "1 contradiction(s) unrelated", "consistent")
        (a / "scripts/check-comment-constants.py").write_text("import sys\nsys.exit(0)\n")

        # A manifest without the magic is refused before anything is read.
        (a / "genesis/mainnet.manifest").write_bytes(b"NOTAMANIFEST" + b"\0" * 16)
        expect("manifest without magic refused", run(a, "--epoch", "3400"), 1, "BPOSMAN")
    print("arm-lifecycle-epoch.selftest: all cases behave as documented")


if __name__ == "__main__":
    main()
