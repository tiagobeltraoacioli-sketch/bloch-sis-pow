#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Plan, arm, verify or rehearse the ADR-041 lifecycle flag day (epoch L).

The five ADR-041 constants in `crates/bloch-pos-committee/src/params.rs` —
`FUNDED_VALIDATOR_ADMISSION`, `EXIT_AUTH`, `WITHDRAWAL`, `SLASHING_EVIDENCE`
and `RANDAO_RECOMMIT` (`_ACTIVATION_EPOCH`) — ship at `u64::MAX` and a
compile-time assert in the same file refuses a build in which they differ.
Arming them is ONE edit to ONE number, made once, in the commit that also
carries the runbook (`deploy/FLAG-DAY-LIFECYCLE.md`) and retires the
tripwire tests that pin `u64::MAX`. This tool does the mechanical half of
that commit and MEASURES the semantic half, so the arming engineer works
from a list the tree produced rather than one somebody remembered.

Modes (exactly one):

  plan  (default)   Print what arming at --epoch would change and whether
                    the epoch is admissible against the manifest clock.
                    Touches nothing.
  --write           Apply the five constants and the runbook line to the
                    checkout. Refuses a partially armed tree, an epoch in
                    the past, or one with less lead than --min-lead-epochs.
  --verify          Assert the checkout is self-consistent: five constants
                    equal, `DEPOSIT_ACTIVATION_EPOCH` still `u64::MAX`, the
                    runbook line matches, no retired tripwire survives an
                    armed tree, and `scripts/check-comment-constants.py`
                    passes. Exit 1 on any mismatch. Runs no cargo.
  --rehearse        Copy the tree to a temporary directory (`git ls-files`),
                    arm the copy at --epoch, and run the gate-related test
                    filters of both live crates plus the comment guard.
                    Prints every test and comment that would go red at L —
                    the tripwires the arming commit must retire — and
                    deletes the copy. The checkout is never edited.

The epoch's wall-clock time comes from the genesis manifest (`genesis_time_ms`
and `slot_ms` at fixed offsets behind the `BPOSMAN` magic), never from a
hard-coded date. `SLOTS_PER_EPOCH` is read from params.rs for the same reason.
"""
from __future__ import annotations

import argparse
import datetime as dt
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]  # overridden by --root
PARAMS = Path("crates/bloch-pos-committee/src/params.rs")
RUNBOOK = Path("deploy/FLAG-DAY-LIFECYCLE.md")
MANIFEST = Path("genesis/mainnet.manifest")
TOOLCHAIN = Path("crates/bloch-pos-node/rust-toolchain.toml")

GATES = [
    "FUNDED_VALIDATOR_ADMISSION",
    "EXIT_AUTH",
    "WITHDRAWAL",
    "SLASHING_EVIDENCE",
    "RANDAO_RECOMMIT",
]
# Must never move: the unfunded legacy era does not reopen (ADR-041 D5).
PINNED_MAX = ["DEPOSIT"]
LIFECYCLE_NAMES = [f"{g}_ACTIVATION_EPOCH" for g in GATES + PINNED_MAX]

# The runbook carries one machine-readable line; `--write` flips it and
# `--verify` holds it to the constant, the same pairing
# `leak_recovery_armed_epoch_matches_the_runbook` enforces for epoch 2700.
RUNBOOK_LINE = re.compile(r"^LIFECYCLE_EPOCH = (unarmed|\d+)$", re.M)

# Tripwire tests whose own doc comment says "whoever arms it deletes this
# test". Their survival in an armed tree is a verify-time error; every other
# test that flips meaning at L is found by `--rehearse`, not by this list.
RETIRE_ON_ARM = [
    ("crates/bloch-pos-committee/src/transition.rs", "fn exit_auth_gate_is_inert()"),
    ("crates/bloch-pos-committee/src/transition.rs", "fn slashing_evidence_gate_is_inert()"),
    ("crates/bloch-pos-committee/src/transition.rs", "fn randao_recommit_gate_is_inert()"),
    ("crates/bloch-pos-committee/src/transition.rs", "fn withdrawal_gate_is_inert()"),
    (
        "crates/bloch-pos-node/tests/slashing_backed_finality_claims.rs",
        "fn the_activation_constant_exists_in_one_place_and_is_not_armed()",
    ),
]

# Six days at 90 epochs/day — the lead the epoch-2700 flag day was armed
# with (chain at ~2075 on 2026-09-06), and 3x the demonstrated 64-validator
# rollout time. A shorter lead is a founder decision, passed explicitly.
DEFAULT_MIN_LEAD_EPOCHS = 540

# The gate-related test filters run by --rehearse. libtest matches a test
# when ANY filter is a substring of its path, so this is a union.
COMMITTEE_FILTERS = [
    "gate",
    "inert",
    "armed",
    "below_the_gate",
    "funded",
    "lifecycle",
    "withdraw",
    "exit_v2",
    "recommit",
    "evidence",
]
NODE_TARGETS = [
    ["--test", "slashing_backed_finality_claims"],
    ["--bin", "bloch-pos", "validator_admission_tests"],
    ["--bin", "bloch-pos", "rpc"],
    ["--test", "validator_deposit_cli"],
]


def die(message: str, code: int = 1) -> "NoReturn":  # noqa: F821
    print(f"arm-lifecycle-epoch: {message}", file=sys.stderr)
    raise SystemExit(code)


# ── Source readers ──────────────────────────────────────────────────────────


def const_pattern(name: str) -> re.Pattern:
    return re.compile(
        rf"^pub const {name}_ACTIVATION_EPOCH: u64 = (u64::MAX|\d[\d_]*);$", re.M
    )


def read_constant(source: str, name: str) -> str:
    hits = const_pattern(name).findall(source)
    if len(hits) != 1:
        die(f"{name}_ACTIVATION_EPOCH must be declared exactly once in {PARAMS}; found {len(hits)}")
    return hits[0]


def as_epoch(value: str) -> int | None:
    return None if value == "u64::MAX" else int(value.replace("_", ""))


def slots_per_epoch(source: str) -> int:
    hit = re.search(r"^pub const SLOTS_PER_EPOCH: u64 = (\d+);$", source, re.M)
    if not hit:
        die("SLOTS_PER_EPOCH not found in params.rs")
    return int(hit.group(1))


def manifest_clock(path: Path) -> tuple[int, int]:
    """(genesis_time_ms, slot_ms) — the two fixed-offset fields behind the magic."""
    head = path.read_bytes()[:24]
    if len(head) < 24 or not head.startswith(b"BPOSMAN"):
        die(f"{path} does not start with the BPOSMAN manifest magic")
    genesis_ms = struct.unpack_from("<Q", head, 8)[0]
    slot_ms = struct.unpack_from("<Q", head, 16)[0]
    if slot_ms == 0:
        die(f"{path} declares slot_ms = 0")
    return genesis_ms, slot_ms


class Clock:
    def __init__(self, manifest: Path, spe: int) -> None:
        self.genesis_ms, self.slot_ms = manifest_clock(manifest)
        self.epoch_ms = self.slot_ms * spe

    def epoch_utc(self, epoch: int) -> dt.datetime:
        ms = self.genesis_ms + epoch * self.epoch_ms
        return dt.datetime.fromtimestamp(ms / 1000, dt.timezone.utc)

    def wall_epoch(self, now: dt.datetime | None = None) -> int:
        now = now or dt.datetime.now(dt.timezone.utc)
        elapsed_ms = int(now.timestamp() * 1000) - self.genesis_ms
        return max(elapsed_ms, 0) // self.epoch_ms

    def per_day(self) -> float:
        return 86_400_000 / self.epoch_ms


def fmt(t: dt.datetime) -> str:
    return t.strftime("%Y-%m-%d %H:%M UTC")


def lifecycle_contradictions(guard_output: str) -> tuple[list[str], int]:
    """(FAIL blocks naming a lifecycle constant, count of other FAIL blocks).

    `check-comment-constants.py` reports every stale value claim in the
    workspace; this tool answers for the six lifecycle constants only and
    reports the rest as a count, so a pre-existing contradiction elsewhere
    neither hides a lifecycle one nor blocks a verdict it has nothing to do
    with. The general guard stays a CI job in its own right.
    """
    blocks: list[list[str]] = []
    for line in guard_output.splitlines():
        if line.lstrip().startswith("FAIL "):
            blocks.append([line.strip()])
        elif blocks and line.startswith(" ") and blocks[-1] and not line.lstrip().startswith("FAIL"):
            if line.strip().startswith(("the comment says", "the code says", "declared at")):
                blocks[-1].append(line.strip())
    ours = ["\n      ".join(b) for b in blocks if any(n in " ".join(b) for n in LIFECYCLE_NAMES)]
    return ours, len(blocks) - len(ours)


# ── Runbook line ────────────────────────────────────────────────────────────


def runbook_value(text: str) -> str:
    hits = RUNBOOK_LINE.findall(text)
    if len(hits) != 1:
        die(f"{RUNBOOK} must carry exactly one `LIFECYCLE_EPOCH = ...` line; found {len(hits)}")
    return hits[0]


def set_runbook_value(text: str, value: str) -> str:
    runbook_value(text)
    return RUNBOOK_LINE.sub(f"LIFECYCLE_EPOCH = {value}", text, count=1)


# ── Arming edit ─────────────────────────────────────────────────────────────


def arm_source(source: str, epoch: int) -> str:
    out = source
    for gate in GATES:
        current = read_constant(out, gate)
        if current != "u64::MAX":
            die(
                f"{gate}_ACTIVATION_EPOCH is already {current}; this tool arms an "
                "unarmed tree only. A second change of the epoch is a new flag day."
            )
        out = const_pattern(gate).sub(
            f"pub const {gate}_ACTIVATION_EPOCH: u64 = {epoch};", out, count=1
        )
    for gate in PINNED_MAX:
        if read_constant(out, gate) != "u64::MAX":
            die(f"{gate}_ACTIVATION_EPOCH must stay u64::MAX (ADR-041 D5)")
    return out


def admissible_epoch(clock: Clock, epoch: int, min_lead: int) -> list[str]:
    """Reasons the epoch is NOT admissible; empty means it is."""
    now_epoch = clock.wall_epoch()
    reasons = []
    if epoch <= now_epoch:
        reasons.append(
            f"epoch {epoch} is not strictly in the future: the wall clock is at epoch "
            f"{now_epoch}. An epoch already past arms silently against the whole history."
        )
    elif epoch - now_epoch < min_lead:
        reasons.append(
            f"lead is {epoch - now_epoch} epochs ({(epoch - now_epoch) / clock.per_day():.1f} days); "
            f"minimum is {min_lead} ({min_lead / clock.per_day():.1f} days). "
            "Pass --min-lead-epochs explicitly if the founder accepts a shorter rollout."
        )
    return reasons


# ── Modes ───────────────────────────────────────────────────────────────────


def mode_plan(args, source: str, clock: Clock) -> None:
    epoch = args.epoch
    print(f"Lifecycle flag day plan — epoch {epoch}")
    print(f"  epoch {epoch} begins   {fmt(clock.epoch_utc(epoch))}")
    now_epoch = clock.wall_epoch()
    print(f"  wall clock now        epoch {now_epoch} ({fmt(dt.datetime.now(dt.timezone.utc))})")
    print(f"  lead                  {epoch - now_epoch} epochs = {(epoch - now_epoch) / clock.per_day():.1f} days")
    print("  constants:")
    for gate in GATES:
        print(f"    {gate}_ACTIVATION_EPOCH: {read_constant(source, gate)} -> {epoch}")
    for gate in PINNED_MAX:
        print(f"    {gate}_ACTIVATION_EPOCH: {read_constant(source, gate)} (unchanged, pinned)")
    print(f"  runbook line          LIFECYCLE_EPOCH = {epoch}   ({RUNBOOK})")
    reasons = admissible_epoch(clock, epoch, args.min_lead_epochs)
    for reason in reasons:
        print(f"  REFUSED: {reason}")
    print("  tripwires: run --rehearse to measure which tests and comments go red at this epoch.")
    if reasons:
        raise SystemExit(1)


def mode_write(args, source: str, clock: Clock) -> None:
    reasons = admissible_epoch(clock, args.epoch, args.min_lead_epochs)
    if reasons:
        die("refusing to arm:\n  " + "\n  ".join(reasons))
    runbook_path = ROOT / RUNBOOK
    if not runbook_path.is_file():
        die(f"{RUNBOOK} is missing; the runbook lands before the constant, not after")
    runbook = runbook_path.read_text()
    if runbook_value(runbook) != "unarmed":
        die(f"{RUNBOOK} already records LIFECYCLE_EPOCH = {runbook_value(runbook)}")
    armed = arm_source(source, args.epoch)
    (ROOT / PARAMS).write_text(armed)
    runbook_path.write_text(set_runbook_value(runbook, str(args.epoch)))
    print(f"armed: five constants = {args.epoch} in {PARAMS}; LIFECYCLE_EPOCH = {args.epoch} in {RUNBOOK}")
    print(f"epoch {args.epoch} begins {fmt(clock.epoch_utc(args.epoch))}")
    print("next: retire the tripwires (--rehearse lists them), then --verify, then the release cut.")


def mode_verify(args, source: str, clock: Clock) -> None:
    errors: list[str] = []
    values = {gate: read_constant(source, gate) for gate in GATES}
    distinct = set(values.values())
    if len(distinct) != 1:
        errors.append("the five ADR-041 constants differ: " + ", ".join(f"{k}={v}" for k, v in values.items()))
    for gate in PINNED_MAX:
        if read_constant(source, gate) != "u64::MAX":
            errors.append(f"{gate}_ACTIVATION_EPOCH moved off u64::MAX")
    armed = as_epoch(next(iter(distinct))) if len(distinct) == 1 else None
    runbook_path = ROOT / RUNBOOK
    if runbook_path.is_file():
        recorded = runbook_value(runbook_path.read_text())
        expected = "unarmed" if armed is None else str(armed)
        if recorded != expected:
            errors.append(f"{RUNBOOK} records LIFECYCLE_EPOCH = {recorded}; params.rs says {expected}")
    else:
        errors.append(f"{RUNBOOK} is missing")
    if args.epoch is not None and armed != args.epoch:
        errors.append(f"--epoch {args.epoch} given but the tree is armed at {armed}")
    if armed is not None:
        for rel, needle in RETIRE_ON_ARM:
            if needle in (ROOT / rel).read_text():
                errors.append(f"{rel}: `{needle}` still pins u64::MAX in an armed tree")
        print(f"armed at epoch {armed} = {fmt(clock.epoch_utc(armed))}")
    else:
        print("unarmed: all five constants at u64::MAX")
    guard = subprocess.run(
        [sys.executable, "scripts/check-comment-constants.py"],
        cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    ours, others = lifecycle_contradictions(guard.stdout)
    if ours:
        errors.append("comment claims about lifecycle constants are stale:\n    " + "\n    ".join(ours))
    if others:
        print(f"note: check-comment-constants.py reports {others} contradiction(s) unrelated to the lifecycle "
              "constants; that guard is its own CI job and its verdict is not this tool's to override")
    if errors:
        print("VERIFY FAILED")
        for e in errors:
            print(f"  - {e}")
        raise SystemExit(1)
    print("verify: consistent")


def pinned_toolchain() -> str:
    pin = re.search(r'^channel\s*=\s*"([^"]+)"', (ROOT / TOOLCHAIN).read_text(), re.M)
    if not pin:
        die(f"cannot read the toolchain pin from {TOOLCHAIN}")
    return pin.group(1)


def copy_tree(dest: Path) -> None:
    files = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=ROOT
    ).decode().split("\0")
    for name in files:
        if not name:
            continue
        rel = Path(name)
        if rel.is_absolute() or ".." in rel.parts:
            die("unexpected path in the source inventory")
        src = ROOT / rel
        if src.is_file():
            target = dest / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, target)


FAILED_LINE = re.compile(r"^test (\S+) \.\.\. FAILED$", re.M)
RESULT_LINE = re.compile(r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed", re.M)


def run_capture(cmd: list[str], cwd: Path, env: dict) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


def mode_rehearse(args, source: str, clock: Clock) -> None:
    epoch = args.epoch
    toolchain = pinned_toolchain()
    cargo = ["cargo", f"+{toolchain}"]
    print(f"Rehearsing the arming commit at epoch {epoch} ({fmt(clock.epoch_utc(epoch))}) in a disposable copy.")
    with tempfile.TemporaryDirectory(prefix="bloch-lifecycle-arming-") as temp:
        copy = Path(temp)
        copy_tree(copy)
        (copy / PARAMS).write_text(arm_source(source, epoch))
        runbook = copy / RUNBOOK
        if runbook.is_file():
            runbook.write_text(set_runbook_value(runbook.read_text(), str(epoch)))
        env = os.environ.copy()
        # ALWAYS a separate target, never the shipping one, and no override:
        # measured 2026-09-11 — pointing this at the developer's `target/`
        # left an ARMED committee rlib that the shipping tree's next
        # `cargo test -p bloch-pos-node` linked against, so five prose-lock
        # tests reported the flag day armed on an unarmed checkout. A cold
        # build here costs minutes; a contaminated shipping build costs a
        # wrong verdict.
        env["CARGO_TARGET_DIR"] = str(ROOT / "target" / "lifecycle-arming-rehearsal")

        print("\n[1/4] compile-time arming-order asserts (cargo check)")
        check = run_capture([*cargo, "check", "--locked", "-p", "bloch-pos-committee"], copy, env)
        if check.returncode != 0:
            print(check.stdout)
            die("the armed copy does not compile — the const asserts in params.rs refused it")
        print("  ok: an armed committee crate compiles")

        print("\n[2/4] comment claims that become false (scripts/check-comment-constants.py)")
        guard = run_capture([sys.executable, "scripts/check-comment-constants.py"], copy, env)
        stale, unrelated = lifecycle_contradictions(guard.stdout)
        if not stale:
            print("  none")
        for block in stale:
            print(f"  {block}")
        if unrelated:
            print(f"  ({unrelated} contradiction(s) unrelated to the lifecycle constants also reported — "
                  "pre-existing, not created by arming)")

        red: list[str] = []
        infra: list[str] = []

        def collect(label: str, cmd: list[str]) -> None:
            proc = run_capture(cmd, copy, env)
            failed = FAILED_LINE.findall(proc.stdout)
            results = RESULT_LINE.findall(proc.stdout)
            if not results:
                infra.append(f"{label}: no test result line (compile error or missing target)\n{proc.stdout[-4000:]}")
                return
            passed = sum(int(r[1]) for r in results)
            print(f"  {label}: {passed} passed, {len(failed)} failed")
            red.extend(f"{label} :: {name}" for name in failed)

        print("\n[3/4] committee tests that go red at L (filters: " + ", ".join(COMMITTEE_FILTERS) + ")")
        collect(
            "bloch-pos-committee --lib",
            [*cargo, "test", "--locked", "-p", "bloch-pos-committee", "--lib", "--", *COMMITTEE_FILTERS],
        )
        print("\n[4/4] node tests that go red at L")
        for target in NODE_TARGETS:
            collect(
                "bloch-pos-node " + " ".join(target),
                [*cargo, "test", "--locked", "-p", "bloch-pos-node", *target[:2], *target[2:]],
            )

    if (ROOT / PARAMS).read_text() != source:
        die("the checkout changed during the rehearsal; it must not")
    print("\n══ Tripwires the arming commit must retire (measured at epoch %d) ══" % epoch)
    if not red and not stale:
        print("  none — the tree arms clean")
    for name in red:
        print(f"  test    {name}")
    for block in stale:
        print(f"  comment {block}")
    for item in infra:
        print(f"  INFRA   {item}")
    print(
        "\nEach red test pinned `u64::MAX` or asserted an epoch above L is closed. Per the "
        "epoch-2700 precedent (`leak_recovery_armed_epoch_matches_the_runbook`), a pin test "
        "becomes an armed-epoch-matches-the-runbook test in the same commit; a "
        "function-of-the-epoch test keeps its shape with L as the boundary. Do not delete a "
        "test without replacing what it guarded. The checkout was not modified."
    )
    if infra:
        raise SystemExit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--write", action="store_true", help="arm the checkout at --epoch")
    mode.add_argument("--verify", action="store_true", help="assert the checkout is self-consistent")
    mode.add_argument("--rehearse", action="store_true", help="measure the tripwires at --epoch in a disposable copy")
    parser.add_argument("--epoch", type=int, help="the lifecycle epoch L (required except for --verify)")
    parser.add_argument("--root", type=Path, help="repository root (default: this script's repository; the selftest points it at a synthetic tree)")
    parser.add_argument("--manifest", type=Path, default=MANIFEST, help=f"genesis manifest (default {MANIFEST})")
    parser.add_argument(
        "--min-lead-epochs", type=int, default=DEFAULT_MIN_LEAD_EPOCHS,
        help=f"minimum epochs between now and L for plan/--write (default {DEFAULT_MIN_LEAD_EPOCHS})",
    )
    args = parser.parse_args()
    global ROOT
    if args.root is not None:
        ROOT = args.root.resolve()
    if not args.verify and args.epoch is None:
        parser.error("--epoch is required")
    if args.epoch is not None and args.epoch <= 0:
        parser.error("--epoch must be a positive epoch number")
    source = (ROOT / PARAMS).read_text()
    manifest = args.manifest if args.manifest.is_absolute() else ROOT / args.manifest
    clock = Clock(manifest, slots_per_epoch(source))
    if args.write:
        mode_write(args, source, clock)
    elif args.verify:
        mode_verify(args, source, clock)
    elif args.rehearse:
        mode_rehearse(args, source, clock)
    else:
        mode_plan(args, source, clock)


if __name__ == "__main__":
    main()
