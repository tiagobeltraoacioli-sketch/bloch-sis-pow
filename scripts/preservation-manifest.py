#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""
The preservation manifest, executable.

Answers ONE question objectively: does a given worktree still contain
everything `deploy/armado-e1400` (ab9ca4e1) put on 64 live nodes?

The manifest was derived from `deploy/armado-e1400` itself and from the seven
perf commits listed in PERF_SYMBOLS below.  It was NOT derived from anyone's
integration result; a ruler measured against the thing it is judging measures
nothing.

# Why this file is paranoid

The defect it exists to catch is a suite that PASSES EMPTY.  Two of the five
proof suites in this repo are 100% `#[ignore]`d, so a bare `cargo test`
reports `ok` for them having run zero tests.  Therefore:

  * a missing file is a FAIL, never a skip;
  * a test that cannot be found is a FAIL, never a skip;
  * a cargo run that reports fewer tests RUN than the source declares
    `#[test]` is a FAIL, even when cargo says `ok`;
  * a symbol that exists but is only ever called from `#[cfg(test)]` code is
    a FAIL — the manifest is about the hot path, not about file presence;
  * and if the number of checks actually executed is zero, the script exits
    non-zero with a loud banner instead of printing a clean report.

Usage:
    preservation-manifest.py --worktree PATH [--label NAME]
                             [--no-cargo] [--target-dir DIR]
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

# ─────────────────────────── the manifest itself ────────────────────────────

COMMITTEE = "crates/bloch-pos-committee"
NODE = "crates/bloch-pos-node"

PARAMS = f"{COMMITTEE}/src/params.rs"

# The five suites the armed build shipped as its proof, with the crate they
# belong to and how they must be invoked.
# (path, crate, cargo target selector, tests the ARMED build put there)
#
# The named tests matter as much as the path.  `properties.rs` exists on the
# merge base too, with 27 tests; a file-exists check calls that PASS while the
# two differential tests 401ed4e2 added are gone.  That is the shape of the
# vacuous pass, so every suite carries the specific names it must still hold.
SUITES = [
    (f"{NODE}/tests/replay_hotpath_perf.rs",            "bloch-pos-node",      ("--test", "replay_hotpath_perf"),
     ["perf_incremental_path_vs_full_root", "perf_steady_state_loop", "perf_state_root_breakdown"]),
    (f"{COMMITTEE}/tests/state_root_carryover_scale.rs","bloch-pos-committee", ("--test", "state_root_carryover_scale"),
     ["state_root_differential_at_carryover_scale", "measured_tree_depth_scaling"]),
    (f"{COMMITTEE}/tests/forkchoice_asymptotics.rs",    "bloch-pos-committee", ("--test", "forkchoice_asymptotics"),
     ["head_step_count_is_linear_in_depth_and_the_old_one_was_quadratic"]),
    (f"{COMMITTEE}/tests/properties.rs",                "bloch-pos-committee", ("--test", "properties"),
     ["forkchoice_head_matches_the_reference_implementation",
      "a_fully_tied_tree_resolves_identically_in_both_implementations"]),
    (f"{NODE}/src/engine/replay_bench.rs",              "bloch-pos-node",      ("--lib",),
     ["perf_end_to_end_replay", "perf_replay_depth_curve_justified"]),
]

# `replay_bench.rs` is an inline module of the lib target, so its tests share
# the `--lib` harness with everything else in bloch-pos-node.  Its tests are
# recognised by this prefix.
REPLAY_BENCH_PREFIX = "engine::replay_bench::"

# The perf symbols, derived commit by commit.  Each entry:
#   (commit, symbol, defining file, must-be-called-from-production)
# "called from production" = at least one reference outside every
# `#[cfg(test)]` module and outside `tests/`.
PERF_SYMBOLS = [
    # 229d95a6 — perf(state-root): make the SMT incremental
    ("229d95a6", "Smt",                          f"{COMMITTEE}/src/state_root.rs", True),
    ("229d95a6", "node_insert",                  f"{COMMITTEE}/src/state_root.rs", True),
    ("229d95a6", "node_remove",                  f"{COMMITTEE}/src/state_root.rs", True),
    ("229d95a6", "from_leaf_map",                f"{COMMITTEE}/src/state_root.rs", True),
    ("229d95a6", "state_root_with_eutxo_tree",   f"{COMMITTEE}/src/state_root.rs", True),
    ("229d95a6", "build_state_tree_with_eutxo_tree", f"{COMMITTEE}/src/state_root.rs", True),
    # 22751083 — perf(state-root): bulk-build the eUTXO subtree from scratch
    ("22751083", "build_subtree",                f"{COMMITTEE}/src/state_root.rs", True),
    # 401ed4e2 — perf(forkchoice): LMD-GHOST head bottom-up
    ("401ed4e2", "subtree_weights",              f"{COMMITTEE}/src/forkchoice.rs", True),
    ("401ed4e2", "head_reference",               f"{COMMITTEE}/src/forkchoice.rs", False),  # differential oracle, test-only by design
    # 126d41a1 — perf(engine): skip the fork-choice recompute
    ("126d41a1", "ForkChoiceInputs",             f"{NODE}/src/engine.rs", True),
    ("126d41a1", "forkchoice_inputs",            f"{NODE}/src/engine.rs", True),
    # b945a09e — perf: memoize the rolled state; reorg from the fork point
    ("b945a09e", "StateCell",                    f"{NODE}/src/engine.rs", True),
    ("b945a09e", "rolled_to",                    f"{NODE}/src/engine.rs", True),
    ("b945a09e", "rolled_to_uncached",           f"{NODE}/src/engine.rs", False),  # `#[cfg(test)]` differential oracle by design
    ("b945a09e", "remember_state",               f"{NODE}/src/engine.rs", True),
    ("b945a09e", "state_at_canonical",           f"{NODE}/src/engine.rs", True),
    ("b945a09e", "MEMO_CAP",                     f"{NODE}/src/engine.rs", True),
    ("b945a09e", "REORG_STATE_WINDOW",           f"{NODE}/src/engine.rs", True),
    # e46a13d4 — perf: the third state root a slot paid for was a log line
    ("e46a13d4", "root_computations",            f"{COMMITTEE}/src/transition.rs", False),  # counter, read by the budget tests
    # ae4cffbb — perf(rpc): getchaininfo re-hashed a root the header carried
    ("ae4cffbb", "head_state_root",              f"{NODE}/src/engine.rs", True),
]

# Structural pins.  A symbol can survive a merge and still be off the hot
# path if the CALL SHAPE reverts.  Each pin is (name, file, regex, must_match).
#
# ae4cffbb's whole point: `chain_info_json` stopped deriving the root and
# started taking it as a parameter, and the engine hands it the head header's
# root.  Reverting either half silently restores the 733 ms walk per RPC call.
STRUCTURAL_PINS = [
    ("getchaininfo takes the root as a parameter",
     f"{NODE}/src/rpc.rs",
     r'fn\s+chain_info_json\s*\((?:[^)]|\n)*?\bstate_root\s*:\s*\[\s*u8\s*;\s*32\s*\]', True),
    ("getchaininfo does NOT re-derive the root",
     f"{NODE}/src/rpc.rs",
     r'\bfn\s+chain_info_json\b(?:[^\n]*\n){0,140}?[^\n]*\bstate\.state_root\s*\(', False),
    ("serve_rpc feeds ChainInfo the head header root",
     f"{NODE}/src/engine.rs",
     r'RpcRequest::ChainInfo\s*=>\s*Ok\(\s*rpc::chain_info_json\((?:[^\n]*\n){0,12}?[^\n]*self\.head_state_root\s*\(\s*\)', True),
    ("apply_block reaches the incremental root, not a full walk",
     f"{COMMITTEE}/src/transition.rs",
     r'state_root_with_eutxo_tree\s*\(', True),
    ("the memoised rolled state is what the engine serves",
     f"{NODE}/src/engine.rs",
     r'\bfn\s+rolled_to\s*\(&self,\s*epoch:\s*u64\)\s*->\s*Arc<CommittedState>', True),
    # 229d95a6 replaced the flat BTreeMap tree with a node tree.  The name
    # `Smt` survives the revert; the representation does not.
    ("the SMT is node-based, not a flat leaf map",
     f"{COMMITTEE}/src/state_root.rs",
     r'\benum\s+Node\b', True),
    ("the eUTXO set hands out a tree, not a leaf map",
     f"{COMMITTEE}/src/transition.rs",
     r'\bfn\s+tree\s*\(&self\)\s*->\s*&(?:crate::)?state_root::Smt', True),
]

TRIPWIRE = "leaked_roster_armed_epoch_matches_the_runbook"
TRIPWIRE_FILE = f"{COMMITTEE}/src/transition.rs"

ARMED_EPOCH = 1400

# ─────────────────────────────── reporting ──────────────────────────────────

class Report:
    def __init__(self, label):
        self.label = label
        self.rows = []          # (group, item, status, detail)
        self.executed = 0

    def add(self, group, item, ok, detail=""):
        self.executed += 1
        self.rows.append((group, item, "PASS" if ok else "FAIL", detail))
        return ok

    def note(self, group, item, detail):
        """A recorded measurement, not a pass/fail gate. Does NOT count."""
        self.rows.append((group, item, "INFO", detail))

    @property
    def failures(self):
        return [r for r in self.rows if r[2] == "FAIL"]

    def render(self):
        w = max(len(r[1]) for r in self.rows) if self.rows else 10
        out = []
        out.append("=" * (w + 60))
        out.append(f"PRESERVATION MANIFEST — {self.label}")
        out.append("=" * (w + 60))
        group = None
        for g, item, st, detail in self.rows:
            if g != group:
                out.append("")
                out.append(f"[{g}]")
                group = g
            out.append(f"  {st:<4}  {item:<{w}}  {detail}")
        out.append("")
        out.append("-" * (w + 60))
        gates = [r for r in self.rows if r[2] in ("PASS", "FAIL")]
        npass = sum(1 for r in gates if r[2] == "PASS")
        nfail = len(gates) - npass
        out.append(f"gates executed: {len(gates)}   PASS {npass}   FAIL {nfail}")
        return "\n".join(out)


# ────────────────────────────── rust helpers ────────────────────────────────

CFG_TEST_RE = re.compile(r'#\[cfg\(test\)\]')

def strip_cfg_test(src: str) -> str:
    """Blank out every `#[cfg(test)] ... { ... }` item by brace matching.

    Conservative: on any structure it does not understand it blanks nothing,
    which can only produce a FALSE PASS on the *call-site* check — so the
    caller must treat a stripped-out ratio of 0 on a file that clearly has
    `#[cfg(test)]` as suspicious.  We report the stripped byte count so that
    is visible rather than silent.
    """
    out = list(src)
    for m in CFG_TEST_RE.finditer(src):
        i = src.find("{", m.end())
        if i == -1:
            continue
        # refuse to jump over another item's body: only accept a `{` that is
        # preceded by mod/fn/impl-ish text with no `;` in between
        between = src[m.end():i]
        if ";" in between:
            continue
        depth = 0
        j = i
        n = len(src)
        in_str = in_chr = in_lc = in_bc = False
        while j < n:
            c = src[j]
            nxt = src[j + 1] if j + 1 < n else ""
            if in_lc:
                if c == "\n":
                    in_lc = False
            elif in_bc:
                if c == "*" and nxt == "/":
                    in_bc = False
                    j += 1
            elif in_str:
                if c == "\\":
                    j += 1
                elif c == '"':
                    in_str = False
            elif in_chr:
                if c == "\\":
                    j += 1
                elif c == "'":
                    in_chr = False
            else:
                if c == "/" and nxt == "/":
                    in_lc = True
                    j += 1
                elif c == "/" and nxt == "*":
                    in_bc = True
                    j += 1
                elif c == '"':
                    in_str = True
                elif c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                    if depth == 0:
                        j += 1
                        break
            j += 1
        for k in range(m.start(), min(j, n)):
            out[k] = " "
    return "".join(out)


def strip_comments(src: str) -> str:
    out = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/":
            while i < n and src[i] != "\n":
                i += 1
        elif c == "/" and nxt == "*":
            i += 2
            while i < n and not (src[i] == "*" and i + 1 < n and src[i + 1] == "/"):
                i += 1
            i += 2
        elif c == '"':
            out.append(c); i += 1
            while i < n:
                if src[i] == "\\":
                    i += 2
                    continue
                if src[i] == '"':
                    break
                i += 1
            out.append('"'); i += 1
        else:
            out.append(c); i += 1
    return "".join(out)


TEST_MOD_DECL = re.compile(r'#\[cfg\(test\)\]\s*(?:pub\s+)?mod\s+(\w+)\s*;')

def production_sources(root: Path):
    """Every .rs under the two consensus crates' src/, minus test-only files.

    A file pulled in by `#[cfg(test)] mod foo;` is not production code even
    though nothing inside it says so — `engine/replay_bench.rs` is exactly
    that.  Counting a call from there as "on the hot path" is the vacuous
    pass this whole script exists to refuse.
    """
    files = []
    for crate in (COMMITTEE, NODE):
        d = root / crate / "src"
        if not d.is_dir():
            continue
        files.extend(sorted(d.rglob("*.rs")))
    excluded = set()
    for p in files:
        try:
            txt = p.read_text()
        except OSError:
            continue
        for m in TEST_MOD_DECL.finditer(txt):
            name = m.group(1)
            stem = p.with_suffix("")
            for cand in (p.parent / f"{name}.rs", stem / f"{name}.rs",
                         p.parent / name / "mod.rs", stem / name / "mod.rs"):
                excluded.add(cand.resolve())
    for p in files:
        if p.resolve() in excluded:
            continue
        yield p


def const_value(text: str, name: str):
    m = re.search(r'\bconst\s+' + re.escape(name) + r'\s*:\s*u64\s*=\s*([^;]+);', text)
    return m.group(1).strip() if m else None


# ────────────────────────────────── checks ──────────────────────────────────

def check_constants(root: Path, rep: Report):
    g = "A. consensus constants"
    p = root / PARAMS
    if not p.is_file():
        rep.add(g, PARAMS, False, "FILE MISSING — the params module is gone")
        rep.add(g, "LEAKED_ROSTER_ACTIVATION_EPOCH == 1400", False, "unresolvable: params.rs missing")
        rep.add(g, "FUNDED_STAKE_ACTIVATION_EPOCH inert", False, "unresolvable: params.rs missing")
        return
    text = strip_comments(p.read_text())

    v = const_value(text, "LEAKED_ROSTER_ACTIVATION_EPOCH")
    if v is None:
        rep.add(g, "LEAKED_ROSTER_ACTIVATION_EPOCH == 1400", False,
                "CONSTANT ABSENT from params.rs — the armed flag day was deleted")
    else:
        rep.add(g, "LEAKED_ROSTER_ACTIVATION_EPOCH == 1400", v.replace("_", "") == str(ARMED_EPOCH),
                f"found `{v}` (ab9ca4e1 armed it at {ARMED_EPOCH}; it is live on 64 nodes)")

    v = const_value(text, "FUNDED_STAKE_ACTIVATION_EPOCH")
    if v is None:
        # Absent is the deployed reality: the funded-stake work is not in
        # ab9ca4e1 at all.  Absent == cannot fire == inert.  Recorded as a
        # distinct state, never silently folded into PASS.
        rep.add(g, "FUNDED_STAKE_ACTIVATION_EPOCH inert", True,
                "ABSENT — constant not present on this branch, so nothing can arm (state: NOT-INTEGRATED)")
    else:
        armed = v.replace("_", "").strip() != "u64::MAX"
        rep.add(g, "FUNDED_STAKE_ACTIVATION_EPOCH inert", not armed,
                f"found `{v}` — must be u64::MAX; arming is the founder's decision, not a merge's")


def check_tripwire_source(root: Path, rep: Report):
    g = "B. tripwire (source)"
    p = root / TRIPWIRE_FILE
    if not p.is_file():
        rep.add(g, f"{TRIPWIRE} present", False, f"FILE MISSING: {TRIPWIRE_FILE}")
        rep.add(g, f"{TRIPWIRE} actually asserts", False, "unresolvable: transition.rs missing")
        return None
    src = p.read_text()
    m = re.search(r'fn\s+' + re.escape(TRIPWIRE) + r'\s*\(', src)
    if not m:
        rep.add(g, f"{TRIPWIRE} present", False,
                f"test function NOT FOUND in {TRIPWIRE_FILE} — the pin on the armed epoch is gone")
        rep.add(g, f"{TRIPWIRE} actually asserts", False, "unresolvable: the test does not exist")
        return None
    line = src[:m.start()].count("\n") + 1
    rep.add(g, f"{TRIPWIRE} present", True, f"{TRIPWIRE_FILE}:{line}")
    # a tripwire with no assertion is a tripwire that passes empty
    body = src[m.end(): m.end() + 2000]
    end = body.find("\n    }")
    body = body[: end if end != -1 else 2000]
    has_assert = "assert" in body
    mentions_const = "LEAKED_ROSTER_ACTIVATION_EPOCH" in body
    mentions_value = re.search(r'\b1400\b|1_400', body) is not None
    rep.add(g, f"{TRIPWIRE} actually asserts", has_assert and mentions_const and mentions_value,
            f"assert={has_assert} names-const={mentions_const} names-1400={mentions_value}")
    return line


def declared_tests(path: Path) -> int:
    """Count `#[test]` attributes outside comments."""
    if not path.is_file():
        return -1
    return len(re.findall(r'#\[\s*test\s*\]', strip_comments(path.read_text())))


def check_suites_source(root: Path, rep: Report):
    g = "C. proof suites (source)"
    present = []
    for rel, crate, sel, required in SUITES:
        p = root / rel
        if not p.is_file():
            rep.add(g, rel, False, "FILE MISSING")
            continue
        n = declared_tests(p)
        if n <= 0:
            rep.add(g, rel, False, f"file present but declares {n} `#[test]` — a suite that can only pass empty")
            continue
        src = strip_comments(p.read_text())
        missing = [t for t in required if not re.search(r'\bfn\s+' + re.escape(t) + r'\s*\(', src)]
        size = p.stat().st_size
        if missing:
            rep.add(g, rel, False,
                    f"{n} `#[test]` declared, {size} bytes — but MISSING the armed build's tests: {', '.join(missing)}")
            continue
        rep.add(g, rel, True, f"{n} `#[test]` declared, {size} bytes, all {len(required)} pinned test(s) present")
        present.append((rel, crate, sel, n, required))
    return present


def check_symbols(root: Path, rep: Report):
    g = "D. perf symbols on the hot path"
    # build the production corpus once
    corpus = {}
    for p in production_sources(root):
        raw = p.read_text()
        corpus[p] = strip_comments(strip_cfg_test(raw))

    for commit, sym, rel, must_be_prod in PERF_SYMBOLS:
        p = root / rel
        if not p.is_file():
            rep.add(g, f"{sym} ({commit})", False, f"defining file MISSING: {rel}")
            continue
        defsrc = strip_comments(p.read_text())
        defined = re.search(
            r'\b(fn|struct|enum|const|static|type|trait)\s+' + re.escape(sym) + r'\b', defsrc)
        if not defined:
            rep.add(g, f"{sym} ({commit})", False, f"SYMBOL NOT DEFINED in {rel}")
            continue
        line = defsrc[:defined.start()].count("\n") + 1
        if not must_be_prod:
            rep.add(g, f"{sym} ({commit})", True, f"defined {rel}:{line} (oracle/counter — no prod call required)")
            continue
        # find a use outside cfg(test), outside the definition line itself
        uses = []
        pat = re.compile(r'\b' + re.escape(sym) + r'\b')
        for q, txt in corpus.items():
            for m in pat.finditer(txt):
                ln = txt[:m.start()].count("\n") + 1
                # skip the definition site
                ctx = txt[max(0, m.start() - 40):m.start()]
                if re.search(r'\b(fn|struct|enum|const|static|type|trait)\s+$', ctx):
                    continue
                uses.append(f"{q.relative_to(root)}:{ln}")
        if uses:
            rep.add(g, f"{sym} ({commit})", True,
                    f"defined {rel}:{line}; {len(uses)} production use(s), e.g. {uses[0]}")
        else:
            rep.add(g, f"{sym} ({commit})", False,
                    f"defined {rel}:{line} but NEVER referenced from non-test code — file kept, hot path lost")


def check_structural(root: Path, rep: Report):
    g = "D2. structural pins (call shape)"
    for name, rel, pattern, must_match in STRUCTURAL_PINS:
        p = root / rel
        if not p.is_file():
            rep.add(g, name, False, f"FILE MISSING: {rel}")
            continue
        txt = strip_comments(strip_cfg_test(p.read_text()))
        hit = re.search(pattern, txt)
        ok = bool(hit) if must_match else not hit
        where = ""
        if hit:
            where = f"{rel}:{txt[:hit.start()].count(chr(10)) + 1}"
        rep.add(g, name, ok,
                (f"matched at {where}" if hit else "no match")
                + ("" if must_match else "  (this pattern MUST NOT appear)"))


# ─────────────────────────────── cargo gates ────────────────────────────────

def run(cmd, cwd, env, timeout=5400):
    t0 = time.time()
    pr = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout)
    return pr, time.time() - t0


def parse_libtest_json(out: str):
    """Return (started, ok, failed, names) from `--format json` output."""
    started = ok = failed = 0
    names = []
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if ev.get("type") == "test" and ev.get("event") == "started":
            started += 1
            names.append(ev.get("name", ""))
        elif ev.get("type") == "test" and ev.get("event") == "ok":
            ok += 1
        elif ev.get("type") == "test" and ev.get("event") in ("failed", "timeout"):
            failed += 1
    return started, ok, failed, names


def parse_plain(out: str):
    """Fallback: sum `test result:` lines."""
    passed = failed = 0
    for m in re.finditer(r'test result: \w+\. (\d+) passed; (\d+) failed', out):
        passed += int(m.group(1))
        failed += int(m.group(2))
    return passed, failed


def cargo_env(target_dir):
    env = dict(os.environ)
    if target_dir:
        env["CARGO_TARGET_DIR"] = str(target_dir)
    env["RUSTC_BOOTSTRAP"] = "1"   # allows -Z unstable-options for --format json
    return env


def check_cargo(root: Path, rep: Report, present, target_dir):
    g = "E. proof suites (executed)"
    env = cargo_env(target_dir)

    # 1. everything must compile first; a compile error is a FAIL, not a skip.
    pr, secs = run(["cargo", "build", "--workspace", "--tests"], root, env)
    if not rep.add(g, "cargo build --workspace --tests", pr.returncode == 0,
                   f"{secs:.0f}s" + ("" if pr.returncode == 0 else
                                     " — " + (pr.stderr.strip().splitlines() or ["?"])[-1][:160])):
        rep.add(g, "suites executed", False, "not attempted: the workspace does not build")
        return

    for rel, crate, sel, declared, required in present:
        cmd = ["cargo", "test", "-p", crate, *sel, "--",
               "--include-ignored", "--test-threads", "1",
               "-Z", "unstable-options", "--format", "json"]
        if sel == ("--lib",):
            cmd.insert(cmd.index("--"), REPLAY_BENCH_PREFIX)
        pr, secs = run(cmd, root, env)
        started, ok, failed, names = parse_libtest_json(pr.stdout)
        detail = f"declared {declared}, ran {started}, ok {ok}, failed {failed}, {secs:.0f}s"
        if started == 0:
            rep.add(g, rel, False, detail + "  <-- SUITE RAN EMPTY (this is the defect)")
        elif failed or pr.returncode != 0:
            bad = [n for n in names]
            rep.add(g, rel, False, detail + f"  first={bad[0] if bad else '?'}")
        elif started < declared:
            rep.add(g, rel, False, detail + "  <-- fewer tests ran than the source declares")
        else:
            never_ran = [t for t in required if not any(n.endswith(t) or n == t for n in names)]
            if never_ran:
                rep.add(g, rel, False, detail + f"  <-- pinned test(s) never RAN: {', '.join(never_ran)}")
            else:
                rep.add(g, rel, True, detail + f"; all {len(required)} pinned test(s) ran")

    # 2. the tripwire must run, by name, and report exactly one test.
    cmd = ["cargo", "test", "-p", "bloch-pos-committee", "--lib", TRIPWIRE, "--",
           "--exact", "--include-ignored", "-Z", "unstable-options", "--format", "json"]
    pr, secs = run(cmd, root, env)
    started, ok, failed, names = parse_libtest_json(pr.stdout)
    matched = [n for n in names if n.endswith(TRIPWIRE)]
    rep.add("B. tripwire (source)", f"{TRIPWIRE} runs and passes",
            started >= 1 and ok >= 1 and failed == 0 and bool(matched) and pr.returncode == 0,
            f"ran {started}, ok {ok}, failed {failed}, matched-by-name={bool(matched)}, {secs:.0f}s")

    # 3. workspace test count, for comparison against the lastro's 550.
    total_run = total_ok = total_failed = 0
    pr, secs = run(["cargo", "test", "--workspace", "--", "-Z", "unstable-options", "--format", "json"],
                   root, env)
    s, o, f, _ = parse_libtest_json(pr.stdout)
    if s == 0:
        s2, f2 = parse_plain(pr.stdout)
        s, o, f = s2 + f2, s2, f2
    total_run, total_ok, total_failed = s, o, f
    rep.add("F. workspace", "cargo test --workspace is green", f == 0 and pr.returncode == 0,
            f"{total_run} run, {total_ok} ok, {total_failed} failed, {secs:.0f}s")
    rep.note("F. workspace", "workspace test count (default, no --include-ignored)", str(total_run))

    pr, secs = run(["cargo", "test", "--workspace", "--",
                    "--include-ignored", "-Z", "unstable-options", "--format", "json"],
                   root, env, timeout=10800)
    s, o, f, _ = parse_libtest_json(pr.stdout)
    rep.note("F. workspace", "workspace test count (--include-ignored)", f"{s} run, {o} ok, {f} failed, {secs:.0f}s")


# ──────────────────────────────────── main ──────────────────────────────────

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--worktree", required=True)
    ap.add_argument("--label", default=None)
    ap.add_argument("--no-cargo", action="store_true",
                    help="static gates only; the report is marked INCOMPLETE")
    ap.add_argument("--target-dir", default=None)
    args = ap.parse_args()

    root = Path(args.worktree).resolve()
    if not root.is_dir():
        print(f"FATAL: worktree {root} does not exist", file=sys.stderr)
        return 2
    label = args.label or f"{root} @ {subprocess.run(['git','-C',str(root),'rev-parse','--short','HEAD'],capture_output=True,text=True).stdout.strip()}"

    rep = Report(label)
    check_constants(root, rep)
    check_tripwire_source(root, rep)
    present = check_suites_source(root, rep)
    check_symbols(root, rep)
    check_structural(root, rep)
    if not args.no_cargo:
        check_cargo(root, rep, present, args.target_dir)
    else:
        rep.note("E. proof suites (executed)", "cargo", "SKIPPED by --no-cargo; report is INCOMPLETE")

    # ── the self-guard: a verifier that verified nothing must not look clean
    gates = [r for r in rep.rows if r[2] in ("PASS", "FAIL")]
    print(rep.render())
    if len(gates) == 0:
        print("\n" + "!" * 70)
        print("!! THE VERIFIER EXECUTED ZERO GATES. This report means NOTHING.")
        print("!" * 70)
        return 2
    expected_min = 2 + 2 + len(SUITES) + len(PERF_SYMBOLS) + len(STRUCTURAL_PINS)
    if not args.no_cargo:
        expected_min += 3  # build + tripwire-run + workspace-green
    if len(gates) < expected_min:
        print("\n" + "!" * 70)
        print(f"!! ONLY {len(gates)} GATES RAN; the manifest declares at least {expected_min}.")
        print("!! Something was skipped rather than failed. Treat as FAIL.")
        print("!" * 70)
        return 2
    if rep.failures:
        print(f"\nRESULT: FAIL ({len(rep.failures)} gate(s) failed)")
        for g, item, _, detail in rep.failures:
            print(f"  - [{g}] {item}: {detail}")
        return 1
    print("\nRESULT: PASS — every gate in the preservation manifest holds")
    return 0


if __name__ == "__main__":
    sys.exit(main())
