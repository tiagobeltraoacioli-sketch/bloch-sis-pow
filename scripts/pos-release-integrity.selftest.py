#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Prove the lockfile section of `pos-release-integrity.sh` fires, and on the right file.

Why this file exists
--------------------
The lockfile guard was green for its whole life while guarding nothing. It
resolved `--locked` from inside crates/bloch-pos-node and crates/bloch-pos-
committee and then diffed *their* Cargo.lock files — but both crates are
members of the root virtual workspace, so cargo has never read either file.
Measured on the tree before the fix: append a line to the root Cargo.lock and
the guard's drift diff still exited 0. Six dead per-member lockfiles had
accumulated beside live crates, reading as authoritative.

A guard nobody has tried to break is a guard nobody knows works. So this drives
the REAL script — copied byte-for-byte into a synthetic workspace built in a
temporary directory, never the real tree — in its `--locks-only` mode, and
asserts BOTH directions:

  * an honest tree passes, and passes for the stated reason (the success line
    must say the ROOT lock governs the members);
  * a stale root Cargo.lock FAILS — the case the old guard could not see;
  * a resurrected per-member Cargo.lock FAILS and is named, so the deletion
    cannot quietly undo itself;
  * a member that grows its own `[workspace]` table FAILS instead of going
    unguarded — the shape the old comments wrongly believed was already true;
  * a renamed PoS crate FAILS rather than dropping out of the guard's scope.

The post-build drift diff (section 3) needs a compiler and a minute of build to
reach, so it is asserted at the source level instead: it must name the root
Cargo.lock and must name no per-member lockfile.

Run: `python3 scripts/pos-release-integrity.selftest.py`
Exit 0 = the guard behaves as documented on all cases.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
GUARD = os.path.join(HERE, "pos-release-integrity.sh")

ROOT_MANIFEST = """\
[workspace]
resolver = "2"
members = [
{members}]
"""

CRATE_MANIFEST = """\
[package]
name = "{name}"
version = "0.1.0"
edition = "2021"
"""


def build_fixture(tmp: str, members=("bloch-pos-node", "bloch-pos-committee")) -> str:
    """A minimal, dependency-free stand-in for the real workspace layout."""
    root = os.path.join(tmp, "repo")
    os.makedirs(os.path.join(root, "scripts"))
    shutil.copy(GUARD, os.path.join(root, "scripts", "pos-release-integrity.sh"))
    write_root(root, members)
    for name in members:
        crate = os.path.join(root, "crates", name)
        os.makedirs(os.path.join(crate, "src"))
        write(os.path.join(crate, "Cargo.toml"), CRATE_MANIFEST.format(name=name))
        write(os.path.join(crate, "src", "lib.rs"), "")
    relock(root)
    # A git repo, because the drift assertion the guard shares between sections
    # 1 and 3 is a `git diff` — the very check that used to watch the wrong
    # files. Without a repo it could not be exercised at all.
    git(root, "init", "-q")
    git(root, "add", "-A")
    git(root, "-c", "user.email=selftest@invalid", "-c", "user.name=selftest",
        "commit", "-qm", "fixture")
    return root


def git(root: str, *args: str) -> None:
    subprocess.run(["git", "-C", root, *args], check=True, capture_output=True)


def write(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def write_root(root: str, members) -> None:
    body = "".join(f'    "crates/{m}",\n' for m in members)
    write(os.path.join(root, "Cargo.toml"), ROOT_MANIFEST.format(members=body))


def relock(root: str) -> None:
    subprocess.run(
        ["cargo", "generate-lockfile", "--offline"],
        cwd=root, check=True, capture_output=True,
    )


def run_guard(root: str):
    return subprocess.run(
        ["bash", os.path.join(root, "scripts", "pos-release-integrity.sh"),
         "--locks-only"],
        cwd=root, capture_output=True, text=True,
    )


FAILURES: list[str] = []


def expect_pass(case: str, root: str, must_say: str) -> None:
    res = run_guard(root)
    out = res.stdout + res.stderr
    if res.returncode != 0:
        FAILURES.append(f"{case}: honest tree was rejected (exit {res.returncode})\n{out}")
    elif must_say not in out:
        FAILURES.append(f"{case}: passed, but not for the stated reason "
                        f"(missing {must_say!r})\n{out}")
    else:
        print(f"  ok   {case}")


def expect_fail(case: str, root: str, must_say: str) -> None:
    res = run_guard(root)
    out = res.stdout + res.stderr
    if res.returncode == 0:
        FAILURES.append(f"{case}: guard PASSED on a tree it must reject\n{out}")
    elif must_say not in out:
        FAILURES.append(f"{case}: failed, but for the wrong reason "
                        f"(missing {must_say!r})\n{out}")
    else:
        print(f"  ok   {case}")


def main() -> int:
    if shutil.which("cargo") is None:
        print("pos-release-integrity.selftest: FAIL — cargo is not on PATH; "
              "this selftest cannot certify the guard without it.", file=sys.stderr)
        return 1

    print("pos-release-integrity.selftest: driving scripts/pos-release-integrity.sh "
          "--locks-only against synthetic workspaces")

    # 1 — honest tree passes, and says the ROOT lock is what governs.
    with tempfile.TemporaryDirectory() as tmp:
        expect_pass("honest workspace", build_fixture(tmp),
                    "root Cargo.lock resolves --locked")

    # 2 — the case the old guard could not see: the root lock no longer matches
    #     the manifests. A third member is added without regenerating the lock.
    with tempfile.TemporaryDirectory() as tmp:
        root = build_fixture(tmp)
        crate = os.path.join(root, "crates", "bloch-pos-extra")
        os.makedirs(os.path.join(crate, "src"))
        write(os.path.join(crate, "Cargo.toml"),
              CRATE_MANIFEST.format(name="bloch-pos-extra"))
        write(os.path.join(crate, "src", "lib.rs"), "")
        write_root(root, ("bloch-pos-node", "bloch-pos-committee", "bloch-pos-extra"))
        expect_fail("stale root Cargo.lock", root, "root Cargo.lock is stale")

    # 3 — a deleted per-member lockfile comes back.
    with tempfile.TemporaryDirectory() as tmp:
        root = build_fixture(tmp)
        shutil.copy(os.path.join(root, "Cargo.lock"),
                    os.path.join(root, "crates", "bloch-pos-committee", "Cargo.lock"))
        expect_fail("resurrected per-member lockfile", root,
                    "crates/bloch-pos-committee/Cargo.lock")

    # 4 — a PoS crate grows its own [workspace] table. It then really would need
    #     its own lock, so the guard must stop rather than keep reporting green.
    #     The split crate is given a lock of its own here on purpose: without
    #     one the guard already dies at the --locked resolve, and it is the
    #     *plausible* variant — split, locked, looks tidy — that has to be
    #     caught by the membership assert rather than sailing through.
    with tempfile.TemporaryDirectory() as tmp:
        root = build_fixture(tmp)
        crate = os.path.join(root, "crates", "bloch-pos-node")
        with open(os.path.join(crate, "Cargo.toml"), "a", encoding="utf-8") as fh:
            fh.write("\n[workspace]\n")
        write_root(root, ("bloch-pos-committee",))
        relock(root)
        relock(crate)
        expect_fail("member split into its own workspace", root, "workspace root")

    # 5 — a PoS crate is renamed. The guard must not quietly narrow its scope.
    with tempfile.TemporaryDirectory() as tmp:
        root = build_fixture(tmp, members=("bloch-pos-node", "bloch-pos-consensus"))
        expect_fail("renamed PoS crate", root, "is not a member")

    # 6 — the defect itself, behaviourally: a rewritten ROOT Cargo.lock must be
    #     caught. Measured on the real tree before the fix, the guard's drift
    #     diff named crates/bloch-pos-{node,committee}/Cargo.lock and exited 0
    #     on exactly this mutation. A pristine per-member lockfile is planted
    #     alongside so a guard that regressed to the old paths would still see
    #     "no change" and pass — the fixture reproduces the fail-open, not just
    #     the drift.
    with tempfile.TemporaryDirectory() as tmp:
        root = build_fixture(tmp)
        shutil.copy(os.path.join(root, "Cargo.lock"),
                    os.path.join(root, "crates", "bloch-pos-node", "Cargo.lock.pristine"))
        with open(os.path.join(root, "Cargo.lock"), "a", encoding="utf-8") as fh:
            fh.write("\n# rewritten by a build\n")
        expect_fail("rewritten root Cargo.lock", root, "root Cargo.lock differs")

    # 7 — source assertion for section 3's call site, which needs a real build
    #     to reach: it must go through the shared root-lock assertion and must
    #     not have drifted back to a per-member path.
    with open(GUARD, encoding="utf-8") as fh:
        src = fh.read()
    diff_lines = [ln for ln in src.splitlines() if "git diff --exit-code" in ln]
    if len(diff_lines) != 1:
        FAILURES.append("drift check: expected exactly one `git diff --exit-code` "
                        f"line (inside assert_root_lock_undrifted), found "
                        f"{len(diff_lines)}")
    elif '"$REPO_ROOT/Cargo.lock"' not in diff_lines[0]:
        FAILURES.append("drift check: does not watch the root Cargo.lock: "
                        f"{diff_lines[0].strip()!r}")
    elif re.search(r"/Cargo\.lock", diff_lines[0].replace('"$REPO_ROOT/Cargo.lock"', "")):
        FAILURES.append("drift check: also watches another Cargo.lock; only the "
                        "root lock is written by a build: "
                        f"{diff_lines[0].strip()!r}")
    elif src.count("assert_root_lock_undrifted") < 3:
        FAILURES.append("section 3 no longer calls assert_root_lock_undrifted — "
                        "the post-build drift check is gone or was inlined "
                        "past the selftest's reach.")
    else:
        print("  ok   drift check watches only the root Cargo.lock, from both sections")

    if FAILURES:
        print("\npos-release-integrity.selftest: FAIL", file=sys.stderr)
        for f in FAILURES:
            print(f"\n- {f}", file=sys.stderr)
        return 1
    print("\npos-release-integrity.selftest: PASS — the lockfile guard fires on "
          "root-lock drift, on resurrected per-member lockfiles, and on a "
          "workspace layout it no longer covers.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
