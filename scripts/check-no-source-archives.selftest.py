#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Prove check-no-source-archives.py fires on a tracked compiled artifact and on a source-carrying archive.

Round-1 finding LOW-9 added the compiled-artifact check (a tracked .pyc/.pyo/
.class/.o/.so — caught in the wild as
`tools/genesis4-carryover/__pycache__/build_carryover.cpython-314.pyc`); this
selftest builds a synthetic git repo in a temp dir — never the real one — and
asserts:

  * a tracked .pyc fails, named by path;
  * an ALLOWLISTed .pyc-shaped path stays green (same escape hatch the
    archive check already has, exercised the same way);
  * a tracked archive containing a source file still fails (the pre-existing
    behaviour this change must not regress);
  * a tracked archive containing only data stays green;
  * a repo with neither shape stays green.

Run: python3 scripts/check-no-source-archives.selftest.py
Exit 0 = the guard behaves as documented on all cases.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tarfile
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
CHECKER = os.path.join(HERE, "check-no-source-archives.py")


def git(*args: str, cwd: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True, check=True,
        env={**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
             "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"},
    )


def init_repo() -> str:
    tmp = tempfile.mkdtemp()
    git("init", "-q", cwd=tmp)
    return tmp


def run_checker(repo_root: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, CHECKER], cwd=repo_root, capture_output=True, text=True,
    )


def commit_all(repo_root: str) -> None:
    git("add", "-A", cwd=repo_root)
    git("commit", "-q", "-m", "t", cwd=repo_root)


def case_tracked_pyc_fails() -> str | None:
    repo = init_repo()
    pkg = os.path.join(repo, "tools", "genesis4-carryover", "__pycache__")
    os.makedirs(pkg, exist_ok=True)
    with open(os.path.join(pkg, "build_carryover.cpython-314.pyc"), "wb") as fh:
        fh.write(b"\x00fake bytecode\x00")
    commit_all(repo)
    r = run_checker(repo)
    if r.returncode == 0:
        return "tracked .pyc did not fail the guard:\n%s" % r.stdout
    if "build_carryover.cpython-314.pyc" not in r.stdout:
        return "failure did not name the .pyc path:\n%s" % r.stdout
    return None


def case_allowlisted_pyc_passes() -> str | None:
    # Exercise the ALLOWLIST escape hatch with a copy of the real checker
    # patched to allow one path — proves the hatch works without needing to
    # touch the real ALLOWLIST (which is empty by design).
    repo = init_repo()
    os.makedirs(os.path.join(repo, "vendor"), exist_ok=True)
    target = os.path.join(repo, "vendor", "frozen.pyc")
    with open(target, "wb") as fh:
        fh.write(b"\x00frozen\x00")
    commit_all(repo)

    with open(CHECKER, encoding="utf-8") as fh:
        src = fh.read()
    patched = src.replace(
        "ALLOWLIST: dict[str, str] = {}",
        'ALLOWLIST: dict[str, str] = {"vendor/frozen.pyc": "test fixture"}',
    )
    assert patched != src, "selftest fixture drift: ALLOWLIST sentinel not found"
    checker_copy = os.path.join(repo, "checker.py")
    with open(checker_copy, "w", encoding="utf-8") as fh:
        fh.write(patched)

    r = subprocess.run([sys.executable, checker_copy], cwd=repo, capture_output=True, text=True)
    if r.returncode != 0:
        return "an ALLOWLISTed .pyc still failed the guard:\n%s%s" % (r.stdout, r.stderr)
    if "ALLOWED" not in r.stdout:
        return "allowlisted case did not print ALLOWED:\n%s" % r.stdout
    return None


def case_archive_with_source_fails() -> str | None:
    repo = init_repo()
    src_file = os.path.join(repo, "leaked.rs")
    with open(src_file, "w", encoding="utf-8") as fh:
        fh.write("fn main() {}\n")
    archive_path = os.path.join(repo, "bundle.tar.gz")
    with tarfile.open(archive_path, "w:gz") as tf:
        tf.add(src_file, arcname="crates/leaked.rs")
    os.remove(src_file)
    commit_all(repo)
    r = run_checker(repo)
    if r.returncode == 0:
        return "an archive containing a .rs file did not fail:\n%s" % r.stdout
    if "bundle.tar.gz" not in r.stdout or "leaked.rs" not in r.stdout:
        return "failure did not name the archive and the source member:\n%s" % r.stdout
    return None


def case_data_only_archive_passes() -> str | None:
    repo = init_repo()
    data_file = os.path.join(repo, "snapshot.tsv")
    with open(data_file, "w", encoding="utf-8") as fh:
        fh.write("a\tb\tc\n")
    archive_path = os.path.join(repo, "snapshot.tsv.gz")
    import gzip
    with open(data_file, "rb") as src, gzip.open(archive_path, "wb") as dst:
        dst.write(src.read())
    os.remove(data_file)
    commit_all(repo)
    r = run_checker(repo)
    if r.returncode != 0:
        return "a data-only .gz was rejected:\n%s%s" % (r.stdout, r.stderr)
    return None


def case_clean_repo_passes() -> str | None:
    repo = init_repo()
    with open(os.path.join(repo, "README.md"), "w", encoding="utf-8") as fh:
        fh.write("hello\n")
    commit_all(repo)
    r = run_checker(repo)
    if r.returncode != 0:
        return "a repo with neither shape failed the guard:\n%s%s" % (r.stdout, r.stderr)
    return None


def main() -> int:
    if not os.path.exists(CHECKER):
        print("selftest: FAIL — checker script not found at %s" % CHECKER)
        return 1

    cases = [
        ("tracked .pyc fails, named by path", case_tracked_pyc_fails),
        ("ALLOWLISTed .pyc stays green", case_allowlisted_pyc_passes),
        ("archive containing a source file still fails (no regression)", case_archive_with_source_fails),
        ("archive containing only data stays green (no regression)", case_data_only_archive_passes),
        ("a clean repo stays green", case_clean_repo_passes),
    ]

    failures = []
    for name, fn in cases:
        err = fn()
        if err:
            failures.append((name, err))

    if failures:
        print("check-no-source-archives selftest: FAIL — %d/%d cases\n" % (len(failures), len(cases)))
        for name, err in failures:
            print("  * %s\n    %s" % (name, err.replace("\n", "\n    ")))
        return 1

    print("check-no-source-archives selftest: OK — %d cases behave as documented" % len(cases))
    return 0


if __name__ == "__main__":
    sys.exit(main())
