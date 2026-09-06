#!/usr/bin/env python3
"""Refuse a binary archive of source files under version control.

WHY THIS EXISTS
---------------
`tools/staking-cli/integration-merge/merged-consensus-files.tar.gz` — 276,226
bytes, sha256 f51dc32e2aaa86f9de2e18c8511ab397594590785dab9c02bda3fb894cb58c99 —
is a gzip of SIX consensus and node source files:

    crates/bloch-pos-committee/src/params.rs
    crates/bloch-pos-committee/src/staking.rs
    crates/bloch-pos-committee/src/transition.rs
    crates/bloch-pos-node/src/engine.rs
    crates/bloch-pos-node/src/rpc.rs
    crates/bloch-pos-node/src/store.rs

Measured 2026-09-02 it is reachable from ~130 refs including `validator-ops`
(the branch checked out in the main working tree) and it is pushed to BOTH
`origin` and `github`. Its own README names base commit `e4083f96`, which is
six commits behind fleet tip `46133196`, missing exactly `47f7644b`,
`0a3a436a`, `c99b9a12`, `650ebc4e`, `cd0cefa8` and `46133196` — the first of
those is the consensus commit the fleet runs on.

Against tag `g4-node-20260901` the archived copies differ by 347 lines
(params.rs), 229 (staking.rs), 3,306 (transition.rs), 1,314 (engine.rs), 13
(rpc.rs) and 133 (store.rs).

Unpacking it over a checkout — which its README frames as the way to reproduce
"the verified combination" — reverts six fleet commits including consensus, in
one command, from an artifact that NO diff, NO lint, NO review and NO other CI
job in this repository reads. `git diff` on a .tar.gz prints "Binary files
differ" and stops. That is the whole hazard: the bytes are versioned, they are
authoritative-looking, they are stale, and they are invisible to every reading
tool the project owns.

The README is also wrong about its own contents. It says the archive holds
"the five contested files" and states that `store.rs` "comes verbatim from
[its] branch and is not duplicated here". `store.rs` IS in the archive. So the
one human-readable description of the blob under-declares it by one consensus-
adjacent file. An archive whose own manifest is wrong is not a reference copy.

WHAT THIS GUARD DOES
--------------------
Fails the pipeline if any TRACKED file is an archive that contains source
files. Not "is large", not "is binary" — the test is specifically: does a
versioned archive carry the kind of file that version control is supposed to
be the single source of truth for.

It ALSO fails on any tracked .pyc/.pyo/.class/.o/.so — a compiled artifact
committed directly, no archive needed, same class of invisible-diff hazard in
miniature (Round-1 finding LOW-9). Caught here:
`tools/genesis4-carryover/__pycache__/build_carryover.cpython-314.pyc`,
force-added past `.gitignore`'s own `__pycache__/` + `*.pyc` rules — removed
from the index in the same commit that added this check.

Deliberately also fails on an archive it cannot open. An opaque versioned blob
that will not list is the same hazard with less evidence, and "the guard could
not read it" must not read as "the guard passed".

Binary fixtures that are genuinely data — corpora, snapshots, test vectors —
are unaffected, because they contain no source files. If one ever must contain
source, add it to ALLOWLIST below WITH a written reason, the way deny.toml
requires a rationale for an ignored advisory.

Pure Python 3. No toolchain, no build, no network.
"""

import os
import subprocess
import sys
import tarfile
import zipfile

# Extensions treated as archives. `.gz`/`.xz`/`.bz2`/`.zst` alone are single-
# file compressions rather than archives; they are still checked, because a
# compressed `transition.rs` is exactly as invisible as a tarred one.
ARCHIVE_EXTS = (
    ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz",
    ".tar.zst", ".zip", ".jar", ".7z", ".rar",
)
SOLO_COMPRESSED_EXTS = (".gz", ".bz2", ".xz", ".zst", ".lz4", ".br")

# A file inside an archive counts as SOURCE if it ends in one of these. Kept
# deliberately narrow: the point is code and build definitions, the things a
# reviewer would expect to read as a diff.
SOURCE_EXTS = (
    ".rs", ".toml", ".py", ".sh", ".bash", ".yml", ".yaml", ".nix",
    ".c", ".h", ".cc", ".cpp", ".hpp", ".go", ".js", ".ts", ".sql",
    ".lock", ".proto",
)

# TRACKED COMPILED ARTIFACTS — a second, narrower check alongside the archive
# scan above (Round-1 finding LOW-9 / the tracked `__pycache__` escape). A
# compiled .pyc/.pyo/.class/.o/.so committed directly (no archive needed) is
# the same hazard in miniature: it is a binary blob that can silently diverge
# from the source that produced it, `git diff` on it prints "Binary files
# differ", and unlike an archive it is not even labelled as a bundle of
# something — it just looks like build noise nobody meant to commit. Caught
# in the wild here: `tools/genesis4-carryover/__pycache__/
# build_carryover.cpython-314.pyc`, force-added despite `.gitignore`'s
# `__pycache__/` + `*.pyc` rules (removed from the index in the same commit
# that added this check).
COMPILED_ARTIFACT_EXTS = (".pyc", ".pyo", ".class", ".o", ".so")


def compiled_artifacts(paths: list[str]) -> list[str]:
    return [p for p in paths if p.lower().endswith(COMPILED_ARTIFACT_EXTS)]

# path -> reason. Empty on purpose. Adding an entry is a review decision.
ALLOWLIST: dict[str, str] = {}


def tracked_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", "-z"],
        check=True, stdout=subprocess.PIPE,
    ).stdout
    return [p for p in out.decode("utf-8", "surrogateescape").split("\0") if p]


def is_archive(path: str) -> bool:
    low = path.lower()
    return low.endswith(ARCHIVE_EXTS) or low.endswith(SOLO_COMPRESSED_EXTS)


def members(path: str) -> tuple[list[str] | None, str | None]:
    """Return (member names, None) or (None, why-it-could-not-be-listed)."""
    low = path.lower()
    try:
        if low.endswith((".zip", ".jar")):
            with zipfile.ZipFile(path) as z:
                return z.namelist(), None
        if tarfile.is_tarfile(path):
            with tarfile.open(path) as t:
                return t.getnames(), None
    except Exception as exc:  # noqa: BLE001 - any failure is a refusal
        return None, f"{type(exc).__name__}: {exc}"

    # Single-file compression carries exactly one member and its name is the
    # path with the compression suffix removed. `carryover.tsv.gz` is the
    # Genesis-1 carryover UTXO set (452,726 rows of real data) and must stay;
    # `transition.rs.gz` would be the hazard this guard exists for. Judging by
    # the inner name separates them without an allowlist entry for either.
    for ext in SOLO_COMPRESSED_EXTS:
        if low.endswith(ext):
            return [path[: -len(ext)]], None

    # A format Python cannot open (.7z, .rar). Opaque.
    return None, "not a listable archive format"


def main() -> int:
    root = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        check=True, stdout=subprocess.PIPE, text=True,
    ).stdout.strip()
    os.chdir(root)

    all_tracked = tracked_files()
    archives = [p for p in all_tracked if is_archive(p)]
    compiled = compiled_artifacts(all_tracked)
    print(f"check-no-source-archives: {len(archives)} tracked archive(s), "
          f"{len(compiled)} tracked compiled artifact(s) found")

    findings: list[str] = []
    for path in sorted(compiled):
        if path in ALLOWLIST:
            print(f"  ALLOWED  {path}\n           reason: {ALLOWLIST[path]}")
            continue
        findings.append(
            f"{path}\n    a tracked compiled artifact "
            f"({os.path.splitext(path)[1] or path}) — build output, not source, "
            f"and it can silently diverge from whatever produced it."
        )
    for path in sorted(archives):
        if path in ALLOWLIST:
            print(f"  ALLOWED  {path}\n           reason: {ALLOWLIST[path]}")
            continue
        names, why = members(path)
        if names is None:
            findings.append(
                f"{path}\n    could not be listed ({why}).\n"
                f"    An opaque versioned blob is refused: a guard that cannot\n"
                f"    read a file must not report that the file is fine."
            )
            continue
        src = [n for n in names if n.lower().endswith(SOURCE_EXTS)]
        if src:
            shown = "\n".join(f"      {n}" for n in sorted(src)[:20])
            more = "" if len(src) <= 20 else f"\n      ... and {len(src) - 20} more"
            findings.append(
                f"{path}\n    contains {len(src)} source file(s) of "
                f"{len(names)} member(s):\n{shown}{more}"
            )
        else:
            print(f"  ok       {path}  ({len(names)} members, no source)")

    if not findings:
        print("check-no-source-archives: PASS")
        return 0

    print()
    print("=" * 74)
    print("REFUSED: a binary archive or compiled artifact is under version control.")
    print("=" * 74)
    for f in findings:
        print(f"\n  {f}")
    print(
        "\n  Source files belong in the tree, where git diff, review, clippy and\n"
        "  every test can read them. Inside an archive, or compiled into a\n"
        "  .pyc/.pyo/.class/.o/.so, they are versioned but unreadable: they can\n"
        "  silently replace or diverge from the tree's own source with no\n"
        "  reading tool this project owns showing the change.\n"
        "\n  Delete the archive or compiled artifact and reconstruct from source,\n"
        "  or, if the bytes must be kept, add the path to ALLOWLIST in this\n"
        "  script with a written reason. There is no third option that leaves\n"
        "  the pipeline green.\n"
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
