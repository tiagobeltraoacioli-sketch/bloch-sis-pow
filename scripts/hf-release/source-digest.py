#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Compute the bloch-pos source-digest of an unpacked source tree.

usage: source-digest.py --tree <dir>

Re-implements crates/bloch-pos-node/build_source_digest.rs (scope v1): every
.rs/.toml/.c/.h/.S/.s/.macros file under <tree>/crates (skipping any `.git` and
`target` directory), plus root Cargo.toml, Cargo.lock and rust-toolchain.toml.
Entries are sorted by workspace-relative, forward-slashed path; each is fed as
path, NUL, u64-LE length, bytes into SHA3-256 after the domain tag
"bloch-pos/source-digest/v1\\0".

Prints "<hex digest> <files> <bytes>", the same three values the binary reports
on the second line of `bloch-pos --version`
("source-digest sha3-256:<hex> (<files> files, <bytes> bytes) ...").
A symlink, a non-UTF-8 name or a missing root file is a hard failure, exactly
as in the build script: a partial inventory is not a source identity.
"""
import argparse
import hashlib
import os
import stat
import sys

SOURCE_EXT = {"rs", "toml", "c", "h", "S", "s", "macros"}
EXTRA = ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml")


def fail(message):
    sys.exit(f"source-digest: FAIL - {message}")


def collect(root, directory, out):
    with os.scandir(directory) as entries:
        for entry in entries:
            name = entry.name
            if name in (".git", "target"):
                continue
            mode = entry.stat(follow_symlinks=False).st_mode
            if stat.S_ISLNK(mode):
                fail(f"symlink in the hashed scope: {entry.path}")
            if stat.S_ISDIR(mode):
                collect(root, entry.path, out)
            elif stat.S_ISREG(mode):
                ext = name.rsplit(".", 1)[1] if "." in name[1:] else ""
                if ext in SOURCE_EXT:
                    rel = os.path.relpath(entry.path, root).replace("\\", "/")
                    out.append((rel, entry.path))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--tree", required=True)
    args = parser.parse_args()
    root = os.path.abspath(args.tree)
    files = []
    collect(root, os.path.join(root, "crates"), files)
    for extra in EXTRA:
        path = os.path.join(root, extra)
        try:
            mode = os.lstat(path).st_mode
        except FileNotFoundError:
            fail(f"missing {extra}")
        if not stat.S_ISREG(mode):
            fail(f"{extra} is not a regular file")
        files.append((extra, path))
    if not files:
        fail("empty inventory")
    # Rust sorts (String, PathBuf) tuples by the UTF-8 bytes of the String;
    # sorting by the encoded bytes reproduces that order exactly.
    files = sorted(set(files), key=lambda item: (item[0].encode("utf-8"), item[1]))
    hasher = hashlib.sha3_256()
    hasher.update(b"bloch-pos/source-digest/v1\0")
    total = 0
    for rel, path in files:
        with open(path, "rb") as handle:
            body = handle.read()
        total += len(body)
        hasher.update(rel.encode("utf-8"))
        hasher.update(b"\0")
        hasher.update(len(body).to_bytes(8, "little"))
        hasher.update(body)
    print(hasher.hexdigest(), len(files), total)


if __name__ == "__main__":
    main()
