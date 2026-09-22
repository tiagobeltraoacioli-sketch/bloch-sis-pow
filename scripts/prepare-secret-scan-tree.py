#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Copy tracked working-tree inputs for scanning, without following symlinks.

Generated/untracked build outputs are outside this source scan. Reachable Git
history is covered by the separate history job. Missing tracked files are
working-tree deletions; unmerged entries, submodules and special files refuse.
"""
from pathlib import Path
import os
import shutil
import stat
import subprocess
import sys

root = Path.cwd().resolve()
destination = Path(sys.argv[1]).resolve()
entries = subprocess.check_output(["git", "ls-files", "--stage", "-z"]).split(b"\0")
for entry in entries:
    if not entry:
        continue
    metadata, raw_name = entry.split(b"\t", 1)
    mode, _, stage = metadata.split()
    if stage != b"0" or mode == b"160000":
        raise SystemExit("secret scan: unmerged entries or submodules need explicit source coverage")
    name = Path(os.fsdecode(raw_name))
    if name.is_absolute() or ".." in name.parts:
        raise SystemExit("secret scan: invalid tracked path")
    source = root / name
    if not source.parent.resolve().is_relative_to(root):
        raise SystemExit("secret scan: tracked path traverses an external symlink")
    try:
        details = source.lstat()
    except FileNotFoundError:
        continue
    target = destination / name
    target.parent.mkdir(parents=True, exist_ok=True)
    if stat.S_ISLNK(details.st_mode):
        # Scan the committed kind of content (link text), never an external file.
        target.write_bytes(os.fsencode(os.readlink(source)))
    elif stat.S_ISREG(details.st_mode):
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        with os.fdopen(os.open(source, flags), "rb") as incoming:
            if not stat.S_ISREG(os.fstat(incoming.fileno()).st_mode):
                raise SystemExit("secret scan: tracked input changed to a special file")
            with target.open("wb") as outgoing:
                shutil.copyfileobj(incoming, outgoing)
    else:
        raise SystemExit("secret scan: tracked special file is not a source input")
