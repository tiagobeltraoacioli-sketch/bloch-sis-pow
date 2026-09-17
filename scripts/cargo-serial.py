#!/usr/bin/env python3
"""Serialize build commands using a private, user-owned lock, never a /tmp executable."""
import fcntl
import os
from pathlib import Path
import stat
import subprocess
import sys


def run(command, directory):
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise PermissionError("build lock directory must be user-owned and mode 0700")
    fd = os.open(directory / "cargo.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise PermissionError("build lock must be a private user-owned regular file")
        fcntl.flock(fd, fcntl.LOCK_EX)
        return subprocess.call(command)
    finally:
        os.close(fd)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit("usage: cargo-serial.py COMMAND [ARG ...]")
    try:
        raise SystemExit(run(sys.argv[1:], Path.home() / ".cache" / "bloch-build-lock"))
    except (OSError, ValueError) as error:
        raise SystemExit(f"build command refused: {error}")
