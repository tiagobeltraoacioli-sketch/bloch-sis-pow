#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Write a slot-bounded prefix COPY of a Genesis-4 block log.

usage: log-prefix.py --source <dir> --dest <new dir> --before-slot <n>

Reads <source>/blocks.idx (BPOSIDX1: slot u64 LE | offset u64 LE | len u32 LE
per frame, see crates/bloch-pos-node/src/store.rs) to find the first frame whose
slot is >= <n>, and copies every byte of <source>/blocks.log before that frame
into <dest>/blocks.log. meta.bin and ws_latest.bin are copied by name. No
blocks.idx is written: the node rebuilds a missing index on open. The source is
opened read-only and never modified.

Prints one line: "prefix frames=<k> last_slot=<s> bytes=<b> before_slot=<n>".
"""
import argparse
import os
import shutil
import struct
import sys

IDX_MAGIC = b"BPOSIDX1"
ENTRY = struct.Struct("<QQI")


def fail(message):
    sys.exit(f"log-prefix: FAIL - {message}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--dest", required=True)
    parser.add_argument("--before-slot", required=True, type=int)
    args = parser.parse_args()

    log_path = os.path.join(args.source, "blocks.log")
    idx_path = os.path.join(args.source, "blocks.idx")
    for path in (log_path, idx_path, os.path.join(args.source, "meta.bin")):
        if not os.path.isfile(path):
            fail(f"{path} missing (the prefix needs the source's blocks.idx)")
    if os.path.exists(args.dest):
        fail(f"{args.dest} exists; give a new directory")
    log_size = os.path.getsize(log_path)

    with open(idx_path, "rb") as idx:
        if idx.read(8) != IDX_MAGIC:
            fail("blocks.idx has the wrong magic")
        body = idx.read()
    count = len(body) // ENTRY.size
    if count == 0:
        fail("blocks.idx is empty")
    cut = None
    frames = 0
    last_slot = None
    prev_slot = -1
    expected_offset = 0
    for i in range(count):
        slot, offset, length = ENTRY.unpack_from(body, i * ENTRY.size)
        if slot <= prev_slot or offset != expected_offset:
            fail(f"blocks.idx entry {i} is out of order or not contiguous; rebuild it on a stopped copy")
        prev_slot = slot
        expected_offset = offset + 4 + length
        if cut is None and slot >= args.before_slot:
            cut = offset
            with open(log_path, "rb") as log:
                log.seek(offset)
                prefix = log.read(4)
            if len(prefix) != 4 or struct.unpack("<I", prefix)[0] != length:
                fail(f"frame at offset {offset} does not carry the indexed length")
        if cut is None:
            frames += 1
            last_slot = slot
    if expected_offset > log_size:
        fail("blocks.idx points past the end of blocks.log")
    if cut is None:
        if expected_offset != log_size:
            fail("cut slot lies beyond the indexed part of blocks.log; the index lags the log")
        fail(f"no frame at or after slot {args.before_slot}: the copy ends at slot {last_slot}")
    if frames == 0:
        fail("the prefix would be empty")

    os.makedirs(args.dest, mode=0o700)
    with open(log_path, "rb") as src, open(os.path.join(args.dest, "blocks.log"), "xb") as dst:
        remaining = cut
        while remaining:
            chunk = src.read(min(remaining, 16 << 20))
            if not chunk:
                fail("blocks.log shrank while copying")
            dst.write(chunk)
            remaining -= len(chunk)
        dst.flush()
        os.fsync(dst.fileno())
    for name in ("meta.bin", "ws_latest.bin"):
        path = os.path.join(args.source, name)
        if os.path.isfile(path):
            shutil.copyfile(path, os.path.join(args.dest, name))
    print(f"prefix frames={frames} last_slot={last_slot} bytes={cut} before_slot={args.before_slot}")


if __name__ == "__main__":
    main()
