#!/usr/bin/env python3
"""Prepare a conservative signing reservation for a fenced legacy validator.

This creates a NEW staging file, not an import or reset of an existing journal.
The operator must first stop every instance of this identity and establish an
upper bound on every slot it could have signed. The output reserves all proposal
and attestation slots through that bound, and source/target epochs through its
epoch. Install only for a legacy signer with NO existing journal, after checking
the identity and network again. Keep the original public history as evidence.
No private key is read. This does not choose a canonical chain or start a node.
"""

import argparse
import hashlib
import os
from pathlib import Path
import struct


def prepare(meta: bytes, pubkey_hash: str, through_slot: int) -> bytes:
    if (len(meta) != 44 or meta[:8] != b"BPOSMETA"
            or meta[8:12] != struct.pack("<I", 0xB10C0005)):
        raise ValueError("expected the validator's 44-byte public network metadata")
    public = bytes.fromhex(pubkey_hash)
    if len(public) != 32 or len(pubkey_hash) != 64:
        raise ValueError("expected a 32-byte SHA3-256 public-key hash")
    if not 0 < through_slot < (1 << 64) - 1:
        raise ValueError("through-slot must be positive and below the unarmed sentinel")
    # Genesis-4 fixes 32 slots per epoch. The Rust compatibility test binds this
    # calculation to the actual consensus constant and the shipped journal reader.
    epoch = through_slot // 32
    body = b"BPOSSLP2" + struct.pack("<IQQQQ", 2, through_slot, through_slot, epoch, epoch)
    body += public + meta[12:44]
    return body + hashlib.shake_256(body).digest(32)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--meta", type=Path, required=True)
    parser.add_argument("--pubkey-hash", required=True)
    parser.add_argument("--through-slot", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    record = prepare(args.meta.read_bytes(), args.pubkey_hash, args.through_slot)
    # Never truncate, replace, follow a destination symlink, or lower an existing
    # watermark. A partial failed write remains a corrupt staging file, not a pass.
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as target:
        target.write(record)
        target.flush()
        os.fsync(target.fileno())
    directory = os.open(args.output.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    print(f"Prepared reservation through slot {args.through_slot}; no validator was started.")


if __name__ == "__main__":
    main()
