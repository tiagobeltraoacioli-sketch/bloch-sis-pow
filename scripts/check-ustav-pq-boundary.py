#!/usr/bin/env python3
"""Tripwire against classical signature libraries entering the native Ustav tree.

Run from the repository root; optional arguments select Cargo/toolchain, e.g.
python3 scripts/check-ustav-pq-boundary.py cargo +1.94.1
This is a dependency regression guard, not a cryptographic proof or binary audit.
"""
import subprocess
import sys

CLASSICAL = {
    "ecdsa", "k256", "p256", "p384", "p521", "elliptic-curve",
    "secp256k1", "secp256k1-sys", "ed25519", "ed25519-dalek", "rsa",
}


def main():
    cargo = sys.argv[1:] or ["cargo"]
    result = subprocess.run(
        cargo + ["tree", "--locked", "-p", "bloch-ustav", "--edges", "normal", "--prefix", "none", "--format", "{p}"],
        check=True, capture_output=True, text=True,
    )
    packages = {line.split()[0] for line in result.stdout.splitlines() if line.strip()}
    if "bloch-ustav" not in packages:
        raise SystemExit("Cannot establish the native Ustav dependency graph")
    forbidden = packages & CLASSICAL
    if forbidden:
        raise SystemExit("Classical signature dependency in native Ustav: " + ", ".join(sorted(forbidden)))
    print("Ustav native dependency boundary: OK (no listed classical signature libraries)")


if __name__ == "__main__":
    main()
