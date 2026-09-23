# Bloch PoS validator upgrade — 2026-09-22

This directory contains the signed Linux x86-64 validator binary built from
commit `dade5a330181a7dd136cab1f6f173f31dbd70966`.

Binary SHA-256:

```text
1962c4a26c526e362e128a1b4ce45c20eded2c009e48f5d9eaea17741b9f5041
```

Verify the signed checksum before installing:

```bash
minisign -Vm SHA256SUMS -p bloch-release-20260922.pub
sha256sum --check SHA256SUMS
./bloch-pos --version
```

The expected version identifies source commit
`dade5a330181a7dd136cab1f6f173f31dbd70966`.

This is an upgrade artifact for an existing synchronized Genesis-4 node. It
does not include validator keys, passphrases, chain data, genesis material or
a current weak-subjectivity checkpoint. Preserve the existing node arguments
and slashing-protection data, stop the old process cleanly, replace only the
executable, and retain the prior executable for rollback.
