# Bloch PoS validator upgrade — 2026-10-14 (native L2 activation at epoch 5850)

This directory contains the Linux x86-64 validator binary built from commit
`78b7343a347d2c53944a7058b7cb1c2ca4efe842` in the canonical release container
(`deploy/pos-release/Dockerfile`, `scripts/build-pos-release-container.sh`).

Binary SHA-256:

```text
fa9996eda48a8d3a5beff249c1c7d9f666d9e8207c4f0a1825ba3dba3889fc18
```

Verify the signed checksum before installing:

```bash
minisign -Vm SHA256SUMS -p bloch-release-20260922.pub
sha256sum --check SHA256SUMS
./bloch-pos --version
```

The expected version is:

```text
bloch-pos-node 0.1.0-mainnet (78b7343a347d2c53944a7058b7cb1c2ca4efe842) (Genesis-4, block version 0xb10c0005)
source-digest sha3-256:820f775507cd41651adf4ed9a1aeb0ace434917ac86d5dd051593fb91aa3ea1d (299 files, 8426777 bytes) commit-source:asserted tree:asserted-clean
```

**Consensus change.** This release arms the native L2 settlement at epoch
**5850** (first slot 187200, 2026-10-17 21:31:19 UTC). Every node must run
this binary before that epoch; a node on an older binary forks off the network
at epoch 5850. Before epoch 5850, rolling back to the previous release
(`bloch-pos-2026-09-22`) is safe. After the first block of epoch 5850 is
finalized there is no rollback; the remedy for a defect is a new forward
release. If the activation is postponed, the replacement release
`bloch-pos-2026-10-14-l2-postpone` (same build, gate disarmed) must be
installed before epoch 5850.

This is an upgrade artifact for an existing synchronized Genesis-4 node. It
does not include validator keys, passphrases, chain data, genesis material or
a current weak-subjectivity checkpoint. Preserve the existing node arguments
and slashing-protection data, stop the old process cleanly, replace only the
executable, and retain the prior executable for rollback.
