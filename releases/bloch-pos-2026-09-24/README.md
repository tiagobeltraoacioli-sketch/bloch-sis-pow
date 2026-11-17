# Bloch PoS validator upgrade — 2026-09-24

Signed Linux x86-64 binary built from source commit
`4d4c5075872c622fdd26aa418a9d249ec95fbcea`.

- [Download the binary](https://blochl1.com/releases/2026-09-24/bloch-pos)
- [Validator guide](https://blochl1.com/validators/guide)
- [Source at the build commit](https://github.com/tiagobeltraoacioli-sketch/bloch-sis-pow/tree/4d4c5075872c622fdd26aa418a9d249ec95fbcea)
- [Previous signed release](https://blochl1.com/releases/2026-09-22/README.md)

## Verify before installing

The release uses the existing `bloch-release-20260922.pub` signing key. Verify
its identity against your previously trusted copy or an independent trusted
channel before trusting a newly downloaded key.

Download the files into a new directory on the target Linux host:

```bash
base=https://blochl1.com/releases/2026-09-24
for name in bloch-pos SHA256SUMS SHA256SUMS.minisig bloch-release-20260922.pub BUILD-INFO release.json; do
  curl --fail --show-error --location "$base/$name" --output "$name" || exit 1
done
minisign -Vm SHA256SUMS -p bloch-release-20260922.pub || exit 1
sha256sum --check SHA256SUMS || exit 1
chmod 0755 bloch-pos
./bloch-pos --version
```

Proceed only if both signature and checksum verification succeed. Expected
binary SHA-256:

```text
fb8a65cbd9721d794bd4c2151b50d82d85a7df2299d59d7bad44a7635c30b46a
```

The version must identify source commit
`4d4c5075872c622fdd26aa418a9d249ec95fbcea`, Genesis-4 and block version
`0xb10c0005`. The release binary was reproduced byte for byte on two Linux
builders; `BUILD-INFO` records the source, build snapshot and artifact hash.
The detached signature authenticates `SHA256SUMS` and therefore the binary;
`BUILD-INFO`, this README and `release.json` are supplementary metadata.

## Upgrade an existing synchronized node

1. Preserve the service configuration, key environment, chain data and
   slashing-protection records. Retain the previous executable for rollback.
2. Review weak-subjectivity arguments before restarting. This release requires
   `--ws-checkpoint`, `--ws-signer-set` and `--ws-signer-set-sha3` together.
   If the first two are already configured, include the independently verified
   SHA3-256 digest of that signer set as the third argument. Hashing an
   untrusted downloaded file alone does not establish its authenticity.
3. Stop the old process cleanly and replace its executable with the verified
   binary. Preserve the existing arguments and add the required signer-set pin
   where it is absent. Start only one process for each validator identity.
4. Allow local replay to finish. The new process may report `starting` while
   rebuilding state, then remain `validator_active=false` during doppelganger
   observation. The two-epoch observation is 64 slots, approximately 32 minutes
   on Genesis-4, after replay. Do not disable this protection to speed up rollout.
5. Before proceeding to the next batch, verify the running executable's SHA,
   `status=ok`, `is_syncing=false`, `behind_by_slots <= 2` and
   `validator_active=true`. Investigate unexpected service restarts.

This upgrade artifact contains no validator keys, passphrases, chain data,
genesis material or current weak-subjectivity checkpoint. A fresh node also
requires independently verified, current bootstrap material; an archived
checkpoint must not be treated as current simply because this binary is new.
