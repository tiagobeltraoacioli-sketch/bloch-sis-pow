<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Run a public Genesis-4 observer

Updated September 26, 2026. This guide uses the signed Linux x86-64 release
`4d4c5075872c622fdd26aa418a9d249ec95fbcea` and the
[epoch-3328 public checkpoint](../checkpoints/epoch-3328/README.md).
An observer follows and verifies the chain without a validator key or stake.
Validator admission and exchange deposit/withdrawal qualification are separate.

**Before bootstrap, approve the trust anchor:** epoch 3328 is cryptographically
valid and current at publication, but the three keys were used on one
operator-controlled machine. Independent custody and an external auditor's
attestation remain unverified. The signer-set `EXTERNAL` flags do not establish
those facts. If your policy requires independent custodians, wait for a ceremony
that meets it. Otherwise, authenticate and explicitly accept the operator's
anchor, WS digest and signer-set fingerprint through a separate trusted channel.
This guide does not change the protocol's stated custody requirements.

The checkpoint expires for initial synchronization on **2026-10-12 at
06:35:19 UTC**, epoch **5344**. The old epoch-1536 publication is expired.
Use a synchronized system clock and recheck freshness immediately before launch.

## 1. Verify the executable

Use Linux x86-64 with `curl`, `minisign`, `python3`, `gzip` and `sha256sum`.
Work in a new directory. Download the September 24 package:

```bash
mkdir -p bloch-observer
cd bloch-observer
base=https://blochl1.com/releases/2026-09-24
for name in bloch-pos SHA256SUMS SHA256SUMS.minisig bloch-release-20260922.pub; do
  curl --fail --show-error --location "$base/$name" --output "$name" || exit 1
done
```

Authenticate the release key against an already trusted copy or another trusted
channel before using the downloaded key. Its published public value is:

```text
RWT3XpXEpZZdGtghC5SmyRj2VRTAGUfO5KxBucYVTRfriNE13wsXhfj6
```

Then verify and inspect the executable:

```bash
minisign -Vm SHA256SUMS -p bloch-release-20260922.pub || exit 1
sha256sum --check SHA256SUMS || exit 1
chmod 0755 bloch-pos
./bloch-pos --version
./bloch-pos selfcheck || exit 1
```

Expected binary SHA-256:
`fb8a65cbd9721d794bd4c2151b50d82d85a7df2299d59d7bad44a7635c30b46a`.
The version must identify source `4d4c5075872c622fdd26aa418a9d249ec95fbcea`,
Genesis-4 and block version `0xb10c0005`.

## 2. Fetch and verify genesis material

```bash
src=https://raw.githubusercontent.com/tiagobeltraoacioli-sketch/bloch-sis-pow/4d4c5075872c622fdd26aa418a9d249ec95fbcea
curl --fail --show-error --location "$src/genesis/mainnet.manifest" -o mainnet.manifest || exit 1
curl --fail --show-error --location "$src/carryover.tsv.gz" -o carryover.tsv.gz || exit 1
gzip -dk carryover.tsv.gz || exit 1
sha256sum --check <<'HASHES' || exit 1
7eef82a70ef9b0e1dd86f86d33cba11fc10cdfc7395c2e5f6669613fa1beb2dd  mainnet.manifest
84ddbbac2afdd5c78618096a7d4f66cf5b04a3e5757a03fe90550e50096183f6  carryover.tsv
HASHES
```

Stop on a checksum failure. The manifest is 247,514 bytes. The uncompressed
carryover is 54,780,151 bytes and 452,726 lines; the node consumes the TSV, not
the gzip file, and checks its commitments against the manifest.

## 3. Fetch the checkpoint and authenticate the signer set

```bash
mkdir -p checkpoint
cpbase=https://raw.githubusercontent.com/tiagobeltraoacioli-sketch/bloch-sis-pow/main/checkpoints/epoch-3328
for name in wscheckpoint-3328.envelope.bin signer-set-1.bin wscheckpoint-3328.bin wscheckpoint-3328.json SHA256SUMS verification.json; do
  curl --fail --show-error --location "$cpbase/$name" -o "checkpoint/$name" || exit 1
done
(cd checkpoint && sha256sum --check SHA256SUMS) || exit 1
```

The published signer-set SHA3-256 fingerprint is
`bccb7c5ee127f806ac7da69a6dfab0a0b1c3d2750d6224bbfb652baa3322d627`.
Set `WS_SIGNER_SET_SHA3` to the value you authenticated through the trusted
channel and approved under the custody limitation above. Then check the file:

```bash
: "${WS_SIGNER_SET_SHA3:?Set the independently authenticated, approved signer-set fingerprint}"
export WS_SIGNER_SET_SHA3
python3 - <<'PY' || exit 1
import hashlib, os, pathlib, re
pin = os.environ['WS_SIGNER_SET_SHA3'].lower()
if not re.fullmatch(r'[0-9a-f]{64}', pin):
    raise SystemExit('Invalid signer-set fingerprint')
raw = pathlib.Path('checkpoint/signer-set-1.bin').read_bytes()
if hashlib.sha3_256(raw).hexdigest() != pin:
    raise SystemExit('Signer-set fingerprint mismatch')
pathlib.Path('checkpoint/signer-set.sha3').write_text(pin + '\n')
PY
```

Stop on a mismatch. This is SHA3-256 over the entire arrangement file, not
SHA-256 or Ethereum Keccak-256. Downloading a file and trusting its own hash
does not authenticate it. Retain the trusted-channel evidence with your node's
configuration record.

## 4. Verify signatures and freshness

```bash
now_epoch=$(python3 - <<'PY'
import time
print((int(time.time()) - 1786656679) // 960)
PY
)
./bloch-pos ws-verify \
  --envelope checkpoint/wscheckpoint-3328.envelope.bin \
  --signer-set checkpoint/signer-set-1.bin \
  --genesis mainnet.manifest --now-epoch "$now_epoch" --require-fresh || exit 1
```

Require three `VALID` signatures, the intended network and genesis, and this
WS digest matching your authenticated publication:

```text
f4f067929ee881f671df54a5849edec4106c712f28b2286ab1a7fc58e587fbc0
```

At publication, freshness was `FRESH`. The command rejects an unknown clock or
`EXPIRED`, but can exit successfully with `STALE`: inspect the printed result
and request a newer checkpoint if stale. Soft staleness starts at epoch 4336;
refusal starts at epoch 5344. Never change the clock or bypass the checkpoint
gate to make an expired anchor pass. This verifier checks signatures and age;
the publication's block/state cross-check was performed separately on two
operator-controlled archival nodes.

## 5. Start a keyless observer

After the trust, artifact and freshness checks pass, save this as
`run-observer.sh` inside `bloch-observer`:

```bash
#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")"
mkdir -p data
test ! -e data/validator.key || {
  echo 'Validator key present: stop and review.' >&2
  exit 1
}
pin=$(cat checkpoint/signer-set.sha3)
exec ./bloch-pos run \
  --data-dir "$PWD/data" --genesis "$PWD/mainnet.manifest" \
  --carryover "$PWD/carryover.tsv" --transport devnet \
  --listen 19000 --listen-addr 127.0.0.1 \
  --peers 139.180.166.5:19100,139.180.173.231:19100 \
  --rpc-port 16400 --rpc-bind 127.0.0.1 \
  --metrics-port 17400 --metrics-bind 127.0.0.1 \
  --ws-checkpoint "$PWD/checkpoint/wscheckpoint-3328.envelope.bin" \
  --ws-signer-set "$PWD/checkpoint/signer-set-1.bin" \
  --ws-signer-set-sha3 "$pin"
```

Run `chmod 0750 run-observer.sh`, then `./run-observer.sh`. Use one process per
data directory. The `devnet` name identifies the transport used by this mainnet;
it does not select a test network. Both published bootnodes accepted TCP
connections on September 26. The listener, RPC and metrics stay on loopback.

This checkpoint anchors and cross-checks replay from genesis. It is not a
downloadable state snapshot. Allow replay to finish before using the RPC as a
synchronized chain reference. This publication was verified cryptographically
and against live finality; a full fresh replay with this package was not run.

## 6. Confirm synchronization

```bash
curl --fail --show-error http://127.0.0.1:17400/health
curl --fail --show-error -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"getchaininfo","params":[]}' \
  http://127.0.0.1:16400
```

During startup, the health endpoint can return HTTP 503 while replay runs.
Afterward require `status=ok`, `is_syncing=false` and `behind_by_slots <= 2`.
An observer's `validator_active=false` is expected. Confirm that finalized
epochs advance and compare block/state roots at the same finalized slot with
another trusted node. Never compare roots from different slots.

Both listed bootnodes share an operator and provider family. Add independently
operated references when available; these two provide redundant entry points,
not independently governed consensus. A completed sync does not by itself
qualify exchange crediting or establish independent signer custody.
