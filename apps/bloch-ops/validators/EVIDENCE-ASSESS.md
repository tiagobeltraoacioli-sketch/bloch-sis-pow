# Compare validator evidence locally

`evidence-assess.cjs` compares two saved local bundles from [preflight](PREFLIGHT.md) and [checkpoint verification](CHECKPOINT-VERIFY.md). It performs no network request, runs no binary and accepts no key. Use Node.js 18+.

```sh
node evidence-assess.cjs \
  --preflight ./preflight-evidence-new \
  --checkpoint ./checkpoint-evidence-new \
  --expect-domain "$TRUSTED_NETWORK_DOMAIN" \
  --expect-genesis-sha256 "$TRUSTED_GENESIS_MANIFEST_SHA256" \
  --max-age-minutes 30 \
  --json
```

Supply both 64-character digests from independently authenticated release material. The tool checks each bundle's `SHA256SUMS`, schema and manual gate; checks that the preflight's network domain matches the independently supplied domain; and checks that the manifest file fingerprint recorded by `checkpoint-verify.cjs` matches the independently supplied SHA-256. It also compares the checkpoint verifier's printed epoch, root, digest, freshness and acceptance with its structured report and the preflight's reported chain epoch and finalized checkpoint.

The assessor reads the UTC `observedAt` timestamps written by both bundle producers and requires the preflight bundle and its nested report to agree. It rejects malformed timestamps, evidence older than `--max-age-minutes`, evidence more than 120 seconds in the future, and a checkpoint timestamp more than 120 seconds before preflight or more than the age limit after it. The default limit is 30 minutes; the operator may set an integer from 1 to 1440. The 120-second allowance is for host clock skew, not an extension of the evidence age limit. Run both tools close together with synchronized clocks, then assess them promptly. The JSON result records the chosen limit, skew allowance and each temporal check. Timestamps come from the hosts that created the bundles; they are not independently authenticated, so review clock synchronization and evidence origin manually.

If your authenticated release material publishes SHA-256 digests for the **exact node binary file** and **exact signer-set file** used in checkpoint verification, pin either or both as well:

```sh
node evidence-assess.cjs \
  --preflight ./preflight-evidence-new \
  --checkpoint ./checkpoint-evidence-new \
  --expect-domain "$TRUSTED_NETWORK_DOMAIN" \
  --expect-genesis-sha256 "$TRUSTED_GENESIS_MANIFEST_SHA256" \
  --expect-binary-sha256 "$TRUSTED_BINARY_SHA256" \
  --expect-signer-set-sha256 "$TRUSTED_SIGNER_SET_SHA256" \
  --json
```

Each supplied pin is compared with the corresponding `inputFingerprints.binary.sha256` or `inputFingerprints.signerSet.sha256` in the checkpoint evidence. A missing, malformed or different recorded fingerprint fails the assessment. A malformed CLI digest is rejected. These are file fingerprints from `checkpoint-verify.cjs`; they do not prove that the same binary is running on every validator host or authenticate the release material. Omit an optional pin only when you do not have an independently authenticated digest for that exact file, and complete the binary and signer-arrangement checks manually.

If the preflight finalized epoch equals the checkpoint epoch, roots must match. If the preflight node has finalized a later epoch, its latest root cannot establish the older checkpoint root; compare that older root on an independent archival node. If the preflight finality is behind the checkpoint, the assessment fails. The head epochs must also be within one epoch of each other for this local comparison. Run both checks again if the chain advanced.

Exit code `1` and `REVIEW_MANUAL_REQUIRED` mean the available fields agree but the manual gate is still `NOT_VERIFIED`. Exit code `2` and `FAIL` mean a contradiction or failed check; malformed, altered, oversized or unsupported bundles also exit `2`. There is no approval status or exit code `0` for a validator opening. The JSON printed with `--json` includes SHA-256 fingerprints of both input reports and the explicit unresolved gates, but is not saved automatically.

`SHA256SUMS` is a local integrity check, not a signature or proof of who created the bundle. Authenticate the release, signer arrangement, expected digests and node independence separately. Confirm the exact deployed release's exit, withdrawal delay and spendable payout before any bond. Do not place keys, seeds or RPC credentials in these bundles.

Run offline tests with `node --test evidence-assess.test.cjs`.
