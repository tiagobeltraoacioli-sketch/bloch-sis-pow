# Compare validator evidence locally

`evidence-assess.cjs` compares two saved local bundles from [preflight](PREFLIGHT.md) and [checkpoint verification](CHECKPOINT-VERIFY.md). It performs no network request, runs no binary and accepts no key. Use Node.js 18+.

```sh
node evidence-assess.cjs \
  --preflight ./preflight-evidence-new \
  --checkpoint ./checkpoint-evidence-new \
  --expect-domain "$TRUSTED_NETWORK_DOMAIN" \
  --expect-genesis-sha256 "$TRUSTED_GENESIS_MANIFEST_SHA256" \
  --json
```

Supply both 64-character digests from independently authenticated release material. The tool checks each bundle's `SHA256SUMS`, schema and manual gate; checks that the preflight's network domain matches the independently supplied domain; and checks that the manifest file fingerprint recorded by `checkpoint-verify.cjs` matches the independently supplied SHA-256. It also compares the checkpoint verifier's printed epoch, root, digest, freshness and acceptance with its structured report and the preflight's reported chain epoch and finalized checkpoint.

If the preflight finalized epoch equals the checkpoint epoch, roots must match. If the preflight node has finalized a later epoch, its latest root cannot establish the older checkpoint root; compare that older root on an independent archival node. If the preflight finality is behind the checkpoint, the assessment fails. The two checks may be run at different times; the head epochs must be within one epoch of each other for this local comparison. Run them again close together if the chain advanced.

Exit code `1` and `REVIEW_MANUAL_REQUIRED` mean the available fields agree but the manual gate is still `NOT_VERIFIED`. Exit code `2` and `FAIL` mean a contradiction or failed check; malformed, altered, oversized or unsupported bundles also exit `2`. There is no approval status or exit code `0` for a validator opening. The JSON printed with `--json` includes SHA-256 fingerprints of both input reports and the explicit unresolved gates, but is not saved automatically.

`SHA256SUMS` is a local integrity check, not a signature or proof of who created the bundle. Authenticate the release, signer arrangement, expected digests and node independence separately. Confirm the exact deployed release's exit, withdrawal delay and spendable payout before any bond. Do not place keys, seeds or RPC credentials in these bundles.

Run offline tests with `node --test evidence-assess.test.cjs`.
