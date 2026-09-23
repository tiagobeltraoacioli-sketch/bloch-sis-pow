# Verify a Genesis-4 checkpoint on your own node

Download [checkpoint-verify.cjs](checkpoint-verify.cjs) and run it locally with Node.js 18+ and the **installed `bloch-pos` binary for the release you are auditing**. Obtain the checkpoint envelope, signer-set file, canonical Genesis-4 manifest, and expected 64-character WS digest from independently authenticated channels. The script downloads nothing and selects no trust anchor. It calls only `bloch-pos ws-verify` and reads no private keys.

```sh
node checkpoint-verify.cjs \
  --binary /opt/bloch/bin/bloch-pos \
  --envelope /secure/releases/wscheckpoint-epoch.envelope.bin \
  --signer-set /secure/releases/signer-set.bin \
  --genesis /secure/releases/mainnet.manifest \
  --rpc 127.0.0.1:16400 \
  --expect-digest YOUR_INDEPENDENTLY_PUBLISHED_64_HEX_DIGEST \
  --evidence-dir ./checkpoint-evidence-new
```

Replace every example path and the RPC port with your actual release and node. `--rpc` is a `host:port`, **not** an HTTPS URL: the `ws-verify` client in `crates/bloch-pos-node/src/ws_tool.rs` makes a direct, plaintext TCP HTTP request. Prefer a node under your control on loopback. Never put credentials into this argument. The supplied binary computes freshness from `getchaininfo` on that node; the script does not override the clock with `--now-epoch`.

The script fingerprints the four supplied files with SHA-256, executes the binary without a shell, limits runtime to 30 seconds and combined output to 64 KiB, then checks its exit status, `VERDICT`, `WS DIGEST`, and `FRESHNESS` lines. `CRYPTO_ACCEPTED_MANUAL_REQUIRED` means the supplied binary accepted the envelope, its digest matched the independently supplied digest, and its node reported `FRESH`. `REVIEW` means the envelope was accepted but already `STALE`; `FAIL` means a refusal, mismatch, expiry, missing result, timeout or output limit. None of these statuses qualify staking or change the worksheet's `NOT_QUALIFIED` state.

`--evidence-dir` creates a **new** owner-only directory with `checkpoint-verification.json` and `SHA256SUMS`; it refuses to overwrite an existing directory. The JSON contains fingerprints, bounded verifier stdout/stderr and explicit pending manual gates. Review it before sharing: the verifier may print local file paths. The bundle does not include the supplied file contents, RPC target or keys. Exit codes are 0 for accepted with manual work pending, 1 for review and 2 for failure.

Read the full verifier output and follow [the checkpoint runbook](https://github.com/tiagobeltraoacioli-sketch/bloch-sis-pow/blob/main/docs/CHECKPOINT-RUNBOOK.md), especially its independent-publication and archival-root comparisons. Authenticate the manifest, signer set, release binary and digest through independent channels; a binary or arrangement that an attacker substituted can print a plausible `ACCEPTED` line. Compare the checkpoint with independent archival nodes and retain human review. Exact-release mainnet exit, production withdrawal delay and spendable payout are separate validator opening gates.
