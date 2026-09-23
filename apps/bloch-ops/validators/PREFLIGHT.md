# Genesis-4 validator preflight

`preflight.cjs` is a dependency-free Node.js 18+ read-only check for an operator's own RPC. It calls only `getchaininfo`, `getbuildinfo`, and `getvalidatoradmission`. It does not accept keys or mnemonics and cannot create a bond, exit, withdrawal or delegation transaction.

```sh
node preflight.cjs \
  --rpc http://127.0.0.1:8545 \
  --reference-rpc https://posternlabs.com/g4rpc \
  --expect-domain "$BLOCH_NETWORK_DOMAIN"
```

Set `BLOCH_NETWORK_DOMAIN` from independently authenticated Genesis-4 release material before running the example. A public RPC response is not a trusted source for this value. Replace the example local URL with your node's actual RPC URL. Remote URLs must use HTTPS. Never expose a private node RPC unauthenticated on the internet.

For a machine-readable result, add `--json`. `--max-lag-slots` defaults to 2. The three methods are called in sequence so small nodes and gateways do not receive a burst. `--timeout-ms` sets the timeout **per method** (default 20000; allowed range 1000–60000); a primary and reference together can therefore take up to six times this value. Each response is limited to 64 KiB and must have a matching JSON-RPC 2.0 request ID and a result object. Each result records method, endpoint role, elapsed time and any HTTP, RPC or timeout error. Diagnostics omit RPC error messages, response bodies and raw transport errors. A failed method does not suppress the remaining probes and always makes the overall result `FAIL`.

To save an operator evidence bundle, add `--evidence-dir ./preflight-2026-09-23T120000Z` and choose a **new** directory for each run. The tool creates it with owner-only permissions and writes `evidence.json` plus `SHA256SUMS`. The JSON contains the report, selected public fields from each method response, build identity, timestamps and a manual-gate checklist. It omits RPC URLs, credentials and unknown response fields. It does not fetch or authenticate a signed manifest or checkpoint; the checklist remains `NOT_VERIFIED` even when read-only checks pass. Keep separately authenticated manifest, checkpoint, artifact and lifecycle evidence with the operator record. Treat the bundle as operational data and review it before sharing. The script refuses to overwrite an existing directory. A failed probe still produces a bundle with `FAIL` status when a directory is requested.

Exit code 0 means the **read-only checks** passed and the report says `CHECKS_PASS_MANUAL_REQUIRED`; exit code 1 means review is needed; exit code 2 means a check failed or an RPC method was unavailable. Every result still contains a manual gate for checkpoint authentication and the full exit-to-payout lifecycle. An active admission flag is not proof that staking or delegation is safe to open.

The optional reference compares network domains, source digests and finalized roots **only when both nodes report the same finalized epoch**. A matching public gateway does not establish independent operation or checkpoint authenticity. Compare the manifest, signed weak-subjectivity checkpoint and release artifact through trusted channels before any value-bearing action.

Run offline fixture tests with `node --test preflight.test.cjs`.
