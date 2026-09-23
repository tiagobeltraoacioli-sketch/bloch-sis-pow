# Read-only RPC compatibility probe

Keep `probe.cjs` and [catalog.v1.json](catalog.v1.json) in the same directory. The probe sends six no-argument read requests from that catalog to the primary endpoint. With a reference RPC, it makes only two additional read requests: `getchaininfo` and `getvalidatoradmission`. It checks JSON-RPC envelopes, result type, and the presence of catalogued fields. It never submits transactions, requests secret material, or enumerates validator and UTXO records.

Run with Node.js 20 or later:

```sh
node probe.cjs --rpc https://posternlabs.com/g4rpc --json
node probe.cjs --rpc http://127.0.0.1:16400/rpc --timeout-ms 20000 --json > rpc-probe.json
node probe.cjs --rpc https://node-a.example/rpc --reference-rpc https://node-b.example/rpc --expect-domain "$BLOCH_NETWORK_DOMAIN" --json > rpc-cross-check.json
node --test probe.test.cjs
```

Endpoints must use HTTPS, except for loopback HTTP. Credentials, query strings, and fragments in URLs are rejected. The reference must have a different URL origin (scheme, host or port). Set `BLOCH_NETWORK_DOMAIN` to the 64-character hexadecimal domain from a trusted network manifest before using the comparison example; do not copy an RPC response. The reference should be operated independently; a different origin can still lead to the same backend. Requests run sequentially with a timeout per method (default 12 seconds, maximum 30 seconds) and a 1 MiB response limit. Output includes individual method diagnostics; exit code `0` means all six primary responses had the expected field shape and any requested cross-check matched, `1` means a shape error, mismatch, or inconclusive cross-check, and `2` means invalid command arguments. A timeout or gateway error does not prevent later methods from being checked.

The cross-check compares `network_domain` with the trusted expected value when supplied, compares the two reported domains, and compares `finalized.epoch` and `finalized.root` when both endpoints report the **same finalized epoch**. Different epochs, missing fields, and unavailable reference requests are inconclusive. A same-epoch root conflict or domain mismatch fails the check. The JSON report includes the observed values and specific finding codes; it contains no keys or transaction data. Do not publish the report if your endpoint URL or operational metadata is sensitive.

The result is a compatibility observation at one time. A matching `source_digest`, domain, or finalized root is self-reported; matching gateway replies do not prove chain consensus, operator independence, or an authenticated checkpoint. Before production use, compare a trusted network manifest, checkpoint, release artifact, and independent nodes. Shape compatibility does not verify field semantics, finality policy, uptime, or transaction submission.

## Compare two saved observations

Run the same probe at two distinct times and keep the original JSON files as evidence. `compare-reports.cjs` reads those files offline; it makes no RPC or network requests. Keep the comparator and `probe.cjs` in the same directory.

```sh
node probe.cjs --rpc https://node-a.example/rpc --expect-domain "$BLOCH_NETWORK_DOMAIN" --json > earlier.json
# Run again later against the same endpoint and reference configuration.
node probe.cjs --rpc https://node-a.example/rpc --expect-domain "$BLOCH_NETWORK_DOMAIN" --json > later.json
node compare-reports.cjs --before earlier.json --after later.json --expect-domain "$BLOCH_NETWORK_DOMAIN" > comparison.json
```

The comparator requires the later report timestamp to be greater and the endpoint configuration to match. It checks the observed network domain against the trusted value, detects domain changes, decreasing finalized epochs or heights, and contradictory roots at the same finalized epoch. It also preserves a failed or inconclusive reference cross-check from either report. A higher epoch may have a different root. Missing data, changed endpoints, or unverified time order make the longitudinal check inconclusive. Findings are emitted as machine-readable JSON. Exit code `0` means match, `1` means fail or inconclusive, and `2` means invalid input. Each input is limited to 1 MiB. Keep the original reports private if endpoint URLs or operational metadata are sensitive; the comparison output omits endpoint URLs.

These files and timestamps are supplied by the operator and are not authenticated. A match cannot establish continuous uptime, independent agreement, chain consensus, or settlement finality. Use an independent trusted checkpoint and your own transaction policy for operational decisions.
