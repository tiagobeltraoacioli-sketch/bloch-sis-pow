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
