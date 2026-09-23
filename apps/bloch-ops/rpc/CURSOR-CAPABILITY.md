# Check the optional UTXO cursor on your endpoint

The current node source has an optional third `getutxos` parameter. Supplying `null` requests a first page with `at_head`, `at_slot`, and `next_cursor`; legacy two-parameter calls retain the old response. **This source contract does not mean the public Genesis-4 gateway or your node runs that release.** Measure your own endpoint before changing wallet behavior. The [RPC catalog v1](catalog.v1.json) describes the older deployed surface and does not claim cursor availability.

`cursor-capability.cjs` is an opt-in, read-only observation. Use Node.js 20 or later and a public script hash controlled or approved by your operator. It sends one `getbuildinfo` request and one `getutxos(script_hash, 1, null)` request; only when the reply includes a `next_cursor` does it send a third request to follow one page. It never enumerates the UTXO set, signs, or broadcasts. It rejects non-HTTPS endpoints except loopback HTTP, credentials and query strings in URLs, and responses larger than 128 KiB per request. Each request has a 12-second default timeout (30-second maximum).

```sh
node cursor-capability.cjs --rpc https://YOUR-RPC/rpc --script-hash "$SCRIPT_HASH" --probe-cursor --json
node --test cursor-capability.test.cjs
```

The script hash must be exactly 64 hexadecimal characters. `--probe-cursor` is required; omission sends zero requests. The JSON report contains the endpoint and script hash, so keep it private if those details are sensitive. RPC errors report only numeric codes; malformed and transport failures use local diagnostic text rather than copying server messages. Exit code `0` means a strictly validated cursor response was observed; `1` means a legacy shape, unavailable method, stale head, invalid response, timeout, or other inconclusive result; `2` means invalid arguments. The exit code is based on the observed `getutxos` shape, never the self-reported build marker.

`build_marker` reports whether `getbuildinfo.features` contains `utxo_cursor_v1`: `advertised`, `absent`, `unavailable`, `timeout`, or `invalid_response`. The feature list is validated and bounded; a missing field is `absent`. `marker_shape_relation` compares this marker with the first `getutxos` response: `advertised_and_observed`, `advertised_but_legacy`, `unadvertised_but_observed`, `unadvertised_and_legacy`, `marker_unknown`, or `shape_unknown`. Any mismatch deserves investigation. The marker is self-reported, so even `advertised_and_observed` does not attest to the binary or prove complete pagination.

| Status | Meaning |
| --- | --- |
| `legacy_shape` | The three-argument request returned the valid older shape, with no cursor fields. The endpoint may have ignored the third argument. |
| `unavailable` | The endpoint returned a JSON-RPC error for the first request. Check the code and gateway policy. |
| `cursor_shape_observed` | Cursor fields were valid, but no next page existed for this script hash. Page-following behavior remains unmeasured. |
| `two_pages_observed` | A second, distinct output was returned at the same reported head with a structurally valid cursor. This still does not prove complete enumeration. |
| `stale_head` | The node reported `-32020` on the follow-up; retry later if needed. Do not combine pages from different heads. |
| `invalid_response`, `timeout`, `inconclusive` | The bounded observation cannot qualify the extension. Inspect the report. |

The tool validates response counts, UTXO fields, the 101-byte version-1 cursor token, and its binding to head, script hash, and last output. It does not trust self-reported build information as remote attestation and does not certify a mainnet release. A live wallet should handle head changes, duplicate outputs, and an unavailable cursor according to its own policy. Never treat a single shape check as evidence of a complete wallet balance or settlement finality.
