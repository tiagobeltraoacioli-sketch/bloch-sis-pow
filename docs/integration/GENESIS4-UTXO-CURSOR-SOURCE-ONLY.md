# Genesis-4 UTXO cursor extension (source only)

Status: implemented and tested in the local node source on 2026-09-23. This is **not a claim that the current mainnet RPC binary supports it**. Check the deployed node build before using a third parameter in production. The older two-parameter contract and response remain unchanged.

`getutxos` and its alias `listunspent` accept an optional third parameter, `cursor`. Start with an explicit `null`; omission selects the legacy response with no cursor:

```json
{"jsonrpc":"2.0","id":1,"method":"listunspent","params":["<64-hex script hash>",1000,null]}
```

The opted-in result retains `script_hash`, `total`, `returned`, `truncated`, and `utxos`, and adds `at_head` (64-hex block ID), `at_slot` (integer), and `next_cursor` (hex string or null). Supply `next_cursor` as the third parameter until it is null. Outputs are ordered lexicographically by the raw 32-byte transaction ID, then by the numeric `vout`. The page limit is clamped to 1–1,000. A page reads at most `limit + 1` indexed outputs; later pages seek directly to the outpoint after the cursor.

The version-1 cursor encodes one byte of version (`01`), the 32-byte committed block ID, the 32-byte script hash, the 32-byte last outpoint transaction ID, and the 4-byte big-endian `vout` (101 bytes, 202 hex characters). Treat it as an opaque continuation token. Malformed or wrong-script tokens return JSON-RPC `-32602`. If the committed block ID has changed, the node returns `-32020` (`UTXO cursor is stale`). On that error, discard all pages from the attempt and restart from `null`; mixing pages from different heads can omit or duplicate outputs. An unchanged head allows consistent enumeration of the committed eUTXO snapshot, but the result is not a finality assertion.

An exchange that must work against the currently deployed binary should continue using the documented two-parameter behavior and `gettxout(txid, vout)` for specific outpoints until a node release with this extension is deployed and verified.
