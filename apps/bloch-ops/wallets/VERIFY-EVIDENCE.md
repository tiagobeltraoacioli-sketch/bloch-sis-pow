# Offline reconciliation evidence check

The Bloch Ops wallet inspector exports `bloch.genesis4.reconciliation-evidence.v2`
JSON for an **included** Genesis-4 transaction. The file contains a selected
public receipt, the browser's UTC observation time, the previous public
observation from that tab (if any), a comparison result and an optional output
match. No mnemonic or private key belongs in this file.

The portable verifier archive contains this readme and five `.mjs` files.
Extract all of them into one directory and run with Node.js 20 or later:

```sh
tar -xzf bloch-reconciliation-verifier-v2.tgz
node verify-evidence.mjs /path/to/bloch-tx-...-evidence.json
```

The command prints only a compact JSON summary and exits nonzero for a
malformed or contradictory file. It accepts one regular JSON file up to 6 MiB.
It recalculates the comparison and optional script-hash/amount match, checks
receipt structure, and rejects extra properties or a different schema version.
It does not contact the network or verify that the receipt came from an
authentic indexer. A passing result is **structural only**. Query the txid
again through independently trusted infrastructure, compare block identity,
and apply your own ownership, duplicate-credit, confirmation and finality
policy before moving value. The browser's `observed_at` is its local clock.

The older v1 export lacked the prior observation needed to recalculate its
comparison; this verifier deliberately rejects v1 files.
