# Bloch reference apps

Small, self-contained, permissively-licensed apps that talk to a Bloch node's
JSON-RPC. Companions to the [developer portal](../docs/portal/index.md).

> **⚠️ Honesty rails (binding).** Building on Bloch today is **EXPERIMENTAL**.
> Unaudited mainnet-beta; relaxed PoW (**k=4**) makes work **trivially
> forgeable**; the network is small and **51%-attackable**. Bloch is
> **ownerless / neutral / agnostic** — anyone can build; **Postern Labs is one
> builder among many, with no special protocol access.** **BLCH is neutral
> native gas** (ETH-like at the protocol level, usable for development) — **never
> a value or investment claim**; no price, no value claim from anyone; 17%
> founder premine disclosed. **Do not build here because "the token will
> appreciate."** Integer satoshis are the truth (`1 BLOCH = 1e8 sat`); the
> `bloch` float is display-only.
>
> **Every app here is labelled: reference, UNTESTED against a live node.**

## The apps

| App | File | What it does | How to run |
|---|---|---|---|
| **Balance + UTXO viewer** | `balance-viewer/index.html` | Validates an address, then shows its balance and unspent outputs. | Open the file in a browser. |
| **Tiny block explorer** | `block-explorer/index.html` | Chain tip + recent blocks, drill into a block's transactions and a tx's outputs/status. | Open the file in a browser. |
| **Payment builder (preview)** | `payment-builder/payment-builder.js` | Reads UTXOs, does coin selection, prints the **unsigned** transaction plan (inputs/outputs/change/fee). Does **not** sign or broadcast unless you supply an external signer. | `node payment-builder.js --help` (Node ≥ 18). |

## Design notes

- **No build step, dependency-light.** The two viewers are single self-contained
  HTML files. The payment builder is pure Node (≥ 18, uses the global `fetch`) —
  no `npm install`.
- **All three share one JSON-RPC helper** that handles Bloch's non-standard
  **`result.error` quirk** (method-level failures arrive inside `result`, not as
  a top-level JSON-RPC `error`). See
  [Build your first Bloch app](../docs/portal/01-build-your-first-bloch-app.md).
- **Why the payment app only previews.** Bloch outputs are fixed **P2PKH** and a
  `script_sig` is a hybrid **Falcon-1024 ‖ ML-DSA-65** post-quantum signature.
  That signature must come from the reference signer (`bloch-cli` /
  `bloch-wallet` / `WalletCore`) — a browser or plain Node cannot produce it. The
  demo builds and previews the unsigned plan and hands signing off. This is
  honest by design, not a limitation to work around.
- **Node config.** Reads are usually public; a node may require an `X-API-Key`
  for writes, and **localhost bypasses auth**. Browser apps need the node's CORS
  to allow your origin (opening `file://` may require running the node with a
  permissive CORS setting or serving the HTML from `http://localhost`).

## Verification status

- `balance-viewer/index.html` and `block-explorer/index.html` — self-contained;
  their inline `<script>` was syntax-checked with `node --check`. **Untested
  against a live node.**
- `payment-builder/payment-builder.js` — passes `node --check`. **Untested
  against a live node.**

None of these has been run against a live Bloch node in this build; treat all
behaviour as **reference only**.

## License

Every file here is offered under **MIT OR Apache-2.0** (permissive). Adopt
freely, including commercially. Each file also carries its own honesty + license
header.
