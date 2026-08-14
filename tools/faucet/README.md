# Bloch Testnet Faucet (reference)

A small, standalone service that dispenses **test BLCH** to a testnet
`bloch1t…` address: it selects UTXOs from a funding wallet via the node's
JSON-RPC (`getutxos`), hands an **unsigned payment job** to an external signer,
and broadcasts the signed transaction via `sendrawtransaction`. It ships a tiny
web form and a JSON API, with per-address and per-IP rate limiting.

> **License:** MIT OR Apache-2.0 — a *different*, more permissive licence than
> the protocol itself. This line used to claim "the same permissive terms as the
> Bloch protocol", which was never true: the Genesis-3 node shipped
> AGPL-3.0-or-later, and the Genesis-4 crates were relicensed to match on
> 2026-08-11. Whether these two G3-era tools should follow is an open
> founder/PMO call; the false claim is corrected here regardless, because a
> wrong licence statement misleads whether or not the licence changes.

---

## ⚠️ Status & honesty rails (binding — read before use)

- **SCAFFOLD / reference tool. Unaudited. Pre-production.** Do not treat this as
  a secure, production faucet.
- **Testnet-only.** It only accepts `bloch1t…` addresses and refuses mainnet
  addresses.
- **Test BLCH has NO value.** This is a faucet for a **zero-security testnet**.
  BLCH is **not a security**; nobody makes any value or investment claim.
- **Reference, untested against a live network.** It builds and runs, and the
  full pipeline is exercised offline (dry-run), but it has not been validated
  end-to-end against a live Bloch node/testnet. Do **not** read any claim that
  it "works end-to-end" — there is none.
- **HISTORICAL — GENESIS-3.** This faucet targets the proof-of-work chain and
  its testnet. That chain stopped permanently at height 39,918 on 2026-08-13.
  The live chain is **Genesis-4, proof of stake** (30 s slots, 32-slot epochs,
  finality by epoch), with a different and much smaller RPC method set. This
  tool has not been ported to it.
- **Postern Labs is one builder among many** with **no protocol privilege**;
  this faucet confers no special status on anyone. ("Ownerless" was retracted —
  see `docs/adr/ADR-036-retract-ownerless-adopt-foundation.md`.)
- **Nothing here is secure, and the risk has changed shape.** The old rail —
  relaxed PoW at k=4, trivially forgeable, the network 51%-attackable —
  described Genesis-3 and was true of it. Under Genesis-4 the security question
  is concentration: **all 64 validators are run by one entity**, **93.94% of the
  carryover sits at a single address**, and **56.05 B of the 57.15 B BLOCH
  issued at genesis is held by the founder and the Foundation**.

---

## How it works

```
address ──▶ [validate: local checksum + node validateaddress]
        ──▶ [rate limit: per-address cooldown + per-IP window]
        ──▶ getutxos(funding)  ──▶ greedy coin selection
        ──▶ Signer.buildSignedPayment(job)   ← key lives HERE, never in the faucet
        ──▶ sendrawtransaction(rawHex)  ──▶ { txid }
```

Bloch JSON-RPC quirks handled by `src/rpc.ts`:
- params are a **positional array**;
- an HTTP 200 can still carry an **application error inside `result.error`**
  (a string) — the client unwraps and throws on it;
- auth/rate-limit failures use a real top-level `error` object (`-32001` /
  `-32002`).

## The signing seam (no hardcoded secrets)

The faucet **never holds a private key** and does **not** reimplement Bloch's
hybrid **Falcon-1024 ‖ ML-DSA-65** signing or the stratum tx serialisation.
Instead it builds an unsigned `PaymentJob` and delegates to a `Signer`:

- **`ExternalCommandSigner`** (real path) — spawns the command in
  `FAUCET_SIGNER_CMD` (e.g. the reference `bloch-wallet` / WalletCore). Contract:
  - **stdin** receives `JSON.stringify(PaymentJob)`
    (`{ network, toAddress, amountSats, feeSats, changeAddress, fundingAddress, selectedUtxos }`);
  - **stdout** returns either the signed raw-tx **hex**, or a JSON object
    `{"rawHex":"…","txid":"…?"}`;
  - **exit 0** on success (non-zero => error; stderr is surfaced).
- **`StubSigner`** (dry-run) — returns a deterministic, clearly-fake placeholder;
  never broadcast.

This keeps key material entirely in the operator's chosen tool and out of this
service. Configure it via env; **never commit secrets**.

## Configuration

Copy `.env.example` to `.env` and edit. Key vars:

| var | meaning |
|---|---|
| `FAUCET_RPC_URL` | node JSON-RPC endpoint (default `http://127.0.0.1:16210/`) |
| `FAUCET_RPC_API_KEY` | optional `X-API-Key` for write methods |
| `FAUCET_FUNDING_ADDRESS` | testnet `bloch1t…` wallet that holds test BLCH |
| `FAUCET_CHANGE_ADDRESS` | change address (default = funding) |
| `FAUCET_AMOUNT_SATS` | drip amount in sat (default `100000000` = 1 test BLCH) |
| `FAUCET_FEE_SATS` | flat fee in sat |
| `FAUCET_SIGNER_CMD` | external signer command (see above) |
| `FAUCET_DRY_RUN` | `true` (default) uses stub RPC + stub signer, **never broadcasts** |
| `FAUCET_PER_ADDRESS_WINDOW_MS` | per-address cooldown (default 24h) |
| `FAUCET_PER_IP_WINDOW_MS` / `FAUCET_PER_IP_MAX` | per-IP window + cap |

## Build & run

```bash
cd tools/faucet
npm install
npm run typecheck     # tsc --noEmit
npm run build         # tsc -> dist/
npm run selftest      # offline pipeline test (dry-run, no node, no keys)

# Dry-run server (default; safe, no broadcast):
npm start             # http://127.0.0.1:8080

# Live testnet (requires a node + a configured signer):
FAUCET_DRY_RUN=false FAUCET_SIGNER_CMD="bloch-wallet faucet-sign" \
FAUCET_FUNDING_ADDRESS=bloch1t… npm start
```

`npm run dev` and `npm run selftest` compile with `tsc` first, then run the
emitted JS from `dist/` (NodeNext `.js` import specifiers).

## API

- `GET /` — web form.
- `POST /api/faucet` — body `{"address":"bloch1t…"}` → `{ ok, txid, amountSats, dryRun, signer }` or `{ ok:false, error, code }`.
- `GET /api/health` — liveness.
- `GET /api/status` — mode, amounts, rate-limit config, rails.

## Known limitations

- Rate-limit state is in-memory (not durable across restarts, not shared across
  replicas). Back it with a shared store for real deployments.
- No CAPTCHA / anti-Sybil beyond IP+address windows.
- Coin selection is naive (greedy largest-first); no UTXO consolidation.
- Not audited; not load-tested.

## Naming

This is the **community edition**. Do not refer to it as "Postern OS", and never
use the name "BABA YAGA".
