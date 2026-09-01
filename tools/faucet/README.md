# Bloch Testnet Faucet (reference)

A small, standalone service that dispenses **test BLCH** to a Genesis-4
`script_hash`: it selects UTXOs from a funding `script_hash` via the node's
JSON-RPC (`getutxos`), hands an **unsigned payment job** to an external signer,
and broadcasts the signed transaction via `sendrawtransaction`. It ships a tiny
web form and a JSON API, with per-recipient, per-IP and global rate limiting.

**The recipient is a 64-hex `script_hash`, never an address.** Genesis-4 locks
an output to `SHA3-256(the owner's hybrid public key)` — 32 bytes, no address
encoding — which is what `bloch-pos spendkey` prints. An address is refused with
an explanation rather than converted: zero-extending an address's 20 bytes gives
a *different key in the eUTXO set*, consensus opens both, and the funded party
would read a zero balance with nothing anywhere reporting an error.

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
- **Testnet-only, and bound to one testnet.** In LIVE mode it refuses to start
  unless the node at `FAUCET_RPC_URL` reports the genesis block id set in
  `FAUCET_EXPECT_GENESIS_BLOCK_ID`. That replaced a `bloch1t…` prefix check on
  the funding string, which inspected a string in isolation from the RPC URL and
  therefore proved nothing about the chain at the other end of the socket.
- **Test BLCH has NO value.** This is a faucet for a **zero-security testnet**.
  BLCH is **not a security**; nobody makes any value or investment claim.
- **Reference, untested against a live network.** It builds and runs, and the
  full pipeline is exercised offline (dry-run), but it has not been validated
  end-to-end against a live Bloch node/testnet. Do **not** read any claim that
  it "works end-to-end" — there is none.
- **Bloch is ownerless and neutral.** Postern Labs is **one builder among many**
  with **no protocol privilege**. This faucet confers no special status on
  anyone.
- The base is **experimental mainnet-beta**: the relaxed PoW regime (k=4) is
  **trivially forgeable** and the network is **51%-attackable**. Nothing here is
  secure.

---

## How it works

```
startup ──▶ [preflight: getblockbyslot(0).block_id == FAUCET_EXPECT_GENESIS_BLOCK_ID]

script_hash ──▶ [parse: 64 hex, or a refusal that says what to send instead]
            ──▶ [rate limit: per-recipient cooldown + per-IP window + global ceiling]
            ──▶ getutxos(FAUCET_FUNDING_SCRIPT_HASH)  ──▶ greedy coin selection
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
| `FAUCET_FUNDING_SCRIPT_HASH` | 64-hex `script_hash` holding the test BLCH (from `bloch-pos spendkey`) |
| `FAUCET_CHANGE_SCRIPT_HASH` | where change goes (default = funding) |
| `FAUCET_EXPECT_GENESIS_BLOCK_ID` | 64-hex `getblockbyslot(0).block_id`; the network binding, required in LIVE mode |
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
FAUCET_FUNDING_SCRIPT_HASH=<64 hex> FAUCET_EXPECT_GENESIS_BLOCK_ID=<64 hex> npm start
```

`npm run dev` and `npm run selftest` compile with `tsc` first, then run the
emitted JS from `dist/` (NodeNext `.js` import specifiers).

## API

- `GET /` — web form.
- `POST /api/faucet` — body `{"scriptHash":"<64 hex>"}` → `{ ok, txid, amountSats, scriptHash, dryRun, signer }` or `{ ok:false, error, code }`. (`address` is still read, purely so that sending one returns the specific refusal instead of "missing field".)
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

## Status, honestly

This service is a **reference implementation that has never been run against a
live Genesis-4 node.** Two classes of defect were found and fixed in
2026-08-31; the second one is the reason for the warning above.

### Fixed: the rate limiter was decorative

The previous limiter checked the quota, awaited the payment, and only then
recorded the hit — so every request arriving inside that window saw an
un-recorded quota. Measured: **47 of 100 concurrent requests for one address
all paid out.** Three further bypasses existed alongside it: address keys were
not case-normalised (Bloch addresses are checksum-case-insensitive, so one
address had ~2^40 spellings, each with its own 24 h quota), failed requests
were never recorded at all (making them an unbounded free DoS against both this
host and the node), and there was no global ceiling of any kind.

`RateLimiter` now reserves atomically and the caller settles the ticket:
`commit()` on payout, `release()` on failure. `release()` returns the address
cooldown and the spend but **not** the per-IP hit, so the IP budget bounds work
done rather than money paid. A rolling global ceiling bounds the sum across all
clients. All of this is covered by `npm run selftest`.

State is still process-local, so **a restart clears every cooldown.** That is
acceptable only because the coins are worthless.

### Fixed: the RPC surface did not exist

This client was written against four methods the Genesis-4 node does not
implement — `validateaddress`, `getnetworkinfo`, `gettxstatus`, and
`getutxos(address)`. The node's actual `getutxos`/`listunspent` takes a
**32-byte `script_hash` as 64 hex**, never an address, and there is no
address-validation RPC at all. The LIVE path could not have completed a single
drip.

The recipient model was wrong for the same reason. An address carries a
20-byte hash; a native Genesis-4 key's `script_hash` is `SHA3-256(pubkey)`, a
full 32 bytes with **no address encoding**. A partner who follows the
onboarding guide (`keygen`, then `spendkey`) has a `script_hash` that could not
be expressed as an address, so an address-only faucet could never have funded
them. `script_hash` is now the primary input form; `bloch1t…` addresses are
REFUSED, not converted — see the note at the top of this file.

### Still open

- **No signer ships.** `FAUCET_SIGNER_CMD` is a seam, not an implementation.
  Building one means computing the fee exactly (`gas = 5,000 + tx_bytes×16 +
  72,748 per signature`, priced at the base fee from `getchaininfo`), and it
  must be validated against a live node before it is trusted with coins. It was
  deliberately not written blind.
- **Never commissioned.** Nothing here has been exercised end to end against a
  real node. Do not enable LIVE mode until it has been.
