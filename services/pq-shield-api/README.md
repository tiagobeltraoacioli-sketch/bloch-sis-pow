# PQ-Shield API — a non-custodial developer endpoint for PQ-Shield Bitcoin vaults

> ## ⚠️ SIGN LOCALLY — NON-CUSTODIAL
> **This server never handles a private key and never signs.** Every route does
> **construction + verification only** and returns an *unsigned* artifact — a vault
> address, a witnessScript, an unsigned transaction, a BIP-143 sighash, or the anchor
> commitment bytes — for **you to sign locally**. All secret material stays 100%
> client-side:
> - the BTC **hot / recovery secp256k1 private keys** (sign the sighashes),
> - the **PQ secret key** — ML-DSA-65 ‖ Falcon-1024 (signs the anchor commitment),
> - the recovery **preimage `r`** (you send only the *hash* `H(r)`; `r` is revealed
>   only in a witness you assemble on your own device).
>
> Any request whose JSON contains a field that looks like secret material
> (`secret`, `seed`, `priv`, `mnemonic`, `wif`, `preimage`, a bare `r`/`sk`, …) is
> **rejected with HTTP 400**. Pubkey fields must be 33-byte *compressed* secp256k1
> keys — a 32-byte value (private-key / x-only length) is rejected.

This service wraps the public, non-secret functions of the
[`bloch-pq-vault`](../../crates/bloch-pq-vault) crate. It builds a **commit-delay-reveal
P2WSH vault + a PQ-gated clawback on stock Bitcoin**, plus a **PQ-signed Bloch anchor**.
It is *not* the video/demo — this endpoint is how third-party builders integrate the
feature into their own products.

Read the crate's `HONEST LIMITS` and the security audit before shipping value: this is
**transition-era defense-in-depth, NOT unconditional quantum immunity**.

---

## Run it

```bash
cd services/pq-shield-api
cargo run                       # binds 127.0.0.1:8787
PQ_SHIELD_BIND=0.0.0.0:8787 cargo run   # custom bind
cargo test                      # 7 endpoint tests (round-trip vs. the crate)
```

The service is its **own cargo workspace** — building or running it does **not** touch
the Bloch chain node. Do **not** colocate it on a founder/chain node.

- `GET /` — HTML landing page + route table
- `GET /health` — liveness JSON

---

## The vault flow (what the routes build)

```
   DEPOSIT V (P2WSH)              TRIGGER T (P2WSH, OP_IF)                spend
   ┌──────────────┐   unvault    ┌───────────────────────────┐
   │ OP_SHA256    │──────tx──────▶│ IF  Δ OP_CSV <hot> CHECKSIG│──branch A (delayed)──▶ destination
   │  <H(r)>      │  (reveals r)  │ ELSE SHA256 <H(r)> EQ-VER  │
   │ OP_EQUALVERIFY│              │      <recovery> CHECKSIG   │──branch B (immediate)─▶ safe_dest
   │ <hot> CHECKSIG│              │ ENDIF                      │   = PQ-gated CLAWBACK
   └──────────────┘              └───────────────────────────┘
```

- **Branch A** carries the CSV relative-timelock Δ (normal, delayed spend, hot key).
- **Branch B** is immediate but gated by revealing the PQ-derived preimage `r` +
  a recovery-key signature — the *clawback* an owner/watchtower uses to beat an
  attacker within Δ.
- The **Bloch anchor** is the PQ-signed record binding
  `{vault address, H(r), pq pubkey, safe dest, Δ, policy}`; Bitcoin enforces the
  hash+timelock half, Bloch enforces the PQ half.

---

## Routes

Every response includes a `"non_custodial"` banner field. All returned transactions are
**unsigned** (empty witnesses).

### `POST /vault/address`
Build the P2WSH deposit + trigger from **public inputs only**.

Request:
```json
{
  "network": "regtest",
  "hot_pubkey": "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
  "recovery_pubkey": "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
  "recovery_hash": "5a5a...5a5a",
  "csv_delay": 144
}
```
- `recovery_hash` = `H(r) = SHA256(r)`, **computed client-side** from your PQ key. You
  send only the hash.

Response (abridged):
```json
{
  "deposit": {
    "address": "bcrt1qa9v7ehe02n543amlw5r2dn2m65xcrww6espn02l9vh4v5hw88q9sr6zmyg",
    "witness_script_hex": "a820<H(r)>8821<hot>ac",
    "script_pubkey_hex": "0020...",
    "spend_witness": "[ <hot_ECDSA_sig ‖ SIGHASH_ALL>, <r> ] then the witnessScript"
  },
  "trigger": { "address": "bcrt1q8g7...", "witness_script_hex": "63...68", "branch_a_witness": "...", "branch_b_witness": "..." },
  "import_descriptor": "addr(bcrt1qa9v7...)",
  "non_custodial": "SIGN LOCALLY — …"
}
```

### `POST /vault/unvault-tx`
The unsigned **DEPOSIT → TRIGGER** transaction + the **hot-key** sighash.
```json
{
  "network": "regtest",
  "vault": { "hot_pubkey": "...", "recovery_pubkey": "...", "recovery_hash": "...", "csv_delay": 144 },
  "deposit_outpoint": { "txid": "<deposit txid>", "vout": 0 },
  "deposit_amount_sat": 100000,
  "fee_sat": 500
}
```
Returns `unsigned_tx_hex`, `txid`, and `sighashes[0]` with `sighash_hex`,
`witness_script_hex`, `sign_with: "hot_key"`. **You** sign the sighash locally and
assemble the witness `[ <hot_sig>, <r> ]` (revealing `r` locally).

### `POST /vault/branch-a-tx`
The normal, **delayed** withdrawal **TRIGGER → destination** (matures after Δ).
```json
{
  "network": "regtest",
  "vault": { "hot_pubkey": "...", "recovery_pubkey": "...", "recovery_hash": "...", "csv_delay": 144 },
  "trigger_outpoint": { "txid": "<trigger txid>", "vout": 0 },
  "trigger_amount_sat": 99500,
  "destination": "bcrt1q...",
  "fee_sat": 500
}
```
Returns the unsigned tx + `sighashes[0]` (`sign_with: "hot_key"`); witness
`[ <hot_sig>, 0x01 ]`. The tx's `nSequence` encodes Δ, so the network rejects it until
Δ blocks after the trigger confirms.

### `POST /vault/clawback-tx`
The **immediate PQ-gated clawback** **TRIGGER → safe_destination** (branch B).
```json
{
  "network": "regtest",
  "vault": { "hot_pubkey": "...", "recovery_pubkey": "...", "recovery_hash": "...", "csv_delay": 144 },
  "trigger_outpoint": { "txid": "<trigger txid>", "vout": 0 },
  "trigger_amount_sat": 99500,
  "safe_destination": "bcrt1q<fresh unexposed cold addr>",
  "fee_sat": 500
}
```
Returns the unsigned tx + `sighashes[0]` (`sign_with: "recovery_key"`); witness
`[ <recovery_sig>, <r>, <> ]` — you sign with the **recovery** key and **reveal `r`**
locally (trailing empty item selects branch B). `safe_destination` must equal the
anchored `designated_safe_dest` and be a **fresh, unexposed** address.

### `POST /anchor/commitment`
The canonical bytes to **PQ-sign client-side** (ML-DSA-65 ‖ Falcon-1024). The server
does **not** sign.
```json
{
  "target_chain": "bitcoin",
  "btc_vault_address": "bcrt1q<deposit addr>",
  "recovery_hash": "5a5a...",
  "pq_recovery_pubkey": "<hex of enveloped ML-DSA65‖Falcon1024 PUBLIC key>",
  "designated_safe_dest": "bcrt1q<safe addr>",
  "csv_delay": 144,
  "policy": "watchtower-01",
  "btc_pubkey": "02...            (optional; adds the Custody 2-of-2 guard hash)"
}
```
Returns `commitment_bytes_hex` (sign these locally), `bloch_governance_guard_hash`
(and `bloch_custody_guard_hash` if `btc_pubkey` given).

### `POST /anchor/verify`
Verify a PQ signature over an anchor (safe server-side — no secrets). Supply either the
fields + `signature`, or a full `signed_anchor_hex` blob.
```json
{ "target_chain":"bitcoin", "btc_vault_address":"...", "recovery_hash":"...",
  "pq_recovery_pubkey":"...", "designated_safe_dest":"...", "csv_delay":144,
  "policy":"watchtower-01", "signature":"<hex PQ signature>" }
```
Returns `{ "valid": true|false, "reason": "...", "commitment_bytes_hex": "..." }`.
Tampering with any committed field fails closed.

---

## Example flow (curl): create vault → anchor → clawback

`hot_pubkey`, `recovery_pubkey`, `H(r)`, and the PQ keypair are all derived
**on the client** (e.g. via `bloch-pq-vault::derive_vault_keys` + `derive_recovery` in
your own binary). Only public values are sent below.

```bash
BASE=http://127.0.0.1:8787
HOT=0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
REC=02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5
HR=5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a

# 1) vault address (fund this deposit address on-chain)
curl -s -X POST $BASE/vault/address -d "{
  \"network\":\"regtest\",\"hot_pubkey\":\"$HOT\",\"recovery_pubkey\":\"$REC\",
  \"recovery_hash\":\"$HR\",\"csv_delay\":144}"

# 2) anchor commitment → PQ-sign the returned commitment_bytes_hex LOCALLY
curl -s -X POST $BASE/anchor/commitment -d "{
  \"target_chain\":\"bitcoin\",\"btc_vault_address\":\"bcrt1q...deposit...\",
  \"recovery_hash\":\"$HR\",\"pq_recovery_pubkey\":\"<pq pubkey hex>\",
  \"designated_safe_dest\":\"bcrt1q...safe...\",\"csv_delay\":144,\"policy\":\"wt-01\"}"

# 3) verify your PQ signature before publishing the anchor
curl -s -X POST $BASE/anchor/verify -d "{
  \"target_chain\":\"bitcoin\",\"btc_vault_address\":\"bcrt1q...deposit...\",
  \"recovery_hash\":\"$HR\",\"pq_recovery_pubkey\":\"<pq pubkey hex>\",
  \"designated_safe_dest\":\"bcrt1q...safe...\",\"csv_delay\":144,\"policy\":\"wt-01\",
  \"signature\":\"<your PQ signature hex>\"}"

# 4) attacker unvaults → you clawback within Δ to the anchored safe dest
curl -s -X POST $BASE/vault/clawback-tx -d "{
  \"network\":\"regtest\",
  \"vault\":{\"hot_pubkey\":\"$HOT\",\"recovery_pubkey\":\"$REC\",\"recovery_hash\":\"$HR\",\"csv_delay\":144},
  \"trigger_outpoint\":{\"txid\":\"<trigger txid>\",\"vout\":0},
  \"trigger_amount_sat\":99500,\"safe_destination\":\"bcrt1q...safe...\",\"fee_sat\":500}"
# → sign sighashes[0] with your RECOVERY key locally; witness [sig, r, <>]; broadcast.
```

---

## Security notes

- **Hardened recovery derivation (audit finding M1, Medium).** The security audit's
  single Medium finding: the recovery key must **not** be a *non-hardened* BIP-32
  sibling of the hot key, or a hot-key compromise plus a watch-only account xpub can
  derive the recovery key too — collapsing the hot-vs-recovery separation. **Derive the
  recovery key on a HARDENED path** (e.g. a separate hardened account
  `m/84'/coin'/1'/0/0`) client-side. The API cannot enforce this (it only ever sees
  public keys), so it is your responsibility and is flagged in `/vault/address` notes.
- **P2WSH, not Taproot.** Deposits use P2WSH so every pubkey is behind `SHA256` at
  rest. Taproot publishes a live EC output key and is *not* quantum-safe at rest.
- **`designated_safe_dest` must be fresh + unexposed.** Clawing back to a
  reused/Taproot address just moves the same exposure.
- **`r` is single-use and public after reveal.** Use a unique `vault_id` per vault
  (client-side) so preimages are independent; never re-fund a spent deposit address.
- **Honest ceiling.** Protection is a *spend-window delay + PQ-authorized recovery*, and
  depends on the owner/watchtower being online during Δ and winning the fee race. It is
  not unconditional quantum immunity. The Bloch-side PQ enforcement (`bloch-euvm`) is
  itself FOUNDATION / not consensus-wired. The real fix is a PQ soft fork (BIP-360).

## Non-custodial audit of the routes (self-check)

| Route | Needs a secret? | What the client signs locally |
|---|---|---|
| `POST /vault/address` | no | nothing (returns scripts/addresses) |
| `POST /vault/unvault-tx` | no | the hot-key sighash; reveals `r` in witness |
| `POST /vault/branch-a-tx` | no | the hot-key sighash |
| `POST /vault/clawback-tx` | no | the recovery-key sighash; reveals `r` |
| `POST /anchor/commitment` | no | PQ-signs the returned commitment bytes |
| `POST /anchor/verify` | no | nothing (verification only) |
| `GET /health`, `GET /` | no | — |

No route accepts, needs, stores, or produces a private key or signature. The crate's
secret-requiring functions (`sign_anchor`, `ecdsa_witness_sig`, `derive_vault_keys`, the
preimage derivation) are **never** called by the service.

## Hosting

- Runs anywhere as a single static binary: `cargo build --release` →
  `target/release/pq-shield-api`. Put it behind a TLS reverse proxy (nginx/Caddy) or on
  a small VM / container. It is stateless and holds no keys, so it needs no secrets
  store and no persistence.
- A Cloudflare Worker (WASM) port is possible in principle but the `bitcoin` crate + PQ
  crypto are heavy for `wasm32`; the native binary is the recommended host.
- **Do not** deploy it onto the founder/chain node — it is a separate, standalone
  service.
