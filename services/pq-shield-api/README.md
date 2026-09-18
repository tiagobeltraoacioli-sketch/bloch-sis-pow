# PQ-Shield API — a non-custodial developer endpoint for PQ-Shield Bitcoin vaults

> ## ⚠️ SIGN LOCALLY — NON-CUSTODIAL
> **This server does not sign and does not require private keys.** Every route does
> **construction + verification only** and returns an *unsigned* artifact — a vault
> address, a witnessScript, an unsigned transaction, a BIP-143 sighash, or the anchor
> commitment bytes — for **you to sign locally**. Keep all secret material
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
P2WSH construction + hashlocked classical recovery on stock Bitcoin**, plus an
off-chain **PQ-signed anchor commitment**.
It is *not* the video/demo — this endpoint is how third-party builders integrate the
feature into their own products.

Read the crate's `HONEST LIMITS` and
[`CONSTRUCTION-AUDIT.md`](../../crates/bloch-pq-vault/CONSTRUCTION-AUDIT.md) before
testing it. Those are internal follow-up notes, not external product qualification.
This is **transition-era defense-in-depth, NOT unconditional quantum immunity**.

---

## Run it

```bash
cd services/pq-shield-api
cargo run                       # binds 127.0.0.1:8787
PQ_SHIELD_BIND=127.0.0.1:8787 cargo run   # loopback only
cargo test                      # endpoint and audit regression tests
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
   │ <hot> CHECKSIG│              │ ENDIF                      │   = hashlocked RECOVERY
   └──────────────┘              └───────────────────────────┘
```

- **Branch A** carries the CSV relative-timelock Δ (normal, delayed spend, hot key).
- **Branch B** is immediate and requires the PQ-derived preimage `r` plus a
  recovery-key signature. The unvault reveals `r`, so after that event the
  recovery signature is the remaining authorization check.
- The **Bloch anchor** is the PQ-signed record binding
  `{vault address, H(r), pq pubkey, safe dest, Δ, policy}`. This repository can
  construct and verify that record off chain, but does not post, order, revoke,
  or enforce it on Bloch consensus. Bitcoin enforces only its own script.

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
The **immediate hashlocked recovery** **TRIGGER → safe_destination** (branch B).
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
fields + `signature`, or a full `signed_anchor_hex` blob — **plus a required
`trusted_pq_pubkey`**.
```json
{ "target_chain":"bitcoin", "btc_vault_address":"...", "recovery_hash":"...",
  "pq_recovery_pubkey":"...", "designated_safe_dest":"...", "csv_delay":144,
  "policy":"watchtower-01", "signature":"<hex PQ signature>",
  "trusted_pq_pubkey":"<hex of the PQ pubkey YOU already trust for this vault>" }
```
Returns `{ "valid": true|false, "reason": "...", "non_custodial": "..." }`.
Tampering with any committed field fails closed. Verification no longer echoes
supplied trusted-key bytes or commitment bytes (BV-20). Obtain signing bytes
from `/anchor/commitment`, where returning the public policy is necessary.

> **`trusted_pq_pubkey` is not optional, and it is the whole point.** An anchor carries
> its own `pq_recovery_pubkey`, so checking the signature against *that* is
> self-certifying: an attacker generates a PQ keypair, writes their own
> `designated_safe_dest` into an anchor, signs it with their own secret, and publishes a
> blob that "verifies" perfectly. A watchtower trusting that answer could accept the
> attacker's destination as authorized. Authenticity here means *signed by **the** owner*,
> so you must pass the key you obtained out-of-band — from vault registration or from
> the anchor guard hash, which commits to it. A mismatch returns
> `reason: "UntrustedKey"`. Omitting the field is a `400`, never an implicit "valid".

`csv_delay` is a `u16` (Bitcoin's actual CSV width); a wider value is rejected, not
truncated. `version` is honored — an anchor from an unknown format version is refused.

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

# 3) verify your PQ signature before publishing the anchor.
#    trusted_pq_pubkey = the key you already trust for this vault (here, your own).
curl -s -X POST $BASE/anchor/verify -d "{
  \"target_chain\":\"bitcoin\",\"btc_vault_address\":\"bcrt1q...deposit...\",
  \"recovery_hash\":\"$HR\",\"pq_recovery_pubkey\":\"<pq pubkey hex>\",
  \"designated_safe_dest\":\"bcrt1q...safe...\",\"csv_delay\":144,\"policy\":\"wt-01\",
  \"signature\":\"<your PQ signature hex>\",
  \"trusted_pq_pubkey\":\"<pq pubkey hex>\"}"

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

- **Hardened recovery derivation (historical finding M1).** The recovery key must
  **not** be a *non-hardened* BIP-32
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
- **A broadcaster is keyless only when it receives finite pre-signed replacements.**
  Giving a service `recovery_sk` or a signing oracle makes it custodial and able to
  redirect funds; the RBF sequence bit alone grants no replacement authority.
- **Honest ceiling.** Protection is a *spend-window delay + hashlocked classical recovery*, and
  depends on the owner/watchtower being online during Δ and winning the fee race. It is
  not unconditional quantum immunity. The separate PQ commitment is verified off chain;
  no Bloch anchor registry is consensus-wired. The real fix is a PQ soft fork (BIP-360).

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


## Internal audit hardening (2026-09-17)

The binary now refuses non-loopback listeners. Expose it only through a local
TLS proxy with authentication and per-client rate limits. POST routes require
`Content-Type: application/json`, reject browser `Sec-Fetch-Site: cross-site`,
and cap bodies at 128 KiB. The existing concurrency ceiling limits simultaneous
requests; asynchronous timeouts do not preempt synchronous signature checks.

Construction and verification accept only valid Bitcoin addresses sharing a
network, and require a CSV delay of at least 144 blocks, including nested vault
parameters and serialized anchor requests. Non-Bitcoin target-chain construction
is unsupported. Transaction construction rejects outputs below the default
Bitcoin dust threshold, amounts above MAX_MONEY, and fees over 10% of the input.
This fee limit is API policy, not a dynamic fee estimator; clients must still
prepare and validate an emergency fee strategy before funding a vault.

The two anchor verification request forms are exclusive: either provide typed
anchor fields and `signature`, or provide `signed_anchor_hex`. Unknown fields
are rejected in both forms. The field-name guard catches common accidental
secret submissions; it cannot recognize arbitrary secret bytes in allowed
strings or undo disclosure after a request reaches the service. Public keys
and unvault plans are sensitive to the vault threat model even though they are
not private keys: prefer local construction and never treat a remote API as a
privacy boundary. Address validation does not establish freshness, ownership,
or correspondence to a particular on-chain vault script.

For new client-side vault key generation, use the explicitly versioned
`derive_vault_keys_v3` and persist `VaultKeyDerivation::V3HardenedRoles` in the
backup. V3 uses `m/1999'/coin'/0'/{0',1'}` and a separate PQ domain. V1 and V2
outputs remain unchanged for recovery of existing funds. This does not retrofit
existing vaults: moving funds requires a separately reviewed migration. It also
does not resolve deposit/branch-A key reuse, keyless watchtower fee bumping,
anchor revocation, or recovery preimage lifecycle design.

### Response minimization (BV-20, 2026-09-17)

Invalid JSON/schema, secret-shaped field names and unsupported network/chain
errors do not repeat submitted keys or values. Verification returns its verdict
without echoing the input key or policy-containing commitment. This changes
response fields; clients should retain their own public inputs and use the
commitment endpoint for signing bytes. No request-content secret detector is
claimed: allowed policy text remains public, is committed exactly as supplied,
and is necessarily included in the commitment endpoint's bytes. Never send
secrets in policy text or other allowed fields. These changes cannot erase data
already disclosed in a request, nor control proxy/access-log configuration.
