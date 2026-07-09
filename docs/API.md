# Bloch-SIS Protocol (BLOCH) API Quick Start

**Version:** v0.5.9
**Protocol:** JSON-RPC 2.0 over HTTP
**Formal spec:** [`docs/openapi.yaml`](openapi.yaml) — renders at [`docs/api.html`](api.html)

This is a hands-on introduction. For the authoritative schema of every
method and response, read `openapi.yaml`.

---

## Transport

Single endpoint: **`POST /`** on port **16210**.

Every call is a JSON-RPC 2.0 envelope:

```json
{ "jsonrpc": "2.0", "method": "<method>", "params": [<args>], "id": 1 }
```

Default bind is `127.0.0.1` (localhost only). Public nodes run with
`--rpc-public` to bind `0.0.0.0:16210`. There is currently **no
authentication** — operators exposing the API publicly must front it
with a reverse proxy + auth (planned: Sprint M).

## Hello world

```bash
curl -s -X POST http://127.0.0.1:16210/ \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getblockcount","params":[],"id":1}'
```

Response:

```json
{ "jsonrpc": "2.0", "result": 9, "id": 1 }
```

## Authentication (Sprint M — v0.5.9+)

The node supports optional shared-secret API key authentication for
write operations. Read methods are always public by design (explorers
and dashboards need them).

### Quick start

```bash
# Generate a strong key
openssl rand -hex 32 > /etc/bloch-layer/api-key
chmod 600 /etc/bloch-layer/api-key

# Start a node with auth required for writes
./bloch \
  --rpc-public \
  --rpc-api-key-file /etc/bloch-layer/api-key \
  --rpc-require-auth-for-writes
```

### Sending authenticated requests

Using `X-API-Key` header (preferred):

```bash
curl -s -X POST http://node.example:16210/ \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $(cat /etc/bloch-layer/api-key)" \
  -d '{"jsonrpc":"2.0","method":"sendrawtransaction","params":["..."],"id":1}'
```

Or using `Authorization: Bearer`:

```bash
curl -s -X POST http://node.example:16210/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $(cat /etc/bloch-layer/api-key)" \
  -d '{"jsonrpc":"2.0","method":"sendrawtransaction","params":["..."],"id":1}'
```

If both headers are present, `X-API-Key` wins.

### Behavior

- **Localhost (127.0.0.1 / ::1) always bypasses** auth and rate limit.
- **Read methods** (`getblock`, `getbalance`, `getchainstats`, etc.) are
  always public.
- **Write methods** (`sendrawtransaction` — currently the only one) are
  always rate-limited; auth required only when
  `--rpc-require-auth-for-writes` is on.
- **Rate limits per IP**: 60 reads/min, 5 writes/min by default.
  Configurable with `--rpc-rate-limit-reads` and
  `--rpc-rate-limit-writes`.
- **Invalid keys are rejected** even on read methods (probing protection).

### Deployment matrix

| `rpc_bind` | `rpc_api_key` | `rpc_require_auth_for_writes` | Behavior |
|---|---|---|---|
| 127.0.0.1 | (none) | false | Dev default. No auth, no rate limit. |
| 127.0.0.1 | any | any | Auth ignored for localhost. |
| 0.0.0.0 | (none) | false | Public reads + public writes, rate-limited. Warning at startup. |
| 0.0.0.0 | (none) | true | **Refused at startup.** Needs a key to require auth. |
| 0.0.0.0 | set | false | Public reads + writes (rate-limited). Key is optional. |
| 0.0.0.0 | set | true | **Recommended production.** Reads public, writes require `X-API-Key`. |

### Error codes

| HTTP | JSON-RPC code | Meaning |
|---|---|---|
| 401 | -32001 | Unauthorized — valid `X-API-Key` required |
| 429 | -32002 | Rate limit exceeded — retry after ~60s |

### Production recommendations

1. **Always use `--rpc-api-key-file` in production**, not `--rpc-api-key`.
   The CLI flag leaks the key into `ps aux`.
2. **Put nginx/Caddy with TLS in front** of the node. The API key
   travels in cleartext otherwise.
3. **Rotate the key periodically** by writing a new value to the file
   and restarting the node.
4. **Monitor 401/429 rates** — spikes indicate probing or misconfigured
   clients.

---

## Top 10 methods you'll actually use

### 1. Check node health

```bash
curl -s -X POST http://127.0.0.1:16210/ \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getnetworkinfo","params":[],"id":1}'
```

Returns block count, peer count, mempool size, sync status.

### 2. Read a block

By height:

```bash
curl -s -X POST http://127.0.0.1:16210/ \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getblockbyheight","params":[9, true],"id":1}'
```

Second param `true` expands transactions inline. Pass `false` (or omit)
to get only txids for a compact response.

By hash: use `getblock` with the same second parameter.

### 3. Look up an address balance

```bash
curl -s -X POST http://127.0.0.1:16210/ \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getbalance","params":["bloch1q...placeholder...address..."],"id":1}'
```

Response includes both `satoshis` (integer, lossless) and `bloch`
(float, for display only). Never do arithmetic on `bloch`.

### 4. Get UTXOs for coin selection

```bash
curl -s -X POST http://127.0.0.1:16210/ \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getutxos","params":["bloch1q..."],"id":1}'
```

Returns each unspent output: txid, index, value, script_pubkey. This
is the input for wallet software building a new transaction.

### 5. Transaction history (paginated)

```bash
curl -s -X POST http://127.0.0.1:16210/ \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"listtransactions","params":["bloch1q...", 50, 0, 1000, 0],"id":1}'
```

Positional args: `[address, limit, start_height, end_height, offset]`.
`limit` max is 1000. Use `offset` for pagination.

### 6. Transaction lookup by txid

```bash
curl -s -X POST http://127.0.0.1:16210/ \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"gettransaction","params":["abc123...def"],"id":1}'
```

Returns the full transaction + block context + confirmations.

Lightweight variant: `gettxstatus` returns only `{status, confirmations, block_height}`.

### 7. Broadcast a transaction

```bash
curl -s -X POST http://127.0.0.1:16210/ \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"sendrawtransaction","params":["0100...fe"],"id":1}'
```

The hex is a bincode-serialized `Transaction`. Wallet libraries produce
it; see `bloch-wallet` CLI for the reference implementation. Returns
`{txid}` on success or `{error}` on failure.

### 8. Fee estimate before signing

```bash
curl -s -X POST http://127.0.0.1:16210/ \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"estimatefeeadvanced","params":[],"id":1}'
```

Returns priority tiers: `next_block_sats`, `medium_priority`,
`slow_priority`, plus current mempool median.

### 9. Address validation

Before you send to an address a user typed:

```bash
curl -s -X POST http://127.0.0.1:16210/ \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"validateaddress","params":["bloch1q..."],"id":1}'
```

Returns `{isvalid, network, checksum}`. Never skip this step for
user-supplied addresses — a typo becomes a lost transaction.

### 10. Chain analytics (for dashboards)

```bash
curl -s -X POST http://127.0.0.1:16210/ \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getchainstats","params":[],"id":1}'
```

All-in-one stats: total blocks, hashrate, difficulty, 24h counters.

---

## Common patterns

### Unit convention

All monetary values are exposed in **both** units:

- `satoshis` (or `*_sats`) — integer, the source of truth. Do all
  arithmetic here.
- `bloch` (or `*_bloch`) — float, display only. 1 BLOCH = 10^8 satoshis.

Floats lose precision for large values. Never store balances as `bloch`.

### Hex encoding

- Block hashes, txids: 32-byte values, encoded as **64 lowercase hex
  chars**.
- Address hashes (internal): 20-byte values, 40 hex chars.
- Bech32-style user addresses: `bloch1q` (mainnet) or `bloch1t` (testnet)
  prefix, followed by 40 hex + 8 hex checksum.

### Timestamps

All timestamps are Unix epoch **seconds**, UTC. Multiply by 1000 for
JavaScript `Date`.

### Errors

Bloch-SIS Protocol currently returns errors inside `result.error`:

```json
{ "jsonrpc": "2.0", "result": { "error": "not found" }, "id": 1 }
```

This is non-standard JSON-RPC (standard uses a top-level `error`
object). Client libraries should handle both. Will be normalized in a
future release.

### Pagination

`listtransactions` accepts `offset` and `limit`. The response includes
`total_available` so you know whether another page exists.

For `getrecentblocks`, the max is 50 per call. For historical sweeps,
iterate by height.

### Confirmations

- `0` = in mempool, unconfirmed
- `1..99` = `confirmed`
- `>= 100` = `final` (coinbase maturity)

Applications requiring strong finality should wait for 100+
confirmations, matching the coinbase maturity rule.

---

## Known issues in v0.5.9

These are documented here and in the method pages for transparency.

| Method | Issue | Tracker |
|---|---|---|
| `getpeers` | Lists stale peers that failed Kyber handshake; `peer_count` overstates mesh size | SPRINTS.md |
| `getchainstats` / `gethashrate` | `avg_block_time_secs` may be very large when DAG has out-of-order timestamps | SPRINTS.md |
| `listtransactions` | Address-history indexer does not roll back on reorg | SPRINTS.md |
| `sendrawtransaction` | Mempool validation is slightly stricter than block validation in some edge cases | SPRINTS.md Sprint N-full |

---

## Generating client SDKs

The spec is machine-readable. To generate clients:

```bash
# TypeScript
npx @openapitools/openapi-generator-cli generate \
  -i docs/openapi.yaml -g typescript-fetch -o sdk/ts

# Python
openapi-generator-cli generate \
  -i docs/openapi.yaml -g python -o sdk/python

# Go
openapi-generator-cli generate \
  -i docs/openapi.yaml -g go -o sdk/go
```

Note: because Bloch-SIS Protocol uses JSON-RPC envelope rather than one
endpoint per method, generated REST clients need a thin wrapper to
marshal calls into the envelope. See `clients/` in the repo (when
populated) for pre-wrapped reference clients.

---

## Support

- Schema questions / issues: file on GitHub
- Security issues: see `SECURITY.md` for private disclosure
- General integration help: open a Discussion on the repo
