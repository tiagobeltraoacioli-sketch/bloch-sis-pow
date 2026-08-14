# blochclient (Python) — community Bloch JSON-RPC client

> ## ⛔ Historical — Genesis-3. Read this first.
>
> **This client targets the Genesis-3 proof-of-work JSON-RPC surface, and that
> chain stopped permanently at height 39,918 on 2026-08-13.** The live chain is
> **Genesis-4, proof of stake** (30 s slots, 32-slot epochs, finality by epoch);
> its public read RPC is `https://posternlabs.com/g4rpc`. Genesis-4 exposes a
> different and much smaller method set (`getblockbyslot`, `getvalidator`,
> `getvalidatorcount`, `getchaininfo`, `listunspent`, …), so most calls this
> client makes — `getdaginfo`, `gethashrate`, `getblockbyheight`,
> `getblocktemplate` — have no counterpart on it. Do not point it at the live
> chain and expect it to work. Kept because Genesis-4's opening ledger is
> derived from Genesis-3.

Typed Python client for the **Bloch (bloch-sis)** JSON-RPC 2.0 API. It is
**generated** from `docs/openapi.yaml` by `sdk/codegen/generate.py` — the spec
drives the client; regenerate on any spec change.

## Status & honesty rails (read before you rely on this)

- **SCAFFOLD / generated / pre-production / UNAUDITED.** This client is
  machine-generated from `docs/openapi.yaml` and has not completed a security
  audit. Expect rough edges; pin a commit and review before production use.
- **This SDK grants no special rights** and makes no promises of support.
  ("Ownerless / no company behind the base protocol" was retracted — see
  `docs/adr/ADR-036-retract-ownerless-adopt-foundation.md`.)
- **The security question is concentration, not hashrate.** The old caveat here
  — proof of work at k = 4, witness trivially forgeable, the chain
  51%-attackable — described Genesis-3 and was true of it. Under Genesis-4:
  **all 64 validators are run by one entity**, **93.94% of the carryover sits
  at a single address**, and **56.05 B of the 57.15 B BLOCH issued at genesis
  is held by the founder and the Foundation**. One operator can halt the chain
  and one holder can outvote every other. A third party cannot yet join — the
  transport is a point-to-point TCP full mesh with a fixed peer list, no
  discovery and no authentication, and `Deposit`/`Delegate` are refused at
  every node's mempool.
- **BLCH is neutral protocol gas.** It is **NOT a security**, share, or claim
  on anyone's revenue — no yield, dividend, or profit is offered or implied.
  The "17% premine" disclosed here is Genesis-3 tokenomics V2 and no longer
  describes the supply: under Genesis-4 the founder holds **27.04% of the 100 B
  cap** (`FOUNDER_TOTAL_BLOCH` in
  `crates/bloch-pos-committee/src/tokenomics_v4.rs`) and the Foundation a
  further **29.00%**.
- **Plans, not promises.** Anything forward-looking here is a plan and may
  change or never ship.

This is the community edition. It is not, and must not be described as, any
branded/commercial distribution.


## Install

```bash
pip install -e sdk/python
# or just add sdk/python to your PYTHONPATH — the package has zero deps.
```

## Usage

```python
from blochclient import BlochClient, BlochRpcError, parse_sats, sats_to_bloch

client = BlochClient("http://127.0.0.1:16210")

height = client.get_block_count()
info = client.get_network_info()          # -> NetworkInfo (TypedDict)
bal = client.get_balance("bloch1q...")    # -> Balance

# Amounts arrive as DECIMAL STRINGS. parse_sats() gives you an exact int and
# also accepts the legacy bare-int form from Genesis-3 nodes.
sats = parse_sats(bal["satoshis"])
print(sats_to_bloch(sats), "BLCH")

try:
    client.get_transaction("deadbeef")     # bad hash
except BlochRpcError as e:
    # Both failure shapes land here:
    #   e.source == "result-error"  (HTTP 200, string result.error)
    #   e.source == "jsonrpc-error" (top-level error; e.is_unauthorized / e.is_rate_limited)
    print("rpc failed:", e)
```

### The two error shapes

Bloch reports failures in two places and the client normalizes both into
`BlochRpcError`:

- **Top-level `error`** — transport/auth only: `-32001` unauthorized (HTTP 401),
  `-32002` rate limited (HTTP 429). `source == "jsonrpc-error"`.
- **`result.error` string** — most method failures (HTTP 200). `source ==
  "result-error"`.

Network / malformed-response problems raise `BlochTransportError`.

### Amounts

A satoshi amount is a **decimal string** on the wire, not a JSON number. The
supply cap is 10^19 satoshis — about 1110x JavaScript's exact-integer limit of
2^53 — so a JSON number is silently rounded by any IEEE-754 reader, and real
Bloch balances are already ~187x past that limit. Python's `int` is
arbitrary-precision, so Python was never the victim; it shares the wire.

Run every amount through `parse_sats()` (accepts the string form and the legacy
bare int from Genesis-3 nodes, returns an exact `int`, rejects negatives and
anything above the cap) and `format_sats()` on the way out. The `*_bloch` float
companions are display-only and lossy — never use them for accounting. Rule:
`docs/specs/BLOCH-SATOSHI-ENCODING.md`.

### Writes and signing

The only write is `send_raw_transaction(hex)`, which takes an **already-signed**
raw transaction. This SDK does **not** implement Bloch's hybrid
Falcon-1024 || ML-DSA-65 signing — see `signer.py` for the `Signer` seam and
bring your own tx-builder. When the node runs with write-auth enabled and you
call from a non-local IP, pass `api_key=...` (or `bearer=True`).

## Regenerating

```bash
python3 sdk/codegen/generate.py
```

`models.py` and `client.py` carry a `@generated` banner and must not be edited
by hand.

## License

Dual-licensed under **MIT OR Apache-2.0**. See `LICENSE-MIT` and `LICENSE-APACHE`.
