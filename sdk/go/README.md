# blochclient (Go) — community Bloch JSON-RPC client

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

Typed Go client for the **Bloch (bloch-sis)** JSON-RPC 2.0 API. It is
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
go get github.com/bloch-community/blochclient-go
```

(Or vendor `sdk/go` directly; the module has zero non-stdlib dependencies.)

## Usage

```go
package main

import (
	"fmt"
	"log"

	blochclient "github.com/bloch-community/blochclient-go"
)

func main() {
	c := blochclient.New("http://127.0.0.1:16210")

	height, err := c.GetBlockCount()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("height:", height)

	bal, err := c.GetBalance("bloch1q...")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(blochclient.SatsToBloch(bal.Satoshis), "BLCH")

	if _, err := c.GetTransaction("deadbeef"); err != nil {
		// Both failure shapes arrive as *RPCError:
		//   Source == "result-error"  (HTTP 200, string result.error)
		//   Source == "jsonrpc-error" (top-level error; IsUnauthorized/IsRateLimited)
		if rpcErr, ok := err.(*blochclient.RPCError); ok {
			fmt.Println("rpc failed:", rpcErr.Source, rpcErr.Message)
		}
	}
}
```

### The two error shapes

Bloch reports failures in two places; the client surfaces both as `*RPCError`:

- **Top-level `error`** — transport/auth only: `-32001` unauthorized (HTTP 401),
  `-32002` rate limited (HTTP 429). `Source == "jsonrpc-error"`; use
  `IsUnauthorized()` / `IsRateLimited()`.
- **`result.error` string** — most method failures (HTTP 200). `Source ==
  "result-error"`.

Network / malformed-response problems return `*TransportError`.

### Amounts

`Satoshis` is a `uint64` in memory and a **decimal string** on the wire
(`satoshis.go`). It is not `int64`, and not a JSON number, for two separate
reasons: the supply cap is 10^19 satoshis, which is 108% of `int64`'s positive
range, and — the reason that actually drove the design — about 1110x
JavaScript's exact-integer limit of 2^53, so a JSON number is silently rounded
by every browser reading the same response. Real Bloch balances are already
~187x past that limit.

`MarshalJSON` emits the string form and rejects amounts above the cap;
`UnmarshalJSON` accepts the string form and the legacy bare-number form from
Genesis-3 nodes, parsing the raw token rather than a float. Use
`ParseSatoshis`, `.Uint64()`, `.String()`, `SatsToBloch`, `BlochToSats`. The
`*_bloch` float companions are display-only and lossy — never use them for
accounting. Rule: `docs/specs/BLOCH-SATOSHI-ENCODING.md`.

### Writes and signing

The only write is `SendRawTransaction(hex)`, which takes an **already-signed**
raw transaction. This SDK does **not** implement Bloch's hybrid
Falcon-1024 || ML-DSA-65 signing — see `signer.go` for the `Signer` seam and
bring your own tx-builder. For write-auth on a non-local node, set
`client.APIKey` (and optionally `client.Bearer = true`).

## Regenerating

```bash
python3 sdk/codegen/generate.py
```

`models.go` and `client.go` carry a `@generated` banner and must not be edited
by hand.

## License

Dual-licensed under **MIT OR Apache-2.0**. See `LICENSE-MIT` and `LICENSE-APACHE`.
