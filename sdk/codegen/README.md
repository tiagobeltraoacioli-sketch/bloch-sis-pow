# Bloch SDK code generator

> ## ⛔ Historical — Genesis-3.
>
> `docs/openapi.yaml`, and therefore every client this generator emits,
> describes the **Genesis-3 proof-of-work JSON-RPC surface**. That chain stopped
> permanently at height 39,918 on 2026-08-13. The live chain is **Genesis-4,
> proof of stake**, whose RPC (`crates/bloch-pos-node/src/rpc.rs`, public read
> endpoint `https://posternlabs.com/g4rpc`) exposes a different and much smaller
> method set — `getblockbyslot`, `getvalidator`, `getvalidatorcount`,
> `getchaininfo`, `listunspent`, … — and is **not** described by the spec this
> generator reads. Regenerating produces Genesis-3 clients. Writing a Genesis-4
> spec is the work that would change that; nothing here does it.

**The spec drives the clients. Regenerate on any spec change.**

`generate.py` reads the single source of truth — `docs/openapi.yaml` (OpenAPI
3.1.0 describing a **JSON-RPC 2.0** API over one `POST /` endpoint) — and
deterministically emits typed clients:

- `sdk/python/` — a typed Python package (`blochclient`)
- `sdk/go/` — a typed Go module (`blochclient`)

```bash
python3 sdk/codegen/generate.py
```

Re-running is idempotent: same spec in, byte-identical clients out.

## What it does

1. **Parses** `components.schemas` (the domain types) and the
   `x-json-rpc-methods` vendor extension (name -> positional params -> result
   schema). OpenAPI can't model JSON-RPC natively, so the real method surface
   lives in that extension.
2. **Emits typed models** from the schemas:
   - scalar schemas (`Hex32`, `Hex20`, `Address`) -> type aliases,
   - `Satoshis` -> a per-language codec, NOT an alias (see below),
   - object schemas -> Python `TypedDict`s / Go structs,
   - `oneOf`-of-objects -> a merged optional-field type (union shape),
   - `oneOf` with a `null` variant -> `Optional` / pointer,
   - inline nested objects (e.g. `Pools.pools`) -> hoisted synthetic models.
3. **Emits one typed wrapper per JSON-RPC method** that packs positional
   `params` into the `{jsonrpc, id, method, params}` envelope. Trailing optional
   params equal to their default are trimmed (matching the hand-written TS SDK).
4. **Ships a JSON-RPC transport** that normalizes BOTH Bloch error shapes:
   - the standard top-level `error` object (transport/auth: `-32001`/`-32002`),
   - the non-standard string `result.error` (HTTP 200, most method failures).
5. **Applies rails + licensing** from the start: SPDX headers on every file,
   `LICENSE-MIT` + `LICENSE-APACHE` in each package, honesty rails in each
   README, and a `@generated from docs/openapi.yaml` banner on the derived
   model/client files.

6. **Runs `gofmt -w`** over the emitted Go files when the Go toolchain is on
   PATH. The emitter writes single-space struct fields; gofmt column-aligns
   them, so this keeps regeneration byte-identical to what is committed. When
   `gofmt` is absent the output is still valid Go, just unaligned — the run
   prints which happened.

## Amounts are not a scalar alias

`Satoshis` is the one schema that does not become a plain type alias. The
Genesis-4 supply cap is 10^19 satoshis
(`crates/bloch-pos-committee/src/tokenomics_v4.rs`) — 108% of `i64::MAX` and
about 1110x JavaScript's exact-integer limit of 2^53 — so an amount travels the
wire as a **decimal string** and each language binds its own codec:

- Go: `type Satoshis uint64` with `MarshalJSON`/`UnmarshalJSON`, in
  `satoshis.go` (+ `satoshis_test.go`, both static assets).
- Python: `Satoshis = Union[str, int]` (the wire shape) with `parse_sats()` /
  `format_sats()` in `units.py`.

Do not "simplify" either back to a JSON number: it would fix nothing and break
every JavaScript consumer silently. Rule and rationale:
`docs/specs/BLOCH-SATOSHI-ENCODING.md`.

## Files

- `generate.py` — the generator (stdlib + PyYAML only).
- `static_assets.py` — verbatim scaffold (errors, unit helpers, the amount
  codec + its tests, the `Signer` seam, packaging metadata, READMEs, licenses).
  Not spec-derived, so these carry the SPDX header but not the `@generated`
  banner.

## Signing seam

Clients deliberately do **not** implement Bloch's hybrid
Falcon-1024 || ML-DSA-65 signing. The only write, `sendrawtransaction`, takes an
already-signed raw tx hex; each client exposes a `Signer` interface seam only.

## Rails

SCAFFOLD / generated / unaudited / pre-production. No privileged access
("ownerless" retracted — `docs/adr/ADR-036-retract-ownerless-adopt-foundation.md`).
The generated clients target the retired Genesis-3 chain. Under the live
Genesis-4 chain the security question is concentration, not hashrate: all 64
validators are run by one entity, 93.94% of the carryover sits at a single
address, and 56.05 B of the 57.15 B BLOCH issued at genesis is held by the
founder and the Foundation. BLCH is neutral protocol gas, NOT a security; the
"17% premine" is Genesis-3 tokenomics V2 — under Genesis-4 the founder holds
27.04% of the 100 B cap. Plans, not promises.
