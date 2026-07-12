# Bloch SDK code generator

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
   - scalar schemas (`Hex32`, `Hex20`, `Address`, `Satoshis`) -> type aliases,
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

## Files

- `generate.py` — the generator (stdlib + PyYAML only).
- `static_assets.py` — verbatim scaffold (errors, unit helpers, the `Signer`
  seam, packaging metadata, READMEs, licenses). Not spec-derived, so these carry
  the SPDX header but not the `@generated` banner.

## Signing seam

Clients deliberately do **not** implement Bloch's hybrid
Falcon-1024 || ML-DSA-65 signing. The only write, `sendrawtransaction`, takes an
already-signed raw tx hex; each client exposes a `Signer` interface seam only.

## Rails

SCAFFOLD / generated / unaudited / pre-production. Bloch is ownerless and
neutral (no privileged access). Base is experimental mainnet-beta (k=4 trivially
forgeable, 51%-attackable). BLCH is neutral protocol gas, NOT a security,
worthless by design as anything but gas; 17% premine disclosed. Plans, not
promises.
