# Wave 169 — CR-07 bounded disclosure CLI read

Date: 2026-09-19
Comparison base: `9d8c0ed4`

## Reproduced residual

Both `postern-wallet verify-bundle` and `postern-wallet watch` converged on
`load_and_verify_bundle`, which used `std::fs::read_to_string` without a byte
budget. The typed verifier later limits the entry count, text fields and
Base64-decoded key/signature fields, but those checks ran only after the CLI
had allocated and read the complete file and Serde had materialized its
strings.

Before this correction, a sparse 67,108,865-byte file reached JSON parsing and
failed with `Bundle parse failed: expected value at line 1 column 1`. That
demonstrates that the former path read beyond the repository's established
64 MiB ordinary-wallet input budget instead of rejecting at the file boundary.

## Correction

- Route the shared disclosure CLI loader through the existing bounded file
  reader with the established 64 MiB default budget.
- Read at most one byte beyond the budget to distinguish an exact-bound file
  from an excess file, then reject before JSON parsing.
- Parse directly from the bounded byte buffer instead of an unbounded UTF-8
  `String`. This replaces the input owner; it does not eliminate the one
  admitted file buffer.
- Preserve the same `DisclosureBundle` Serde schema and the same compatible or
  canonical verification policy after parsing.

The budget has ample headroom over canonical/ordinary serialization of the
bounded typed fields: at most 1,024 entries are accepted; each accepted entry
has at most 10,924 encoded public-key bytes and 21,848 encoded signature bytes,
while the three signed text fields are each limited to 4,096 bytes and a valid
address has fixed encoding. The change therefore does not alter repository-
produced bundle output, signature bytes, digest construction, schema, public
APIs, KDF or RNG behavior. Oversized CLI input now receives a specific
input-limit diagnostic.

## Adversarial regression

`cli_disclosure_file_budget_accepts_exact_limit_and_rejects_one_more_byte`
uses a valid serialized bundle padded with JSON whitespace. It proves that:

- the exact configured byte limit is read and deserialized;
- one additional byte is rejected with the resource-limit diagnostic; and
- the excess input never reaches the JSON parse-error path.

Focused validation:

- `cargo test -p bloch-crypto --features wallet-cli --offline cli_disclosure_file_budget_accepts_exact_limit_and_rejects_one_more_byte -- --nocapture`
  - library target: `1 passed; 0 failed; 240 filtered out`.

Full relevant validation:

- `cargo test -p bloch-crypto --features wallet-cli --offline`
  - library target: `239 passed; 0 failed; 2 ignored`;
  - ACVP integration: `3 passed; 0 failed`;
  - Falcon integration: `2 passed; 0 failed`;
  - transaction integration: `1 passed; 0 failed`;
  - doc tests: `0 failed; 2 ignored`;
  - aggregate: `245 passed; 0 failed; 4 ignored`.

## Boundary and residuals

- The bounded reader necessarily allocates the admitted file byte buffer, and
  Serde still allocates the typed strings for an admitted bundle.
- JSON with more than 64 MiB of otherwise ignorable whitespace or unknown
  fields can deserialize to the same typed bundle, but is intentionally outside
  this bounded CLI policy and is rejected before parsing.
- This CLI policy does not change the public in-memory
  `DisclosureBundle::verify` API; callers of that API remain responsible for
  bounding their own transport and deserialization.
- The limit is applied after filesystem open and ordinary metadata lookup; it
  is a byte budget, not filesystem authenticity or TOCTOU protection.
- Crypto backends and the compiler may retain opaque copies outside the
  repository's observable ownership.
- `CR-07` remains `PARTIAL`.
