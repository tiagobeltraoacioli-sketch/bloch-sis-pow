# Wave 123 — EN-08 direct canonical block framing

Date: 2026-09-19
Comparison base: `1719acf`

## Finding

`net::block_frame` encoded a borrowed block envelope into a temporary
`Vec<u8>`, then copied the complete payload into the final transport frame
after `FRAME_BLOCK`. Locally produced blocks take this path through
`PreparedBlockBroadcast` for devnet, libp2p and dual transport, so every local
announcement briefly retained and recopied an otherwise unnecessary canonical
payload of up to the existing block limit.

The final frame vector is required by the existing broadcast APIs and remains
owned exactly as before. Only the intermediate encoded payload is removed.

## Correction

`block_frame` now reserves `1 + encoded_envelope_len(env)`, writes the unchanged
`FRAME_BLOCK` tag, and calls the canonical `codec::write_envelope` emitter
directly into that final vector. `encode_envelope`, persistence and framing
therefore share the same byte-emission authority rather than maintaining a
second encoding implementation.

The public `block_frame(&BlockEnvelope) -> Vec<u8>` API, exact
`FRAME_BLOCK || encode_envelope(env)` bytes, prepared block id, devnet/libp2p/
dual routing, queue accounting and downstream decode are unchanged. Existing
producer/admission caps are also unchanged; the capacity calculation is only a
hint for the already-admissible envelope.

## Adversarial evidence

- `block_frame_matches_canonical_oracle_for_empty_full_and_large_bodies` pins
  exact bytes against an independently assembled
  `FRAME_BLOCK || encode_envelope` oracle for empty, attestation/transaction
  and 1 MiB-body envelopes. It also pins exact encoded length and successful
  payload decode with unchanged header, signature, transactions and
  attestation count.
- `prepared_block_broadcast_binds_large_wire_bytes_and_exact_id` now uses the
  explicit public-codec oracle rather than calling `block_frame` to construct
  its expectation, and preserves the exact id/frame binding for a 1 MiB body.
- `devnet_predecode_charge_matches_the_engine_release_charge` preserves the
  wire-derived queue charge and release symmetry.

Validation:

```text
cargo check -p bloch-pos-node --bin bloch-pos --offline
# passed

cargo test -p bloch-pos-node --bin bloch-pos --offline \
  block_frame_matches_canonical_oracle_for_empty_full_and_large_bodies -- --nocapture
# 1 passed; 0 failed; 604 filtered out

cargo test -p bloch-pos-node --bin bloch-pos --offline \
  prepared_block_broadcast_binds_large_wire_bytes_and_exact_id -- --nocapture
# 1 passed; 0 failed; 604 filtered out

cargo test -p bloch-pos-node --bin bloch-pos --offline \
  devnet_predecode_charge_matches_the_engine_release_charge -- --nocapture
# 1 passed; 0 failed; 604 filtered out
```

```text
cargo test -p bloch-pos-node --bin bloch-pos --offline
# outside the sandbox; 586 passed; 0 failed; 19 ignored; 60.25s
# includes two_nodes_form_a_mesh_and_keep_exchanging_blocks
```

## Residual boundary

The final transport frame remains a `Vec<u8>` because both broadcast stacks
consume owned frames. Dual transport still makes the existing second owned
copy so its independently scheduled stacks cannot alias mutable ownership, and
libp2p still hands its payload to gossipsub's owned message API. This patch
removes only the canonical payload temporary and copy during local block frame
construction; it does not claim an exact heap/RSS reduction. No wire, API,
protocol, consensus, verdict, cap, recovery or activation rule changed.
