# Wave 94 — NET-04 directed-sync byte preflight

Date: 2026-09-19
Comparison base: `9a57c21`

## Finding

`p2p::read_sync_page` asked the generic store page for up to 8 MiB of encoded
block bodies and only afterwards applied the tighter libp2p response budget of
`MAX_SYNC_FRAME - 1024`, charging four framing bytes per envelope. The first
body outside that prefix was therefore read from disk and allocated even
though it could never enter the response.

## Correction

- The public `Store::blocks_after` API and the devnet caller retain their
  historical payload-only 8 MiB page semantics, including first-frame
  handling.
- A crate-private `Store::blocks_after_p2p` variant supplies the exact existing
  libp2p rule: saturating `sum(envelope_len + 4) <= MAX_SYNC_FRAME - 1024`.
- The shared scan still validates the index binding and canonical fixed header
  first, but now stops before allocating or reading a body rejected by that
  transport budget.
- Count limits, returned order and bytes, permits, wire encoding and response
  decoding are unchanged. Index/header errors are still checked before the
  preflight; an I/O fault inside a body that is now deliberately never read is
  likewise no longer observed by this response.

This removes one avoidable body read and allocation at a byte-page boundary;
it is not a claim about exact heap/RSS reduction.

## Adversarial evidence

- `p2p_byte_preflight_matches_postfilter_and_skips_the_boundary_body`
  constructs the old post-filter result as an oracle, proves equality is
  admitted and the next frame is refused, and uses the body-read counter to
  prove only the returned body was read. Reducing the injected cap by one byte
  returns the same empty prefix without reading the first body.
- `p2p_real_cap_first_oversized_is_empty_but_generic_wrapper_still_serves_it`
  stores a codec-valid envelope whose `len + 4` is exactly one byte above the
  real libp2p budget. The generic/public wrapper still serves it, while the p2p
  variant returns the same empty page as the former post-filter without reading
  its body.

Validation:

```text
cargo check -p bloch-pos-node --bin bloch-pos --offline
# finished successfully

cargo test -p bloch-pos-node --bin bloch-pos --offline p2p_ -- --nocapture
# 2 passed; 0 failed; 595 filtered out; 0.29s

cargo test -p bloch-pos-node --bin bloch-pos --offline \
  a_cold_node_is_served_the_whole_chain_from_genesis -- --nocapture
# 1 passed; 0 failed; 596 filtered out; 5.69s

cargo test -p bloch-pos-node --bin bloch-pos --offline \
  a_restarted_node_recovers_only_what_it_missed -- --nocapture
# 1 passed; 0 failed; 596 filtered out; 5.26s

cargo test -p bloch-pos-node --bin bloch-pos --offline
# 578 passed; 0 failed; 19 ignored; 56.46s
```

## Residual boundary

A historical/imported envelope may be codec-valid up to 8 MiB while exceeding
the smaller directed-sync page budget. If such an envelope is first after the
request cursor, the old post-filter returned an empty short page; the receiver
does not page-chase it and its periodic behind-head request retries the same
cursor. This pre-existing recovery livelock is deliberately preserved by this
performance-only correction. Current local production is bounded by
`MAX_PROPOSAL_ENVELOPE_BYTES` (`4 MiB - 1024`), so it cannot create that case,
but repairing historical oversized recovery would require a separate transport
policy decision rather than silently changing this patch's semantics.
