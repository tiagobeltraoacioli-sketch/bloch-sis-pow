# Wave 87 — NET-04 / EN-08 prepared local block broadcast

Date: 2026-09-19
Starting consolidation: `be16a79`

## Residual addressed

After a locally produced block passed transition and entered the block store,
the producer cloned the complete retained `BlockEnvelope` only to encode it for
broadcast. The libp2p command loop then decoded that same just-produced frame,
allocating its complete body again, solely to recover the fixed-header
`block_id` used by outbound re-gossip suppression. The decoded envelope had no
other consumer; publication used the original encoded payload.

For a proposal near the existing wire/body limits, this was one avoidable body
clone followed by one avoidable body decode/allocation on the honest production
path. It was bounded work, not a retention-cap or consensus bypass.

## Correction and consumer proof

`Net::broadcast_block` now borrows the already-stored immutable envelope and
creates one private `PreparedBlockBroadcast`. Its private constructor derives
both the exact `block_frame` bytes and `block_id` from that same borrow; private
fields prevent another module from pairing unrelated bytes and an identity.

The three transport modes remain exact:

- devnet receives the prepared frame unchanged;
- libp2p receives the prepared frame plus its bound suppression id; and
- dual transport clones the one encoded frame for devnet and moves the same
  prepared value to libp2p, as the prior generic path already cloned wire bytes.

The engine no longer calls `.cloned()` on the stored envelope. The private
libp2p command uses the bound id directly and does not decode its payload.
Consumer search confirms the only former result of that decode was
`Loop::note_block`; gossipsub publication always used the original payload.

The existing generic `broadcast(Vec<u8>)` API and command remain unchanged for
all other callers and tests. A generic block frame still performs the same
best-effort canonical decode before `note_block`, and a malformed generic frame
still publishes without inventing a suppression id. No public API, frame byte,
topic, consensus rule, verdict, cap, peer score, storage or recovery behavior
changed.

## Adversarial coverage

- `prepared_block_broadcast_binds_large_wire_bytes_and_exact_id` builds a
  one-MiB-body envelope and proves the private prepared value contains exactly
  `block_frame(&env)` and exactly `env.block_id()`.
- `prepared_block_id_suppresses_without_decode_and_generic_fallback_is_unchanged`
  uses an intentionally undecodable payload at the private branch unit boundary
  to prove the prepared id suppresses without consulting the decoder. It also
  proves the generic canonical fallback still decodes and suppresses, and
  malformed generic bytes remain publishable without adding a suppression
  entry. The typed constructor separately prevents that synthetic mismatch in
  production.

## Validation

```text
cargo check -p bloch-pos-node --tests --offline
# passed

cargo test -p bloch-pos-node --bin bloch-pos \
  prepared_block_broadcast_binds_large_wire_bytes_and_exact_id \
  --offline -- --nocapture
# 1 passed; 0 failed; 587 filtered out

cargo test -p bloch-pos-node --bin bloch-pos \
  prepared_block_id_suppresses_without_decode_and_generic_fallback_is_unchanged \
  --offline -- --nocapture
# 1 passed; 0 failed; 587 filtered out
```

Compiler output contained only existing unused-code/import warnings.

## Residual risk

- Encoding the outbound block and gossipsub's own message hashing remain
  necessary boundary work.
- Dual transport still needs one byte clone because two independent transports
  own their outbound messages; this change does not claim zero-copy transport.
- Generic raw-frame callers intentionally retain best-effort decode for exact
  block-id suppression. Only the typed local-production path can safely skip it.
- No exact heap/RSS reduction is claimed. Allocator capacity and libp2p's
  internal buffers remain outside this focused proof.
- Full node, hosted CI, Linux reproducibility, release signing, rollback and
  fleet qualification remain outside this focused correction.
