# Wave 149 — EN-08 allocation-free block queue length

Date: 2026-09-19
Comparison base: `a58e2ad2`

## Residual addressed

Every decoded block crossing the engine-facing queue boundary was serialized
again into a fresh `Vec<u8>` solely to obtain its canonical length. The
temporary allocation and body copy were proportional to the complete envelope
and were paid by devnet gossip, libp2p block gossip and directed libp2p sync
before their already-reserved raw charge could be attached to the event.

The serialization did not provide a byte comparison: callers compared only
the resulting length with the already bounded raw frame length. The shared
`codec::encoded_envelope_len` authority already computes exactly that length
without owning a second copy of the payload.

## Correction and invariants

The block arm of `net::queued_bytes` now uses
`codec::encoded_envelope_len`. Empty, populated and one-MiB-body regressions
pin its result to both `encode_envelope(env).len()` and the queue charge.

The transport sequence is unchanged: reserve the bounded raw size, decode,
compare the decoded canonical length with the raw size, attach the private
reservation, then emit. Event class, source identity, aggregate/source caps,
release charge, `Ignore`/`Reject` verdicts and recovery behavior are unchanged.
Source-free block events receive the same exact canonical charge as before.
There is no wire, public API, disk-format, consensus or activation change.

For every transported envelope the existing frame cap keeps the calculation
far below `usize` saturation. An internally constructed object too large for
that assumption saturates the length and therefore fails a finite byte quota
closed rather than allocating an equally oversized temporary encoding.

## Adversarial coverage

- `block_queue_charge_matches_canonical_length_for_empty_full_and_large_bodies`
  covers empty, signature/attestation/transaction-populated and one-MiB body
  shapes and pins exact encoder/helper/queue-charge parity.
- `encoded_envelope_len_tracks_empty_collections_fields_and_limits` retains
  field, collection and limit parity for the shared length authority.
- `devnet_predecode_charge_matches_the_engine_release_charge` retains exact
  raw admission, mutation-resistant retained charge and symmetric release.
- `sync_envelopes_reserve_before_decode_and_release_every_exit` retains
  directed-sync predecode admission, malformed/saturated release and single
  reservation attachment.

## Validation

```text
cargo test -p bloch-pos-node --bin bloch-pos \
  block_queue_charge_matches_canonical_length_for_empty_full_and_large_bodies \
  --offline -- --nocapture
# 1 passed; 0 failed; 613 filtered out

cargo test -p bloch-pos-node --bin bloch-pos \
  encoded_envelope_len_tracks_empty_collections_fields_and_limits \
  --offline -- --nocapture
# 1 passed; 0 failed; 613 filtered out

cargo test -p bloch-pos-node --bin bloch-pos \
  devnet_predecode_charge_matches_the_engine_release_charge \
  --offline -- --nocapture
# 1 passed; 0 failed; 613 filtered out

cargo test -p bloch-pos-node --bin bloch-pos \
  sync_envelopes_reserve_before_decode_and_release_every_exit \
  --offline -- --nocapture
# 1 passed; 0 failed; 613 filtered out

cargo check -p bloch-pos-node --bin bloch-pos --offline
# passed

cargo test -p bloch-pos-node --bin bloch-pos --offline
# 595 passed; 0 failed; 19 ignored; 64.09s
```

The initial full-suite sandbox attempt reached and passed the new regression,
but its socket-backed engine, RPC, devnet and libp2p fixtures could not bind
localhost. The complete suite then passed outside the sandbox.

## Residual boundary

- The exact-length calculation still walks the envelope collections; the
  removed work is allocation and copying of their complete byte contents, not
  all O(number-of-fields) CPU.
- Canonical decode, final owned fields, block identity hashing, verification
  and transition work remain necessary.
- Attestation and transaction source-free queue sizing still creates their
  canonical byte vectors; this wave changes only the materially larger block
  path backed by the existing shared length authority.
- Allocator behavior, decoded object overhead and RSS are not claimed.
- Hosted CI, release signing, deployment, rollback and fleet qualification
  remain outside source verification.
