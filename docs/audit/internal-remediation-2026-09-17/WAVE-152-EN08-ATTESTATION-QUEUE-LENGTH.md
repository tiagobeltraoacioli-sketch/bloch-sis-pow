# Wave 152 — EN-08 allocation-free attestation queue length

Date: 2026-09-19
Comparison base: `1d6a6bf5`

## Residual addressed

After Wave 149 removed the equivalent block copy, attestation queue sizing
still serialized every decoded attestation into a fresh `Vec<u8>` solely to
read its length. The allocation and copy were proportional to the complete
signature and were paid after predecode capacity reservation by devnet and
libp2p gossip before the raw charge could be attached to the event.

The transport boundary compared only the resulting length with the bounded
raw frame length. It did not compare the temporary encoding's bytes.

## Correction and invariants

The codec now owns one private exact-length authority for an attestation: its
124 fixed data/validator bytes, four-byte signature-length prefix and signature
length. Both `encoded_envelope_len` and the attestation arm of
`net::queued_bytes` call that helper, so the formula cannot drift independently
between retained-block accounting and the engine queue.

Empty, realistic hybrid-size and one-MiB signature regressions pin the helper
to `encode_attestation` and the queue charge. Sizing is now constant-time and
does not allocate or copy the signature.

The admission sequence remains reserve bounded raw size, decode through EOF,
compare exact canonical length with raw length, attach the private source
reservation and emit. Class/source identity, aggregate and source caps,
release charge, malformed handling, `Ignore`/`Reject` verdicts and recovery
remain unchanged. There is no wire, public API, disk-format, consensus or
activation change.

For transported input the existing frame cap keeps the calculation far below
`usize` saturation. An impossible internally constructed object saturates and
therefore fails any finite byte quota closed.

## Adversarial coverage

- `encoded_attestation_len_matches_encoder_for_empty_realistic_and_large_signatures`
  pins exact encoder/helper parity for empty, 4,589-byte and one-MiB
  signatures.
- `attestation_queue_charge_matches_canonical_length_without_payload_owner`
  pins the same three shapes to both source-free queued and charged bytes.
- `encoded_envelope_len_tracks_empty_collections_fields_and_limits` proves the
  centralized attestation formula remains exact inside complete envelopes.
- `devnet_reserves_before_decode_and_releases_malformed_frames` retains
  predecode admission and symmetric malformed release.
- `source_free_queue_events_fall_back_to_canonical_size` retains source-free
  reserve/release symmetry.
- `predecode_peer_admission_releases_failures_and_is_not_charged_twice`
  retains libp2p's single-reservation ownership contract.

## Validation

```text
cargo test -p bloch-pos-node --bin bloch-pos \
  encoded_attestation_len_matches_encoder_for_empty_realistic_and_large_signatures \
  --offline -- --nocapture
# 1 passed; 0 failed; 615 filtered out

cargo test -p bloch-pos-node --bin bloch-pos \
  attestation_queue_charge_matches_canonical_length_without_payload_owner \
  --offline -- --nocapture
# 1 passed; 0 failed; 615 filtered out

cargo test -p bloch-pos-node --bin bloch-pos \
  encoded_envelope_len_tracks_empty_collections_fields_and_limits \
  --offline -- --nocapture
# 1 passed; 0 failed; 615 filtered out

cargo test -p bloch-pos-node --bin bloch-pos \
  devnet_reserves_before_decode_and_releases_malformed_frames \
  --offline -- --nocapture
# 1 passed; 0 failed; 615 filtered out

cargo test -p bloch-pos-node --bin bloch-pos \
  source_free_queue_events_fall_back_to_canonical_size \
  --offline -- --nocapture
# 1 passed; 0 failed; 615 filtered out

cargo test -p bloch-pos-node --bin bloch-pos \
  predecode_peer_admission_releases_failures_and_is_not_charged_twice \
  --offline -- --nocapture
# 1 passed; 0 failed; 615 filtered out

cargo check -p bloch-pos-node --bin bloch-pos --offline
# passed

cargo test -p bloch-pos-node --bin bloch-pos --offline
# 597 passed; 0 failed; 19 ignored; 63.19s
```

The complete suite ran outside the restricted sandbox so its localhost
transport fixtures could bind.

## Residual boundary

- Attestation decode still allocates its final owned signature, and signature
  verification remains necessary.
- Raw transport ownership, canonical decode and the constant number of length
  additions remain.
- Transaction source-free queue sizing still creates canonical bytes because
  no shared exact-length authority currently exists for all transaction
  variants; this wave does not introduce a second transaction codec.
- Allocator behavior, decoded object overhead and RSS are not claimed.
- Hosted CI, release signing, deployment, rollback and fleet qualification
  remain outside source verification.
