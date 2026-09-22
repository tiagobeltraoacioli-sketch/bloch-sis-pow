# Wave 186 — EN-08 moved local-attestation ownership

Date: 2026-09-19
Comparison base: `803ac608`

## Reproduced residual

After signing a local attestation, `Engine::attest` cloned the complete
`Attestation` into the loose pool and then encoded the original value for
broadcast. The signature is the proportional field (a hybrid ML-DSA-65 plus
Falcon-1024 witness), so every successful local attestation allocated and
copied that signature solely to maintain two temporary owners.

The canonical outbound frame already is the independent byte owner required
by the transport. Once that frame exists, the typed attestation itself has
only one remaining consumer: the pool.

## Correction and invariants

The local duty path now prepares `net::att_frame(&att)` while borrowing the
freshly signed value, derives the unchanged pool key, and moves `att` into the
pool. It broadcasts the prepared owned frame only after insertion, preserving
the former publication order without cloning the typed value or its signature.

Signing data, hybrid signature, `(validator, signing_root)` pool key, canonical
frame bytes/tag, pool-before-broadcast order, slashing watermark, log fields,
transport behavior and remote attestation verdict paths are unchanged. Frame
preparation is a pure canonical encoding with no externally visible state;
the pool remains populated before any network publication. There is no wire,
public API, disk-format, protocol, activation, verdict or consensus change.

## Adversarial coverage

- `locally_signed_attestation_prepares_frame_then_moves_into_pool` pins the
  production ownership/order seam: no `att.clone()`, frame preparation from a
  borrow, the exact historical pool key with an owned move, then broadcast of
  that prepared frame.
- `every_signature_leaves_a_durable_watermark_the_next_boot_can_read` still
  drives a real epoch-1 attester duty and restart watermark refusal. It now
  additionally verifies the pool-owned hybrid signature against the fixture
  validator key and proves that the canonical tagged frame decodes, with no
  trailing bytes, to exactly that stored duty.

## Validation

```text
cargo test -p bloch-pos-node --bin bloch-pos --offline \
  local_attestation_ownership -- --nocapture
# 1 passed; 0 failed; 628 filtered out

cargo test -p bloch-pos-node --bin bloch-pos --offline \
  every_signature_leaves_a_durable_watermark_the_next_boot_can_read -- --nocapture
# 1 passed; 0 failed; 628 filtered out; 0.95s

cargo check -p bloch-pos-node --bin bloch-pos --offline
# passed

cargo test -p bloch-pos-node --bin bloch-pos --offline
# 610 passed; 0 failed; 19 ignored; 61.59s

git diff --check
# clean
```

The functional focus and complete node suite ran outside the restricted
sandbox because production engine/transport fixtures bind localhost sockets.

## Residual boundary

- The canonical transport frame and pool-owned typed attestation remain two
  necessary representations with different consumers; this removes only the
  otherwise-unused intermediate typed clone.
- Canonical attestation encoding, its final frame allocation, one pool owner,
  hybrid signing/verification, transport queue retention and socket/kernel
  copies remain.
- This makes no exact heap/RSS or latency claim and does not alter queue
  fairness, peer policy, non-preemptible cryptography or consensus-thread
  scheduling. `EN-08` remains `PARTIAL`.
