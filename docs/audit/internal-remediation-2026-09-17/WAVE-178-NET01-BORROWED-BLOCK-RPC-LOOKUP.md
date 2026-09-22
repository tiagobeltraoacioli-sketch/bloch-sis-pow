# Wave 178 — NET-01 borrowed stored-block RPC lookup

Date: 2026-09-19
Comparison base: `1a4d4307`

## Reproduced residual

Both `getblockbyslot` and `getblockbyid` resolved a retained block through
`Engine::envelope_by_id`, which returned an owned `BlockEnvelope` by calling
`.cloned()` on the authoritative block map entry. `block_reply` then read only
the fixed header plus transaction and attestation counts; the RPC response does
not return either body. A request could therefore copy every transaction,
attestation and signature allocation in a large retained envelope on the
single consensus thread without those copied bytes contributing to its reply.

Genesis is different: it is synthesized and intentionally absent from
`Engine::blocks`, so its lookup genuinely needs one small owned envelope.

## Correction and invariants

`envelope_by_id` now returns `Cow<BlockEnvelope>`. The genesis identity returns
`Cow::Owned` from the unchanged synthesis path, while every retained map entry
returns `Cow::Borrowed` from its immutable authoritative owner. Both RPC arms
pass the resulting borrow to the unchanged `block_reply` renderer.

Lookup order, canonical/finality classification, height and timestamp
calculation, header and count fields, genesis synthesis, slot-empty and
unknown-id errors are unchanged. No retained object is mutated, moved or kept
alive beyond the synchronous reply. There is no public API, JSON, wire,
disk-format, protocol, activation, verdict or consensus change.

## Adversarial coverage

- `genesis_is_owned_stored_body_is_borrowed_and_both_rpc_routes_match` proves
  genesis selects the owned `Cow` variant, then installs a retained envelope
  with a 1 MiB transaction body and proves both the envelope pointer and the
  proportional body allocation are the exact store owners.
- The same test compares the complete `BlockById` and `BlockBySlot` JSON for
  genesis and the retained block against direct `block_reply` output.
- It also pins the existing `SLOT_EMPTY` and `BLOCK_NOT_FOUND` error codes.

## Validation

```text
cargo test -p bloch-pos-node --bin bloch-pos \
  genesis_is_owned_stored_body_is_borrowed_and_both_rpc_routes_match --offline
# 1 passed; 0 failed; 624 filtered out

cargo check -p bloch-pos-node --bin bloch-pos --offline
# passed

cargo test -p bloch-pos-node --bin bloch-pos --offline
# 606 passed; 0 failed; 19 ignored; 63.09s
```

The focused and complete node suites ran outside the restricted sandbox
because the engine fixture binds localhost sockets.

## Residual boundary

- JSON construction and fixed header hashing remain on the consensus thread;
  this change removes only the unused proportional envelope/body clone.
- The small synthesized genesis envelope remains owned because no stored owner
  exists.
- Stored block bodies and the final JSON response remain necessary owners;
  allocator capacity, exact heap/RSS, kernel copies and response latency are
  not claimed.
- Moving all block/store RPC work off the consensus thread, RPC authentication,
  transport exposure and fleet qualification remain outside this local fix.
  `NET-01` remains `PARTIAL`.
