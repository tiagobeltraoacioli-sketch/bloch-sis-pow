# Wave 182 — EN-08 lazy refused-proposal cleanup

Date: 2026-09-19
Comparison base: `185f57e6`

## Reproduced residual

After building a locally proposed `BlockEnvelope`, `Engine::propose` cloned
the complete `env.body.transactions` vector before handing the envelope to
local ingestion. The clone existed only so the h28080 fail-safe could remove
those canonical keys if the probe-approved block was refused by the real
transition. On the normal adopted-block path it was discarded unused.

This was proportional work on the slot-critical consensus thread: up to the
bounded transaction body was copied into a second set of owned byte vectors,
with one allocation per carried transaction plus the outer vector. The exact
decoded `txs` selection from which those bytes had just been encoded remained
alive across ingestion already.

## Correction and invariants

The ordinary path now retains only `txs.len()` for the existing refusal log.
If, and only if, local ingestion fails to make the proposed ID the head, the
fail-safe canonicalizes each transaction from that unchanged decoded
selection and removes the resulting key from the mempool. The successful path
therefore performs no cleanup copy and no cleanup re-encoding.

The selected transaction order, body bytes and body root are unchanged: the
envelope still owns the `tx_bytes` produced from the same `txs` in the probe
loop. Local ingestion, real signature verification, head comparison, refusal
log and count, exact mempool removals, stored-body lookup and block broadcast
remain in the same order. A refused own block still drops every transaction it
carried, while entries excluded from that proposal remain untouched.

There is no wire, public API, disk-format, protocol, activation, verdict or
consensus change.

## Adversarial coverage

- `adopted_proposal_keeps_the_exact_canonical_body_without_a_cleanup_copy`
  funds and signs a real transfer, proposes it with the production hybrid
  verifier, proves the block is adopted and stored with the exact canonical
  transaction bytes, and proves the included mempool key is removed.
- `refused_own_block_reencodes_only_its_selection_for_exact_cleanup` bypasses
  ordinary admission with a valid-shape transfer carrying a corrupted hybrid
  signature. The probe accepts it, the real transition refuses it, the head
  stays at genesis, the exact proposed key is removed, and a legacy exit that
  packing excluded remains in the mempool.
- `proposal_cleanup_has_no_eager_body_clone` pins the production structure:
  no body clone or former `produced_txs` owner, count from `txs`, and canonical
  cleanup strictly after local ingestion and the refused-head branch.

## Validation

```text
cargo test -p bloch-pos-node --bin bloch-pos --offline \
  proposal_body_ownership -- --nocapture
# 3 passed; 0 failed; 625 filtered out

cargo check -p bloch-pos-node --bin bloch-pos --offline
# passed

cargo test -p bloch-pos-node --bin bloch-pos --offline
# 609 passed; 0 failed; 19 ignored; 105.01s

git diff --check
# clean
```

The focused end-to-end tests and complete node suite ran outside the
restricted sandbox because production transport fixtures bind localhost
sockets.

## Residual boundary

- The decoded selection and the canonical body remain simultaneous owners;
  the transition probe needs typed transactions while the envelope, store and
  transport need canonical bytes. This correction removes only the additional
  cleanup copy.
- A refused own block now pays one canonical re-encoding per carried
  transaction before exact mempool removal. That is the deliberately rare,
  already-loud fail-safe path; moving it to success would recreate the issue.
- Selection clones typed transactions from the mempool and the canonical body
  owns its final bytes. Those owners are outside this local equivalence.
- No exact heap/RSS, allocator-capacity or latency reduction is claimed.
  Signature verification, transition work, transport copies and peer policy
  are unchanged. `EN-08` remains `PARTIAL`.
