# Wave 80 — NET-04 / EN-08 authenticated held replay

Date: 2026-09-19
Starting consolidation: `f787b25`

## Residual addressed

Held attestations paid hybrid signature verification before entering the
bounded pending pool, but release sent them through the fresh-input API and
paid the same verification again. A fully populated pool could therefore
schedule up to 256 avoidable hybrid verifications after its missing blocks
arrived, even though every retained message was already authenticated.

Replay must still re-evaluate mutable facts: the slot window, checkpoint
sanity, dedup/equivocation state, committee membership, current key lookup,
capacity and block availability. Only the cryptographic proof for unchanged
message bytes under an unchanged public key is reusable.

## Hardening

Each pending entry now retains a SHA3-256 fingerprint of the public key used
for its successful verification. Extraction for replay produces a non-cloneable
opaque token whose fields and constructor are private. The only API that
accepts that token reruns the complete admission pipeline and skips hybrid
verification only when the current registry key has the same fingerprint.

If the current key differs, replay invokes the normal verifier and fails
closed on an invalid signature. A re-hold carries the current fingerprint, so
an attestation missing both head and target can cross both release stages
without repeated crypto while preserving the key-binding invariant.

The node's bounded FIFO release scheduler now consumes the opaque tokens.
Fresh wire input still has no way to select the authenticated path. Source
identity survives extraction and re-hold, while verification budgets are
charged only if cryptography actually runs.

This is volatile relay admission only. Attestation bytes, signature domains,
committee selection, fork choice, consensus transitions, state roots and
persistence are unchanged. Capacity refusals remain `Ignore`, and all
membership or malformed-message `Reject` semantics are preserved.

## Adversarial coverage

- A same-key release uses a verifier that panics if called and still accepts.
- A two-root waiter re-holds and later accepts with the panic verifier on both
  releases, proving the proof survives only through the controlled token path.
- A registry-key-change control uses a counting rejecting verifier and proves
  exactly one fresh verification occurs, the attestation is rejected, and no
  acceptance state is recorded.
- The node scheduler regression continues to prove one waiter per control turn
  and root FIFO fairness, now through authenticated replay.

Focused validation:

```text
cargo test -p bloch-pos-committee gossip::tests --lib --offline
# 28 passed; 0 failed

cargo check -p bloch-pos-node --offline
# passed

cargo test -p bloch-pos-node \
  authenticated_held_replay_skips_second_verification_and_preserves_root_fifo \
  --offline
# 1 passed; 0 failed (outside sandbox for the fixture's loopback listener)
```

Compiler output contained only existing unused-code/import warnings. The
in-sandbox node attempt reached the fixture and failed only because loopback
binds are denied there; the identical authorized outside-sandbox run passed.

## Residual risk

- Initial admission still requires one non-preemptible hybrid verification.
- SHA3-256 key fingerprints introduce the ordinary cryptographic collision
  assumption; storing full keys would retain substantially more attacker-sized
  data per pending entry without a practical security benefit.
- Replay remains bounded to one waiter per engine turn, so a full pool takes
  cooperative scheduler turns to drain even though unchanged-key crypto is
  skipped.
- If a future registry design permits a key change at an existing index, that
  replay intentionally pays fresh verification; repeated projection changes
  could therefore reintroduce bounded work but cannot bypass authentication.

External binary release gates are unchanged: independently authenticated
Linux build comparison, hosted CI evidence, signed release/rollback artifacts,
fresh independent WS evidence, scratch-host rollback rehearsal and staged
canary evidence remain required.
