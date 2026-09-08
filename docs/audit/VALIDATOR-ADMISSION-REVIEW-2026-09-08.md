# Validator admission: focused second-pass review

Reviewed base: `6e4b5323ed40631a8c847fa06bbb4c4eab38acbd`, the merge of PR #6.
Its tree is identical to PR head `1fb019b678d249bd41378461c270d5467024c7aa`.
Scope: funded registration, transaction authorization, accounting, mempool
integration, activation, offline signing and joining-node identity. This is a
second-pass implementation review, not an independent audit or formal proof.

## Verdict

The implementation is a sound **pre-activation foundation**, with meaningful
security improvements over the unfunded legacy deposit. It is **not ready to
open public mainnet admission**. Keep the admission epoch unarmed. The remaining
work includes lifecycle release dependencies, an explicit finality policy for
activation, and stronger state-aware mempool admission.

No stake-creation-without-inputs or ECDSA authorization path was found in the
new `FundedDeposit` transition during this review. This is a scoped observation,
not a claim that every consensus, cryptographic or networking path is secure.

## Findings and remaining work

| ID | Priority | Finding | Current disposition |
|---|---|---|---|
| VAD-01 | High: release blocker | Admission can be armed independently while authenticated exits, withdrawals, slashing evidence and RANDAO recommit remain unarmed. | Documented but unresolved; do not accept public bonds. |
| VAD-02 | High: protocol decision | Eight elapsed epochs can activate an unfinalized registration. | Reproduced; delay is not finality. No consensus-break proof is claimed. |
| VAD-03 | Medium | Valid PQ signatures admit a deposit with nonexistent funding into the mempool. Fee-based eviction also relies on the announced tip before funding is checked. | Admission reproduced; consensus rejects the transaction and continues proposing. |
| VAD-04 | Medium: validation gap | The positive two-node rehearsal uses two `Engine` instances, not two networked processes. | Add transport, restart and partition qualification before release. |
| VAD-05 | Low: operator compatibility | Funding requires an exact 32-byte suite-1 key hash; carried 20-byte padded outputs cannot fund a deposit directly. | Require a verified migration transfer into a native suite-1 output; document it in onboarding. |
| VAD-06 | Low: signing workflow | `sign` displays the draft's network digest but does not independently bind it to a locally supplied trusted manifest. | Add a required expected-network/manifest check for production signing. |

### VAD-01 — close the validator lifecycle before opening admission

`params.rs` leaves all of these at `u64::MAX`:

- `FUNDED_VALIDATOR_ADMISSION_ACTIVATION_EPOCH`;
- `EXIT_AUTH_ACTIVATION_EPOCH`;
- `WITHDRAWAL_ACTIVATION_EPOCH`;
- `SLASHING_EVIDENCE_ACTIVATION_EPOCH`;
- `RANDAO_RECOMMIT_ACTIVATION_EPOCH`.

The admission flag day also disables unauthenticated legacy `Exit`. That is
the correct protection against another party forcing an exit, but it does not
provide an authenticated exit or a withdrawal. The 8,192-reveal RANDAO chain
is finite and the node's proposal path explicitly reports that recommit is
not wired. Local signing protection does not replace consensus penalties for
a malicious operator.

Required release work: reconcile the contested lifecycle wire assignments,
complete and qualify the authenticated lifecycle, test boundary compatibility
and rollback procedures, then coordinate the finite activation epoch. There
is no reason to weaken PQ authorization to solve this release dependency.

### VAD-02 — activation is independent of registration finalization

`staking::resolve_activations` uses `(deposit_epoch, public_key_hash)`, an
eight-epoch delay and a four-validator churn cap. `close_epoch` applies the
result without requiring the registration to be in a finalized checkpoint.

The existing `funded_multiblock_replay_activation_churn_and_new_proposer` test
submits no attestations, activates five new keys over epochs 8 and 9, and
observes a new key proposing. The additional audit assertion confirms that
finality is still at epoch 0. This behavior was reproduced locally.

Before release, choose and specify one policy. A conservative policy queues
activation only after the funding registration is covered by finalized state,
then applies the delay and churn rules. That change requires explicit state
and fork-handling rules; changing the queue function alone is insufficient.
If activation without finalization is retained, justify safety and liveness
under prolonged finality stalls, competing registries and long-range forks.

The existing documentation already says that the delay is not a finality proof.
This finding verifies that boundary; it does not assert an undocumented
regression or claim an exploit against a running network.

### VAD-03 — signature validity is not funding validity at the mempool door

`Engine::on_transaction` checks the genesis domain and `admissible` verifies
both complete hybrid authorizations. It does not check UTXO existence,
ownership, funding conservation or duplicate registration there. A correctly
signed deposit with an invented input is accepted and broadcast.

Local reproduction with real hybrid keys:

1. Build the existing admission fixture in a disposable epoch-zero build.
2. Replace the input transaction ID with `[0xfa; 32]`, assert the UTXO is absent,
   set the tip and re-sign both roles.
3. Observe successful mempool admission.
4. Propose slot 1: consensus returns `Transaction(0)`, the proposer removes and
   bars that transaction, and a valid empty block is produced. No validator is
   registered and no stake is created.

The reproduction passed. Run the diagnostic with:

```sh
python3 scripts/rehearse-validator-admission.py --audit-mempool
```

**Diagnostic success means that the gap was reproduced**, not that the
mempool is secure. The source copy and its epoch-zero artifacts are discarded;
the shipping activation stays unarmed.

The capacity branch can replace a lower-tip entry after this same limited
check. That eviction extension follows directly from the code; the local
diagnostic exercises admission and subsequent consensus rejection, not a
4,096-entry saturation campaign. Per-source quotas of 64 are helpful but
generating another public key does not require capital. The same broad
state-validation gap predates this PR in legacy transfer admission.

Recommended repair: share a read-only funded-deposit validation stage with
consensus, run it before eviction/broadcast, and revalidate on head changes.
Handle pending conflicts, expiry and base-fee changes as local policy. Preserve
the proposer's indexed-offender removal and the consensus recheck; mempool
acceptance must never become consensus authority.

### VAD-04 — qualify the network and operational boundary

The rehearsal demonstrates two real engines applying the same blocks, a new
proposer and attester, replay, RANDAO positioning and persistent signing
protection. It passes envelopes directly to `ingest`/`ingest_replay`; it does
not boot two independent `run` processes connected through P2P.

Release qualification should cover separate processes and data directories,
late joining after registrations, restart after several reveals, reordered
registrations on competing branches, a partition longer than the activation
delay, finality recovery, pending authentication after registry growth, and
load from many independently operated candidates. This is additional coverage,
not a claim that the existing rehearsal is ineffective.

### VAD-05 and VAD-06 — make the signing ceremony explicit

`apply_funded_deposit` uses the exact suite-enveloped funding key hash. It does
not use the legacy `owns` helper's 20-byte padded fallback. Do not silently
weaken this new format to accept a different key geometry: migrate the coins
to a full native PQ script first, then sign the deposit. The transfer route's
separate network-binding gate remains a distinct review concern.

The offline `sign` command verifies role ownership, existing signatures and
the validator RANDAO seed, which is good. It prints the network digest from
the supplied draft, however, rather than deriving an expected digest from a
trusted local manifest at signing time. Production operators should compare
that digest independently; a future CLI improvement should enforce the
comparison before unlocking a key. The withdrawal script likewise needs a
verified recipient key and backup procedure; a 32-byte value alone proves
no one controls its spending key.

## Properties that held up under review

- Both roles require ML-DSA-65 **and** Falcon-1024, with independent funding
  and possession domains and a complete signed intent.
- The genesis-manifest digest includes the clock; expiry is checked at
  inclusion. Signatures bind inputs, stake, keys, withdrawal, change and fees.
- Input values are read from committed state. The bond plus change plus fees
  conserves funding; unused base-fee budget returns to the signed change script.
- The decoder bounds input counts and byte vectors. The deterministic witness
  reservation avoids Falcon's randomized size affecting the signed declaration.
- All fallible registration checks precede state mutation. Funded bonds do
  not enter the legacy `unfunded_bonded` exception.
- Auto-index duties resolve the public key on the relevant branch. The signing
  journal is bound to the key and genesis digest, not a guessed registry index.
- The sorted activation scheduler has differential coverage against the prior
  epoch scan. The minimum stake and per-key cap are not a Sybil-identity system
  and must not be described as proof of operator decentralization.

## Validation evidence and limits

All required GitHub checks on the reviewed PR head completed successfully,
including the live-crate suite, native kernel, hardened Clippy, dependency and
license scanners, secret scanning and the activated admission rehearsal.
Informational fuzz and Miri jobs passed. The informational cargo-geiger job
failed on dependency scanning warnings; it is not silently counted as a pass.

This review additionally ran the real-PQ unfunded-input mempool diagnostic and
the multiblock activation test with an explicit finality-at-genesis assertion.
Both confirmed the behavior described above. No mainnet epoch, consensus wire
assignment, release deployment or running validator configuration was changed.

Sources:

- [Reviewed PR and checks](https://github.com/tiagobeltraoacioli-sketch/bloch-sis-pow/pull/6)
- [Funded transition](https://github.com/tiagobeltraoacioli-sketch/bloch-sis-pow/blob/6e4b5323ed40631a8c847fa06bbb4c4eab38acbd/crates/bloch-pos-committee/src/transition/funded.rs)
- [Node integration](https://github.com/tiagobeltraoacioli-sketch/bloch-sis-pow/blob/6e4b5323ed40631a8c847fa06bbb4c4eab38acbd/crates/bloch-pos-node/src/engine.rs)
- [Release specification](../specs/BLOCH-FUNDED-VALIDATOR-ADMISSION.md)
