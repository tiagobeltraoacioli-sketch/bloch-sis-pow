# Slashing: pre-activation offence exposure (incident 2026-10-19)

CONFIDENTIAL. Keep this file in the local repository only. Do not push it.

Branch `codex/bloch-slash-exposure-20261019`, based on `dd287b6c`. The source
is identical to release `78b7343a` apart from release notes and docs.

## 1. Finding

`SLASHING_EVIDENCE_ACTIVATION_EPOCH = 2884` gates only the epoch of the block
that includes the evidence (`transition.rs`, the `SlashingEvidence` arm of the
tx loop). Neither `slashing.rs::process_with_effective_exposure` nor
`apply_slashing_evidence` checks the epoch of the offence itself. Attestation
signing roots (`AttestationData::signing_root`) carry no network, fork or epoch
domain. Validator keys never rotate: the registry key is the genesis key.
Because of this, every conflicting pair ever signed is slashable today, however
old it is.

The offline scan (`watch-equivocation`, `codex/bloch-p5b-detector-20261019`)
found 15,932 pairs, all from attestations included in blocks: 15,568 surround
votes and 364 double votes. They come from 50 own validators (indices 1-63)
at target epochs 664-1486.

## 2. Validity check against the real code

- **Tool:** `bloch-pos slash-rehearsal`, a hidden offline subcommand on this
  branch. It calls `CommittedState::rehearse_slashing_evidence`
  (`transition/slashing_rehearsal.rs`), which runs the transition's own gate
  and then the real `apply_slashing_evidence` with the production
  `keys::HybridVerifier`.
- **State:** a copy of `archival-next/state.cache` on 139.180.173.231, decoded
  with `CommittedState::decode_local_cache`. The head header was recovered from
  a byte-exact copy of the block-log prefix: epoch 6026, 157,024 blocks,
  149 registry records, 106 in the roster.
- **Evidence:** the release decoder (`PosTransaction::from_canonical_bytes`)
  accepted every `evidence_tx_hex`. All runs stayed on 139.180. Nothing was
  submitted anywhere.

| Check | Result |
|---|---|
| Registry keys vs genesis manifest (64 genesis records) | 0 differ |
| Already slashed / ejected | none |
| Sample: 20 evidences, 10 validators, both offence kinds | 20/20 accepted, both signatures valid, ~5% penalty each in isolation |
| One evidence per offender (50) | 50/50 accepted |

**Verdict: the evidence is valid and would be accepted today by every node
running this release.** The mempool also accepts it: `admissible` only checks
the wall-clock gate, and `validate_lifecycle_transaction` runs the same
`apply_slashing_evidence` path. Once accepted, our own proposers pack it into
their blocks.

## 3. Exposure (chained rehearsal, one evidence per offender, one epoch)

- **Bond:** the 50 offenders have 485.3 M BLCH of own bond in total.
- **Penalty:** grows from about 5% up to 100% once the slashed share of the
  window reaches about 1/3. The window is fed with the raw bond lost, but the
  denominator is total effective stake, so the penalty saturates after about 20
  validators.
- **Own-bond burn:**

  | Inclusion order | Own bond burned | Share of 485.3 M |
  |---|---|---|
  | Index order | 373.3 M BLCH | 77% |
  | Largest bond first | 345.8 M BLCH | 71% |

  Delegator ledger losses (`delegator_slash_losses`) come on top of these
  figures and were not totalled.
- **Whistleblower reward:** 1/32 of the operator loss goes to the including
  proposer, up to about 11.7 M BLCH, capped at the backed loss.
- **Ejection:** all 50 offenders are ejected at epoch+1, including v58, v60 and
  v63, which are already exiting with effective weight 0.
  - They hold 66.1% of the current effective weight: 132.7 M of 200.8 M BLCH.
  - Remaining roster: about 68.7 M BLCH.
    - Non-offending indices 0-65 hold about 44.8 M (65.2%).
    - Indices 96-139 hold about 23.9 M (34.8%), assumed external.
  - The fleet alone would fall just below 2/3 of the new roster. Finality would
    then depend on the 96-139 cohort, and that cohort could block it (it has
    more than 1/3) until the inactivity leak wears it down.
- **Who can trigger it:** anyone. They can submit to any of our nodes, which
  admit it, relay it and include it, or any external proposer can put it
  directly into its own block.

## 4. Mitigation (code on this branch)

### (a) Node policy: ship now, no consensus change

- `slashing::evidence_offence_epoch` returns the larger target epoch of an
  attestation pair, or the epoch of the slot of a header pair.
  `offence_predates_activation` returns `< 2884`. Both are pure functions of
  the evidence bytes.
- `engine::admissible` refuses pre-activation offences unconditionally. This
  covers RPC, gossip and the local `report_equivocation` path.
- `candidate_is_backed` makes the proposer drop such evidence even if it got
  into the mempool another way.
- Test: `pre_activation_offence_is_refused_at_the_door_after_the_flag_day`.

This protects only blocks that our own nodes produce. It does not stop an
external proposer that includes the evidence itself.

### (b) Consensus rule (soft fork)

- `params::PRE_ACTIVATION_OFFENCE_REFUSAL_EPOCH` is set to `u64::MAX`
  (unarmed) in this draft. Once it binds, using the including block's committed
  epoch, a block that carries evidence for which `offence_predates_activation`
  is true fails with `TxReject::EvidenceNotActive`.
  `validate_lifecycle_transaction` mirrors the same check.
- Tests:
  - `pre_activation_offence_rejects_the_block_once_the_refusal_binds`, with an
    unbound-refusal control.
  - `post_activation_offence_still_slashes_under_the_refusal`.
  - `offence_epoch_is_the_later_message_and_gates_on_activation`.
  - `pre_activation_refusal_is_unarmed_in_this_draft`, a pin that goes red when
    the rule is armed.
- **Using the later message is deliberate.** A pair whose later vote targets
  epoch 2884 or later was signed after slashing existed, so it stays
  slashable. The detected pairs all have max target ≤ 1486, so every one of
  them is covered. For attestations, a pair straddling the boundary is only
  possible as a surround whose outer vote has a source below 2884. That cannot
  happen while justification is past 2884.
- **Soft-fork analysis:** the rule only removes blocks from the valid set.
  - Upgraded nodes with about 88% of the weight do not attest to a block that
    carries such evidence. They keep building on its parent, so LMD-GHOST
    orphans it within a slot or two.
  - Non-upgraded externals follow the heavier branch and reorg away. They
    cannot finalize the other branch, because they hold about 12%.
  - Risk: until the whole own fleet runs the rule, a mixed own fleet can split
    on such a block. Roll out (a) first, then (b) to all own nodes before the
    arming epoch.
- **Arming value:** any epoch ≥ 2884 is replay-safe as long as the canonical
  chain from 2884 up to that epoch carries no pre-activation evidence. That
  holds today:
  - Included evidence either slashes someone (sets `slashed`) or makes its block
    invalid.
  - At e6026 no record is slashed.

  Arming at 2884 makes the rule effective the moment each node upgrades.
  Arming at a near-future epoch keeps the exposure open until that epoch.
  Recommendation: arm at 2884 and confirm with a full replay of the
  archival-next log before release.

### (c) Also required

1. **Gossip.** The attestation pool only judges recent attestations (a window
   of about 2 epochs) and keeps `observed_proposals` for 2 epochs. Live
   detection therefore never re-finds historical pairs. Keep it that way.
2. **Archival and RPC nodes.** These run the same `admissible` path, so they
   need (a). Until they have it, an RPC submission will be relayed.
3. **Rollout.** Ship (a) everywhere, then (b) armed. Keep the rehearsal tool
   available to re-check after upgrade. A rehearsal with the refusal bound
   must report `gate_open=false` for every evidence.
4. **Mempool revalidation.** `revalidate_lifecycle_mempool` uses
   `validate_lifecycle_transaction`, so with (b) armed, pending pre-activation
   evidence is evicted.
5. **Secrecy.** `evidence.jsonl` on 139.180 is a ready-made weapon. Keep it at
   mode 600 and delete it once (b) is live everywhere.
6. **Root cause of the own equivocations.** The double votes in the same block
   (source 651/652 for target 664) and the long surround spans show that the
   validator client re-voted after its justified view went backwards
   (restarts/resyncs). Slashing protection must refuse these before any real
   post-activation recurrence.
7. **Detector.** Run `watch-equivocation` on post-2884 history as well. Those
   offences would remain slashable under (b).
