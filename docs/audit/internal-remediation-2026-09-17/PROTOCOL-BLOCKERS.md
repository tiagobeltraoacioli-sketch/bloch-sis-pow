# Protocol blockers: recovery, cohort concentration and partition finality

Review date: **2026-09-17**. Reviewed the remediation working tree based on `203b410`, descended from the `b066e3c` recovery lineage. This is a source review and an analytical risk memo, not a production observation or an activation proposal. No protocol source or gate was changed for this review.

## Release position and audit-base reconciliation

**Keep `DUTY_ROSTER_RECOVERY_ACTIVATION_EPOCH = u64::MAX`.** The existing regression establishes that the candidate can restore a nonempty proposer schedule. It does not establish safe finality recovery, agreement across partitions, reward correctness, or compatibility with every other consumer of the restored weights.

The supplied audit reviewed `562e220`. Do not repeat its old gate values as the current implementation:

| Rule | Value in the reviewed source | Operational meaning |
| --- | --- | --- |
| Leak-adjusted duty roster | Epoch 1,400 | Already a historical rule in this lineage. |
| Leak recovery and half-denominator floor | Epoch 2,880 | Already armed in this lineage; historical epochs retain their earlier rules. |
| Funded admission, authenticated exits, withdrawals, slashing evidence, RANDAO recommit | Epoch 2,884 | Already armed together; the statement that funded admission is universally unavailable is obsolete for this source. |
| Legacy unfunded deposit | `u64::MAX` | Remains disabled. |
| Rewards v2 | `u64::MAX` | Remains disabled. Its interaction with the recovery candidate still needs qualification before either is activated. |
| Candidate all-zero roster recovery | `u64::MAX` | Disabled, including at a synthetic maximum epoch through the shared gate helper. |

Sources: [params.rs:362](../../../crates/bloch-pos-committee/src/params.rs#L362), [leak recovery gate](../../../crates/bloch-pos-committee/src/params.rs#L1202), [lifecycle gate consistency](../../../crates/bloch-pos-committee/src/params.rs#L1972), [rewards-v2 gate](../../../crates/bloch-pos-committee/src/params.rs#L1646), [candidate gate](../../../crates/bloch-pos-committee/src/params.rs#L1983). Source constants do not prove which binary any external validator runs. Inventory actual binary digests and network/manifest identity before planning a coordinated change.

## FC-01: restoring proposers does not immediately restore finality

`consensus_roster_at` first obtains the post-cohort-cap roster, then subtracts committed leak debt. Without the candidate, an all-zero result cannot produce an eligible proposer. With the test gate enabled, the candidate returns the **post-cap, unleaked** roster only when every leaked weight is zero. It preserves validator indices and does not reset the leak ledger or finality checkpoints. See [transition.rs:2570](../../../crates/bloch-pos-committee/src/transition.rs#L2570) and the [positive-weight proposer filter](../../../crates/bloch-pos-committee/src/sample.rs#L75).

The available test, [`audit_complete_inactivity_has_a_gated_recovery_schedule`](../../../crates/bloch-pos-committee/src/transition.rs#L14172), drives 80 empty finality epochs for four validators, demonstrates the zero-weight schedule, enables the test-only gate, and finds a proposer. It does **not** restart real nodes, produce and import the first recovery blocks, recover finality, or reconcile competing branches. Its test-only override is not an activation rehearsal at a proposed epoch.

The following interactions remain unqualified:

| Consumer | Concrete interaction |
| --- | --- |
| Proposer selection and active-validator queries | The all-zero fallback changes the weights used to select duties. The first participant whose leak is repaid can make the fallback switch off again, leaving only partially recovered weights. Test that transition explicitly. |
| Finality | Finality receives the unleaked active roster and separately subtracts the unchanged leak ledger. Restoring duties does not restore the quorum numerator. Valid included votes can repay leak even while finality remains stalled. |
| Fork choice | Block processing accumulates fork-choice weight from the consensus roster. During fallback, these weights can differ sharply from the leak-adjusted finality numerator. Branch selection during the recovery window needs an explicit trace. |
| Funded admission | Transaction validation derives `total_active` from the consensus roster and uses it to calculate the per-validator admission cap. Fallback can therefore change admission limits, not just duty scheduling. |
| Rewards v2 | Its issuance basis also calls `consensus_roster_at`. Simultaneously enabling rewards v2 could restore an issuance basis that the leak otherwise removed. This gate is still off. |

Sources: [finality input construction](../../../crates/bloch-pos-committee/src/transition.rs#L4885), [finality weight subtraction](../../../crates/bloch-pos-committee/src/finality.rs#L334), [participation recovery](../../../crates/bloch-pos-committee/src/finality.rs#L543), [fork-choice accumulation and transaction total](../../../crates/bloch-pos-committee/src/transition.rs#L5806), [funded admission cap](../../../crates/bloch-pos-committee/src/transition/funded.rs#L293), [rewards-v2 issuance roster](../../../crates/bloch-pos-committee/src/transition.rs#L5007).

**Analytical example, not a recovery-time measurement:** suppose all weights have fully leaked, the post-cap total `U` remains fixed, every validator returns, every necessary vote is included and valid, and the already-armed recovery rule returns approximately 1/16 of outstanding leak per epoch. After `k` recovery updates, recovered weight is approximately `U × (1 − (15/16)^k)`. With the denominator floored at `U/2`, the quorum needs at least `U/3`; approximately seven recovery updates are needed even with full participation. Tallying precedes the recovery update, and finalization also requires consecutive justified checkpoints, so this is not seven epochs to finality. At the nominal 32 × 30-second cadence, seven epochs alone are 112 minutes. Integer rounding, scheduling, vote inclusion, source-checkpoint agreement and the fallback switch require a real end-to-end measurement. **Do not describe this candidate as minute-scale finality recovery.** See [quorum calculation](../../../crates/bloch-pos-committee/src/finality.rs#L450), [recovery ordering](../../../crates/bloch-pos-committee/src/finality.rs#L492), and [recovery quotient](../../../crates/bloch-pos-committee/src/params.rs#L218).

`MAX_EPOCH_ADVANCE = 4096` bounds transition work; it is not a supported outage-duration or recovery-time guarantee. Inactivity bite uses threshold 4 and divisor 64, and can exhaust remaining stake. Exact exhaustion depends on stake size and integer rounding. Do not turn the audit's approximate “60 epochs” or the old “45 days” comment into an SLA.

## FC-02 / ST-01: calendar taper can transfer control to very little outside stake

The cap becomes meaningful at only one minimum deposit, 25,000 BLOCH. If non-cohort stake is `O` and the calendar cap is `s`, the implementation permits cohort weight at most `s / (1 − s) × O`. This constrains the final **weighted share**, not the ratio of outside deposits to the original cohort's economic stake. The floor is 3,333 basis points. See [cap constants and calendar](../../../crates/bloch-pos-committee/src/genesis_cohort.rs#L55), [minimum outside stake and cap status](../../../crates/bloch-pos-committee/src/genesis_cohort.rs#L109), and [cap application](../../../crates/bloch-pos-committee/src/genesis_cohort.rs#L163).

For example, 64 cohort validators each bonded at 25,000 BLOCH total 1.6 million BLOCH. At the taper floor, a single non-cohort validator bonded at 25,000 BLOCH can limit their combined effective weight to approximately 12,498.125 BLOCH. The outsider then holds approximately **66.67% of the capped total**, although its bond is only a small fraction of the original economic stake. This is an illustrative calculation, not a claim about today's registered identities or ownership. Around the middle of the taper its weighted share approaches one third; exact threshold epochs and per-validator integer rounding must be tested.

Funded admission also calculates a per-validator cap from active weight, floored at the minimum deposit. The block execution path supplies its already adjusted consensus-roster total. Thus the cap's denominator can constrain a larger single deposit after the cohort has been scaled down or leaked. The complete remedy must review both **voting-weight allocation** and **admission-cap basis**, rather than changing only a dashboard or the cohort threshold. See [block transaction total](../../../crates/bloch-pos-committee/src/transition.rs#L5829) and [funded deposit validation](../../../crates/bloch-pos-committee/src/transition/funded.rs#L275).

The recovery candidate does not fix this concentration: its fallback restores the capped roster, not uncapped stake. Leak debt is subtracted after the cohort cap, so a calendar or admission-driven reduction in cohort weight can also make existing absolute leak debt exhaust more of the reduced weight. Conversely, one positive-weight outsider prevents the all-zero fallback from activating. These are concrete interactions to reproduce, not grounds to silently alter existing economic rules.

The proposed review direction remains stake-proportional weight with an explicitly justified concentration policy. It is **not implemented or approved as an activation plan**. Validator keys and non-cohort indices do not establish independent operators; splitting one owner's stake across keys cannot prove decentralization. The source itself acknowledges that an owner can fund new keys outside the fixed genesis cohort. Any operational ownership assessment must be recorded separately from on-chain arithmetic.

## FC-07: a half-denominator floor does not ensure unique finality across partitions

Define `U` as the **unleaked, post-cohort-cap active weight** for a fixed comparison epoch; it is not necessarily the sum of raw validator bonds. Finality computes `D = max(leak_adjusted_total, U/2)` after epoch 2,880 and accepts a target with `3 × vote_weight ≥ 2 × D`. After enough absent stake leaks, a disjoint partition retaining fraction `p` of `U` can pass whenever `p ≥ 1/3`. Two disjoint halves, or idealized disjoint thirds at exact integer thresholds, can therefore qualify on their separate histories. Different histories have different leak ledgers and denominators. The proof that two roots cannot both reach two thirds **inside one state** does not prove uniqueness between such states. Sources: [denominator](../../../crates/bloch-pos-committee/src/finality.rs#L345), [vote tally](../../../crates/bloch-pos-committee/src/finality.rs#L450), and [explicit residual in params](../../../crates/bloch-pos-committee/src/params.rs#L232).

Each validator may sign only its own partition's monotone checkpoint sequence. Divergent finality alone is not a same-validator double vote or surround vote. Slashing support being armed at 2,884 does not manufacture slashable evidence against disjoint honest signers. See [`SlashingEvidence::offense`](../../../crates/bloch-pos-committee/src/slashing.rs#L194). The audit's approximate “25 epochs” must be reproduced under current gates, integer stake, actual block inclusion and the chosen partition fixture; this review did not measure a universal time to divergence.

Two documentation cautions matter for the decision:

- The existing [half-floor test](../../../crates/bloch-pos-committee/src/finality.rs#L1403) records an earlier owner choice and pins `(1, 2)`. It is not a safety proof or new authorization to activate another rule.
- Some nearby prose says a floor of exactly 3/4 guarantees uniqueness. With the actual non-strict quorum inequality, exactly 3/4 still allows two halves at equality after sufficient leak. In the fixed-weight, disjoint-partition model, eliminating that case needs a floor **strictly above** 3/4. Even that algebra is not a full protocol proof under dynamic weights, exits, deposits, slashing and changing checkpoints. No floor change is proposed here.

The FC-01 fallback can restore block production in more than one isolated zero-weight branch. It does not select a globally agreed branch and does not strengthen the half-floor safety bound. Node-local finality latches and signed weak-subjectivity checkpoints can fence adoption against an operator's established anchor, but they do not retroactively make separately finalized roots unique. Rejoining nodes must not silently discard an established conflicting finality anchor.

## Minimum qualification before any activation proposal

| Rehearsal | Required evidence and acceptance question |
| --- | --- |
| Historical gates and replay | Replay the same canonical log under current and candidate builds through epochs 1,400, 2,880 and 2,884, then through a proposed future candidate boundary. Pre-boundary roots and accepted blocks must match exactly. Include fresh replay, cache restore plus tail, and cache invalidation after a build change. No activation epoch is selected by this memo. |
| Complete outage and return | Use real node processes and durable stores; span short outages and 60/64/80+ empty-epoch projections. Return 100%, 60%, 50%, one third and below one third of **weight**. Record first valid proposal, first included vote, leak repayment, fallback on/off transitions, justification, finalization and restart recovery separately. Test staggered returns and missing votes. |
| Partition and rejoin | Exercise 50/50, 60/40, near-one-third boundaries and three-way partitions with fixed and changing stake. Use separate branch histories and controlled clocks; verify every signature and check produced slashing evidence. Record conflicting finality rather than calling local progress a pass. Rejoin using finality latches and independent WS anchors, including explicit conflict refusal. |
| Cohort and admission | Test zero outsiders; one minimum-bond outsider; outsider stake just below/at the cap-deferral threshold; calendar rounding boundaries and taper floor; one owner represented by many keys; and genuinely distinct operational owners without encoding a fictitious ownership oracle. Compare raw bonds, capped weight, leaked weight, proposer share, quorum share and allowed new deposit size. |
| Membership changes during recovery | Include deposits, exits, slashing ejection, withdrawals and RANDAO recommit across epoch boundaries. Verify admitted votes survive into the intended epoch tally, old registry keys do not become authorities for another branch, and returning validators cannot double-sign through replay or migration. |
| Reward and supply accounting | Keep rewards v2 off for the production candidate; additionally exercise an isolated future combined-gate fixture. Reconcile issuance, forfeiture, proposer and attester credits, fee distribution, delegated weight and the first partially recovered roster. Show conservation and deterministic roots. |
| Mixed binaries and operational fencing | Demonstrate expected incompatibility after activation, prove pre-activation compatibility, inventory participating binaries, and qualify rollback boundaries. Obtain the required WS signatures and operator coordination; do not infer consent or independent ownership from a validator count. Measure Linux production-like startup and finality recovery separately. |

A release review must state which safety/liveness trade-off is intended, what an exchange may treat as final under a prolonged partition, and which measured recovery figures are supported. Until the above evidence exists and the economic/finality decisions are explicit, FC-01 remains an **unarmed candidate**, FC-02/ST-01 remain **protocol decisions**, and FC-07 remains **open**.

## Review evidence

This memo was produced by reading the cited source and the supplied audit. The geometric recovery example was calculated directly from the implemented 1/16 recovery rate; it is an approximation, not a simulated chain. No new protocol rehearsal was executed for this memo. Prior isolated roster tests and ordinary passing unit suites must not be substituted for the multi-node activation, partition and economics qualification listed above.
