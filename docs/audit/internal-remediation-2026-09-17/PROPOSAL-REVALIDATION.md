# Proposal revalidation and stale-state signing — 2026-09-17

## EN-06 — proposal-side correction, finding remains partial

`Engine::select_transactions` now rechecks transfer input existence, ownership, duplicate inputs, value conservation, declared size and current fees against the candidate parent before fee sorting and byte packing. `admission::check_transfer` prices against `state.next_base_fee_at(proposed_epoch)`, matching the transition's explicit epoch rule at fee-target activation boundaries. It previously used the parent's epoch implicitly.

Packing reserves each selected transaction's spent outpoints. A lower-priority conflicting spend is skipped without consuming candidate byte capacity, allowing independent transactions behind it to fit. The transition probe still checks the actual combined candidate and remains authoritative. No accepted block format, consensus gate, or historical validation rule changes.

Skipped transactions remain in the mempool and are not entered into the rejection cache by selection. That matters for a fee decrease or a reorganization: the same signed bytes may become eligible again. Existing TTL and other sweep rules remain separate policies.

Funded deposits receive a state-aware check using a lazily constructed proposal-epoch view, its active stake total, the parent's epoch-specific next fee, and the probe verifier. That context is constructed at most once per selection and only when an enabled funded candidate needs it. The current funded admission gate is **epoch 2884**, not `u64::MAX`; candidates before that gate are skipped before projection. Immutable signature checks are not repeated here; admission and final block validation retain their existing roles.

Residual capacity policy: existing mempool entries are still ranked by their advertised tip during capacity eviction. A transaction temporarily invalid under a changed fee can therefore retain capacity priority while selection skips it. This patch does not introduce ordinary-transfer input reservation at admission, fee replacement, package admission, or a new capacity-eviction policy. EN-06 remains partial for those admission/capacity concerns.

### Evidence

- `/private/tmp/bloch-audit-wave5-proposal-final.log`: five tests passed, zero ignored. New tests apply real signed, funded blocks to demonstrate fee increase, stale transaction exclusion without a bar, fee decrease and re-eligibility of the exact same bytes; candidate-epoch pricing at the byte-target boundary; and selection of independent spends behind a higher-tip conflicting spend. Another new test checks multiple funded candidates before the actual activation epoch without state mutation or rejection bars.
- `/private/tmp/bloch-audit-wave5-transfer-compat.log`: all 21 existing transfer end-to-end tests passed. The declared-byte geometry regression now tests the packer directly because its deliberately unsigned/unfunded synthetic inputs are ineligible for proposal selection.
- A new dedicated multiple-funded-candidate test at an **active** admission epoch was not run. No ignored rehearsal was added as qualification, and no activation constant was changed. Existing broader activated-path qualification is tracked by the release coordinator.

Frozen engine source SHA-256: `3883248a6f32ce57a48c1074a726636053c271bcd8cf3e3e8143e761407e10d1`. Admission helper SHA-256: `86304c0849aede7b23c0b6664ad07bce4e0887f51304f696c61247d537b36536`.

## EN-10 — remains open; no new signing veto

The current source still derives duty rosters and seeds from `rolled_to(epoch)` in both `attest` and `propose`. The run loop grants a two-slot boot grace, then permits duties without proof that replay/sync has reached the network's current head. The persistent signing protection and doppelganger checks are distinct safeguards; neither proves synchronization freshness.

A wall-clock/head-gap veto cannot safely close this finding: the same gap occurs when the chain genuinely produced no blocks. Epoch projection over empty slots is also the normal recovery path in that situation. A blanket lag threshold could prevent every honest validator from producing the first recovery block. `needs_sync`, orphan arrival, and peer-advertised heights are unsuitable substitutes because peers can influence them without proving a valid competing state.

No stronger trusted completion signal was found in the current engine that would let this patch distinguish those cases without changing the operational signing policy. The shared sync scheduler improves access to responsive peers but does not establish a global current head or a signing-readiness certificate.

Before adding an automatic veto, define a trusted readiness source and explicit recovery behavior. Qualification must contrast (1) a restarted node catching up while the chain advances, (2) a genuinely halted chain with no fresher blocks, (3) malicious high-head claims and orphan floods, and (4) honest delayed page application. The intended policy must let a halted chain recover while preventing an untrusted peer from indefinitely suppressing duties. No restart-time SLA or stronger freshness guarantee is claimed by this patch.

Source anchors: `engine.rs` methods `rolled_to`, `attest`, `propose`, `select_transactions`, `pack_transactions`, and the run-loop `in_grace` condition; `transition.rs::CommittedState::next_base_fee_at` and `Transition::compute_post_state` for the fee epoch rule.
