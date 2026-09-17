# Proposal revalidation and stale-state signing — 2026-09-17

## EN-06 — proposal-side correction, finding remains partial

`Engine::select_transactions` now rechecks transfer input existence, ownership, duplicate inputs, value conservation, declared size and current fees against the candidate parent before fee sorting and byte packing. `admission::check_transfer` prices against `state.next_base_fee_at(proposed_epoch)`, matching the transition's explicit epoch rule at fee-target activation boundaries. It previously used the parent's epoch implicitly.

Packing reserves each selected transaction's spent outpoints. A lower-priority conflicting spend is skipped without consuming candidate byte capacity, allowing independent transactions behind it to fit. The transition probe still checks the actual combined candidate and remains authoritative. No accepted block format, consensus gate, or historical validation rule changes.

Skipped transactions remain in the mempool and are not entered into the rejection cache by selection. That matters for a fee decrease or a reorganization: the same signed bytes may become eligible again. Existing TTL and other sweep rules remain separate policies.

Funded deposits receive a state-aware check using a lazily constructed proposal-epoch view, its active stake total, the parent's epoch-specific next fee, and the probe verifier. That context is constructed at most once per selection and only when an enabled funded candidate needs it. The current funded admission gate is **epoch 2884**, not `u64::MAX`; candidates before that gate are skipped before projection. Immutable signature checks are not repeated here; admission and final block validation retain their existing roles.

Capacity-time stale-priority cleanup is implemented in the follow-up below. Ordinary-transfer fee replacement, package admission and input reservation at admission remain separate policies; no new general replacement policy is implied.

### Evidence

- `/private/tmp/bloch-audit-wave5-proposal-final.log`: five tests passed, zero ignored. New tests apply real signed, funded blocks to demonstrate fee increase, stale transaction exclusion without a bar, fee decrease and re-eligibility of the exact same bytes; candidate-epoch pricing at the byte-target boundary; and selection of independent spends behind a higher-tip conflicting spend. Another new test checks multiple funded candidates before the actual activation epoch without state mutation or rejection bars.
- `/private/tmp/bloch-audit-wave5-transfer-compat.log`: all 21 existing transfer end-to-end tests passed. The declared-byte geometry regression now tests the packer directly because its deliberately unsigned/unfunded synthetic inputs are ineligible for proposal selection.
- Active-funded selection is now independently tested at the actual epoch 2884, as detailed in the follow-up evidence below. No ignored rehearsal or activation edit is used.

Initial proposal-only checkpoint engine source SHA-256: `3883248a6f32ce57a48c1074a726636053c271bcd8cf3e3e8143e761407e10d1`. Admission helper SHA-256: `86304c0849aede7b23c0b6664ad07bce4e0887f51304f696c61247d537b36536`.

## EN-10 — remains open; no new signing veto

The current source still derives duty rosters and seeds from `rolled_to(epoch)` in both `attest` and `propose`. The run loop grants a two-slot boot grace, then permits duties without proof that replay/sync has reached the network's current head. The persistent signing protection and doppelganger checks are distinct safeguards; neither proves synchronization freshness.

A wall-clock/head-gap veto cannot safely close this finding: the same gap occurs when the chain genuinely produced no blocks. Epoch projection over empty slots is also the normal recovery path in that situation. A blanket lag threshold could prevent every honest validator from producing the first recovery block. `needs_sync`, orphan arrival, and peer-advertised heights are unsuitable substitutes because peers can influence them without proving a valid competing state.

No stronger trusted completion signal was found in the current engine that would let this patch distinguish those cases without changing the operational signing policy. The shared sync scheduler improves access to responsive peers but does not establish a global current head or a signing-readiness certificate.

Before adding an automatic veto, define a trusted readiness source and explicit recovery behavior. Qualification must contrast (1) a restarted node catching up while the chain advances, (2) a genuinely halted chain with no fresher blocks, (3) malicious high-head claims and orphan floods, and (4) honest delayed page application. The intended policy must let a halted chain recover while preventing an untrusted peer from indefinitely suppressing duties. No restart-time SLA or stronger freshness guarantee is claimed by this patch.

Source anchors: `engine.rs` methods `rolled_to`, `attest`, `propose`, `select_transactions`, `pack_transactions`, and the run-loop `in_grace` condition; `transition.rs::CommittedState::next_base_fee_at` and `Transition::compute_post_state` for the fee epoch rule.

## Follow-up: capacity-time backing revalidation

Capacity decisions now compute a transactional cleanup plan when the entry count, encoded-byte budget, or source allowance is exhausted. Entries which cannot currently back their declared fees/inputs are considered for retention eviction before still-paying entries, regardless of their advertised tip. A source at its allowance first reclaims its own stale entries; combined pressure then considers other stale entries. No stale scan is performed on ordinary admission below these bounds.

The plan commits only after the incoming transaction passes structural/signature/lifecycle checks. Invalid incoming bytes cannot evict even a stale entry. Funded conflict checks disregard only stale entries named in that plan, allowing a valid replacement to reclaim their capacity without weakening reservations against retained pending deposits. Cleanup removes admission timestamps and sweep bookkeeping, but does not create rejection bars or increment the paid low-fee replacement counter. Current, equally priced entries retain their original protection against churn.

This closes the previously documented **stale advertised-tip capacity priority** residual. Ordinary-transfer fee replacement/package admission and reservation of conflicting ordinary spends at admission remain separate policies: these transfers may coexist until selection reserves their inputs. No new general replacement policy is claimed.

Evidence:

- `/private/tmp/bloch-audit-wave6-capacity-final.log`: capacity regressions use a real applied full block to increase fees after authenticated admission, then test count, byte and same-source pressure; forged incoming signatures leave the pool unchanged; an equal-fee arrival still cannot evict a currently eligible entry after cleanup.
- `/private/tmp/bloch-audit-wave6-transfer-compat.log`: all 21 existing transfer tests pass. The preactivation compatibility test now asserts that inactive incoming bytes do not commit a stale cleanup plan; it no longer assumes unbacked placeholders must force a misleading full-pool response.
- `/private/tmp/bloch-audit-wave6-active-funded.log`: the previously unqualified active-funded case now passes at the unchanged real epoch **2884**. Two real signed deposit intents are independently validated against the derived epoch view; selection includes only one because they share inputs, and repeating selection preserves the result without evicting either intent. No ignored test or compile-time activation change was used.
