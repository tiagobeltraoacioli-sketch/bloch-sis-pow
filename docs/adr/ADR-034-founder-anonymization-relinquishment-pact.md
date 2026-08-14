# ADR-034 — Founder Anonymization & Relinquishment Pact ("pacta rei heraclitiano")

**Status:** **SUPERSEDED** — **Retracted by ADR-036** (founder decision, 2026-08-10). The trigger written here — "activates at mainnet launch" — must not be read as live: mainnet launched (Genesis-4, 2026-08-13) and **this pact did not take effect**, because it had already been retracted three days earlier. The founder holds 27,046,829,380 BLCH and operates all 64 validators. No anonymisation and no relinquishment has occurred. The chain this ADR governs — Genesis-3, proof of work — stopped permanently at height **39,918** on 2026-08-13. The live chain is **Genesis-4, proof of stake** (30 s slots, 32-slot epochs, finality by epoch, hybrid ML-DSA-65 ‖ Falcon-1024, no mining). The decision, context and consequences below are **not** rewritten: this is a decision log and what was decided, when, is the record. Read it as history, not as guidance.

*Original status line, retained:* **Status:** Proposed (founder pre-commitment; activates at mainnet launch)
**Date:** 2026-07-07
**Author:** BLOCH Founder (anonymous henceforth — see §5)
**Related:** ADR-027 (Founder Commitment Instrument), ADR-023–027 (community handover), ADR-033 (decentralization model), ENSAIO_2 (Pre-Commitment Doctrine), *The Cryptographic Constitution*
**Amends:** ADR-027 §(personal-binding clause)

---

## 1. Context

The founder has declared, in their own words:

> *"Anonimizar o fundador, a partir do lançamento — pacta rei heraclitiano.
> Não terei mais nenhuma ingerência, porque o que é do povo será do povo."*

Rendered: **at mainnet launch the founder becomes anonymous and relinquishes
all governance and operational control of the protocol. What belongs to the
people will belong to the people.** The phrase invokes a *pact* (pacta) that,
like Heraclitus's river, does not run backwards: once the founder dissolves
into the protocol, the control does not return.

This is the logical endpoint of the pre-commitment doctrine the project has
argued since its inception (ENSAIO_2; *The Cryptographic Constitution*): the
only credible way to remove a capture point is to remove the mechanism of its
alteration — here, the founder's own discretionary authority.

## 2. Decision

Effective at **mainnet genesis (Phase 6)**:

1. **Anonymization.** The founder's personal identity is withdrawn from all
   *forward-facing* project materials. New ADRs, RFCs, specs, GIPs, commits,
   and releases are authored under a pseudonymous / anonymous designation
   (**"BLOCH Founder"**), never the legal name.
2. **Relinquishment of control.** The founder retains **no** governance or
   operational authority over the protocol: no admin key, no unilateral
   parameter change, no privileged maintainer status beyond any other
   contributor, no discretionary authority over the validator/oracle pools or
   the compliance list. Protocol change routes solely through the GIP process
   and node-operator activation (ADR-019), identical to Bitcoin.
3. **Handover.** The custody-handover and decentralization-metric triggers
   (ADR-023–027, reframed under the BLOCH Labs model per ADR-033 §8) execute
   without founder discretion. Steward/multisig control transitions to the
   community per those triggers.
4. **Amends ADR-027.** ADR-027 previously stated the Founder Commitment
   Instrument "binds Tiago Acioli personally and is not transferable." Under
   this ADR the binding is to the *role*, and the role is dissolved at launch:
   there is no continuing "founder's office" with authority.

## 3. What this pact does NOT change (honest scope)

This ADR is a genuine relinquishment of **control**, not a rewrite of history
or economics. The following remain true and must not be misrepresented as
"total decentralization like Bitcoin/Kaspa" (see ADR-033 for that distinction):

- **The premine persists.** The 170M founder allocation (17%), locked 10 years
  then vesting 40 years (ADR-033 §8), continues to release to a
  founder-controlled address. Holding 17% of supply is economic weight even
  when the holder is anonymous. Anonymity ≠ absence of stake.
- **BLOCH Labs persists** as the operating entity (trademark, infrastructure,
  pool custody with multisig) until the ADR-025/026 handover triggers fire.
  Someone runs Labs; "no founder ingerência" means the founder is not that
  someone, not that Labs ceases to exist.
- **The compliance layer persists** (Sprint 11; sanctions-root multisig).
  A chain with a freeze/KYC surface is **not** credibly neutral (ADR-033 §8.1);
  anonymizing the founder does not make it so. The list must be governed by
  multisig + GIP, never by the (now anonymous) founder.

These three are in tension with "não terei mais nenhuma ingerência." The pact
resolves the tension **only** for discretionary *control*: the founder keeps a
*stake* (premine) and the ecosystem keeps *entities* (Labs) and *rules*
(compliance), but the founder wields no lever over protocol, pools, or list.

## 4. Limits of anonymization (cannot be undone)

Full retroactive anonymity is **impossible** and this ADR does not claim it:

- The legal name is already public in the **git history on the GitLab remote**
  (past commit/tag authorship) and in anything already cloned or forked.
- *The Cryptographic Constitution* (Acioli 2026) is **published on SSRN** under
  the legal name and is cited in the README.
- The **`@tiagoacioli`** handle and prior public materials persist.
- Tax/legal identity of the premine holder remains known to authorities
  regardless of pseudonymity (see the pending founder personal-tax review).

Anonymity from launch is therefore **forward-looking convention**, not erasure.
A destructive git-history rewrite could scrub *local* history but would not
reach the remote, forks, or the paper, and would invalidate every published
commit hash and open MR — it is **not** performed by this ADR and requires an
explicit, separate decision if ever pursued.

## 5. Consequences

- All new authored artifacts use "BLOCH Founder"; existing forward-facing
  bylines are updated in the working tree (this change set).
- ADR-027's personal, non-transferable binding is superseded by the
  role-dissolution model above.
- The project's public messaging must state honestly what the pact does and
  does not achieve (§3, §4) — anonymized founder with a retained stake and a
  compliance layer, handing governance to the community; **not** a Satoshi-
  grade fair-launch credibly-neutral chain.

## 6. Open questions

1. **Pseudonym.** Use the neutral "BLOCH Founder", or adopt a specific
   Satoshi-style handle? (Set once, everywhere.)
2. **Premine vs relinquishment.** Is keeping a 17% anonymous stake consistent
   with the spirit of "o que é do povo será do povo"? (Founder's call; flagged
   for honesty, not to reopen ADR-033.)
3. **Git-history rewrite.** Pursue the destructive, partial scrub, or accept
   forward-looking anonymization only? (Recommend the latter.)
