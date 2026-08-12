<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# ADR-036 — Retract the ownerless thesis; adopt a Solana-style foundation

- **Status:** Accepted (founder decision, 2026-08-10)
- **Retracts:** ADR-033 (decentralisation model / ownerless base), ADR-034
  (founder anonymisation and relinquishment pact)
- **Relates to:** `docs/specs/BLOCH-TOKENOMICS-V4.md`,
  `docs/specs/BLOCH-POS-SHA3-LATTICE-MIGRATION.md`

## Context

Every design document in this repository has, until now, rested on an ownerless
premise: no issuer, coins do not vote, the founder exits fully, and the chain is
a civic movement rather than an asset. ADR-033 restored that position after an
earlier compliance-first draft; ADR-034 recorded the founder's relinquishment
pact.

Tokenomics V4 is not compatible with it. A 10% allocation sold to funds
introduces investors with a return expectation and, in practice, an issuer. The
Solana revenue model adds delegation and commission — an operator economy. Both
were adopted on 2026-08-10.

Carrying both positions at once was flagged as an open decision, with the note
that one of the two had to be retracted **in writing** before anything is
published. This ADR is that retraction.

## Decision

1. **The ownerless thesis is retracted.** Bloch has an issuer and a sponsoring
   organisation. ADR-033 and ADR-034 no longer describe the project.
2. **The governance model is Solana's**: a non-profit **foundation** holding and
   distributing the non-founder allocations and stewarding the network, beside a
   development company. Solana runs Solana Foundation plus Anza/Solana Labs; the
   two-entity split is the template.
3. **A foundation will be created** if the structure requires it — the founder
   has confirmed this is available rather than a constraint.

## Consequences

### What this unblocks

- **An issuer exists.** Exchange listing was recorded as blocked partly because
  there was no legal person to sign an integration or listing agreement. There
  now is one. (PQ custody remains a separate, harder blocker and is unaffected.)
- **A counterparty for the VC round.** A 10% allocation cannot be sold by
  nobody.
- **A holder for the team, marketing and liquidity allocations**, with vesting
  enforced by consensus and administered by an entity that can be held to it.
- **An answer to weak subjectivity.** The PoS migration design called the
  question "who signs the checkpoint in an ownerless system?" its sharpest
  philosophical conflict, with no clean answer. With a foundation there is one:
  the foundation publishes weak-subjectivity checkpoints. That is a real
  centralisation cost, honestly stated — and it is a cost the ownerless design
  could not pay at all.

### What this obliges

- **Public copy must be rewritten before any announcement.** The node-movement
  voice — "from the people to the people", value beside the point, explicitly
  not a security — becomes false the moment tokens are sold to funds. So does
  "no listing effort". Leaving it up while running a VC round is the kind of
  inconsistency that is quoted back later.
- **The securities question gets harder, not easier.** Selling to investors with
  a return expectation, plus staking yield, plus an identifiable issuer and
  promoter, is close to the centre of the investment-contract test rather than
  the edge of it. Phase 0 legal review in the migration design is now clearly
  blocking rather than precautionary.
- **The founder's public position changes.** ADR-034's relinquishment pact is
  retracted; a 17% allocation with a 24-month cliff and 10-year vest is the
  replacement, and it should be described as what it is.

### What does not change

The cryptography, the consensus design, and the distribution gates G1–G4 are
unaffected. A foundation makes the concentration problem easier to *administer*;
it does not make concentrated stake decentralised, and the gates still have to
be met on measured numbers.
