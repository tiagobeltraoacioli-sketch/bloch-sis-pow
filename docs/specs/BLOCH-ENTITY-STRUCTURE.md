<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# Bloch — two-entity structure

```
Document:  BLOCH-ENTITY-STRUCTURE
Status:    DRAFT — structure proposed, jurisdiction and board not decided
Created:   2026-08-10
Follows:   ADR-036 (ownerless thesis retracted, Solana model adopted)
Relates:   BLOCH-TOKENOMICS-V4.md, BLOCH-POS-SHA3-LATTICE-MIGRATION.md
```

---

## 1. The template

Solana runs three entities, not two, and the shape matters:

| Entity | Form | Role |
|---|---|---|
| **Solana Foundation** | Swiss non-profit, Zug, ~70 staff | Holds the token treasury; grants; validator delegation program; governance; education |
| **Solana Labs** | For-profit, San Francisco | Engineering and product |
| **Anza** | Employee-owned for-profit, spun out of Labs in 2024, funded by a Foundation grant | Core protocol engineering (validator client) |

The Anza spin-out drew public criticism as "decentralisation theatre" — the
same people, a new letterhead. That criticism is the thing to design against,
not a reason to avoid the structure.

## 2. Proposed structure for Bloch

Two entities, because a third has to earn its existence:

| | **Bloch Foundation** *(to be created)* | **Postern Labs Ltda** *(exists)* |
|---|---|---|
| Form | Non-profit; jurisdiction open (§6) | Brazilian limited company |
| Purpose | Steward the protocol; hold and distribute the non-founder allocations | Build the node, the OS, the apps, the wallet |
| Revenue | None — endowed by its allocation | Product revenue plus Foundation grants |
| Protocol authority | Publishes specs, GIPs, checkpoints | **None** |

## 3. Who holds what

| Allocation | Custody | Note |
|---|---|---|
| Founder 17% | Founder personally, or a holding company | Vesting is consensus-enforced either way; the wrapper is a tax question, not a protocol one |
| VC 10% | **Foundation**, until sold | The Foundation is the counterparty of the round |
| Team 10% | **Foundation**, distributed to individuals on grant | Individuals hold their own once granted |
| Marketing 4% | **Foundation** | |
| Liquidity 5% | **Foundation** | Deployed to exchanges and AMMs at genesis |
| Carryover ≤ 0.3% | Holders themselves | Nobody's to hold |
| Validators 53.7% | Nobody — emitted | Never in anyone's custody, which is the point |

The Foundation therefore holds **29% of supply** at genesis, most of it vesting.
It is the largest single holder for the entire first decade. Everything in §5
follows from that.

## 4. Who signs what

| Act | Signatory | Why not the other |
|---|---|---|
| Exchange listing and integration agreements | Foundation | Needs a non-profit counterparty with no product conflict |
| VC subscription agreements | Foundation | The securities-sensitive act; must sit where legal review sits |
| Grants to Postern Labs and to third parties | Foundation | Related-party — see §5.2 |
| Employment of protocol engineers | Postern Labs | Foundation should not be the engineering employer, or the split is cosmetic |
| Release signing keys for the node | Postern Labs | Whoever builds, signs |
| Weak-subjectivity checkpoints | Foundation | §5.3 |
| The genesis taint list | Foundation, published for challenge | §5.4 |

## 5. Four things this structure gets wrong if built naively

### 5.1 The delegation program is a decentralisation illusion

Solana's Foundation delegates its stake to validators that meet performance
requirements, and it is the main reason Solana's validator set grew. Bloch's
Foundation could do the same with its 29%.

**It would make the activation gates pass without decentralising anything.**
The gates G2 and G3 are computed from `Registry::top_share_bps` and
`Registry::nakamoto_coefficient`, which measure the *operator* view — what
consensus sees. Foundation stake spread across forty operators reads as forty
independent participants. The beneficial owner is one entity, and it can
redelegate at will. The delegation module documents this limit explicitly:
those metrics cannot see one owner standing behind several delegators, and no
on-chain metric can.

So: run the delegation program, because bootstrapping a validator set is a real
problem and this solves it — but **do not count Foundation-delegated stake
toward G1–G4**. The gates should be measured on stake whose beneficial owner is
not the Foundation, the founder, or Postern Labs. That is a reporting rule, not
a protocol rule, and it has to be written down before the numbers become
convenient.

### 5.2 Related-party funding needs controls, not disclosure alone

The Foundation funding Postern Labs is the Foundation paying a company the
founder owns. That is normal in this industry and it is also how "decentralisation
theatre" accusations start.

Minimum controls: a Foundation board with a majority of members unaffiliated
with Postern Labs and with the founder; recusal of conflicted members from
grant votes; published grant amounts and terms. None of this is exotic — it is
what makes the two-entity split mean anything beyond letterhead.

### 5.3 Checkpoint publication is a real centralisation point

The PoS design needs weak-subjectivity checkpoints, and ADR-036 resolves the
"who signs them" question by answering "the Foundation". That answer is honest
but it is not free: a node syncing from scratch trusts the Foundation's
checkpoint. Two mitigations worth building in from the start — publish
checkpoints under an *m-of-n* key held by parties beyond the Foundation, and
set an explicit review date at which the arrangement is reconsidered rather
than letting it become permanent by default. Both are adopted with concrete
parameters in `BLOCH-WEAK-SUBJECTIVITY.md` §6 (phased 2-of-3 → 3-of-5 with a
client-enforced external-signer minimum; 12-month review with a hard stop at
15 months).

### 5.4 The taint list is an unaudited power

Which addresses count as "founder" — and are therefore ineligible for the
carryover and for staking — is decided by whoever writes the list. Nothing in
the protocol checks it. Publishing the list with the snapshot announcement, far
enough ahead that it can be argued with before height 80,000 passes, is what
converts it from a private decision into a public one.

## 6. Open — needs counsel, not a guess

1. **Jurisdiction of the Foundation.** Solana chose Switzerland; Cayman and
   Singapore are the other common choices. A Brazilian founder and a Brazilian
   operating company make the tax treatment of a foreign non-profit a real
   question — controlled-foreign-company rules, transfer pricing on the grants,
   and the founder's personal position on a 17% allocation. This needs Brazilian
   and local counsel together, and the answer may change the structure rather
   than just its address.
2. **Who actually sells to the funds** — the Foundation directly, or an SPV.
   This is the securities-sensitive act and belongs with the Phase 0 legal
   review, which ADR-036 already reclassified as blocking.
3. **Board composition and the independence test** (§5.2).
4. **Whether a third entity is warranted.** Anza exists because Solana's core
   engineering grew beyond one company. Bloch's does not have that problem yet.
   A third entity now would be letterhead.

## 7. What this does not fix

A foundation makes concentration easier to **administer** — vesting is
administered, allocations are held by an entity with duties, grants have terms.
It does not make concentrated stake decentralised. G1–G4 still have to be met on
measured numbers, and §5.1 is the specific way this structure could be used to
appear to meet them without meeting them.
