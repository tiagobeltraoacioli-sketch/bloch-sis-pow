<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- SUPERSEDED DRAFT — never published, and MUST NOT be published as written.
     It was drafted 2026-08-12 in anticipation of a halt at height 50,000 and a
     multi-month pause. Neither happened. See the correction block below; it is
     the only part of this file that describes what occurred. -->

# SUPERSEDED DRAFT — "Genesis-3 ends at height 50,000. Genesis-4 will be proof-of-stake."

*Drafted 2026-08-12, never published. Genesis-3 stopped at height **39,918** on
2026-08-13 and Genesis-4 went live the same day. The correction block below is
the only current part of this file.*

---

> # ⚠ SUPERSEDED — read this first
>
> **This announcement was drafted on 2026-08-12 and was never published. It
> describes a plan. The plan is not what happened, and every future-tense
> sentence below is now wrong.** The draft is kept as a record of what was
> written, not as a description of the network. Nothing in it may be published
> or quoted as current.
>
> **What actually happened:**
>
> | This draft says | What occurred |
> |---|---|
> | Genesis-3 stops at height **50,000**, around 15 Aug 2026 | Genesis-3 stopped permanently at height **39,918** on **2026-08-13** — below the announced height |
> | A pause of **several months / ~six months** with no chain | **No pause.** Genesis-4 opened the same day, **21:31:19 UTC, 2026-08-13** |
> | "We will not commit to a Genesis-4 launch date until the code has been through review" | The chain launched **without external review**. **No third-party audit exists.** |
> | "The PoS node is not released software… treat any 'Genesis-4 is live' claim as false" | **Genesis-4 is live.** Public read RPC: `https://posternlabs.com/g4rpc` |
> | Carryover 17,970,880,000 BLCH (17.97%), measured "at height 43,172" | **18,146,400,000 BLOCH (18.15%)**, measured at the terminal height **39,918**, 452,726 outputs, 16 addresses. The old "height 43,172" was a **block count**, not a height |
> | Validator emission 43,029,120,000 (43.03%) | **42,853,600,000 (42.85%)** |
> | Founder holds "roughly 94%" of the crossing supply | **93.94%** — 17,046,829,380 of 18,146,400,000 BLOCH. Essentially unchanged; the correction is a re-measurement, not a distribution |
>
> **The disclosure this draft could not make, and which any future public text
> must carry in its place:** the security question under Genesis-4 is not
> hashrate, it is concentration. **All 64 validators are run by one entity**,
> **93.94% of the carryover sits at a single address**, and **56.05 B of the
> 57.15 B BLOCH issued at genesis is held by the founder and the Foundation**
> — leaving 1,099,570,620 BLOCH, **1.92%**, with everyone else. One operator
> can halt the chain and one holder can outvote every other. A third party
> cannot currently join: the live transport has a fixed peer list with no
> discovery and no authentication, and `Deposit`/`Delegate` are refused at
> every node's mempool because bonding is not yet funded from the UTXO set.
>
> **What in this draft is still true and still worth saying:** balances crossed
> automatically via the signed snapshot; there was no claim process, no swap
> and no migration transaction, and **anyone who asks you to send coins or keys
> to "migrate" is trying to steal from you**; post-halt Genesis-3 chain data is
> cheap to fabricate and must not be trusted — the **signed snapshot artifact
> is the canonical record**, reproducible against the root and file digests
> pinned in `crates/bloch-pos-committee/src/tokenomics_v4.rs`; the
> redenomination created no economic gain for anyone; and BLCH carries no
> promise of value.

---

## The draft as written on 2026-08-12 (historical — not current)

## The short version

- The Genesis-3 chain **stops producing blocks at height 50,000**. This is
  planned and enforced by a consensus rule, not a failure.
- At the current pace that is **around August 15, 2026 (UTC)** — an estimate
  that moves with hashrate, in either direction.
- **Mining ends at that height.** Hashrate pointed at Bloch after 50,000 earns
  nothing on the canonical chain.
- **Balances carry over automatically** through a signed snapshot taken at
  height 50,000. Holders do not need to do anything. There is no claim
  process, no migration transaction, no swap. Anyone telling you otherwise is
  trying to steal from you.
- Between the halt and the Genesis-4 launch there will be a period of
  **several months with no running chain**. The explorer at
  [blochl1.com](https://blochl1.com) stays online serving history.
- On Genesis-4 the total supply is redenominated from 21,000,000,000 to
  **100,000,000,000 BLCH as a pure split (×4.7619)**. Every balance is
  multiplied by the same factor; every percentage stays identical. Nobody
  gains, nobody is diluted. It is not new money.
- Genesis-4 replaces mining with **proof-of-stake**. The planned validator
  bond is approximately **25,000 BLCH** (post-split), and delegation will
  exist for those who do not run a validator.

Everything below is the same information with the reasoning attached.

## 1. The halt is the plan, not an accident

Genesis-3 has served as Bloch's proof-of-work chain since its relaunch on
2026-07-29. It ends at **height 50,000** by a consensus rule: blocks above
that height are invalid to upgraded nodes. The chain does not slow down or
wind down — it stops at that height, and the state at that height is the
starting state of Genesis-4.

**When.** Measured on 2026-08-12: the chain was at height 37,722, averaging
about 20 seconds per block (4,104 blocks in the previous 24 hours). At that
cadence the remaining 12,278 blocks take roughly three days, putting height
50,000 **around August 15, 2026 (UTC)**. This is an estimate, not a schedule.
Block height advances with hashrate: if hashrate rises, the halt comes
earlier; if it falls, later. The height is fixed; the date is not. The
explorer at [blochl1.com](https://blochl1.com) shows the current height at
any time.

**Why halt rather than run both chains.** Had Genesis-3 kept running after
the snapshot, every coin mined after it would be a coin with no future — and
a rational miner switches off the day after the snapshot anyway, leaving the
network undefended exactly while people still have wallets pointed at it.
Stopping cleanly at the snapshot height removes both problems.

## 2. If you mine Bloch

**Mining income from Bloch ends at height 50,000.** This is stated here
plainly because it is a loss of revenue from that point on, and you should
plan for it rather than discover it.

- Blocks above 50,000 are invalid on the canonical chain. Shares submitted
  after the halt pay nothing.
- Rewards for blocks **at or below** 50,000 are part of the snapshot like any
  other balance, and carry over.
- If you merge-mine Bloch alongside Bitcoin (AuxPoW), your Bitcoin side is
  unaffected; only the Bloch side ends.
- A node that has not upgraded to the halt-enforcing release will keep
  accepting blocks past 50,000. That continuation is a fork with no snapshot
  and no future; coins mined on it do not exist in Genesis-4. The canonical
  snapshot is taken at height 50,000 and nowhere else.

Genesis-4 has no mining. If you want to keep participating in consensus, the
path is running a validator or delegating stake — see section 6.

## 3. If you hold BLCH

**Your balance crosses to Genesis-4 automatically.** At height 50,000 a
snapshot of every on-chain balance is taken, hashed, signed, and published.
Genesis-4 opens with those balances (multiplied by the split factor — section
5). The carryover crosses as one set, on equal terms, and it is liquid at
genesis: no lockup is applied to carried-over balances.

**What you need to do: nothing.** There is no registration, no claim site, no
deadline to act by, no transaction to send. If your coins are in a wallet you
control, they will be in the snapshot.

**One genuine deadline:** a transaction is only reflected in the snapshot if
it is **confirmed at or below height 50,000**. If you need to move funds
before the snapshot — for example, out of an address you are losing access
to — do it with margin, not in the final hours.

**What you must not do:**

- Do not send coins to any address that claims to be a "migration",
  "bridge", or "swap" contract. **No such thing exists.** The migration is a
  snapshot; it never asks you for a transaction.
- Do not enter your seed phrase or private keys anywhere to "register" for
  Genesis-4. Nobody legitimate will ever ask for them.
- Do not trust balances or transactions dated after height 50,000. After the
  halt, nobody is spending hashrate to defend the old chain, so post-halt
  chain data is cheap to fabricate. The **signed snapshot artifact is the
  canonical record**, not the chain that produced it; its digest will be
  published through multiple channels and embedded in the Genesis-4 genesis
  block itself, and independent operators will be able to reproduce it from
  their own copies of the chain and compare digests.

The Coherence shielded pool is provably empty on this mainnet, so no shielded
balances are affected.

## 4. The pause between chains

Between the halt and the Genesis-4 launch there is a period with **no running
Bloch chain**. The working plan is on the order of **six months**, spent on
code review and an external audit of the proof-of-stake implementation. That
duration is a plan, not a promise: the PoS node currently runs on an internal
devnet, and **we will not commit to a Genesis-4 launch date until the code
has been through review**. A date announced today would be a date nobody can
guarantee, so we are not announcing one.

During the pause:

- The **explorer at [blochl1.com](https://blochl1.com) stays online**,
  serving the full Genesis-3 history and the snapshot data.
- The signed snapshot and its digest remain published and verifiable.
- No transactions are possible, by design. Balances are fixed at the
  snapshot until Genesis-4 opens with them.

## 5. The supply number changes. Your share does not.

Genesis-4 redenominates the total supply from 21,000,000,000 to
**100,000,000,000 BLCH**. *(The draft as circulated contained a copy bug here,
reading "from 100,000,000,000 to 100,000,000,000"; the correct statement is
21 B → 100 B at ×100/21, as this draft's own Telegram appendix has it.)* This is a **pure split**: every balance, every
allocation, and every protocol constant denominated in BLCH is multiplied by
the same factor, 100/21 ≈ **4.7619**.

Concretely: if you hold 1,000 BLCH at the snapshot, you open Genesis-4 with
approximately 47,619 BLCH — and that larger number is **exactly the same
fraction of total supply** as your 1,000 was, because the total grew by the
identical factor. Everyone's balance scales together. Nobody's percentage
moves. It is the same pie cut into more slices, like a stock split: **more
units, same share, no new money.** If any coverage of this change reads as
"holders receive extra tokens", that coverage is wrong.

Why do it at all: 100 billion at 8 decimal places sits comfortably within the
protocol's integer arithmetic and gives smaller per-unit denominations
without changing anyone's position. The cap is enforced as a consensus
invariant — every node rejects a block whose cumulative issuance would exceed
it, and no mechanism inside the protocol (no vote, no key, no governance
path) can raise it. Stated at its true strength and no stronger: a hard fork
adopted by every operator can change any rule of any chain; what does not
exist is any in-protocol way to change this one.

**Separate from the split, and stated so it is not discovered later:** the
split preserves shares at the moment of genesis, but Genesis-4 — like
Genesis-3 before it — continues to issue new coins afterward. Validator
emission runs over 40 years, and allocations to the foundation, team, and
other buckets vest on published schedules. So a balance's share of *total
eventual supply* is what the split preserves; its share of *circulating*
supply will change over time as emission proceeds, exactly as it did under
mining. The carried-over Genesis-3 supply is **17.97% of the eventual 100 B**.
The full allocation, in post-split terms:

*(Superseded — the two figures marked below were computed against a
provisional carryover reading. Terminal values: carryover **18,146,400,000
(18.15%)**, validator emission **42,853,600,000 (42.85%)**.)*

| Allocation | BLCH | Share | Terms |
|---|---:|---:|---|
| Carryover (all Genesis-3 balances) | ~~17,970,880,000~~ **18,146,400,000** | **18.15%** | liquid at genesis |
| Validator emission | ~~43,029,120,000~~ **42,853,600,000** | **42.85%** | issued over 40 years |
| Founder grant | 10,000,000,000 | 10% | 10-year cliff, then 40-year linear vest |
| VC | 10,000,000,000 | 10% | vesting |
| Team | 10,000,000,000 | 10% | vesting |
| Liquidity | 5,000,000,000 | 5% | — |
| Marketing | 4,000,000,000 | 4% | — |

**On concentration, because it should come from us and not be found:** the
founder's carried-over balance is by far the largest — **93.94% of the
Genesis-3 supply crossing the snapshot, 17,046,829,380 of 18,146,400,000
BLOCH** — and, like every carried-over balance, it is liquid and stakeable in
Genesis-4. Including the 10% grant the founder holds **27.04% of total
supply**; the Foundation holds a further **29.00%**; together that is
**56,046,829,380 of the 57,146,400,000 BLOCH issued at genesis**, leaving
**1.92%** with everyone else. And on the live chain, **all 64 validators are
operated by one entity**, with no permissionless way for anyone else to become
one. The mechanisms that bound
it over time (the founder grant's 10-year cliff and 40-year vest, the
declining cap on the genesis validator cohort, per-validator stake limits)
are published in the tokenomics specification, along with what each does and
does not achieve. We publish the numbers as they are.

BLCH carries no promise of value, and nothing in this announcement is
investment advice. The redenomination in particular creates no economic gain
for anyone, and reading it as one would be a mistake.

## 6. Genesis-4 is proof-of-stake

Genesis-3 was secured by SHA-256d proof-of-work. Genesis-4 replaces it with
proof-of-stake while keeping what Bloch exists for: a post-quantum base
layer, signed with the ML-DSA-65 ‖ Falcon-1024 hybrid suite, unchanged.

What is currently planned — planned, because the implementation is at devnet
stage and details can still change under review:

- **Validator bond: approximately 25,000 BLCH** (post-split). The figure
  targets the same fraction of total supply as Ethereum's 32 ETH. A lower
  bond widens who *may* validate; it does not by itself change who *does*.
- **Delegation** exists for holders who do not want to operate a node:
  stake can be delegated to a validator, with the risks of doing so
  documented alongside the mechanism.
- **Any liquid balance is stakeable**, carried-over balances included, on
  equal terms.
- The **genesis validator set** that produces the first blocks is allocated
  at launch, and a consensus rule requires that cohort's share of the
  validator set to fall below one third within the first year.
- Fees burn during the emission era, then go to validators.

The proof-of-stake node is **not released software**. It runs on an internal
devnet, is licensed AGPL-3.0-or-later, and will go through external review
before any launch. When there is something you can run and verify, this page
will say so — before that, treat any "Genesis-4 is live" claim as false.

## 7. Why we are doing this

Bloch exists to be a self-binding commitment: a post-quantum chain whose
rules — the supply cap among them — hold because every node checks them, not
because anyone promises to behave. The move to proof-of-stake trades the
ongoing energy cost of mining for a security model where holding people to
the rules is done by the people bound by them. Running a validator or
delegating stake in Genesis-4 is the same civic act that running a node has
always been here: upholding a pre-commitment, from the people, for the
people. That is the whole pitch. There is no other one.

## Verify, don't trust

- Chain height and cadence: `https://blochl1.com/rpc` (`getdaginfo`,
  `getchainstats`) or the explorer at [blochl1.com](https://blochl1.com).
- The snapshot digest will be published on this site, on the explorer, and
  embedded in the Genesis-4 genesis block. Compare all three.
- We will never DM you first, never ask for funds to migrate, and never ask
  for keys.

---

## Appendix — Telegram short version (max 6 lines)

**SUPERSEDED — do not send.** Written 2026-08-12 for a halt at 50,000 and a
months-long pause; neither happened. Kept as the record of what was drafted.
Any replacement must lead with the concentration disclosure in the correction
block at the top of this file, not with a hashrate estimate.

> Genesis-3 halts at height 50,000 — by design, enforced by consensus. At current hashrate that is around Aug 15, 2026 (estimate; the height is fixed, the date moves).
> Mining ends there: hashrate on Bloch after 50,000 earns nothing.
> Holders: balances cross to Genesis-4 automatically via a signed snapshot. Do NOTHING — no claim, no swap, no migration tx. Anyone asking you to send coins or keys is a scammer. Just make sure any transfer you need confirms before height 50,000.
> Then a pause of several months with no chain (explorer at blochl1.com stays up) while the proof-of-stake code is reviewed. The PoS node is devnet-stage; no launch date until review is done.
> Supply is redenominated 21B → 100B as a pure ×4.7619 split: more units, identical percentage, nobody diluted, no new money. Not a gain.
> Genesis-4 is proof-of-stake: validator bond ~25,000 BLCH (post-split), delegation available. Details: posternlabs.com. Not investment advice.
