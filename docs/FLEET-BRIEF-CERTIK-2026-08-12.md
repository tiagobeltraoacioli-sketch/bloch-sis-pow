<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Fleet brief — CertiK audit readiness, 2026-08-12

> **Historical — dated brief, figures corrected 2026-08-14.** Written before
> the migration. Since then **Genesis-3 halted permanently at height 39,918 on
> 2026-08-13** (terminal DAG block count 50,690 — height and block count are
> different measurements in a DAG) and **Genesis-4 has been live under proof of
> stake since 21:31:19 UTC that day**: 30 s slots, 32 slots/epoch, 64 genesis
> validators all run by one entity, hybrid ML-DSA-65 ‖ Falcon-1024, finality by
> epoch. The stale supply figures below are corrected in place. **No external
> audit has been completed.**

Read this before starting. Read `docs/FLEET-BRIEF-2026-08-11.md` too — with the
caveat that it is superseded on two points and carries its own correction
banner: the 21 B tokenomics in its item 4 became the 100 B cap on 2026-08-12,
and its item 1 halt height (80,000) is wrong twice over — the chain stopped at
39,918. Its reasoning and working rules still hold; its numbers do not.

## The task

The founder wants Bloch to go through a CertiK audit, and gave the CertiK
Skynet **token scan** of WBNB on BSC as the model:
`https://skynet.certik.com/tools/token-scan/bsc/0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c`

That page evaluates, and scored WBNB 22 passed / 1 attention / 0 alerts:

| Category | Checks |
|---|---|
| **Market** | buy tax, sell tax, buy restrictions, sell restrictions, anti-whale mechanism, anti-whale modifiability |
| **Rugpull** | honeypot, self-destruct |
| **Centralization** | major holder concentration, mintable, blacklist, whitelist, hidden ownership, proxy contract, balance modification, tax modification by privileged roles, transfer cooldown, transfer pausability, ownership renunciation |
| **Transparency** | open-source code |
| **General** | external calls, withdrawal function, backdoor ownership recovery |

WBNB's single attention flag was **major holder ratio at 39.28%**, tagged
"Volatile Market, Centralization".

## Two things to confront before writing anything

**1. This scanner cannot be run against Bloch, and saying otherwise would be a
lie to the founder.** Skynet's token scan is a *bytecode analyser for EVM
contracts*. It reads a deployed contract at an address and looks for mint
functions, owner modifiers, proxy slots, tax logic. Bloch's BLCH is the **base
asset of an L1**, not a contract — there is no address to scan, no owner to
renounce, no proxy to inspect. EVM-at-L1 is a design in progress
(`BLOCH-L1-EVM-STATE-MODEL.md`), not a deployed token.

What CertiK would actually do for a chain like Bloch is a **code audit** of the
node and consensus, and separately a Skynet listing if and when there is an EVM
surface. Your job is not to pretend the checklist maps one-to-one. It is to
answer, for each check: does the *property behind it* hold on Bloch, by what
mechanism, and where is the evidence? A check that does not apply gets "does not
apply, and here is what plays its role instead" — never a blank pass.

**2. The concentration answer is already known, and it is bad.** WBNB drew an
attention flag at 39.28%. Bloch's largest carryover address holds
**17,046,829,380 of 18,146,400,000 BLOCH = 93.94%** of the carried-over supply,
measured at Genesis-3 height 39,918 over 452,726 outputs
(`crates/bloch-pos-committee/src/tokenomics_v4.rs`,
`LARGEST_CARRYOVER_ADDRESS_BLOCH` / `CARRYOVER_TOTAL_BLOCH`;
`BLOCH-TOKENOMICS-V4.md` §4A). Founder total with the genesis grant is
27,046,829,380 — **27.04% of the 100 B cap**; foundation buckets a further
**29.00%**; together 56,046,829,380 of the 57,146,400,000 issued at slot 0,
leaving **1,099,570,620 BLOCH (1.92%)** in third-party hands. If that balance
is staked — it is stakeable **by design**, decided 2026-08-11, though `Deposit`
and `Delegate` are today refused at every node's mempool
(`crates/bloch-pos-node/src/engine.rs:1900-1906`) because bonding is not yet
funded from the UTXO set — it would be 93.94% of active stake, with a Nakamoto
coefficient of 1. That coefficient is 1 today regardless of staking: all 64
genesis validators are run by one entity, and the live transport is a
point-to-point TCP full mesh with a fixed peer list, no discovery and no
authentication, which is why a third party cannot yet join the network at all.
There is no framing that makes this pass. **Do not try to find one.** The
deliverable on this point is: the
exact number, measured; the mechanisms that bound it (the genesis-cohort
declining cap, the 25 bps churn rate, the per-validator 1% cap); what each of
those does and does not reach; and the arithmetic in `BLOCH-TOKENOMICS-V4.md`
§4A.1 showing G1 is unreachable by emission alone. An auditor who finds you
softened this finds everything else suspect.

## Decisions taken the same day — build against these, not against the repo

The repo will still say 21 B when you start; the change lands in parallel with
this wave. Work from these numbers and flag anything you find that contradicts
them.

1. **Total supply 21 B → 100,000,000,000**, as a **pure split (×100/21)**: every
   bucket scales, every percentage is unchanged, nobody is diluted. Founder
   2.1 B → 10 B (10%); VC/team likewise; marketing 4 B (4%); liquidity 5 B (5%).
   Economically this changes nothing — it is a redenomination, and any document
   that calls it "more supply for holders" is wrong.

   **The carryover and validator figures in the original text of this item were
   provisional and are superseded.** The chain was still minting when they were
   written. Final, measured at the terminal snapshot (Genesis-3 height 39,918,
   452,726 outputs): **carryover 18,146,400,000 (18.15%)**, from a
   Genesis-3-side total of 3,810,744,000 — the two sides of the same split,
   the same coins; **validator emission 42,853,600,000 (42.85%)** over 40
   years; genesis issues **57,146,400,000**. Do not reuse 17,970,880,000 /
   17.97% or 43,029,120,000 / 43.03%, nor the earlier 3,773,884,800,
   3,805,746,000 or 18,122,600,000. And do not repeat the label "height
   43,172": 43,172 was a **block count** mislabelled as a height, and the total
   it went with is superseded.
2. **The cap becomes a consensus invariant**: every node refuses a block whose
   cumulative issuance would exceed the cap. No in-protocol mechanism can raise
   it — no vote, no key, no governance path. State the true strength of that
   claim and not a stronger one: a hard fork adopted by every operator can
   change any rule, and "impossible to change" is false. "No mechanism inside
   the protocol can change it" is true and is what an auditor will check.
3. **Validator bond ≈ Ethereum's, as a fraction of supply** — 32 ETH is 2.66e-7
   of ETH supply; the same fraction of the new 100 B lands near 25,000 BLCH,
   down from 100,000. It widens who *may* validate and does nothing about who
   *does*; do not let it be described as fixing concentration.
4. ~~**Genesis-3 halts at height 50,000, not 80,000**~~ — lowered from 80,000
   on 2026-08-12, and **that ceiling was never reached either**. Genesis-3 in
   fact stopped permanently at **height 39,918** on 2026-08-13, and the
   terminal snapshot was taken there. Terminal DAG block count was 50,690,
   which is not the 50,000 height ceiling and must not be read as one — height
   and block count are different measurements in a DAG. The coins between
   39,918 and the planned ceiling were never minted, which is why the carryover
   figure in item 1 is smaller than the provisional one and why there is
   nothing to burn: validator emission is the remainder of a fixed cap.

## What to produce

The deliverable is a **pre-audit dossier**: what an auditor asks for, answered
before they ask, with file:line evidence. Honest gaps listed as gaps. It is
better to hand CertiK a document that says "this is not implemented yet" than
to have them find it.

## Rules

- SPDX `AGPL-3.0-or-later` on new files.
- Never restate a constant — import it or cite the path.
- Measure, do not estimate. If you did not run it, say so.
- Public-facing text is in **English** (`official-language-english`).
- Commit your work in your worktree before you finish. Say what you did NOT do.
- Nothing in `~/dev/posternlabs-deploy` gets edited. Publishing is the founder's
  call, and this wave does not touch the site.
