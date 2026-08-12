<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Fleet brief — CertiK audit readiness, 2026-08-12

Read this before starting. Read `docs/FLEET-BRIEF-2026-08-11.md` too — the
settled facts there still hold.

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
attention flag at 39.28%. Bloch's founder holds ~94% of the carried-over supply
(`bloch-supply-concentration` measurements; `BLOCH-TOKENOMICS-V4.md` §4A), and
if that balance is staked — it is stakeable, decided 2026-08-11 — it is ~94% of
active stake, with a Nakamoto coefficient of 1. There is no framing that makes
this pass. **Do not try to find one.** The deliverable on this point is: the
exact number, measured; the mechanisms that bound it (the genesis-cohort
declining cap, the 25 bps churn rate, the per-validator 1% cap); what each of
those does and does not reach; and the arithmetic in `BLOCH-TOKENOMICS-V4.md`
§4A.1 showing G1 is unreachable by emission alone. An auditor who finds you
softened this finds everything else suspect.

## Decisions taken the same day — build against these, not against the repo

The repo will still say 21 B when you start; the change lands in parallel with
this wave. Work from these numbers and flag anything you find that contradicts
them.

1. **Total supply 21 B → 100,000,000,000**, as a **pure split (×4.7619)**: every
   bucket scales, every percentage is unchanged, nobody is diluted. Carryover
   3,773,884,800 → 17,970,880,000 (17.97%); founder 2.1 B → 10 B (10%);
   VC/team likewise; marketing 4 B (4%); liquidity 5 B (5%); validators
   9,036,115,200 → 43,029,120,000 (43.03%). Economically this changes nothing —
   it is a redenomination, and any document that calls it "more supply for
   holders" is wrong.
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
4. **Genesis-3 halts at height 50,000, not 80,000** (lowered 2026-08-12,
   ~4.4 days out). The snapshot is taken there.

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
