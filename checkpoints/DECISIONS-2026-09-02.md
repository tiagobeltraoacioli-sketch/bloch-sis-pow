<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Checkpoint ceremony — the decisions, and what 77 hours can buy

Written 2026-09-02, with the chain at epoch 1726 (finalized 1724, height
34,352) as reported identically by both keyless archivals.

**This is not a runbook.** The runbook exists and is good:
`docs/CHECKPOINT-RUNBOOK.md` on branch `converge/ws-tool`, 324 lines, written
for an operator who did not write the tool. Do not write a third one — this
repository has already been bitten once by two divergent copies of
`ws_tool.rs`, and the branch that converged them is named after the fact.
What follows is only what that runbook cannot decide.

---

## 1. The deadline, stated as arithmetic instead of a date

Slot geometry: 30-second slots, 32 slots per epoch → **one epoch = 16
minutes**, 90 epochs per day. Genesis-4 slot 0 was 2026-08-13 ~21:31 UTC.

```
WS_PERIOD_EPOCHS = WITHDRAWAL_DELAY_EPOCHS(2048) − EXIT_DELAY_EPOCHS(32) = 2016
                 = 22.4 days
```

A fresh install carries exactly one trust anchor: the release-baked **genesis
anchor** at epoch 0 (`ws::genesis_anchor`, signer-set id 0, no envelope). Its
age is therefore the wall epoch itself. `ws_boot::boot` admits a fresh node
while `anchor_age < WS_PERIOD_EPOCHS` and refuses otherwise:

| wall epoch | fresh install | why |
|---|---|---|
| ≤ 2015 | syncs | genesis anchor is 2015 epochs old — inside the window |
| **2016** | `ERR_WS_REQUIRE_CHECKPOINT` | the only anchor it has aged out |

Epoch 2016 begins **2026-09-05 07:07 UTC** — 77 hours from this writing. That
is the whole deadline. Nothing else changes at that instant.

Proven mechanically rather than asserted:
`crates/bloch-pos-node/src/ws_boot.rs`, test
`genesis_anchor_expires_at_epoch_2016_and_a_1536_checkpoint_moves_it_to_3552`.

### What it is, and what it is not

It is **an onboarding outage**, not a chain halt. Running nodes are
untouched — their own finality is their anchor. The 64-validator fleet does
not notice. What stops is: a new validator joining, an exchange building a
node from nothing, anyone verifying the chain without being handed a database.

It is **fully recoverable at any later date.** Publishing a signed checkpoint
on 2026-09-20 repairs cold start on 2026-09-20. Missing the date costs
credibility and the exchange integration; it costs nothing that cannot be
bought back by holding the ceremony late.

### One consequence worth flagging separately

`docs/integration/BLOCH-GENESIS4-EXCHANGE-INTEGRATION.md` §7 tells integrators
two things that stop being true at epoch 2016:

- *"Syncing from genesis is also supported."* It will not be.
- *"Copy `blocks.log`, `meta.bin` and `ws_latest.bin` from a current node's
  data directory and start."* This is the workaround that will keep working —
  and it is exactly the trust the checkpoint mechanism exists to replace. It
  hands the integrator a 202 MB unsigned tarball, `ws_latest.bin` (the trust
  anchor itself) included, and asks them to believe it. An exchange's security
  review will notice. That paragraph is the strongest argument for holding the
  ceremony, and it needs rewriting either way.

---

## 2. What 77 hours can actually buy

Three things must be true before any envelope verifies, and only one of them
is technical.

| Prerequisite | State today | Owner | Can it be done in 77 h? |
|---|---|---|---|
| The tooling exists and works | **Yes** — six subcommands, rehearsed | — | already true |
| A finalized artifact exists | **Yes** — epoch 1536, corroborated today by both archivals | — | already true |
| Three signers are **named** | **No.** A founder decision, not made | Founder | minutes |
| Signer keys **exist** | **No. Zero keys exist.** | each holder | minutes each, on their own machine |
| The **external** signature | Unscheduled | the audit firm | **unknown — not ours** |

The cryptography takes under a second. The ceremony is a 30-minute call. The
critical path is entirely one external party's calendar, and **every valid
Phase A quorum contains that party** — 2-of-3 with `min_external = 1` and only
one external seat means the auditor is not one of three interchangeable
signers, they are a mandatory signer with two interchangeable co-signers. The
client enforces this; there is no ceremony-side workaround.

**Therefore: the only action with a 77-hour clock on it is contacting the
auditor.** Everything else on the list can be done in an afternoon and can be
done after they answer. If the auditor cannot sign by 2026-09-04, the deadline
is missed no matter what else happens, and the decision moves to §4.

### The shortest honest path

1. **Now (T+0h).** Name the three holders. Send the auditor one message: a
   154-byte file, a 64-hex digest, a link to §3 of the runbook, and a request
   for a 30-minute slot before 2026-09-04 18:00 UTC. This is the only step
   with a deadline.
2. **T+0h.** All three run `ws-keygen` on their own machines and send the
   coordinator their `.pk`. Independent of step 1; do it while waiting.
3. **T+0h.** Coordinator assembles `signer-set-1.bin` (see §3 for
   `--adopted-epoch`) and publishes the arrangement table with the key order.
4. **T+18h or now.** Mint the checkpoint. Epoch **1536** is already minted and
   reproducible today. Epoch **1792** finalizes ~2026-09-02 20:00 UTC and is
   worth waiting for only if the ceremony is not the bottleneck — it buys three
   extra days (cliff 2026-09-25 instead of 2026-09-22) and costs 18 hours of
   the 77. Given that the cadence requires a new checkpoint every 2.84 days
   regardless, **take 1536 and do not wait.**
5. **When the auditor is available.** 30 minutes: three signers re-derive,
   sign, return `.sig`. Coordinator assembles, verifies, publishes on two
   channels.

---

## 3. `--adopted-epoch` — the open decision, resolved

### What it does

It is the **zero of the arrangement's review clock**, and nothing else. From
it `ws::SignerSet` derives two epochs:

```
review_deadline = adopted_epoch + 32_850    (365 days × 90 epochs/day)
hard_stop       = review_deadline + 8_190   (+ 91 days of grace)
```

Both are compared against **the checkpoint's epoch**, never against wall-clock
time — so the judgement is identical on every machine:

- `cp.epoch > review_deadline` → still `VALID`, plus a loud warning that the
  §6.3 review ADR is overdue;
- `cp.epoch > hard_stop` → **`ArrangementExpired`**, refused. Fresh sync
  degrades until governance adopts a new arrangement under a new id. Nodes
  already running are unaffected.

### The recommendation: `--adopted-epoch 0`

`BLOCH-WEAK-SUBJECTIVITY.md` §6.3 already says, in published prose, that the
first review falls *"12 months after Genesis-4 launch"*. Genesis-4 launched at
epoch 0. Only `0` makes the code agree with that sentence, and it lands the
review on **2027-08-13** — the date already on the record elsewhere in this
project. It costs the arrangement the ~20 days between launch and adoption,
out of 456. That is the correct direction in which to be wrong: the switch
fires slightly early rather than slightly late.

### The alternatives, and what each breaks

| Value | Review due | Hard stop | The case against |
|---|---|---|---|
| **`0`** *(recommended)* | epoch 32,850 — **2027-08-13** | 41,040 — 2027-11-12 | ~20 days of the arrangement's life given away |
| `1536` (first signed checkpoint) | 34,386 — 2027-08-30 | 42,576 — 2027-11-29 | makes the governance calendar a function of an operational accident |
| `~1792` (actual adoption) | ~34,642 — 2027-09-01 | ~42,832 — 2027-11-29 | most honest about when the keys existed, but requires correcting the published spec sentence and the announced date in the same breath. Two clocks that disagree is the exact failure this field exists to prevent |
| any future epoch | later | later | see below |

### The failure mode nothing refuses

Nothing in `ws-signer-set`, in `encode_signer_set_file`, or in
`decode_signer_set_file` requires `adopted_epoch` to be in the past, or to be
plausible at all. `hard_stop()` uses `saturating_add`, so an `adopted_epoch`
anywhere near `u64::MAX` produces a hard stop of `u64::MAX` and **silently
disables the dead-man's switch for the life of the arrangement** — precisely
the "review becomes permanent by inertia" outcome §6.3 was written to prevent.
One mistyped flag does it, and no tool says a word.

Mitigation, and it costs nothing: `ws-verify` prints `adopted at epoch`,
`review due` and `hard stop` on every run. **Read those three lines back out
of the assembled file before publishing, and put them in the announcement.**

### One property to know before an adversary explains it to you

Because the comparison is `cp.epoch > hard_stop`, an **old** envelope still
verifies after the hard stop. The switch prevents the arrangement from signing
*new* checkpoints that verify; it does not retroactively invalidate what it
already signed. Anti-rollback (`ws::accept`) and the freshness window are what
bound an old envelope's usefulness — not the review clock.

---

## 3b. The second out-of-band artifact nobody has named yet

The spec (§6.3) says the arrangement is *"hard-coded in the client alongside
the signer pubkeys"*. It is not, in any binary that exists today.
`ws_boot::boot` says so out loud: *"this devnet build bakes no Phase A keys,
so pass `--ws-signer-set <file>`"*. So a consumer needs **two** files, and
only one of them has a published 64-hex digest.

That means `signer-set-1.bin` is itself an unauthenticated download: an
attacker who can substitute it can substitute the keys, and then any envelope
they sign verifies. The checkpoint digest does not protect it — nothing in the
checkpoint commits to the arrangement beyond its integer id.

Two ways to close it, and the announcement needs one of them:

1. **Cheap, available today:** publish `sha3-256(signer-set-1.bin)` on the
   same two independent channels as the ws digest, and put both hashes in the
   same announcement. Sixty-four more hex characters.
2. **Correct, needs a release:** bake the arrangement into the client, as §6.3
   already says it should be, and demote the file to a test fixture.

Do (1) now; schedule (2). Publishing the envelope with an unauthenticated
signer set would leave the whole ceremony resting on a file transfer.

---

## 4. Degraded variants, priced without discount

If the auditor cannot sign in time, these are the options and there are no
others.

**(1) Publish nothing.** Cold start breaks at epoch 2016 and stays broken
until a real ceremony happens. Running nodes and the fleet are untouched. The
exchange integration does not reach production. Repairable at any later date
at no extra cost beyond the delay itself.

**(2) Publish a 2-of-2 internal set under a new id.** This *works*
mechanically — `ws-signer-set` will print `MATCHES NEITHER §6.1 PHASE`, and
`ws-verify` will still say `VALID`, because the set you built is the set you
verify against. Be precise about what it buys:

- **It does protect against:** a corrupted or substituted release artifact, a
  mistyped digest, an operator serving the wrong file, and the compromise of
  any *single* key — an attacker who takes the Foundation's key alone cannot
  publish, because Postern's key is on other premises with other people.
- **It does not protect against:** the Foundation and Postern Labs agreeing.
  They are one social cluster under one founder. That is the entire attack
  rule 4 exists to stop, and a 2-of-2 internal set does not stop it. A
  newcomer syncing under it is trusting Postern Labs, full stop — which is a
  defensible thing to ask, but only if it is what you say out loud.

**(3) Publish (2), labelled as what it is.** Same bytes; announced as an
interim internal-only anchor, with the external seat named as empty and a date
by which it will be filled. An exchange evaluating custody can then see
exactly what they are being asked to trust, and decline if they want to.

**The founder's call is between (1) and (3).** Do not take (2) — publishing an
internal-only set silently, under `signer_set_id = 1`, would be worse than
publishing nothing, because it would look like the arrangement that was
promised.

---

## 5. Decisions, with dates

| # | Decision | Owner | By |
|---|---|---|---|
| 1 | Name the three Phase A holders; confirm the external seat is a genuinely separate organisation | Founder | **2026-09-02 EOD** |
| 2 | Contact the auditor and get a signing slot | Founder | **2026-09-02 EOD** — this is the only step on the 77-hour clock |
| 3 | `--adopted-epoch` = `0` unless the spec sentence is being changed at the same time | Founder | before §3 of the runbook is run |
| 4 | Sign epoch 1536 now rather than waiting 18 h for 1792 | Coordinator | at the ceremony |
| 5 | If the auditor cannot sign by 2026-09-04: variant (1) or (3), never (2) | Founder | **2026-09-04 18:00 UTC** |
| 6 | Land `converge/ws-tool` (tool + runbook) and the `ws-publisher` worktree on `main` | PMO | before the ceremony, so what is rehearsed is what ships |
| 7 | Rewrite `BLOCH-GENESIS4-EXCHANGE-INTEGRATION.md` §7 — "syncing from genesis is also supported" expires at epoch 2016 | PMO | 2026-09-05 |
| 8 | Publish a digest for `signer-set-1.bin` too (§3b), and schedule baking the arrangement into the client | Coordinator / PMO | with the announcement |

---

## 6. Rehearse before convening humans

```
./scripts/ws-ceremony-drill.sh /path/to/bloch-pos
```

Generates three disposable keys, runs the whole ceremony against the live
epoch-1536 artifact, and then makes the verifier refuse a dozen dishonest
envelopes — each one **forged by byte surgery outside the toolchain**, because
a drill in which the tool only refuses to hurt itself proves nothing about an
attacker. Two read-only RPC calls; no production key; nothing written outside
its workdir.

Run it on the exact binary the ceremony will use. A green drill on a different
build is a claim about a different binary.

Measured 2026-09-02: **25 passed / 0 failed** on the `converge/ws-tool` build
(hardened assembler gate), **19 / 0** on the `7c311b04` build (no assembler
gate — section 3 skips itself and says so). Both re-minted epoch 1536 from the
two archivals byte-identically to the committed artifact, digest
`a5d047674074251c7a2031266ac2a3c7e05a82960959ffef847bb4291e744e44`.

### One result worth reading twice

```
FRESHNESS  epoch 1536 vs now 3600: age 2064 of 2016 epochs — EXPIRED
VERDICT: ACCEPTED by ws::verify_envelope.
```

**A green `VERDICT` is not a usable checkpoint.** Signature validity and
freshness are two independent gates: `ws::verify_envelope` has no clock by
design (§2.1 — no expiry field, so the artifact verifies identically on every
machine), and the window is enforced at `ws_boot::boot`. An operator who reads
only the `VERDICT:` line will hand an exchange an expired anchor and be
surprised when the node refuses to start. The `FRESHNESS` line is the one that
decides usability, and it only appears when `--rpc` or `--now-epoch` is passed.
Pass it, always.
