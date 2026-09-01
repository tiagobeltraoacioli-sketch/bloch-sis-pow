# Integration notes — staking-cli and the three staking work streams

Written 2026-08-31, alongside the tool. `bloch-stake` compiles against a
`bloch-pos-committee` that contains ALL THREE staking work streams:

- **funded deposit** (`DepositV2`, tag `0x07`) — branch
  `worktree-agent-a087ea83a391a7f0a`;
- **signed exit + consensus closure of the legacy tags** — branch
  `worktree-agent-a1315f5708e6838b1`;
- **withdrawal crank** (`Withdraw`) — branch
  `worktree-agent-a9c4ba491715890b9`.

All three branch from the same base commit
(`e4083f9684f283af35e6b4a7ff68507b16d9d45f`) and touch the same five files
(`params.rs`, `staking.rs`, `transition.rs`, node `engine.rs`, node
`rpc.rs`). They were merged three-way for this tool's build and tests; the
merge surfaced SEVEN integration facts the stream owners must ratify before
any of these formats is armed:

## 1. WIRE-TAG COLLISION: `DepositV2` and `Withdraw` both shipped as `0x07`

The deposit stream assigned tag `0x07` to `DepositV2`; the withdraw stream
independently assigned tag `0x07` to `Withdraw` ("0x05 burned by evidence,
0x06 by TransferV2 — take the next"). One binary cannot carry both.

**Resolution taken in the merge: `Withdraw` renumbered to `0x08`**, on the
grounds that the funded-format stream owns the funded wire shapes and its
`0x07` is referenced throughout its docs and tests. Both formats are inert
(`u64::MAX` flag days), so no wire bytes exist under either number and the
renumber is free TODAY. It stops being free the moment a flag day is armed.
The owners must ratify (or reverse) this number explicitly.

## 2. `apply_transaction`'s cap parameter came back

The exit stream renamed `total_active_sat` to `_total_active_sat` (its
merge retired the legacy arms that read it). The deposit stream's
`DepositV2` arm reads it again (the per-validator cap). The merge restores
the name and trims the "unused, kept deliberately" comment.

## 3. The legacy arms' `free` charge binding

The withdraw stream's `Withdraw` arm returned the legacy arms' shared
`let free = TxCharge{0,…}` binding; the exit stream's rewrite removed that
binding along with the legacy arms. The merge inlines a zero `TxCharge` in
the `Withdraw` arm (the crank charges nothing at this layer, per its own
docs).

## 4. `deposit_cap_sat` made `pub`

`transition::deposit_cap_sat` (1% of committed active stake, floored at
`MIN_DEPOSIT_SAT`) was private. The client must price a bond against the
SAME derivation — a restated fold in a wallet is a drift waiting to be a
rejected deposit — so the merge makes it `pub` (visibility only).

## 5. The closure vs the one-switch retirement (test expectations)

The deposit stream designed "one switch": the legacy unfunded `Deposit`
keeps applying until `DEPOSIT_FUNDING_ACTIVATION_EPOCH`, which arms the
funded format AND retires the unfunded one. The exit stream's 2026-08-31
closure rejects the legacy staking encodings at EVERY epoch, immediately —
the insider mint does not wait for a flag day. **The closure wins in the
merge** (it is the security fix, and it is strictly tighter). Consequences:

- the deposit stream's retirement gate inside the legacy `Deposit` arm was
  dropped with the arm itself (a1315's reject arm replaces it);
- its flag-day test now pins `StakingNotActive` for the unfunded shape on
  BOTH sides of the switch (rewritten in place, with the history in its doc
  comment).

## 6. Withdraw-stream test fixtures exited through the dead arm

The withdraw stream's fixtures (`exited_payable`, the leak test, the
malformed-credentials test) retired validators via
`apply_transaction(PosTransaction::Exit { .. })` — the arm the closure
rejects. The merge adds a test-mod helper `exit_directly` that performs the
retired arm's two clock writes (`exit_epoch = epoch + EXIT_DELAY_EPOCHS`,
`withdrawable_epoch = exit + WITHDRAWAL_DELAY_EPOCHS`) on the record
directly — the fixtures test the state an exit leaves behind, not exit
authorisation.

## 7. The exit stream's replay-precondition scanner predates the new tags

`bloch-pos-node/src/store.rs`'s scanner (reads a real `blocks.log` through
the real decoder and fails on any staking-tagged block) matches the
transaction enum exhaustively; the merge adds the `DepositV2 => 0x07` and
`Withdraw => 0x08` arms it could not have known about.

Also merged without conflict but worth knowing: the two streams restate the
suite envelope differently (`SUITE_FRAME_MAGIC`/`parse_framed_pubkey` in
the deposit stream, `SUITE_ENVELOPE_HYBRID`/`committed_hybrid_body` in the
exit stream). Both survive the merge and both are pinned against
bloch-crypto by node tests; they should probably be unified into one
statement when the streams land.

## What the tool could and could not build

- **deposit**: complete (the format is complete).
- **withdraw**: complete (given the tag resolution above).
- **exit**: the SEMANTIC format is complete (`staking::ExitTx`, signing
  root, verification against the registered key) and the tool plans/signs
  it — but **no `PosTransaction` variant carries an `ExitTx`**, so there is
  nothing to broadcast. `exit broadcast` refuses with exactly this
  explanation. The carrier variant is the single missing piece between
  "signed exit exists" and "signed exit reaches a block".
- **delegate**: only the state seam exists
  (`CommittedState::apply_delegation(delegator, validator, amount)`);
  the funded wire format — outputs bonded, delegator authorisation — exists
  in no stream. The subcommand refuses and says so. Designing that format
  belongs to the consensus stream, not to a wallet.

## The `bloch-withdraw` question, settled by measurement (2026-08-31)

`crates/bloch-withdraw` (3,344 lines, worktree `agent-a101bfb4ec149a897`, on
no branch, in no status report) was suspected of duplicating this tool's
`withdraw` subcommand. **It does not. They share a word and nothing else.**

The measurement, on each crate's own tree:

| | `tools/staking-cli` (`bloch-stake withdraw`) | `crates/bloch-withdraw` |
|---|---|---|
| transaction built | `PosTransaction::Withdraw` (wire tag `0x08`) | `Transfer` / `TransferV2` (tags `0x01`/`0x06`) |
| what "withdraw" means | return an exited validator's bond to its deposit-time credentials | pay an exchange customer out of a hot wallet |
| occurrences of `PosTransaction::Withdraw`, `withdrawable_epoch`, `exit_epoch`, `validator`, `staked_sat`, `DepositV2` | the subject matter | **0, 0, 0, 0, 0, 0** |
| occurrences of `TransferV2`, `idempot*`, `resubmit`, `sweep`, `cancel`, `finalized` | **0, 0, 0, 0, 0, 0** | the subject matter |
| tests | 25 → **27** passing | 30 passing (22 lib + 8 race) |

Both suites are green. Neither supersedes the other, and deleting either
would destroy working, tested, non-duplicated work.

The deeper reason they cannot merge: the staking crank does not have the
problem `bloch-withdraw` exists to solve. That crate closes a double-payment
race for transfers, which are fee-priced, input-pinned and silently dropped
from the mempool. The staking crank has no inputs, no change and no fee, and
consensus makes it at-most-once itself — the `Withdraw` arm sets
`withdrawable_epoch = u64::MAX` on payout, and that reset IS the committed
withdraw-once marker. Client-side idempotency machinery would be dead code.

**Actions taken instead of a deletion:**

1. `bloch-withdraw` preserved on branch `wt/exchange-payout-client` (commit
   `61f82dc0`). It was on no branch; that invisibility, not duplication, is
   what made it look like a duplicate.
2. Both the runbook and this file now state the distinction, so the next
   agent asked for "a withdrawal client" has to say which one it means.

Adjacent finding, not acted on: `crates/bloch-withdraw`, `tools/partner-send`
and `tools/spend-runbook` all build a `Transfer`. They are not duplicates
either — `partner-send` is attended, capped and refuses a non-terminal, while
`bloch-withdraw` is explicitly unattended — but that family is where a fourth
tool would actually be redundant. Worth a PMO sweep.

## PMO CLAIM PENDING — wire registry §1, tag `0x08`

`docs/WIRE-NAMESPACE-REGISTRY.md` (branch `pmo/wire-namespace-registry`)
records tag `0x08` `Withdraw` as **"Frozen by `crates/bloch-withdraw/tests/
race.rs`"**. That is false: race.rs freezes the double-payment schedule for
transfers and never emits tag `0x08`. Consequence, verified by grep over
`wt/signed-exit-wire`: **no test anywhere froze `0x07` or `0x08`.** The
registry believed a freeze existed that did not.

No new number is requested — the C-4 resolution (`0x07 = DepositV2`,
`0x08 = Withdraw`) stands and is what this branch encodes. Two edits claimed:

- §1 row `0x08`, Owner: `withdraw` → `staking`.
- §1 rows `0x07` and `0x08`, Frozen by: `tools/staking-cli/src/tests.rs::`
  `wire_tags_are_frozen_0x07_deposit_v2_and_0x08_withdraw` (added here). It
  asserts the leading canonical byte of a signed `DepositV2` is `0x07` and of
  a `Withdraw` is `0x08`, that the two differ, and that `Withdraw`
  round-trips through the real decoder.

No PMO agent was reachable when this was written; the claim is recorded here
for ratification.

## Landing checklist

1. Land the three branches (the 3-way merge is mechanical except for the
   four points above; a1315's consensus-reject arms and a087's `DepositV2`
   arm interleave cleanly in `apply_transaction`).
2. Ratify the `Withdraw = 0x08` tag (point 1) BEFORE arming any flag day.
3. ~~Add `"tools/staking-cli"` to the root `Cargo.toml` `members`~~ — **DONE**
   on `wt/withdraw-refusals`, together with the two consensus-side fixes the
   build actually required on `wt/signed-exit-wire`:
   `transition::deposit_cap_sat` made `pub` (visibility only, point 4 above),
   and `StakingFormat::DepositV2` re-pointed from the retired
   `DEPOSIT_FUNDING_ACTIVATION_EPOCH` to `FUNDED_STAKING_ACTIVATION_EPOCH`,
   which is what `deposit_funding_active` reads ("ONE constant for the whole
   feature"). The old name is now pinned by assertion in the gate test, so a
   refusal can never again name a constant the codebase does not have.
4. `cargo test -p bloch-pos-committee -p bloch-staking-cli` — the merged
   consensus suite plus this tool's round-trips and refusals.
5. When the exit carrier variant lands, wire `exit broadcast` (the
   plan/sign artifacts and checks are already carrier-agnostic).
6. When the funded-delegation format lands, give `delegate` its
   plan/sign/broadcast flow.

## Why this crate is not yet in the root workspace

`tools/staking-cli` is deliberately NOT listed in the repo root
`Cargo.toml` `members` today: it compiles only against a
`bloch-pos-committee` that carries the three staking work streams, and
`main` carries none of them (`PosTransaction` there has no `DepositV2` and
no `Withdraw`). Adding it now would break `cargo build --workspace` on
`main`. It is step 3 of the landing checklist above, to be done in the same
commit that lands the streams — the workspace's own rule ("if you add a
crate, add it to members — do not give it a private workspace") applies from
that moment on.

## Test status of the merged tree (2026-08-31)

- `bloch-staking-cli`: **25 passed, 0 failed**.
- `bloch-pos-node`: **127 passed, 0 failed** (11 ignored) — includes the
  cold-node genesis rebuild.
- `bloch-pos-committee`: **306 passed, 5 failed**. The five failures are all
  in `prova.rs`, the relaunch proof harness, and they are **PRE-EXISTING on
  the source branches, not products of this merge**: the identical five
  failures with identical assertion messages reproduce in the unmerged
  `worktree-agent-a087ea83a391a7f0a` (`cargo test -p bloch-pos-committee
  prova::` → `4 passed; 5 failed`).

  They are also self-describing: `s1_disease…` asserts that two nodes
  DIVERGE and reports "different zero-sets produced the SAME step-8
  partition"; the mutation partners report "MUTATION DID NOT BITE". That is
  the signature of the harness's own defect (`committees::epoch_committees`
  filtering `effective_stake > 0` before its Fisher-Yates shuffle) having
  been FIXED upstream, leaving the harness measuring a disease that is no
  longer there. `committees.rs` is untouched by all three staking streams,
  so nothing in this work can have caused or cured it. Whoever owns the
  relaunch proof should retire or re-point the harness; it is not a staking
  blocker.
