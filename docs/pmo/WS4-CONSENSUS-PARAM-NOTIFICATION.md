# WS4 — Consensus-parameter change notification

The exchange found the epoch-800 payload-cap doubling **themselves**. We have no
notification channel.
Status: **DELIVERABLE BY 5 SEP — the most tractable of the four.** Both halves are
already built. Neither is merged. Both have the same known, bounded gap.

## The incident, precisely

`BLOCK_BYTES_V2_ACTIVATION_EPOCH = 800` — `crates/bloch-pos-committee/src/params.rs:308`.
Its own doc comment at `:291-307` **still says "`u64::MAX` until the founder sets
it."** The prose was never updated when the constant was armed. That is not a
footnote; it is the notification defect in miniature — the authoritative
description of the gate contradicted the gate, in the same file, and nobody
noticed until a third party did.

What moved, as one switch (`fee_market.rs:97-99` selects by epoch — splitting them
would make a 300 KiB block read as 2.3× over target):

| Constant | Before epoch 800 | At/after 800 |
| --- | ---: | ---: |
| `MAX_BLOCK_TX_BYTES` → `_V2` (`:65`, `:85`) | 262,144 | **524,288** |
| `BLOCK_TX_BYTES_TARGET` → `_V2` (`:76`, `:86`) | 131,072 | **262,144** |

A sibling gate fired at the same epoch: `TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH = 800`
(`params.rs:288`), which activated the TransferV2 wire tag `0x06`. **The exchange
found one of two simultaneous changes.** They may not know about the other.

Wall clock, pinned exactly (`params_feed.rs:386-413`): genesis
`1_786_656_679_962` ms = 2026-08-13 21:31:19.962 UTC; 30 s slots, 32 slots/epoch
= 16 min/epoch, ~90 epochs/day. **Epoch 800 = 2026-08-22 18:51:19.962 UTC** — the
test comment is emphatic that this is *not* 21 August. Epoch 1400
(`LEAKED_ROSTER`) = 2026-08-29 10:51:19.962 UTC.

Today the chain is at ~epoch 1599. **Both armed gates are in the past, and there
is no armed future flag day anywhere in the tree.** That is the single most
useful thing we can tell the exchange this week, and it is true today.

## What exists (merged)

`self_check()` — `crates/bloch-pos-node/src/main.rs:852-918`. It asserts domain-tag
distinctness, supply bounds, cohort caps, and `SLOT_DURATION_SECS == 30` /
`SLOTS_PER_EPOCH == 32`. **It says nothing about activation epochs.** No `--json`,
no `gates_digest`.

RPC exposes no consensus parameters at all. `chain_info_json` (`rpc.rs:1171`)
returns live chain state; `slots_per_epoch` is the **only** consensus constant an
integrator can read over the wire. There is no `getparams`, no `getgates`.

## Built but unmerged — both halves, independently

**Half 1 — the integrator's poll.** `agent-aeb2ec6de2cd89cbb` @ `858824ef`.
`crates/bloch-pos-committee/src/params_feed.rs` (443 lines). Its module doc names
the incident verbatim: *"On 2026-08-21/22 an exchange discovered on their own that
the block payload cap had doubled to 524,288 bytes at epoch 800."*

This is good work and should land close to as-is:
- `SCHEDULE: &[GatedChange]` with values **referenced** from `crate::params::…`,
  never copied — so the feed cannot drift from the constants it describes.
- `activation_unix_ms(...)` returns `None` for inert gates; `status_at(...)`
  returns `active`/`scheduled`/`inert`, binding at the activation epoch itself.
- `VERSIONED_CONST_ALLOWLIST` with mandatory non-empty reasons, and a test that
  catches a future `_V3` cap being added without an announcement.
- A tripwire that **scans every `.rs` under `src/` at runtime, in both
  directions** — it fails on an omitted gate *and* on a stale entry.
- RPC: `getconsensusschedule` (`rpc.rs:869`, handler `:1258-1325`), envelope
  `schema: "bloch-consensus-schedule/1"`, `before`/`after` as **decimal strings**
  so a u128 never passes through a double, sorted by activation epoch **so an
  arming diffs as one changed line**. Test at `rpc/tests.rs:474-500` asserts the
  reply neither drops nor invents a gate.

**Half 2 — the operator's binary identity.** `selfcheck --json` +
`consensus_gates_digest()`: SHA3-256 over `NAME=<epoch|inert>\n` lines **sorted by
name**, so the digest is a property of the gate *set*, not of declaration order.
Emits `gates_digest`, `knows_gates_through_epoch`, `compatibility_rule`.
Origin `agent-a26bcc84e23ca2e0e` @ `9071ebae`; also in `agent-adef9294360d01725`,
and in `40e22169` (`agent-ad3f0cc77273711fd` / `agent-testnet-deliver`).

**Half 3 — the calendar.** `agent-a5a0a10bb332b59ca` @ `249a192b`,
`docs/RELANCA-G4-DIAS-DE-BANDEIRA.md` §11 (line 928; table §11.1 at 986-1010).
Nine gates:

| # | Gate | Value | State |
| --- | --- | --- | --- |
| 1 | `TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH` | 800 | ARMED, past (2026-08-22) |
| 2 | `BLOCK_BYTES_V2_ACTIVATION_EPOCH` | 800 | ARMED, past (2026-08-22) |
| 3 | `LEAKED_ROSTER_ACTIVATION_EPOCH` | 1400 | ARMED, past (2026-08-29), rolled out |
| 4 | `ANCESTRY_SEED_ACTIVATION_EPOCH` | `u64::MAX` | INERT |
| 5 | `LEAK_RECOVERY_ACTIVATION_EPOCH` | `u64::MAX` | INERT |
| 6 | `VESTING_LOCK_ACTIVATION_EPOCH` | `u64::MAX` | INERT |
| 7 | `FUNDED_STAKING_ACTIVATION_EPOCH` | `u64::MAX` | INERT — `DepositV2` tag `0x07` |
| 8 | `SIGNED_EXIT_ACTIVATION_EPOCH` | `u64::MAX` | INERT |
| 9 | `WITHDRAWAL_ACTIVATION_EPOCH` | `u64::MAX` | INERT — `Withdraw` tag `0x08` |

Ordering `#7 → #9` and `#8 → #9` is enforced at **compile time** by
`const _: () = assert!` in `params.rs` (E0080 on violation). Good.

The `.activation.patch` is **deliberately unapplied and does not compile** — it
carries the literal placeholder `__E_STAR__`. It would arm **only #4 and #5**, at
one shared E\*. Nothing in it arms #6-#9. **The PMO does not apply it. Arming is
the founder's decision, and E\* must be strictly future at tag time and > 1400.**

## The gap — and it is the one the founder warned about

**Both halves scan only `crates/bloch-pos-committee/src/`.** They would ship
silent about every height-gated consensus constant outside that crate:

`AUXPOW_ACTIVATION_HEIGHT = 8500` (`bloch-crypto/src/core/mod.rs:22`, armed),
`EUVM_ACTIVATION_HEIGHT = 4320` (`bloch-euvm/src/harness.rs:52`, armed),
`DIFFICULTY_ANCESTRY_FORK_HEIGHT = 30_030`, `CANONICAL_K_ACTIVATION_HEIGHT = 40_320`,
`K_RULE_ACTIVATION_HEIGHT = 420_480`, `SHA256D_LE_FORK_HEIGHT = 2400`,
`EMISSION_V3_TAIL_ACTIVATION_EPOCH = 6`, `TAIL_ACTIVATION_HEIGHT`,
`CARRYOVER_MEASURED_HEIGHT = 39_918`.

**Union across the tree: 13 distinct gates a complete digest must cover. The best
existing digest covers 5.** Merging either half unwidened produces exactly the
artifact the founder called worse than none: a digest with gaps, which an
integrator will reasonably read as exhaustive.

Second, smaller gap: both halves carry the **677-line** pre-`SLASHING_EVIDENCE`
`params.rs`; mainline is 718 lines with 6 gates. The tripwire *will* fire on merge
— that is it working — but it proves the shipped table is incomplete on arrival.
`agent-a5a0a10bb332b59ca` adds four more on top (9 total).

Third: `DEPOSIT_FUNDING_ACTIVATION_EPOCH` (`agent-a67011fc80485b2b6`,
`agent-a087ea83a391a7f0a`) and `FUNDED_STAKING_ACTIVATION_EPOCH`
(`agent-a5a0a10bb332b59ca`, `signed-exit-wire`) are **two names for the same
gate.** A rename collision in the gate namespace — the same failure class as the
wire registry, one level up. **PMO assigns `FUNDED_STAKING_ACTIVATION_EPOCH` as
canonical** (it is the name in the §11 calendar and in the more advanced pair).

## Everything here is poll-only

No webhook, no feed URL, no signed announcement channel exists or is built. An
integrator who never polls still learns nothing. **For one exchange, a documented
poll plus an email from a human on every arming is sufficient and honest** — do
not build a notification bus for one partner. But say plainly that it is a poll,
so they schedule it.

## Honest date

**4 September, achievable, and it is the strongest thing we can hand this partner
by the deadline.**

1. Merge `params_feed.rs` + `getconsensusschedule` from `agent-aeb2ec6de2cd89cbb`
   (~0.5 day; the tripwire will flag the missing `SLASHING_EVIDENCE` entry and you
   add it).
2. **Widen both tripwires** to scan `bloch-crypto`, `bloch-euvm` and
   `bloch-pos-committee`, and to match `_ACTIVATION_HEIGHT` as well as
   `_ACTIVATION_EPOCH`. Add the 8 missing gates to `SCHEDULE`. **This is the
   critical step — do not merge without it** (~1 day).
3. Merge `selfcheck --json` + `gates_digest` from `agent-a26bcc84e23ca2e0e`
   (~0.5 day).
4. Resolve the `DEPOSIT_FUNDING`/`FUNDED_STAKING` rename before either lands.
5. Add `getconsensusschedule` to `docs/specs/BLOCH-RPC-V4.md` and to the explorer
   proxy allowlist at `apps/explorer/functions/rpc.js` (§7, `:393-402`) — **without
   this the method exists but is unreachable through the public proxy** (~0.5 day).
6. Fix the stale doc comment at `params.rs:291-307`. Five minutes, and it is the
   sentence that caused this.

**Send the exchange, this week, independent of any merge:** the two epoch-800
changes with exact UTC timestamps, the note that they found one of two, the
epoch-1400 change they have not mentioned, and the statement that no armed future
flag day exists today. That is a same-day email and it addresses the actual
complaint, which was not "you lack an RPC method" but "you changed consensus and
did not tell us."
