# WS2 — Hosted testnet + faucet

Purpose: let a third party exercise the deposit/spend/withdraw path without
mainnet funds.
Status: **NOT DELIVERABLE BY 5 SEP as a partner-ready rehearsal environment.**
Fully designed and scripted, **zero percent deployed, one hundred percent
unmerged**, and it carries two defects that would break a partner on first
contact.

## The hard constraint: VERIFIED CLEAN

**Never seed a testnet from the mainnet carryover.** Confirmed satisfied, by
construction rather than by discipline:

- `deploy/testnet/hosted-testnet-up.sh` — *"NO carryover, ever (this script has
  no flag for it); every key is generated fresh ON THIS HOST by this script."*
  Genesis is `genesis --keys <fresh> --alloc "$FAUCET_SH:$FAUCET_ALLOC_SAT"`.
- `local-testnet-up.sh` — *"ingests NO mainnet carryover."*
- The unmerged `genesis --alloc` path sets `carryover: None`,
  `carryover_entries: Vec::new()`.
- A grep of the entire `40e22169` delivery diff for `carryover` returns only
  these negative assertions and the `None` initializers.
- The only carryover consumers — `tools/genesis4-carryover/build_carryover.py`
  and `tools/genesis4-ceremony/` — are mainnet-only and untouched by any testnet
  script.

`HOSTED-TESTNET.md` §0 rule 1 states the threat model correctly and
independently. **No plan reuses carryover data. Nothing here is rejected on
sight.**

Note also: `tools/genesis4-ceremony` **cannot** produce a testnet genesis even if
someone tried — `--carryover` and `--carryover-shake256` are mandatory args, it
refuses any total but 17,970,880,000 BLCH, and it has no faucet-allocation
concept. The constraint is enforced by the tool's own argument parser.

## The premise, confirmed

`spend_signing_root` (`crates/bloch-pos-committee/src/transition.rs:474-532`)
hashes `DS_SPEND ‖ n_spends ‖ [txid‖vout]* ‖ n_outputs ‖ [value‖script_hash]* ‖
tx_bytes ‖ tip`. `DS_SPEND = b"BLCH4:SPEND\0\0\0\0\0"` separates **message
types, not networks** — it is byte-identical in all 56 worktrees that carry it.
**No worktree adds a chain id.** Outpoint disjointness is the only defence, which
is exactly why the carryover rule is absolute.

Worth recording: the codebase already knows this concept and applied it
elsewhere. `crates/bloch-pos-committee/src/ws.rs:215` carries
`network_id: u32 = 0x0004_0001` with `CheckpointReject` on mismatch and the
comment *"a testnet checkpoint must be unusable on mainnet."* Weak-subjectivity
checkpoints are domain-separated by network; spends are not. **PMO recommends
adding a network id to `spend_signing_root` as a post-deadline hardening item** —
it would convert this from a procedural rule that a future agent can forget into
an invariant the code enforces. It is a hard fork and must ship `u64::MAX`-gated.

## What exists (merged)

The read surface an exchange needs: `getutxos`, `listunspent`, `gettxout`,
`getbalance`, `sendrawtransaction` (`crates/bloch-pos-node/src/rpc.rs:862-895`).
`spend_signing_root` + `DS_SPEND`. `admissible()` staking refusals
(`engine.rs:3283-3310`).

**`deploy/testnet/` does not exist in the merged tree at all.**

## Built but unmerged

| Work | Where | Note |
| --- | --- | --- |
| The whole hosted-testnet bundle — 11 files, 1,298 insertions: `HOSTED-TESTNET.md`, `ONBOARDING-PARTNER.md`, `hosted-testnet-up.sh`, `local-testnet-up.sh`, `local-testnet-restart.sh`, `faucet-drip.sh`, `t4-health.sh`, `nginx-t4rpc.conf`, systemd unit + timer | `40e22169` on `agent/testnet-deliver`, `integ/validator-opening`; also `agent-ad531a8ccfff9329a` @ `13b51672` (superset) | Target host chosen and verified: node4 `136.244.82.226` (Edgevana, zero G4 validators). Endpoint `t4rpc.posternlabs.com` behind cloudflared, 4 upstreams `127.0.0.1:18500-18503` with failover. Its own status line: **"plan + scripts, not yet deployed."** The local 4-validator variant *has* run and finalized. |
| **The CLI seam** — `spendkey`, `genesis --alloc`, `submit-tx --raw` (163 lines of `main.rs`) | same commit | **Merged `main.rs` has none of the three. Without them the testnet cannot be created or spent on at all.** This is the critical-path merge. |
| `crates/bloch-withdraw` — 2,578 LOC: idempotent create/tick state machine, coin pinning before signing, fee-move rebuild over pinned coins, conflicting-sweep cancellation, finality-boundary crediting, 8-test race suite, `DOUBLE-PAYMENT-RACE.md` | `agent-a101bfb4ec149a897` @ `61f82dc0` | Serious work. See defect A. |
| `tools/spend-runbook` (566 LOC) | `agent-ae11cce07854da4e6` @ `6a95830c` | Mounts the node's own `codec.rs`/`keys.rs`/`genesis.rs` via `#[path]` so formats cannot drift. Deliberately does not broadcast. |
| `tools/partner-send` (1,782 LOC + `verify_receipt.py`) | `agent-a6dd9e3aeb299f61f` @ `d3211c0a` | Attended-only: 10,000 BLCH cap, dust floor, typed-phrase confirmation that refuses pipes and cron. |
| `DepositV2` (tag `0x07`) + `Withdraw` (tag `0x08`) wire format, signed exits, node admission | `signed-exit-wire` @ `65e7e61a`, `agent-a5a0a10bb332b59ca` @ `249a192b` | `WITHDRAWAL_ACTIVATION_EPOCH = u64::MAX` (`params.rs:385`) — correctly inert, no flag day chosen. |

## "Saque inexistente" — half right, and the halves matter

- **Refuted for exchange payouts.** `crates/bloch-withdraw` is a real, tested
  withdrawal client.
- **Confirmed for staking bonds.** Merged `PosTransaction` has only `Transfer`,
  `TransferV2`, `Deposit`, `Exit`, `Delegate` — **no `Withdraw` variant exists in
  the merged tree**, and `admissible()` refuses `Deposit`/`Delegate`/`Exit`
  outright. Four worktrees add one; the two most advanced also add `DepositV2`.
  All are inert behind `u64::MAX`.

Update the memory note accordingly: the exchange-payout path is built; the
staking-bond withdrawal is built-but-inert and needs a founder flag day.

## Two defects that would break a partner on day one

**A. `bloch-withdraw` cannot run on this testnet.**
`crates/bloch-withdraw/src/address.rs:44-46` hard-refuses non-mainnet addresses:
`if !addr.is_mainnet() { return Err("not a mainnet (bloch1q…) address") }`.
The one real withdrawal client an exchange would integrate is **unusable on the
very testnet built for exchanges to rehearse withdrawals.** Direct contradiction
of the workstream goal.

**B. Two incompatible `script_hash` forms across the deliverables.**
`address.rs:11-20` documents that consensus accepts both `SHA3-256(pubkey)` (full
32 bytes) and the address-derived form (20 bytes zero-padded to 32) — and that
**"the two forms are DIFFERENT keys in the eUTXO set: `getbalance` on one does
not see coins locked under the other."**
`faucet-drip.sh` and `ONBOARDING-PARTNER.md` use the **full 32-byte** form from
`spendkey`. `bloch-withdraw` and `partner-send` use the **20-byte address** form.
A partner funded by the faucet and then running `bloch-withdraw` queries a script
hash with a zero balance and sees nothing — a silent, self-inflicted "your
testnet is broken" report. **One form must be chosen before any partner touches
it.** This is a decision, not a bug fix, and it is small — but it is on the
critical path.

## The faucet

`faucet-drip.sh` is a **101-line operator shell script**, not a service: SSH in,
`getutxos → submit-tx --raw → spendkey --sign → submit-tx`. Real fee arithmetic
(gas = 5000 + bytes×16 + 72748; refuses if base fee ≠ floor 10), single-UTXO
discipline, waits for landing. No HTTP, no rate limit, no queue.
`HOSTED-TESTNET.md` §5 owns that choice explicitly and argues single-digit
partner count justifies it. **For one exchange, that argument holds.**

The only HTTP faucet in the repo, `tools/faucet/` (TypeScript), is **merged but
Genesis-3** — `bloch1t…` bech32, `validateaddress`, G3 tx format — and its own
README calls it *"SCAFFOLD / reference tool. Unaudited… never validated
end-to-end against a live network."* Unusable on G4, and no worktree contains a
rewrite. **A self-service faucet does not exist and is not built.** Do not
promise one.

## Honest date

`HOSTED-TESTNET.md` §9 promises partner-ready **2026-09-04**, on a schedule that
starts 2026-09-01. Today is 31 August and **nothing is merged** — that schedule
assumes the merge lands today and that neither defect above exists. Both
assumptions are false.

**Realistic: 9–11 September**, decomposed:
- merge `40e22169` (the CLI seam is the blocker; without `spendkey`,
  `genesis --alloc`, `submit-tx --raw` nothing else can run) — 1 day
- decide the `script_hash` form and align the four consumers — 1 day, mostly
  decision latency
- fix `bloch-withdraw`'s mainnet-only address refusal — 0.5 day
- deploy to node4 (cloudflared is not even installed on the box) — 1–2 days,
  **founder-authorised fleet work**
- one real end-to-end rehearsal by us before a partner sees it — 1 day

**What is achievable by 5 Sep:** a *local* testnet the exchange runs themselves
from `local-testnet-up.sh` — that variant has actually run and finalized. It
gives them the spend path without mainnet funds, which is the stated purpose,
without waiting on deployment or on node4. **Offer this as the 5 Sep deliverable
and the hosted endpoint as the follow-on.** It is a smaller promise that is
actually true.
