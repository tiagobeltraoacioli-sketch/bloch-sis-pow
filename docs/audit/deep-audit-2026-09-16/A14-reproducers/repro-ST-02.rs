// SPDX-License-Identifier: AGPL-3.0-or-later
//
// ST-02 reproduction — legacy unauthenticated `Exit` (wire 0x03) is live and
// un-capped on mainnet today: one scheduled proposer can retire the whole
// roster (or everyone but itself) in a single block.
//
// HOW TO RUN (not run by the reviewer — build lock held):
//   Paste both functions into `crates/bloch-pos-committee/src/transition.rs`
//   inside `mod tests`, next to `exit_schedules_duty_stop_and_withdrawal_delay`
//   (~line 10775). They use only that module's existing fixtures:
//   `setup(n)` (:6841), `build_block` (:7068), `OkVerifier` (:6391) and the
//   private accessors the sibling tests already call (`validator_record`,
//   `active_validators`, `consensus_roster_at`, `seed_for_epoch`,
//   `close_epoch`, `voluntary_exits_this_epoch`, `apply_transaction`).
//   Then: cargo test -p bloch-pos-committee --lib \
//           st02_one_proposer_can_force_exit -- --nocapture
//
// No rehearsal guard is taken: the point is that the DEFAULT gates
// (`EXIT_AUTH_ACTIVATION_EPOCH == u64::MAX`,
// `FUNDED_VALIDATOR_ADMISSION_ACTIVATION_EPOCH == u64::MAX`) leave the arm
// reachable, exactly as on the live chain at epoch ~3,065.
//
// Manual (live-fleet) equivalent, for completeness: patch one validator's
// `select_transactions` (engine.rs) to append `PosTransaction::Exit{v}` for
// v in 0..64 (or 0..64 minus its own index) to the body of its next scheduled
// block. Every peer imports it through `apply_canonical` → `body_transactions`
// → `apply_block` (engine.rs:3218-3235), which never consults `admissible`
// (only `on_transaction`, engine.rs:3121, does). Thirty-two epochs later
// `getvalidators`/`getroster` on :8080 shows an empty roster and no further
// blocks are produced.

/// The attack as written in ST-02: retire ALL 64 in one block. The chain is
/// then permanently proposer-less from epoch `EXIT_DELAY_EPOCHS` (=32) on,
/// with no panic (every consensus function is total on an empty roster) and
/// no in-protocol way back (a second Exit / any revocation is refused).
#[test]
fn st02_one_proposer_can_force_exit_the_entire_roster_in_one_block_today() {
    const N: u32 =