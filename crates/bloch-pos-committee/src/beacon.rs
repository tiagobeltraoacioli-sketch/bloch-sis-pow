// SPDX-License-Identifier: AGPL-3.0-or-later

//! Hash-based randomness beacon — RANDAO over SHAKE-256 preimage chains
//! (§6.3 of the migration design).
//!
//! ## The mechanism
//!
//! 1. **Commit.** At registration a validator picks a secret 32-byte `seed`
//!    and commits `c_0 = SHAKE-256^k(seed)` with
//!    `k = RANDAO_CHAIN_LENGTH = 8,192` — a hash chain, published in the
//!    registration transaction (`randao_commitment` in the deposit, §7.1).
//! 2. **Reveal.** In a slot it proposes, the validator reveals `r_i`, the
//!    preimage one step down its chain. Every node checks
//!    `SHAKE-256(r_i) == c_i` and advances the committed state to
//!    `c_{i+1} = r_i`.
//! 3. **Mix.** The per-chain randomness feeds one global accumulator:
//!    `randao_mix_{n+1} = SHA3-256(DS_RANDAO ‖ randao_mix_n ‖ r_i)`.
//! 4. **Exhaustion.** After `k` reveals the chain bottoms out at the seed,
//!    which has no registered preimage. Further reveals are rejected until the
//!    validator lands a **re-commit transaction** carrying a fresh `c_0`.
//!
//! ## Why a hash chain and not a signature-based VRF (§6.4 — read this before
//! ## "improving" the design)
//!
//! The obvious alternative is Algorand-style private sortition: the proposer
//! evaluates a VRF on the slot and the hash of the proof is the randomness. A
//! VRF needs **uniqueness** — exactly one valid output per (key, input) pair —
//! and *no signature scheme in this chain's suite has it*:
//!
//! - **ML-DSA-65 is not unique.** FIPS 204 signatures are randomised, and even
//!   the hedged/deterministic modes admit many valid signatures for one
//!   (key, message) pair. `hash(mldsa_sign(sk, slot))` is therefore
//!   **grindable**: a proposer just re-signs until the output favours it.
//! - **Falcon-1024 is not unique either** (Gaussian-sampled lattice points —
//!   many valid signatures per message), and the hybrid is not unique twice
//!   over.
//! - Lattice VRFs (LB-VRF and kin) achieve uniqueness only for a small bounded
//!   number of evaluations per key. Research-grade; not a mainnet foundation.
//!
//! Any design here that treats "hash of a PQ signature" as a VRF output is
//! broken and must be rejected in review. The preimage chain is what restores
//! the property the signatures cannot give: **for a committed `c_i` there is
//! exactly one 32-byte value whose SHAKE-256 image is `c_i` that the validator
//! can produce** — the chain value it committed to at registration. It cannot
//! grind its contribution, because producing *any other* accepted reveal is a
//! SHAKE-256 preimage attack.
//!
//! What remains is the standard RANDAO **last-revealer bias**: the proposer of
//! the last slot before the mix is consumed can *withhold* its reveal (skip
//! the slot). That is a choice between exactly **two** predetermined outcomes
//! — mix-with-`r_i` or mix-unchanged — i.e. at most one bit of influence per
//! withheld slot, and it costs the forfeited proposer reward. Bounded, priced,
//! and accepted (§6.3); the tests below pin the "two outcomes, no third"
//! property.
//!
//! ## Consensus discipline
//!
//! Everything here is a pure function of explicit inputs: committed state in,
//! new state out. No clocks, no caches, no interior mutability — the §5.5 rule
//! (the one that exists because `expected_bits` read node-local mutable state
//! and split consensus on 2026-08-08). [`RevealState`] is the *committed*
//! per-validator state; advancing it returns a new value rather than mutating,
//! so the caller decides what is canonical.

use crate::params::{DS_RANDAO, RANDAO_CHAIN_LENGTH};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Digest, Sha3_256, Shake256,
};

/// One step of the commitment chain: SHAKE-256 restricted to 32-byte output.
///
/// Deliberately *untagged*, exactly as §6.3 specifies (`SHAKE-256(r_i) ==
/// c_i`). Domain separation exists to keep one hash's outputs from being
/// replayed in another context; chain links are uniform 32-byte secrets that
/// exist in no other hashing context, and the place where contexts *do* meet —
/// the global mix — is tagged with `DS_RANDAO`. Adding a tag here would also
/// break the committed `c_0` format for no gain.
fn chain_step(x: &[u8; 32]) -> [u8; 32] {
    let mut h = Shake256::default();
    h.update(x);
    let mut out = [0u8; 32];
    h.finalize_xof().read(&mut out);
    out
}

/// Why a reveal was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BeaconError {
    /// `SHAKE-256(reveal) != c_i`. Either a forgery attempt, a stale reveal
    /// (the chain already advanced past it), or a reveal from deeper down the
    /// chain than one step — all indistinguishable, all rejected.
    InvalidReveal,
    /// The chain has produced `RANDAO_CHAIN_LENGTH` reveals and is spent. The
    /// current commitment is the original seed, whose preimage was never
    /// committed; nothing can extend it. A re-commit transaction with a fresh
    /// `c_0` is required before this validator may contribute again.
    ChainExhausted,
}

// ────────────────────────────────────────────────────────────────────────────
// Validator side: generating and walking the secret chain
// ────────────────────────────────────────────────────────────────────────────

/// The validator-side secret: the full hash chain, precomputed.
///
/// `values[0]` is the seed; `values[j] = SHAKE-256(values[j-1])`;
/// `values[k]` is the public commitment `c_0`. Storing all `k+1` links costs
/// 256 KB and makes every reveal O(1) — the right trade for a value the
/// validator signs blocks with on a schedule.
///
/// This type never appears in consensus. It exists so the crate's tests (and
/// eventually the validator client) exercise the real protocol, not a mock.
pub struct RandaoChain {
    values: Vec<[u8; 32]>,
    revealed: u32,
}

impl RandaoChain {
    /// Build the chain from a secret seed.
    ///
    /// The seed's entropy is the caller's responsibility (the validator
    /// client draws it from the OS RNG); this function is deterministic so
    /// that a chain can be rebuilt from a backed-up seed.
    pub fn generate(seed: [u8; 32]) -> Self {
        let k = RANDAO_CHAIN_LENGTH as usize;
        let mut values = Vec::with_capacity(k + 1);
        values.push(seed);
        for j in 1..=k {
            let next = chain_step(&values[j - 1]);
            values.push(next);
        }
        RandaoChain { values, revealed: 0 }
    }

    /// The public commitment `c_0` — what goes in the registration (or
    /// re-commit) transaction.
    pub fn commitment(&self) -> [u8; 32] {
        self.values[RANDAO_CHAIN_LENGTH as usize]
    }

    /// Reveals still available before the chain is spent.
    pub fn remaining(&self) -> u32 {
        RANDAO_CHAIN_LENGTH - self.revealed
    }

    /// Non-consuming view of the value [`Self::next_reveal`] would return.
    ///
    /// Exists for the block-production path ([`crate::produce`]): the producer
    /// must *check* the candidate reveal against the committed [`RevealState`]
    /// — and refuse to build at all if it does not open the commitment —
    /// **before** anything is consumed, so a refused attempt leaves the chain
    /// position untouched. Peeking has no protocol meaning; only
    /// [`Self::next_reveal`] advances the position.
    pub fn peek_reveal(&self) -> Option<[u8; 32]> {
        if self.revealed >= RANDAO_CHAIN_LENGTH {
            return None;
        }
        Some(self.values[RANDAO_CHAIN_LENGTH as usize - 1 - self.revealed as usize])
    }

    /// Produce the next reveal — the preimage one step below the last value
    /// the network has seen — and advance.
    ///
    /// Returns `None` once all `RANDAO_CHAIN_LENGTH` reveals are spent: the
    /// validator must generate a fresh chain and land a re-commit transaction.
    /// Reveals are consumed **per proposed slot**, not per elapsed slot — a
    /// slot this validator does not propose in touches nothing here.
    pub fn next_reveal(&mut self) -> Option<[u8; 32]> {
        let reveal = self.peek_reveal()?;
        self.revealed += 1;
        Some(reveal)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Consensus side: verifying reveals and advancing committed state
// ────────────────────────────────────────────────────────────────────────────

/// Per-validator beacon state as committed in the chain's state — the only
/// thing every node must agree on about a validator's RANDAO chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RevealState {
    /// `c_i` — the value the next reveal must be a SHAKE-256 preimage of.
    pub commitment: [u8; 32],
    /// Reveals consumed since the last (re-)commit. When this reaches
    /// `RANDAO_CHAIN_LENGTH` the chain is spent.
    pub reveals_used: u32,
}

impl RevealState {
    /// State right after a registration or re-commit carrying `c_0`.
    pub fn register(c0: [u8; 32]) -> Self {
        RevealState { commitment: c0, reveals_used: 0 }
    }

    /// Has the chain produced all `RANDAO_CHAIN_LENGTH` reveals?
    ///
    /// When true, `commitment` is the validator's original seed — a value
    /// whose preimage was never committed to — so no further reveal can be
    /// meaningful and every one is rejected until a re-commit.
    pub fn is_exhausted(&self) -> bool {
        self.reveals_used >= RANDAO_CHAIN_LENGTH
    }

    /// Verify `reveal` against the current commitment and advance one step.
    ///
    /// On success returns the new committed state with `c_{i+1} = r_i` (§6.3
    /// step 2): the reveal itself becomes the next commitment, which is what
    /// makes each reveal single-use — replaying it next slot fails, because
    /// `SHAKE-256(r_i) != r_i`.
    ///
    /// Exhaustion is checked **before** the hash so that a spent chain gives
    /// `ChainExhausted` even for a value that happens to hash correctly (the
    /// seed's own preimage, if the validator kept computing downward, was
    /// never part of the commitment and must not be accepted).
    ///
    /// Pure: `self` is untouched; the caller commits the returned state.
    pub fn verify_and_advance(&self, reveal: &[u8; 32]) -> Result<RevealState, BeaconError> {
        if self.is_exhausted() {
            return Err(BeaconError::ChainExhausted);
        }
        // Public data on both sides — the reveal is broadcast in the block and
        // the commitment is committed state — so a plain comparison is fine;
        // there is no secret for a timing side channel to leak.
        if chain_step(reveal) != self.commitment {
            return Err(BeaconError::InvalidReveal);
        }
        Ok(RevealState { commitment: *reveal, reveals_used: self.reveals_used + 1 })
    }

    /// Apply a re-commit transaction: a fresh `c_0` from a brand-new chain.
    ///
    /// This function is the *state transition* only. **When** a re-commit is
    /// valid for inclusion is the transaction layer's rule (DEV-3): it must be
    /// included at least one epoch before the first slot that uses the new
    /// chain, so the sortition for an epoch never runs against a commitment
    /// chosen after that epoch's schedule was knowable — otherwise re-commits
    /// would be a grinding channel and the §6.4 argument would leak.
    pub fn recommit(&self, new_c0: [u8; 32]) -> RevealState {
        RevealState::register(new_c0)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// The global mix
// ────────────────────────────────────────────────────────────────────────────

/// §6.3 step 3: `randao_mix_{n+1} = SHA3-256(DS_RANDAO ‖ randao_mix_n ‖ r_i)`.
///
/// All inputs are fixed-width (16 ‖ 32 ‖ 32 bytes), so no two distinct input
/// pairs can serialize identically. A **skipped** slot simply does not call
/// this — the mix carries over unchanged. That carry-over *is* the
/// last-revealer bias: the proposer chooses between this function's output
/// and the unchanged mix, two outcomes, one bit, at the price of its proposer
/// reward.
pub fn mix_in(randao_mix: &[u8; 32], reveal: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    Digest::update(&mut h, DS_RANDAO);
    Digest::update(&mut h, randao_mix);
    Digest::update(&mut h, reveal);
    h.finalize().into()
}

/// Full per-slot processing on the consensus side: verify the proposer's
/// reveal against its committed [`RevealState`], and fold it into the global
/// mix. Returns `(new_state, new_mix)`; on error nothing changed and the
/// block carrying the reveal is invalid.
///
/// One function on purpose: a node that advanced the state but not the mix
/// (or vice versa) would be a consensus split, so the two updates are not
/// offered separately to the processing path.
pub fn process_reveal(
    state: &RevealState,
    randao_mix: &[u8; 32],
    reveal: &[u8; 32],
) -> Result<(RevealState, [u8; 32]), BeaconError> {
    let next = state.verify_and_advance(reveal)?;
    Ok((next, mix_in(randao_mix, reveal)))
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 32] = [0x42u8; 32];
    const MIX0: [u8; 32] = [0u8; 32];

    /// Deterministic "random-looking" bytes for forgery attempts, so the
    /// grinding tests are reproducible.
    fn pseudo(i: u64) -> [u8; 32] {
        let mut h = Sha3_256::new();
        Digest::update(&mut h, b"test-grind");
        Digest::update(&mut h, i.to_le_bytes());
        h.finalize().into()
    }

    // ── commit / reveal round trip ──────────────────────────────────────────

    #[test]
    fn chain_is_deterministic_and_seed_sensitive() {
        let a = RandaoChain::generate(SEED);
        let b = RandaoChain::generate(SEED);
        assert_eq!(a.commitment(), b.commitment());
        let c = RandaoChain::generate([0x43u8; 32]);
        assert_ne!(a.commitment(), c.commitment());
        // The commitment is not the seed — k > 0 steps really ran.
        assert_ne!(a.commitment(), SEED);
    }

    #[test]
    fn every_reveal_verifies_and_the_chain_walks_down_to_the_seed() {
        let mut chain = RandaoChain::generate(SEED);
        let mut state = RevealState::register(chain.commitment());
        let mut mix = MIX0;

        for i in 0..RANDAO_CHAIN_LENGTH {
            assert!(!state.is_exhausted(), "exausto cedo demais em {i}");
            let r = chain.next_reveal().expect("chain spent early");
            let (next, new_mix) = process_reveal(&state, &mix, &r).expect("valid reveal rejected");
            // §6.3 step 2: the reveal becomes the next commitment.
            assert_eq!(next.commitment, r);
            assert_eq!(next.reveals_used, i + 1);
            assert_ne!(new_mix, mix, "mix must move on every reveal");
            state = next;
            mix = new_mix;
        }

        // The final reveal was the seed itself: the chain is fully consumed.
        assert_eq!(state.commitment, SEED);
        assert!(state.is_exhausted());
        assert_eq!(chain.next_reveal(), None);
        assert_eq!(chain.remaining(), 0);
    }

    // ── invalid reveals ─────────────────────────────────────────────────────

    #[test]
    fn tampered_reveal_is_rejected_and_state_is_unchanged() {
        let mut chain = RandaoChain::generate(SEED);
        let state = RevealState::register(chain.commitment());
        let mut r = chain.next_reveal().unwrap();
        r[0] ^= 0x01;
        assert_eq!(state.verify_and_advance(&r), Err(BeaconError::InvalidReveal));
        // Pure API: the rejected attempt cannot have moved committed state.
        assert_eq!(state, RevealState::register(RandaoChain::generate(SEED).commitment()));
    }

    #[test]
    fn skipping_a_step_down_the_chain_is_rejected() {
        // r_2 hashes to r_1, not to c_0 — a reveal from two steps down must
        // fail against the current commitment. Order is enforced by the hash
        // structure itself, not by bookkeeping.
        let mut chain = RandaoChain::generate(SEED);
        let state = RevealState::register(chain.commitment());
        let _r1 = chain.next_reveal().unwrap();
        let r2 = chain.next_reveal().unwrap();
        assert_eq!(state.verify_and_advance(&r2), Err(BeaconError::InvalidReveal));
    }

    #[test]
    fn a_reveal_cannot_be_replayed() {
        let mut chain = RandaoChain::generate(SEED);
        let state = RevealState::register(chain.commitment());
        let r1 = chain.next_reveal().unwrap();
        let next = state.verify_and_advance(&r1).unwrap();
        // Same value again: SHAKE-256(r1) == c_0, but the commitment is now
        // r1 itself, and SHAKE-256(r1) != r1.
        assert_eq!(next.verify_and_advance(&r1), Err(BeaconError::InvalidReveal));
    }

    // ── mixing ──────────────────────────────────────────────────────────────

    #[test]
    fn mix_changes_with_any_input() {
        let r = pseudo(1);
        let base = mix_in(&MIX0, &r);
        // Different previous mix → different result.
        assert_ne!(mix_in(&[1u8; 32], &r), base);
        // Different reveal → different result.
        assert_ne!(mix_in(&MIX0, &pseudo(2)), base);
        // Single-bit change in either input → different result.
        let mut r_flip = r;
        r_flip[31] ^= 0x80;
        assert_ne!(mix_in(&MIX0, &r_flip), base);
        // And the mix is not either of its inputs echoed back.
        assert_ne!(base, MIX0);
        assert_ne!(base, r);
    }

    #[test]
    fn mix_uses_the_randao_domain_tag() {
        // Reconstruct §6.3 step 3 by hand: SHA3-256(DS_RANDAO ‖ mix ‖ r).
        // Pins the preimage layout (tag first, fixed widths, this order) so a
        // refactor cannot silently change the mixing format.
        let r = pseudo(3);
        let mut h = Sha3_256::new();
        Digest::update(&mut h, DS_RANDAO);
        Digest::update(&mut h, MIX0);
        Digest::update(&mut h, r);
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(mix_in(&MIX0, &r), expected);
        // An untagged mix would be a different value — the tag is load-bearing.
        let mut h2 = Sha3_256::new();
        Digest::update(&mut h2, MIX0);
        Digest::update(&mut h2, r);
        let untagged: [u8; 32] = h2.finalize().into();
        assert_ne!(mix_in(&MIX0, &r), untagged);
    }

    #[test]
    fn mix_known_answer() {
        // Pinned KAT: zero mix, reveal = first chain reveal from the all-0x42
        // seed. Cross-checked against an independent Python implementation
        // (hashlib shake_256/sha3_256, 8,192-step chain). If this moves, the
        // beacon's wire/state format moved — that is a consensus break and
        // must be a deliberate, flag-dayed decision.
        let mut chain = RandaoChain::generate(SEED);
        let r = chain.next_reveal().unwrap();
        let got = hex::encode(mix_in(&MIX0, &r));
        assert_eq!(got, "a115b8ef9a86416a38f4ec10973658f939eeeef42461a46a8b6708243b9adf60");
    }

    // ── last-revealer bias is one bit, not a grinding channel ───────────────

    #[test]
    fn proposer_has_exactly_two_outcomes_reveal_or_withhold() {
        // §6.4's whole point, as a test. For a committed c_i the proposer's
        // reachable set of next mixes is exactly:
        //   { mix_in(mix, r_true),  mix (by withholding) }.
        // A third outcome would require a second SHAKE-256 preimage of c_i.
        // We can't test preimage resistance itself, but we can pin the
        // protocol shape: every candidate other than the committed preimage
        // is rejected, so nothing a proposer *submits* can create outcome #3.
        let mut chain = RandaoChain::generate(SEED);
        let state = RevealState::register(chain.commitment());
        let r_true = chain.next_reveal().unwrap();

        let mut accepted_mixes = std::collections::BTreeSet::new();
        // Outcome A: honest reveal.
        let (_, m) = process_reveal(&state, &MIX0, &r_true).unwrap();
        accepted_mixes.insert(m);
        // Outcome B: withhold — the mix simply carries over.
        accepted_mixes.insert(MIX0);

        // Grinding attempt: 4,096 forged candidates. All must be rejected —
        // unlike hashing an ML-DSA/Falcon signature, where each re-signing
        // yields a fresh valid candidate and this loop would mint new mixes.
        for i in 0..4096u64 {
            let forged = pseudo(i);
            if forged == r_true {
                continue;
            }
            assert_eq!(
                process_reveal(&state, &MIX0, &forged),
                Err(BeaconError::InvalidReveal),
                "forged reveal {i} accepted — beacon is grindable"
            );
        }
        assert_eq!(accepted_mixes.len(), 2, "bias must be one bit: exactly two outcomes");
    }

    // ── exhaustion and re-commit ────────────────────────────────────────────

    #[test]
    fn exhausted_chain_rejects_everything_until_recommit() {
        // Walk the full chain to exhaustion.
        let mut chain = RandaoChain::generate(SEED);
        let mut state = RevealState::register(chain.commitment());
        while let Some(r) = chain.next_reveal() {
            state = state.verify_and_advance(&r).unwrap();
        }
        assert!(state.is_exhausted());
        assert_eq!(state.reveals_used, RANDAO_CHAIN_LENGTH);

        // The killer case: the validator keeps hashing below its seed and
        // offers a value that DOES hash to the current commitment. It must
        // still be rejected — that preimage was never committed to, and
        // accepting it would extend the chain indefinitely without ever
        // touching the re-commit path.
        // (Finding such a preimage is infeasible for a real adversary; the
        // validator itself could pick seed = SHAKE-256(deeper) at generation
        // time, which is exactly why exhaustion is checked before the hash.)
        let deeper = [0x77u8; 32];
        let seed_like = chain_step(&deeper); // pretend seed = SHAKE(deeper)
        let mut trapped = RevealState { commitment: seed_like, reveals_used: RANDAO_CHAIN_LENGTH };
        assert_eq!(trapped.verify_and_advance(&deeper), Err(BeaconError::ChainExhausted));

        // Re-commit with a fresh chain restores service from zero.
        let mut chain2 = RandaoChain::generate([0x99u8; 32]);
        trapped = trapped.recommit(chain2.commitment());
        assert!(!trapped.is_exhausted());
        assert_eq!(trapped.reveals_used, 0);
        let r = chain2.next_reveal().unwrap();
        let after = trapped.verify_and_advance(&r).expect("post-recommit reveal rejected");
        assert_eq!(after.reveals_used, 1);
        assert_eq!(after.commitment, r);
    }

    #[test]
    fn validator_side_reports_remaining_reveals() {
        let mut chain = RandaoChain::generate(SEED);
        assert_eq!(chain.remaining(), RANDAO_CHAIN_LENGTH);
        chain.next_reveal().unwrap();
        chain.next_reveal().unwrap();
        assert_eq!(chain.remaining(), RANDAO_CHAIN_LENGTH - 2);
    }
}
