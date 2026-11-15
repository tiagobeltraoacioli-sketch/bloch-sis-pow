// SPDX-License-Identifier: AGPL-3.0-or-later
//! Operator-rejected block roots (`--reject-block-root`, incident 2026-11-12).
//!
//! The equivalent of Ethereum clients' `--invalid-block-root`: the operator
//! names a block id, and THIS node treats that block and every descendant of
//! it as never adoptable. It is node-local. No consensus rule, state
//! transition or block validity changes, for this node or any other: the
//! rejected branch is not invalid, it is simply never followed here.
//!
//! Where it is enforced:
//!
//! - **The door** (`Engine::ingest_one_deferred`): a block whose id is
//!   rejected, or whose parent is rejected or a remembered rejected
//!   descendant, is refused before any signature work. Gossip, sync, orphan
//!   promotion and future-block release all pass through that door. The
//!   refused id is remembered in a bounded FIFO (the shape and cap of
//!   `Engine::parked_refused_finality`) so its own children are refused the
//!   same way, and any orphan subtree already parked under it is dropped.
//!   The verdict is `Ignore`: a peer relaying the other branch is honest.
//! - **Fork choice**: a refused block never enters `Engine::blocks`, the only
//!   input `advance` selects a head from, so it can never be selected or
//!   built on, and nothing it carries is weighed.
//! - **Attestations** (`Engine::on_attestation`): a vote whose head or target
//!   is a rejected block is dropped before it can reach the fork-choice pool
//!   or be held waiting for that block.
//! - **Boot** ([`Engine::truncate_rejected_log`]): a block log whose
//!   canonical chain contains a rejected block is truncated, durably and
//!   before any replay or state-cache restore, to the parent of the first
//!   rejected block. A truncation below the stored finality latch, or with
//!   no readable latch record to check it against, refuses to start unless
//!   `--allow-finality-rewind` is set AND the rejected root is named again in
//!   `BLOCH_REJECT_ROOT_FINALITY_REWIND` (audit L1-09, L1-10).
//!
//! Configured through `--reject-block-root <hex>` (repeatable) or
//! `BLOCH_REJECT_BLOCK_ROOTS=<hex>[,<hex>...]`; `main.rs` folds the flags
//! into the variable, so the engine reads one source.
use super::*;

/// The environment variable the engine reads the rejected roots from.
pub(crate) const ENV_REJECT_BLOCK_ROOTS: &str = "BLOCH_REJECT_BLOCK_ROOTS";

/// The dedicated consent for a boot truncation that cuts below the stored
/// finality latch, or that cannot be checked against one (audit L1-09,
/// L1-10): the rejected root(s), named again, as 64-hex block ids. Required
/// in addition to `--allow-finality-rewind`, so a stale
/// `BLOCH_ALLOW_FINALITY_REWIND=1` left in a unit file cannot by itself
/// truncate finalized history.
pub(crate) const ENV_REJECT_ROOT_FINALITY_REWIND: &str = "BLOCH_REJECT_ROOT_FINALITY_REWIND";

/// The operator's rejected roots and what this node has refused because of
/// them.
#[derive(Default)]
pub(super) struct RejectedRoots {
    /// Set once at boot, never changed. Not bounded by anything but the
    /// operator's command line: these are the roots the refusal is anchored
    /// on, and forgetting one would make its branch adoptable again.
    pub(super) configured: BTreeSet<[u8; 32]>,
    /// Descendants refused at the door, so their own children are refused
    /// without a lookup of their ancestry. Bounded FIFO with the cap of
    /// `parked_refused_finality`. Evicting an entry costs only work, never
    /// safety: a child of an evicted descendant waits as an orphan, and the
    /// evicted parent, if fetched again, is refused again on ITS parent, down
    /// to a configured root, which is never evicted.
    pub(super) descendants: VecDeque<[u8; 32]>,
    /// Refused ids whose proposer signature this node could NOT verify
    /// (audit L1-08): a header naming a rejected parent with garbage in place
    /// of a signature, a child of such a header, or a real block refused
    /// while the verification allowance was spent. Kept apart, with the same
    /// cap, so unauthenticated junk can only evict other unauthenticated
    /// junk and never a verified descendant out of `descendants`. Consulted
    /// by the door like `descendants`: an id is a header hash, so an entry
    /// here can only ever name a block whose parent is itself refused.
    pub(super) unauthenticated: VecDeque<[u8; 32]>,
    /// Rejected roots whose boot truncation the operator explicitly
    /// confirmed may cut below (or past an unknown) finality
    /// (`BLOCH_REJECT_ROOT_FINALITY_REWIND`, audit L1-10). Needed together
    /// with `--allow-finality-rewind`; neither suffices alone.
    pub(super) rewind_confirmed: BTreeSet<[u8; 32]>,
    /// Blocks refused, at the door or truncated from the log at boot.
    /// Exported as `bloch_pos_rejected_blocks_total`.
    pub(super) refused: u64,
}

impl RejectedRoots {
    pub(super) fn new(configured: BTreeSet<[u8; 32]>) -> Self {
        Self { configured, ..Self::default() }
    }

    /// Is `id` a rejected root or a remembered rejected descendant?
    pub(super) fn contains(&self, id: &[u8; 32]) -> bool {
        !self.configured.is_empty()
            && (self.configured.contains(id) || self.descendants.contains(id) || self.unauthenticated.contains(id))
    }

    /// Is `id` a configured root or a descendant whose signature verified?
    fn authenticated(&self, id: &[u8; 32]) -> bool {
        self.configured.contains(id) || self.descendants.contains(id)
    }
}

/// The anchor root, when the logged canonical chain holds it at or after
/// index `first` (the first rejected block): the rejected block is then the
/// anchor or one of its ancestors (audit L1-15).
fn rejected_at_or_below_anchor(logged: &[BlockEnvelope], first: usize, anchor: Option<[u8; 32]>) -> Option<[u8; 32]> {
    let anchor = anchor?;
    logged.get(first..)?.iter().any(|env| *env.block_id().as_bytes() == anchor).then_some(anchor)
}

/// Push onto a bounded refusal FIFO, evicting the oldest entries.
fn remember(fifo: &mut VecDeque<[u8; 32]>, id: [u8; 32]) {
    while fifo.len() >= MAX_PARKED_REFUSED_FINALITY {
        fifo.pop_front();
    }
    fifo.push_back(id);
}

/// Parse a comma-separated list of 64-hex-digit block ids. Strict: every
/// entry must be exactly 64 hex digits (no prefix, no empty entries); an
/// empty or all-whitespace string is "no roots".
pub(crate) fn parse_reject_block_roots(raw: &str) -> Result<BTreeSet<[u8; 32]>, String> {
    let mut roots = BTreeSet::new();
    if raw.trim().is_empty() {
        return Ok(roots);
    }
    for entry in raw.split(',') {
        roots.insert(parse_reject_block_root(entry.trim())?);
    }
    Ok(roots)
}

/// One block id: exactly 64 hex digits, either case.
pub(crate) fn parse_reject_block_root(entry: &str) -> Result<[u8; 32], String> {
    if entry.len() != 64 || !entry.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "rejected block root `{entry}` is not a 64-hex-digit block id"
        ));
    }
    let bytes = crate::codec::unhex(entry)?;
    bytes.try_into().map_err(|_| format!("rejected block root `{entry}` is not 32 bytes"))
}

/// The roots configured in the environment, or a boot error naming the
/// malformed entry.
pub(super) fn reject_block_roots_from_env() -> io::Result<BTreeSet<[u8; 32]>> {
    roots_from_env(ENV_REJECT_BLOCK_ROOTS)
}

/// The roots whose finality-crossing truncation the operator confirmed
/// (`BLOCH_REJECT_ROOT_FINALITY_REWIND`), parsed as strictly.
pub(super) fn reject_root_rewind_confirmations_from_env() -> io::Result<BTreeSet<[u8; 32]>> {
    roots_from_env(ENV_REJECT_ROOT_FINALITY_REWIND)
}

fn roots_from_env(name: &str) -> io::Result<BTreeSet<[u8; 32]>> {
    let Some(raw) = std::env::var_os(name) else {
        return Ok(BTreeSet::new());
    };
    let raw = raw.to_str().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, format!("{name} is not UTF-8"))
    })?;
    parse_reject_block_roots(raw).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidInput, format!("{name}: {e}"))
    })
}

impl Engine {
    /// `getchaininfo` plus `rejected_block_roots`: the configured roots, as
    /// hex, in a stable order. Always present; empty when none are set.
    pub(super) fn with_rejected_block_roots(&self, info: rpc::Json) -> rpc::Json {
        match info {
            rpc::Json::Obj(mut fields) => {
                let roots = self.rejected_roots.configured.iter().map(rpc::Json::hex).collect();
                fields.push(("rejected_block_roots".to_string(), rpc::Json::Arr(roots)));
                rpc::Json::Obj(fields)
            }
            other => other,
        }
    }

    /// The door's question: is `id`, or its `parent`, rejected?
    pub(super) fn is_rejected_block(&self, id: &[u8; 32], parent: &[u8; 32]) -> bool {
        self.rejected_roots.contains(id) || self.rejected_roots.contains(parent)
    }

    /// Refuse a block of a rejected branch at the door: count it, remember
    /// it (unless it is a configured root, which is remembered anyway), and
    /// drop every parked orphan that descends from it.
    ///
    /// Audit L1-08: the door runs before any signature work, so what it is
    /// handed may be junk. An id joins `descendants` (the FIFO that keeps
    /// real descendants' children cheap to refuse) only when its parent is
    /// itself authenticated and its proposer signature verifies, drawing on
    /// the same per-source block allowance as the rest of the door; anything
    /// else goes to the separate `unauthenticated` FIFO, where it can only
    /// displace other unauthenticated entries. The refusal itself does not
    /// depend on the verdict: the block is refused either way.
    pub(super) fn refuse_rejected_block(&mut self, env: &BlockEnvelope, id: [u8; 32], src: Source) {
        self.rejected_roots.refused = self.rejected_roots.refused.saturating_add(1);
        crate::net::rejection_log::emit(crate::net::rejection_log::Class::Block, || eprintln!(
            "REJECT_BLOCK_ROOT: refused {} (an operator-rejected block or a descendant of one); \
             refusals so far: {}",
            crate::codec::hex8(&id),
            self.rejected_roots.refused,
        ));
        if !self.rejected_roots.authenticated(&id) {
            let verified = self.rejected_roots.authenticated(&env.header.parent)
                && self.rejected_descendant_signature_verifies(env, src);
            let roots = &mut self.rejected_roots;
            if verified {
                roots.unauthenticated.retain(|seen| *seen != id);
                remember(&mut roots.descendants, id);
            } else if !roots.unauthenticated.contains(&id) {
                remember(&mut roots.unauthenticated, id);
            }
        }
        self.drop_orphan_descendants(BTreeSet::from([id]));
    }

    /// The door's own proposer-signature check, for a block it refuses
    /// (audit L1-08): the same authority state, rule and budgeted lane as
    /// `ingest_one_deferred`. Any doubt (unknown identity, a spent allowance,
    /// a branch-dependent key) is `false`, which only costs work later.
    fn rejected_descendant_signature_verifies(&self, env: &BlockEnvelope, src: Source) -> bool {
        let epoch = epoch_of(env.header.slot);
        let judged_state = self.proposer_authority_state(&env.header.parent);
        let root = env.header.proposal_signing_root();
        if src.bounded_by_wall_clock() {
            let (lane, lane_cap, lane_source_cap) = src.block_verification_allowance();
            let verifier = self
                .gossip_verifier
                .budgeted_lane_for_source(self.wall_slot(), lane, lane_cap, src.verification_source(), lane_source_cap)
                .with_failure_allowance(BLOCK_VERIFICATION_FAILURES_PER_SOURCE_PER_SLOT);
            let verified = bloch_pos_committee::kes::verify_validator(
                &*judged_state,
                &bloch_pos_committee::PolicyVerifier::consensus(&verifier, epoch),
                env.header.proposer_index,
                epoch,
                &root,
                &env.proposer_sig,
            ) == Some(true);
            verified && !verifier.limited()
        } else {
            bloch_pos_committee::kes::verify_validator(
                &*judged_state,
                &bloch_pos_committee::PolicyVerifier::consensus(&self.gossip_verifier, epoch),
                env.header.proposer_index,
                epoch,
                &root,
                &env.proposer_sig,
            ) == Some(true)
        }
    }

    /// Boot, before the state cache is restored and before replay: if the
    /// logged canonical chain contains a rejected block, truncate the log —
    /// durably, through the reorg tail-rewrite helper — to that block's
    /// parent, and drop the truncated blocks from `logged`.
    ///
    /// Crash-safe by construction: the rewrite publishes the shortened log
    /// atomically (staging file, fsync, rename), so a crash leaves either the
    /// old log, which the next boot truncates again, or the new one. A state
    /// cache generation that covers a truncated block no longer matches the
    /// log prefix and is refused by its own checks, so the restore falls back
    /// to an older generation or to replay.
    ///
    /// A truncation below the stored finality latch, or without a readable
    /// latch record, is refused unless the operator's `--allow-finality-rewind`
    /// override is set and the rejected root is confirmed in
    /// `BLOCH_REJECT_ROOT_FINALITY_REWIND`; with both, the latch
    /// reconciliation after replay discards the record, loudly, as it does
    /// for any log that ends below it.
    pub(super) fn truncate_rejected_log(&mut self, logged: &mut Vec<BlockEnvelope>) -> io::Result<()> {
        if self.rejected_roots.configured.is_empty() {
            return Ok(());
        }
        let Some(first) = logged
            .iter()
            .position(|env| self.rejected_roots.configured.contains(env.block_id().as_bytes()))
        else {
            return Ok(());
        };
        let rejected = *logged[first].block_id().as_bytes();
        // `logged[i]` sits at canonical height `i + 1`; keeping `first`
        // frames leaves the parent, at height `first`, as the head.
        let kept_height = first as u64;
        // Audit L1-15: the release-baked checkpoint is finalized canonical
        // history this binary trusts. A rejected root at or below it on the
        // logged chain would truncate the node to below its own anchor and
        // leave it stuck in silence; that is an operator error, refused with
        // no override.
        let anchor = crate::ws_boot::compiled_release_anchor().ok().flatten().map(|cp| cp.block_root);
        if let Some(anchor) = rejected_at_or_below_anchor(logged, first, anchor) {
            return Err(crate::ws_boot::boot_refused(format!(
                "--reject-block-root {} names a block at or below this release's weak-subjectivity \
                 anchor {} (it is the anchor or one of its ancestors on the logged chain). The \
                 anchor is finalized history this binary trusts; refusing to start. Remove the \
                 rejected root.",
                crate::codec::hex32(&rejected),
                crate::codec::hex32(&anchor),
            )));
        }
        // Audit L1-10: crossing finality here needs the generic override AND
        // the rejected root named again in its own variable.
        let consent = self.finality_rewind_override && self.rejected_roots.rewind_confirmed.contains(&rejected);
        let consent_hint = format!(
            "If that is intended, restart with --allow-finality-rewind \
             (BLOCH_ALLOW_FINALITY_REWIND=1) AND {ENV_REJECT_ROOT_FINALITY_REWIND}={}",
            crate::codec::hex32(&rejected)
        );
        let stored = match self.stored_finalized_latch() {
            Ok(stored) => stored,
            Err(e) if consent => {
                eprintln!(
                    "REJECT_BLOCK_ROOT: the finality latch record cannot be read ({e}); \
                     truncating anyway because the operator confirmed this root's rewind"
                );
                None
            }
            Err(e) => {
                return Err(crate::ws_boot::boot_refused(format!(
                    "the block log contains the rejected block {} at height {}, but the finality \
                     latch record cannot be read ({e}), so this node cannot tell whether \
                     truncating to height {kept_height} would cut below a checkpoint it \
                     finalized. Restore the record, or confirm the cut. {consent_hint}.",
                    crate::codec::hex32(&rejected),
                    kept_height.saturating_add(1),
                )));
            }
        };
        match stored {
            // Audit L1-09: no record is not "no finality". The record may
            // have been deleted (an earlier boot error suggests it) or its
            // write may have failed; the log itself may finalize far above
            // the cut. Without the record the cut cannot be checked, so it
            // needs the same explicit consent as a cut below it.
            None if !consent => {
                return Err(crate::ws_boot::boot_refused(format!(
                    "the block log contains the rejected block {} at height {}, but there is no \
                     finality latch record, so this node cannot tell whether truncating to height \
                     {kept_height} would cut below a checkpoint it finalized. Refusing to start. \
                     {consent_hint}.",
                    crate::codec::hex32(&rejected),
                    kept_height.saturating_add(1),
                )));
            }
            None => eprintln!(
                "REJECT_BLOCK_ROOT: no finality latch record; truncating the block log to height \
                 {kept_height} on the operator's explicit confirmation of {}",
                crate::codec::hex32(&rejected),
            ),
            Some(latch) if kept_height < latch.height => {
                if !consent {
                    return Err(crate::ws_boot::boot_refused(format!(
                        "the block log contains the rejected block {} at height {}, and truncating \
                         the chain to its parent (height {kept_height}) would cut below the finalized \
                         checkpoint {} at height {} this node recorded. Refusing to start. {consent_hint}.",
                        crate::codec::hex32(&rejected),
                        kept_height.saturating_add(1),
                        crate::codec::hex8(&latch.root),
                        latch.height,
                    )));
                }
                eprintln!(
                    "REJECT_BLOCK_ROOT: the operator confirmed it — truncating the block log to \
                     height {kept_height}, BELOW the finalized checkpoint {} at height {}. This must \
                     only happen with a human operator's deliberate, informed consent.",
                    crate::codec::hex8(&latch.root),
                    latch.height,
                );
            }
            Some(_) => {}
        }
        let expected_last = first
            .checked_sub(1)
            .and_then(|i| logged.get(i))
            .map(|env| *env.block_id().as_bytes());
        self.store.rewrite_tail_async(kept_height, expected_last, Vec::new())?;
        self.store.flush_rewrite()?;
        let dropped = logged.len().saturating_sub(first);
        logged.truncate(first);
        self.rejected_roots.refused = self.rejected_roots.refused.saturating_add(dropped as u64);
        println!(
            "REJECT_BLOCK_ROOT: the block log held the rejected block {} at height {}; truncated \
             {dropped} block(s) from the log, the canonical head is now height {kept_height}{}",
            crate::codec::hex32(&rejected),
            kept_height.saturating_add(1),
            expected_last.map_or_else(|| " (genesis)".to_string(), |id| format!(" ({})", crate::codec::hex8(&id))),
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(envs: &[BlockEnvelope]) -> Vec<[u8; 32]> {
        envs.iter().map(|env| *env.block_id().as_bytes()).collect()
    }

    /// A fork at height 1 (slot 1). Branch A is one block at slot 2; branch
    /// B is three blocks at slots 3, 4 and 5. All are real blocks from the
    /// production `propose` path, signed by the fixture's single validator.
    /// The engine is handed back on the fork point with none of the branch
    /// blocks stored, so each test chooses what arrives and in which order.
    struct Fork {
        engine: Engine,
        _dir: perf_support::TestDir,
        fork_point: [u8; 32],
        a: BlockEnvelope,
        b: Vec<BlockEnvelope>,
    }

    fn give_back(engine: &mut Engine, to: [u8; 32], envs: &[BlockEnvelope]) {
        assert!(engine.do_reorg(to, Vec::new()), "giving the branch back succeeds");
        engine.store.flush_rewrite().expect("the rewrite is published");
        for env in envs {
            engine.blocks.remove(env.block_id().as_bytes());
        }
    }

    fn fork() -> Fork {
        let (mut engine, dir) = perf_support::proposing_engine();
        engine.propose(1);
        let fork_point = *engine.head_id().as_bytes();
        engine.propose(2);
        let a = engine.blocks[engine.head_id().as_bytes()].clone();
        give_back(&mut engine, fork_point, std::slice::from_ref(&a));
        for slot in 3..=5 {
            engine.propose(slot);
        }
        let b: Vec<BlockEnvelope> = engine.chain[2..]
            .iter()
            .map(|(_, id)| engine.blocks[id.as_bytes()].clone())
            .collect();
        assert_eq!(b.len(), 3);
        give_back(&mut engine, fork_point, &b);
        assert_eq!(*engine.head_id().as_bytes(), fork_point);
        Fork { engine, _dir: dir, fork_point, a, b }
    }

    /// A vote for `head` by the fixture's validator, straight into the
    /// fork-choice pool (as the side-branch tests do): it gives the branch
    /// holding `head` the whole stake.
    fn vote_for(engine: &mut Engine, slot: u64, head: [u8; 32]) {
        let vote = forkchoice_tests::attest(0, slot, head);
        engine.pool.insert((vote.validator, vote.data.signing_root()), vote);
    }

    fn reject(engine: &mut Engine, root: [u8; 32]) {
        engine.rejected_roots = RejectedRoots::new(BTreeSet::from([root]));
    }

    #[test]
    fn parsing_is_strict() {
        let a = "ab".repeat(32);
        let b = "CD".repeat(32);
        let both = parse_reject_block_roots(&format!("{a}, {b}")).expect("two valid roots");
        assert_eq!(both.len(), 2);
        assert!(both.contains(&[0xAB; 32]) && both.contains(&[0xCD; 32]));
        assert!(parse_reject_block_roots("").expect("empty").is_empty());
        assert!(parse_reject_block_roots("  ").expect("blank").is_empty());
        for bad in [
            "ab".repeat(31),
            "ab".repeat(33),
            format!("0x{}", "ab".repeat(31)),
            format!("{}zz", "ab".repeat(31)),
            format!("{a},"),
            format!("{a},,{b}"),
            "not-hex".to_string(),
        ] {
            assert!(parse_reject_block_roots(&bad).is_err(), "`{bad}` must be refused");
        }
    }

    /// (a) Without the flag the heavier branch B wins; with B's first block
    /// rejected the head is A, and stays A as more B blocks and votes arrive.
    #[test]
    fn a_rejected_branch_never_wins_fork_choice() {
        let _clock = validator_lifecycle::clock_at(32);

        // Control: no rejected roots. B carries the vote, so B wins.
        let Fork { mut engine, _dir, fork_point: _, a, b } = fork();
        engine.ingest(a.clone());
        assert_eq!(engine.head_id(), a.block_id(), "A alone is the head");
        for env in &b {
            engine.ingest(env.clone());
        }
        vote_for(&mut engine, 5, *b[2].block_id().as_bytes());
        engine.advance();
        assert_eq!(engine.head_id(), b[2].block_id(), "without the flag the heavier branch B wins");

        // Same blocks, B's first block rejected.
        let Fork { mut engine, _dir, fork_point: _, a, b } = fork();
        reject(&mut engine, *b[0].block_id().as_bytes());
        engine.ingest(a.clone());
        assert_eq!(engine.head_id(), a.block_id());
        for env in &b {
            let before = engine.rejected_roots.refused;
            assert_eq!(
                engine.ingest_judged(env.clone()),
                Verdict::Ignore,
                "an honest peer relaying the other branch is not misbehaving"
            );
            assert_eq!(engine.rejected_roots.refused, before + 1);
            assert!(!engine.blocks.contains_key(env.block_id().as_bytes()), "never a fork-choice input");
            vote_for(&mut engine, env.header.slot, *env.block_id().as_bytes());
            engine.advance();
            assert_eq!(engine.head_id(), a.block_id(), "the head stays on A");
        }
        assert!(engine.orphans.is_empty());
        assert!(!engine.needs_sync, "a rejected parent is not a sync gap");
        // A re-offer is refused at the door again, before any other work.
        assert_eq!(engine.ingest_judged(b[2].clone()), Verdict::Ignore);
        assert_eq!(engine.head_id(), a.block_id());
    }

    /// (b) Descendants arriving before the block they hang from are parked as
    /// orphans and dropped as soon as their parent is refused; re-offers are
    /// refused at the door. An unrelated orphan survives.
    ///
    /// The rejected root is b[0]. Arrival order: the grandchild b[2] first
    /// (an orphan: its parent b[1] is unknown), then the child b[1] (refused
    /// on its parent, the root, which cleans b[2] out of the orphan pool),
    /// then the root itself.
    #[test]
    fn out_of_order_descendants_are_refused_and_the_orphan_pool_is_cleaned() {
        let _clock = validator_lifecycle::clock_at(32);
        let Fork { mut engine, _dir, fork_point: _, a, b } = fork();
        let root = *b[0].block_id().as_bytes();
        reject(&mut engine, root);
        engine.ingest(a.clone());
        let unrelated = {
            let mut env = b[2].clone();
            env.header.parent = [0xEE; 32];
            env
        };
        let unrelated_id = *unrelated.block_id().as_bytes();
        engine.park_orphan(unrelated_id, unrelated, Source::Gossip(None));

        assert_eq!(engine.ingest_judged(b[2].clone()), Verdict::Ignore);
        let parked: Vec<[u8; 32]> = engine.orphans.iter().map(|(id, ..)| *id).collect();
        assert_eq!(parked, vec![unrelated_id, *b[2].block_id().as_bytes()], "fixture: b[2] waits on its parent");

        // The child arrives: refused on the root, and its parked subtree with it.
        assert_eq!(engine.ingest_judged(b[1].clone()), Verdict::Ignore);
        let left: Vec<[u8; 32]> = engine.orphans.iter().map(|(id, ..)| *id).collect();
        assert_eq!(left, vec![unrelated_id], "the rejected subtree is gone, the unrelated gap stays");
        assert!(engine.deferred_orphans.is_empty());
        // The root itself.
        assert_eq!(engine.ingest_judged(b[0].clone()), Verdict::Ignore);
        assert_eq!(engine.rejected_roots.refused, 2);

        // Re-offered: the grandchild is refused on its remembered parent, and
        // is remembered in turn, so its own children are refused on it.
        assert_eq!(engine.ingest_judged(b[2].clone()), Verdict::Ignore);
        assert!(engine.orphans.iter().all(|(id, ..)| *id == unrelated_id));
        assert!(engine.rejected_roots.descendants.contains(b[1].block_id().as_bytes()));
        assert!(engine.rejected_roots.descendants.contains(b[2].block_id().as_bytes()));
        assert!(!engine.rejected_roots.descendants.contains(&root), "configured roots are not duplicated");
        let mut great_grandchild = b[2].clone();
        great_grandchild.header.parent = *b[2].block_id().as_bytes();
        great_grandchild.header.slot += 1;
        assert_eq!(engine.ingest_judged(great_grandchild), Verdict::Ignore);
        assert!(engine.orphans.iter().all(|(id, ..)| *id == unrelated_id), "refused before it could be parked");
        assert_eq!(engine.head_id(), a.block_id());
        for env in &b {
            assert!(!engine.blocks.contains_key(env.block_id().as_bytes()));
        }
    }

    /// `getchaininfo` lists the configured roots; the metric is exported.
    #[test]
    fn rejected_roots_are_visible() {
        let (mut engine, _dir) = perf_support::proposing_engine();
        let roots = |engine: &mut Engine| match engine.serve_rpc(RpcRequest::ChainInfo) {
            Ok(rpc::Json::Obj(fields)) => fields
                .into_iter()
                .find(|(key, _)| key == "rejected_block_roots")
                .map(|(_, value)| value),
            _ => None,
        };
        assert!(matches!(roots(&mut engine), Some(rpc::Json::Arr(items)) if items.is_empty()));
        reject(&mut engine, [0xAB; 32]);
        match roots(&mut engine) {
            Some(rpc::Json::Arr(items)) => {
                assert_eq!(items.len(), 1);
                assert_eq!(items[0].as_str(), Some("ab".repeat(32).as_str()));
            }
            other => panic!("rejected_block_roots missing: {other:?}"),
        }
        assert!(crate::metrics::NODE.render().contains("# TYPE bloch_pos_rejected_blocks_total counter"));
    }

    /// The remembered refusals are bounded like the finality refusals, and a
    /// configured root is never evicted.
    #[test]
    fn remembered_descendants_are_bounded() {
        let _clock = validator_lifecycle::clock_at(32);
        let Fork { mut engine, _dir, fork_point: _, a: _, b } = fork();
        let root = *b[0].block_id().as_bytes();
        reject(&mut engine, root);
        let mut first_junk = None;
        for i in 0..=MAX_PARKED_REFUSED_FINALITY as u64 {
            let mut junk = b[1].clone();
            junk.header.slot = 1_000 + i;
            junk.proposer_sig.fill(0);
            let id = *junk.block_id().as_bytes();
            first_junk.get_or_insert(id);
            engine.refuse_rejected_block(&junk, id, Source::Gossip(None));
        }
        assert_eq!(engine.rejected_roots.unauthenticated.len(), MAX_PARKED_REFUSED_FINALITY);
        assert_eq!(engine.rejected_roots.refused, MAX_PARKED_REFUSED_FINALITY as u64 + 1);
        assert!(!engine.rejected_roots.contains(&first_junk.unwrap()), "the oldest is evicted first");
        assert!(engine.rejected_roots.contains(&root), "a configured root is never evicted");
    }

    /// Audit L1-08: unsigned headers naming the rejected root are refused,
    /// but cannot evict a real, verified descendant from the FIFO that keeps
    /// its own children cheap to refuse; and a child of junk is never
    /// counted as authenticated.
    #[test]
    fn unauthenticated_junk_cannot_evict_a_verified_descendant() {
        let _clock = validator_lifecycle::clock_at(32);
        let Fork { mut engine, _dir, fork_point: _, a: _, b } = fork();
        let root = *b[0].block_id().as_bytes();
        let child = *b[1].block_id().as_bytes();
        reject(&mut engine, root);
        assert_eq!(engine.ingest_judged(b[1].clone()), Verdict::Ignore);
        assert!(engine.rejected_roots.descendants.contains(&child), "a real child is remembered as verified");

        for i in 0..(2 * MAX_PARKED_REFUSED_FINALITY as u64) {
            let mut junk = b[1].clone();
            junk.header.slot = 2_000 + i;
            junk.proposer_sig.fill(0);
            assert_eq!(engine.ingest_from_judged(junk, Source::Gossip(Some([0xBA; 32]))), Verdict::Ignore);
        }
        assert!(engine.rejected_roots.descendants.contains(&child), "junk never evicts it");
        assert_eq!(engine.rejected_roots.descendants.len(), 1);
        assert_eq!(engine.rejected_roots.unauthenticated.len(), MAX_PARKED_REFUSED_FINALITY);

        // The grandchild is still refused on its remembered parent, and is
        // itself verified; a header hanging from junk is refused but stays
        // unauthenticated even with a real signature's bytes.
        let honest = Source::Gossip(Some([0x60; 32]));
        assert_eq!(engine.ingest_from_judged(b[2].clone(), honest), Verdict::Ignore);
        assert!(engine.rejected_roots.descendants.contains(b[2].block_id().as_bytes()));
        let junk_parent = *engine.rejected_roots.unauthenticated.back().unwrap();
        let mut under_junk = b[2].clone();
        under_junk.header.parent = junk_parent;
        let under_junk_id = *under_junk.block_id().as_bytes();
        assert_eq!(engine.ingest_judged(under_junk), Verdict::Ignore);
        assert!(!engine.rejected_roots.descendants.contains(&under_junk_id));
        assert!(engine.rejected_roots.unauthenticated.contains(&under_junk_id));
        assert!(!engine.blocks.contains_key(&under_junk_id));
    }

    /// What a restart leaves of the engine before boot reads its log.
    fn restart(engine: &mut Engine) {
        let genesis = engine.manifest.genesis_id();
        engine.state = StateCell::new(engine.manifest.genesis_state());
        engine.chain = vec![(0, genesis)];
        engine.canonical = BTreeSet::from([*genesis.as_bytes()]);
        engine.blocks.clear();
        engine.pool.clear();
        engine.recent_states.clear();
        engine.reorg_anchors = Default::default();
        engine.tx_slot_index.clear();
        engine.tx_slot_index_order.clear();
        engine.finalized_latch = None;
        engine.live = false;
    }

    /// The fork point, then B, as the canonical chain AND the block log.
    fn on_branch_b() -> (Fork, Vec<BlockEnvelope>) {
        let mut fork = fork();
        let engine = &mut fork.engine;
        for env in &fork.b {
            engine.ingest(env.clone());
        }
        assert_eq!(engine.head_id(), fork.b[2].block_id(), "fixture: B is canonical");
        let logged: Vec<BlockEnvelope> = engine.chain[1..]
            .iter()
            .map(|(_, id)| engine.blocks[id.as_bytes()].clone())
            .collect();
        engine.store.flush_rewrite().expect("no pending rewrite");
        assert_eq!(engine.store.read_all().expect("log").len(), logged.len(), "fixture: B is logged");
        (fork, logged)
    }

    /// (c) A boot whose logged canonical tip is on the rejected branch
    /// truncates the log, durably, to the parent of the first rejected
    /// block, ignores a state cache taken on the rejected branch, and then
    /// follows A.
    #[test]
    fn boot_truncates_a_logged_rejected_branch_and_then_follows_a() {
        let _clock = validator_lifecycle::clock_at(32);
        let (Fork { mut engine, _dir, fork_point, a, b }, mut logged) = on_branch_b();
        engine.write_local_cache().expect("a cache generation on branch B");
        // The record says the fork point (height 1) is final: the cut to it
        // is checkable and not below it.
        engine.finalized_latch = Some((1, fork_point));
        engine.persist_finalized_latch();
        restart(&mut engine);
        reject(&mut engine, *b[0].block_id().as_bytes());

        engine.truncate_rejected_log(&mut logged).expect("truncation is allowed above the latch");
        assert_eq!(ids(&logged), vec![fork_point], "only the fork point is left");
        let on_disk = engine.store.read_all().expect("log");
        assert_eq!(ids(&on_disk), vec![fork_point], "and the truncation is on disk");
        assert_eq!(engine.rejected_roots.refused, b.len() as u64);
        assert!(
            engine.restore_local_cache(&mut logged).is_err(),
            "the cache generation taken on branch B no longer matches the log"
        );
        for env in logged.clone() {
            assert!(engine.ingest_replay(env), "the truncated log replays");
        }
        engine.reconcile_finalized_latch().expect("no latch to contradict");
        engine.live = true;
        assert_eq!(*engine.head_id().as_bytes(), fork_point);

        // A second boot with the same flag finds nothing left to truncate.
        let mut again = engine.store.read_all().expect("log");
        engine.truncate_rejected_log(&mut again).expect("idempotent");
        assert_eq!(again.len(), 1);

        engine.ingest(a.clone());
        assert_eq!(engine.head_id(), a.block_id(), "the node follows A");
        for env in &b {
            assert_eq!(engine.ingest_judged(env.clone()), Verdict::Ignore);
        }
        assert_eq!(engine.head_id(), a.block_id());
    }

    /// (d) A truncation that would cut below the stored finality latch is
    /// refused at boot, leaving the log untouched, unless the operator's
    /// rewind override is set.
    #[test]
    fn truncation_below_the_finality_latch_needs_the_override() {
        let _clock = validator_lifecycle::clock_at(32);
        let (Fork { mut engine, _dir, fork_point, a: _, b }, logged) = on_branch_b();
        // The latch is on B's second block (height 3); truncating to the fork
        // point (height 1) cuts below it.
        engine.finalized_latch = Some((3, *b[1].block_id().as_bytes()));
        engine.persist_finalized_latch();
        restart(&mut engine);
        reject(&mut engine, *b[0].block_id().as_bytes());

        let mut attempt = logged.clone();
        let err = engine.truncate_rejected_log(&mut attempt).expect_err("below the latch");
        assert!(crate::ws_boot::is_non_retryable(&err), "a refusal, not a retryable fault: {err}");
        assert!(err.to_string().contains("--allow-finality-rewind"), "{err}");
        assert_eq!(attempt.len(), logged.len(), "nothing dropped");
        assert_eq!(engine.store.read_all().expect("log").len(), logged.len(), "the log is untouched");

        // A root above the latch is truncated without the override.
        reject(&mut engine, *b[2].block_id().as_bytes());
        let mut above = logged.clone();
        engine.truncate_rejected_log(&mut above).expect("at the latch is not below it");
        assert_eq!(above.len(), 3);
        engine.store.rewrite(&logged).expect("restore the full log for the override case");

        // Audit L1-10: the generic override alone no longer cuts finalized
        // history, nor does the confirmation alone, nor a confirmation of a
        // different root; both together, naming this root, do.
        reject(&mut engine, *b[0].block_id().as_bytes());
        engine.finality_rewind_override = true;
        let mut attempt = logged.clone();
        let err = engine.truncate_rejected_log(&mut attempt).expect_err("the override alone is not consent");
        assert!(err.to_string().contains(ENV_REJECT_ROOT_FINALITY_REWIND), "{err}");
        assert_eq!(attempt.len(), logged.len());
        engine.rejected_roots.rewind_confirmed = BTreeSet::from([*b[1].block_id().as_bytes()]);
        assert!(engine.truncate_rejected_log(&mut logged.clone()).is_err(), "another root's confirmation");
        engine.finality_rewind_override = false;
        engine.rejected_roots.rewind_confirmed = BTreeSet::from([*b[0].block_id().as_bytes()]);
        assert!(engine.truncate_rejected_log(&mut logged.clone()).is_err(), "the confirmation alone");
        assert_eq!(engine.store.read_all().expect("log").len(), logged.len(), "the log is still untouched");

        // Both: the cut goes ahead; the latch reconciliation then discards
        // the record, as for any log that ends below it.
        engine.finality_rewind_override = true;
        let mut allowed = logged.clone();
        engine.truncate_rejected_log(&mut allowed).expect("the override allows it");
        assert_eq!(ids(&allowed), vec![fork_point]);
        for env in allowed {
            assert!(engine.ingest_replay(env));
        }
        engine.reconcile_finalized_latch().expect("the override discards the record");
        assert_eq!(engine.stored_finalized_latch().expect("readable"), None);
    }

    /// Audit L1-15: a rejected root that is the release anchor or one of its
    /// logged ancestors is detected; one above it is not.
    #[test]
    fn a_rejected_root_at_or_below_the_release_anchor_is_detected() {
        let _clock = validator_lifecycle::clock_at(32);
        let (Fork { engine: _, _dir, fork_point: _, a: _, b }, logged) = on_branch_b();
        let at = |id: &BlockEnvelope| logged.iter().position(|env| env.block_id() == id.block_id()).unwrap();
        let anchor = *b[1].block_id().as_bytes();
        assert_eq!(rejected_at_or_below_anchor(&logged, at(&b[0]), Some(anchor)), Some(anchor), "an ancestor");
        assert_eq!(rejected_at_or_below_anchor(&logged, at(&b[1]), Some(anchor)), Some(anchor), "the anchor itself");
        assert_eq!(rejected_at_or_below_anchor(&logged, at(&b[2]), Some(anchor)), None, "above it");
        assert_eq!(rejected_at_or_below_anchor(&logged, at(&b[0]), None), None, "no anchor baked");
        assert_eq!(rejected_at_or_below_anchor(&logged, at(&b[0]), Some([0x5A; 32])), None, "an anchor not on this log");
    }

    /// Audit L1-09: with no finality latch record the cut cannot be checked
    /// against finality, so it is refused like a cut below it, and allowed
    /// only with the same explicit consent.
    #[test]
    fn truncation_without_a_latch_record_needs_explicit_consent() {
        let _clock = validator_lifecycle::clock_at(32);
        let (Fork { mut engine, _dir, fork_point, a: _, b }, logged) = on_branch_b();
        restart(&mut engine);
        assert_eq!(engine.stored_finalized_latch().expect("readable"), None, "fixture: no record");
        reject(&mut engine, *b[0].block_id().as_bytes());

        let mut attempt = logged.clone();
        let err = engine.truncate_rejected_log(&mut attempt).expect_err("an unknown latch is not 'no finality'");
        assert!(crate::ws_boot::is_non_retryable(&err), "{err}");
        assert!(err.to_string().contains("no finality latch record"), "{err}");
        assert_eq!(attempt.len(), logged.len());
        assert_eq!(engine.store.read_all().expect("log").len(), logged.len(), "the log is untouched");

        engine.finality_rewind_override = true;
        engine.rejected_roots.rewind_confirmed = BTreeSet::from([*b[0].block_id().as_bytes()]);
        let mut allowed = logged.clone();
        engine.truncate_rejected_log(&mut allowed).expect("explicit consent");
        assert_eq!(ids(&allowed), vec![fork_point]);
    }

    /// (e) The node neither attests to nor proposes on a rejected block,
    /// and drops other validators' votes for one before they can count.
    #[test]
    fn no_vote_and_no_proposal_on_a_rejected_root() {
        let wall = 40;
        let _clock = validator_lifecycle::clock_at(wall);
        let (mut engine, dir) = perf_support::proposing_engine();
        engine.wall_slot = wall;
        for slot in 1..SLOTS_PER_EPOCH {
            engine.propose(slot);
        }
        let fork_point = *engine.head_id().as_bytes();
        engine.propose(SLOTS_PER_EPOCH);
        let a = engine.blocks[engine.head_id().as_bytes()].clone();
        let a_id = *a.block_id().as_bytes();
        give_back(&mut engine, fork_point, std::slice::from_ref(&a));
        engine.propose(SLOTS_PER_EPOCH + 1);
        let b = engine.blocks[engine.head_id().as_bytes()].clone();
        let b_id = *b.block_id().as_bytes();

        // The fixture's single validator sits in one committee of epoch 1.
        let duty_slot = |engine: &Engine| {
            let rolled = engine.rolled_to(1);
            let seed = Engine::seed_for(&rolled, 1);
            let roster = rolled.active_validators();
            (SLOTS_PER_EPOCH..=wall)
                .find(|&s| committees::committee_for_slot(&seed, s, &roster).binary_search(&0).is_ok())
                .expect("fixture: the validator's epoch-1 duty is at or before the wall slot")
        };

        // A real, signed vote for B, as another node following B would send
        // it: signed while B is the head, under separate slashing protection.
        let sub = dir.0.join("sp-foreign");
        std::fs::create_dir_all(&sub).expect("slashing protection dir");
        let mut foreign_protection = SlashingProtection::open(&sub).expect("slashing protection");
        std::mem::swap(&mut engine.slashprot, &mut foreign_protection);
        engine.attest_for(duty_slot(&engine), wall);
        std::mem::swap(&mut engine.slashprot, &mut foreign_protection);
        let foreign = engine.pool.values().find(|att| att.data.head == b_id).cloned()
            .expect("fixture: a signed vote for B");
        engine.pool.clear();
        give_back(&mut engine, fork_point, std::slice::from_ref(&b));

        reject(&mut engine, b_id);
        engine.ingest(a.clone());
        assert_eq!(engine.head_id(), a.block_id());
        assert_eq!(engine.ingest_judged(b.clone()), Verdict::Ignore);

        // The vote for the rejected block never reaches the fork-choice pool,
        // nor is it held waiting for a block that will never land here.
        engine.on_attestation(foreign.clone(), Origin::none(), 1);
        assert!(engine.pool.is_empty());
        assert_eq!(engine.att_pool.pending_for_root(&b_id), 0, "not held either");
        // Control: without the flag the same vote is held for B.
        engine.rejected_roots = RejectedRoots::default();
        engine.on_attestation(foreign, Origin::none(), 1);
        assert_eq!(engine.att_pool.pending_for_root(&b_id), 1, "fixture: the vote is a real one");
        reject(&mut engine, b_id);

        // Our own duties: the vote is for A, and so is the next block's parent.
        engine.attest_for(duty_slot(&engine), wall);
        let own: Vec<&Attestation> = engine.pool.values().collect();
        assert_eq!(own.len(), 1, "the validator attested");
        assert_eq!(own[0].data.head, a_id);
        assert_ne!(own[0].data.target_root, b_id);
        engine.propose(wall - 1);
        let head = engine.blocks[engine.head_id().as_bytes()].clone();
        assert_eq!(head.header.slot, wall - 1, "the validator proposed");
        assert_eq!(head.header.parent, a_id, "built on A, never on the rejected root");
    }
}
