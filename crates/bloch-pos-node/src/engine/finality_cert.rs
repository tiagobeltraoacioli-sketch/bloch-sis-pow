// SPDX-License-Identifier: AGPL-3.0-or-later

//! `getfinalitycertificate` — the node half of `bloch-finality-cert`.
//!
//! READ-ONLY with respect to consensus. Two things happen here:
//!
//! 1. At every epoch boundary the node crosses on its canonical chain, the
//!    registry of the boundary's checkpoint block (the last block before the
//!    new epoch — `Engine::checkpoint_root`'s convention, the root attesters
//!    vote) is proven against that block's committed `state_root` and kept in
//!    a small ring ([`finality_cert_epochs`] entries, default 16). This is the
//!    only per-block work, it runs once per epoch, reads the post-state the
//!    reorg ring already holds, and is skipped entirely when the ring is
//!    configured to 0 (`BLOCH_FINALITY_CERT_EPOCHS=0`).
//! 2. On request, the votes for the two links are collected from canonical
//!    block bodies (the signatures the transition already verified when it
//!    admitted them), deduplicated, equivocators dropped, and assembled with
//!    the retained registry proof and the requested ancestry.
//!
//! Nothing here feeds a consensus input. A certificate this node cannot build
//! (registry not retained, epoch not finalized) is an RPC error, never a
//! change in behaviour.
//!
//! `getlcproof` is the same certificate plus the state proofs a client needs
//! to judge it after HF1 and after KES binds (`bloch_finality_cert::lc_proof`):
//! the finality leaf and the 0x22 entries, proven at the same boundary, from the
//! same tree, as the registry.

use super::*;
use bloch_finality_cert::lc_proof::{self, CheckpointExtensions, MainnetProof};
use bloch_finality_cert::{Certificate, Link, RegistryProof, Vote};

/// Most checkpoints the ring may hold, whatever the environment asks.
const MAX_CERT_EPOCHS: usize = 4096;

/// Checkpoints retained when `BLOCH_FINALITY_CERT_EPOCHS` is unset or invalid.
const DEFAULT_CERT_EPOCHS: usize = 16;

/// The smallest retention that lets a client hop across the verifier's whole
/// default bound (256 epochs). A prover's follower needs at least this.
const PROVER_CERT_EPOCHS: usize = 300;

/// `BLOCH_FINALITY_CERT_EPOCHS` as the ring size, with what an operator should
/// be told about the value. Never refuses to start: this is an RPC-only setting.
pub(super) fn parse_cert_epochs(raw: Option<&str>) -> (usize, Option<String>) {
    let Some(raw) = raw else {
        return (DEFAULT_CERT_EPOCHS, None);
    };
    match raw.trim().parse::<usize>() {
        Ok(n) if n > MAX_CERT_EPOCHS => (
            MAX_CERT_EPOCHS,
            Some(format!("BLOCH_FINALITY_CERT_EPOCHS={n} is above the limit; using {MAX_CERT_EPOCHS}")),
        ),
        Ok(n) => (n, None),
        Err(_) => (
            DEFAULT_CERT_EPOCHS,
            Some(format!("BLOCH_FINALITY_CERT_EPOCHS={raw:?} is not a number; using {DEFAULT_CERT_EPOCHS}")),
        ),
    }
}

/// How many checkpoint registry proofs to retain. `0` disables the feature
/// (and its once-per-epoch cost) entirely.
pub(super) fn finality_cert_epochs() -> usize {
    static N: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *N.get_or_init(|| parse_cert_epochs(std::env::var("BLOCH_FINALITY_CERT_EPOCHS").ok().as_deref()).0)
}

/// Says at boot what the ring holds, so a mistyped setting on a prover's
/// follower shows in the log and not in the first refused hop.
pub(super) fn announce_finality_cert_retention() {
    let raw = std::env::var("BLOCH_FINALITY_CERT_EPOCHS").ok();
    if let Some(warning) = parse_cert_epochs(raw.as_deref()).1 {
        eprintln!("finality-cert: WARNING: {warning}");
    }
    let n = finality_cert_epochs();
    println!(
        "finality-cert: retaining {n} checkpoint proofs (BLOCH_FINALITY_CERT_EPOCHS; a prover's \
         follower needs at least {PROVER_CERT_EPOCHS}; the ring is rebuilt only from blocks \
         applied in this boot, so a boot from the state cache starts it near empty)"
    );
}

/// Built certificates are immutable once their epoch is finalized (the
/// finality latch forbids rewinding below it), so a few are cached.
const CERT_CACHE: usize = 8;

/// Refusals remembered, so a repeated request that cannot be answered costs
/// a lookup and no block read. An entry is a key and a short message.
const REFUSAL_CACHE: usize = 256;

/// Certificates assembled from the block log per wall slot, across all
/// callers. Assembly reads up to two epochs of blocks on the consensus
/// thread and the method needs no authentication, so the work one slot can be
/// made to do is bounded here. Cached answers and refusals decided before the
/// first read are not counted. A light client at the head needs one assembly
/// per epoch; a prover's follower catching up over the verifier's whole
/// 256-epoch bound is served in 32 slots, retrying on [`rpc::NODE_UNAVAILABLE`].
const CERT_BUILDS_PER_SLOT: u32 = 8;

/// Most ancestry headers one certificate may carry.
const MAX_ANCESTRY: usize = bloch_finality_cert::MAX_ANCESTRY;

#[derive(Default)]
pub(super) struct FinalityCertStore {
    /// `(checkpoint block id, registry proof)`, oldest first.
    pub(super) registry: VecDeque<([u8; 32], Arc<RegistryProof>)>,
    /// `(checkpoint block id, extensions)`, parallel to `registry`.
    pub(super) extensions: VecDeque<([u8; 32], Arc<CheckpointExtensions>)>,
    /// `((epoch, block, set source epoch), reply)`, oldest first.
    pub(super) cache: VecDeque<((u64, Option<[u8; 32]>, u64), Json)>,
    /// The same, for `getlcproof` (its `set_source_epoch` as requested).
    lc_cache: VecDeque<((u64, Option<[u8; 32]>, Option<u64>), Json)>,
    /// `(epoch, justifying source epoch)` of certificates already built. The
    /// default set source of a finalized epoch never changes, so a repeated
    /// request that names none can be answered from `cache` before any block
    /// is read back from the log.
    pub(super) default_source: VecDeque<(u64, u64)>,
    /// `((epoch, block, set source epoch as requested), head, refusal)`,
    /// oldest first. `head` is `None` for a refusal that can never change
    /// (every block it was decided from is below the finality latch) and
    /// otherwise the head it was decided at, the only one it is replayed for.
    refused: VecDeque<((u64, Option<[u8; 32]>, Option<u64>), Option<[u8; 32]>, RpcError)>,
    /// `(wall slot, assemblies started in it)`; see [`CERT_BUILDS_PER_SLOT`].
    pub(super) builds: (u64, u32),
    /// Set when the last assembly failed on a block read: a fault of this
    /// node's disk, not a property of the request, and so never remembered.
    read_failed: bool,
    /// Vote scans (one epoch of blocks read back each) since boot.
    pub(super) vote_scans: u64,
}

impl Engine {
    /// Called right after a canonical block is appended to `self.chain`. If
    /// that block opened a new epoch, its parent is a checkpoint block: prove
    /// the parent's registry against its committed root and retain it.
    pub(super) fn note_checkpoint_registry(&mut self) {
        let cap = finality_cert_epochs();
        if cap == 0 || self.chain.len() < 2 {
            return;
        }
        let (child_slot, _) = self.chain[self.chain.len() - 1];
        let (parent_slot, parent_id) = self.chain[self.chain.len() - 2];
        if epoch_of(child_slot) == epoch_of(parent_slot) {
            return;
        }
        let pid = *parent_id.as_bytes();
        if self.finality_certs.registry.iter().any(|(id, _)| *id == pid) {
            return;
        }
        let Some(state) =
            self.recent_states.iter().find(|(id, _)| *id == pid).map(|(_, s)| Arc::clone(s))
        else {
            return;
        };
        let Some(header) = self.envelope_by_id(&pid).map(|e| e.header.clone()) else {
            return;
        };
        let Some((proof, extensions)) = lc_proof::checkpoint_proofs(&state, header) else {
            // The retained post-state does not commit to the header's root
            // (e.g. an unbound genesis header). Nothing to serve; not an error.
            return;
        };
        self.finality_certs.registry.push_back((pid, Arc::new(proof)));
        self.finality_certs.extensions.push_back((pid, Arc::new(extensions)));
        while self.finality_certs.registry.len() > cap {
            self.finality_certs.registry.pop_front();
            self.finality_certs.extensions.pop_front();
        }
    }

    /// The header of a stored block, without reading the block log: a
    /// released (hollow) block keeps its header in memory. Falls back to the
    /// full lookup only for a block this node does not hold in `blocks`.
    fn header_by_id(&self, id: &[u8; 32]) -> Option<bloch_pos_committee::header::BlockHeaderV4> {
        if self.chain[0].1.as_bytes() == id {
            return Some(self.manifest.genesis_header());
        }
        if let Some(env) = self.blocks.get(id) {
            return Some(env.header.clone());
        }
        self.envelope_by_id(id).map(|e| e.header.clone())
    }

    /// Canonical block ids in `epoch`, ascending slot.
    fn canonical_ids_in_epoch(&self, epoch: u64) -> Vec<[u8; 32]> {
        let first = epoch.saturating_mul(SLOTS_PER_EPOCH);
        let end = first.saturating_add(SLOTS_PER_EPOCH);
        let start = self.chain.partition_point(|(s, _)| *s < first);
        self.chain[start..]
            .iter()
            .take_while(|(s, _)| *s < end)
            .map(|(_, id)| *id.as_bytes())
            .collect()
    }

    /// Every distinct epoch-`t` vote in canonical bodies of epoch `t`, keyed
    /// by validator. A validator with two different votes for target `t` is
    /// an equivocator: the chain counts it for no target, so neither does a
    /// certificate.
    fn canonical_votes(&self, t: u64) -> Result<BTreeMap<u32, (AttestationData, Vec<u8>)>, RpcError> {
        let mut seen: BTreeMap<u32, (AttestationData, Vec<u8>)> = BTreeMap::new();
        let mut equivocators: BTreeSet<u32> = BTreeSet::new();
        for id in self.canonical_ids_in_epoch(t) {
            let env = self.envelope_by_id(&id).ok_or_else(|| {
                RpcError::unavailable(format!(
                    "canonical block {} of epoch {t} is not readable on this node",
                    crate::codec::hex8(&id)
                ))
            })?;
            for att in &env.body.attestations {
                if att.data.target_epoch != t || epoch_of(att.data.slot) != t {
                    continue;
                }
                match seen.get(&att.validator) {
                    None => {
                        seen.insert(att.validator, (att.data, att.signature.clone()));
                    }
                    Some((d, _)) if *d != att.data => {
                        equivocators.insert(att.validator);
                    }
                    Some(_) => {}
                }
            }
        }
        for v in equivocators {
            seen.remove(&v);
        }
        Ok(seen)
    }

    fn link_from(
        votes: &BTreeMap<u32, (AttestationData, Vec<u8>)>,
        source: (u64, [u8; 32]),
        target: (u64, [u8; 32]),
    ) -> Link {
        Link {
            source_epoch: source.0,
            source_root: source.1,
            target_epoch: target.0,
            target_root: target.1,
            votes: votes
                .iter()
                .filter(|(_, (d, _))| {
                    (d.source_epoch, d.source_root) == source && (d.target_epoch, d.target_root) == target
                })
                .map(|(v, (d, sig))| Vote { validator: *v, slot: d.slot, head: d.head, signature: sig.clone() })
                .collect(),
        }
    }

    /// The registry proof retained for checkpoint block `id`, if any.
    fn retained_registry(&self, id: &[u8; 32]) -> Option<Arc<RegistryProof>> {
        self.finality_certs.registry.iter().find(|(x, _)| x == id).map(|(_, p)| Arc::clone(p))
    }

    fn registry_not_retained(src_epoch: u64, src_root: &[u8; 32]) -> RpcError {
        RpcError::unavailable(format!(
            "the registry proof for set-source epoch {src_epoch} (block {}) is not retained \
             on this node (it keeps the last {} checkpoints; BLOCH_FINALITY_CERT_EPOCHS)",
            crate::codec::hex8(src_root),
            finality_cert_epochs()
        ))
    }

    pub(super) fn finality_certificate(
        &mut self,
        epoch: Option<u64>,
        block: Option<[u8; 32]>,
        set_source_epoch: Option<u64>,
    ) -> RpcResult {
        let finalized = self.state.finality().finalized.epoch;
        let e = epoch.unwrap_or(finalized);
        let key = (e, block, set_source_epoch);
        let head = self.chain.last().map(|(_, id)| *id.as_bytes());
        if let Some((_, _, err)) = self
            .finality_certs
            .refused
            .iter()
            .find(|(k, at, _)| *k == key && (at.is_none() || *at == head))
        {
            return Err(err.clone());
        }
        let scans_before = self.finality_certs.vote_scans;
        self.finality_certs.read_failed = false;
        let result = self.assemble_finality_certificate(e, finalized, block, set_source_epoch);
        if let Err(err) = &result {
            // Only a refusal that cost block reads is worth remembering, and
            // not the one that says "ask again shortly".
            if self.finality_certs.vote_scans != scans_before && !self.finality_certs.read_failed {
                // Blocks of epochs `e` and `e + 1` are all at or below the
                // finalized checkpoint once `e + 1 < finalized`; the registry
                // ring only ever loses its oldest entries. Such a refusal is
                // permanent. A younger one holds for this head only.
                let permanent = e.saturating_add(1) < finalized;
                self.finality_certs.refused.retain(|(k, _, _)| *k != key);
                self.finality_certs.refused.push_back((key, if permanent { None } else { head }, err.clone()));
                while self.finality_certs.refused.len() > REFUSAL_CACHE {
                    self.finality_certs.refused.pop_front();
                }
            }
        }
        result
    }

    fn assemble_finality_certificate(
        &mut self,
        e: u64,
        finalized: u64,
        block: Option<[u8; 32]>,
        set_source_epoch: Option<u64>,
    ) -> RpcResult {
        if e == 0 {
            return Err(RpcError::invalid_params(
                "epoch 0 is the genesis root of trust; it has no certificate",
            ));
        }
        if e > finalized {
            return Err(RpcError::new(
                rpc::BLOCK_NOT_FOUND,
                format!("epoch {e} is not finalized on this node (finalized epoch {finalized})"),
            ));
        }
        // Everything below reads released blocks back from the log on the
        // consensus thread, and this method is reachable without
        // authentication. Answer a repeated request from the cache, and
        // refuse a `block` this certificate could never carry, before the
        // first read.
        let known_source = set_source_epoch.or_else(|| {
            self.finality_certs.default_source.iter().find(|(k, _)| *k == e).map(|(_, s)| *s)
        });
        if let Some(src_epoch) = known_source {
            let key = (e, block, src_epoch);
            if let Some((_, j)) = self.finality_certs.cache.iter().find(|(k, _)| *k == key) {
                return Ok(j.clone());
            }
        }
        let root = self.checkpoint_root(e);
        let next_root = self.checkpoint_root(e + 1);
        if let Some(want) = block.filter(|want| *want != root) {
            // The canonical chain is linear, so a canonical block is an
            // ancestor of the checkpoint exactly when it sits below it, and
            // the ancestry the certificate would carry is their height
            // difference. Both are index lookups.
            let Some(want_height) = self.height_of(&want) else {
                return Err(RpcError::new(rpc::BLOCK_NOT_FOUND, "`block` is not canonical on this node"));
            };
            let root_height = self
                .height_of(&root)
                .ok_or_else(|| RpcError::unavailable("checkpoint block not readable"))?;
            if want_height >= root_height {
                return Err(RpcError::new(rpc::BLOCK_NOT_FOUND, "`block` is not an ancestor of the checkpoint"));
            }
            if root_height - want_height > MAX_ANCESTRY as u64 {
                return Err(RpcError::invalid_params(format!(
                    "`block` is more than {MAX_ANCESTRY} blocks below the checkpoint; use an older epoch"
                )));
            }
        }

        // The registry proof decides whether a certificate can be built at
        // all, and looking it up is an index walk: settle it before a block
        // is read. A named set source is checked exactly. Without one the
        // set source is the justifying source, some epoch before `e`, whose
        // checkpoint block therefore sits below epoch `e`: if no retained
        // proof is that old, none can be the one needed.
        match set_source_epoch {
            Some(src_epoch) => {
                if src_epoch >= e {
                    return Err(RpcError::invalid_params("`set_source_epoch` must be before `epoch`"));
                }
                let src_root = self.checkpoint_root(src_epoch);
                if self.retained_registry(&src_root).is_none() {
                    return Err(Self::registry_not_retained(src_epoch, &src_root));
                }
            }
            None => {
                let first = first_slot_of_epoch(e).unwrap_or(u64::MAX);
                if !self.finality_certs.registry.iter().any(|(_, p)| p.header.slot < first) {
                    return Err(RpcError::unavailable(format!(
                        "no registry proof for a set source before epoch {e} is retained on this \
                         node (it keeps the last {} checkpoints; BLOCH_FINALITY_CERT_EPOCHS)",
                        finality_cert_epochs()
                    )));
                }
            }
        }
        let slot = self.wall_slot();
        if self.finality_certs.builds.0 != slot {
            self.finality_certs.builds = (slot, 0);
        }
        if self.finality_certs.builds.1 >= CERT_BUILDS_PER_SLOT {
            return Err(RpcError::unavailable(format!(
                "this node assembles at most {CERT_BUILDS_PER_SLOT} finality certificates per slot; retry in the next slot"
            )));
        }
        self.finality_certs.builds.1 += 1;

        // Justifying link: the source with the most votes for (e, root).
        self.finality_certs.vote_scans += 1;
        let v_e = self.canonical_votes(e).inspect_err(|_| self.finality_certs.read_failed = true)?;
        let mut by_source: BTreeMap<(u64, [u8; 32]), usize> = BTreeMap::new();
        for (d, _) in v_e.values() {
            if d.target_root == root && d.source_epoch < e {
                *by_source.entry((d.source_epoch, d.source_root)).or_insert(0) += 1;
            }
        }
        let Some((&source, _)) = by_source.iter().max_by_key(|(k, n)| (**n, k.0)) else {
            return Err(RpcError::new(
                rpc::BLOCK_NOT_FOUND,
                format!("no canonical votes justify epoch {e}; it is final only as an ancestor of a later checkpoint — ask for that one"),
            ));
        };
        let src_epoch = set_source_epoch.unwrap_or(source.0);
        if src_epoch >= e {
            return Err(RpcError::invalid_params("`set_source_epoch` must be before `epoch`"));
        }
        let key = (e, block, src_epoch);
        if let Some((_, j)) = self.finality_certs.cache.iter().find(|(k, _)| *k == key) {
            return Ok(j.clone());
        }

        let l0 = Self::link_from(&v_e, source, (e, root));
        self.finality_certs.vote_scans += 1;
        let v_next = self.canonical_votes(e + 1).inspect_err(|_| self.finality_certs.read_failed = true)?;
        let l1 = Self::link_from(&v_next, (e, root), (e + 1, next_root));
        if l1.votes.is_empty() {
            return Err(RpcError::new(
                rpc::BLOCK_NOT_FOUND,
                format!("epoch {e} was not finalized by the consecutive link {e}→{}; ask for a later finalized checkpoint", e + 1),
            ));
        }

        let src_root = self.checkpoint_root(src_epoch);
        let registry = self
            .retained_registry(&src_root)
            .ok_or_else(|| Self::registry_not_retained(src_epoch, &src_root))?;

        let checkpoint_header = self
            .header_by_id(&root)
            .ok_or_else(|| RpcError::unavailable("checkpoint block not readable"))?;

        let mut ancestry = Vec::new();
        if let Some(want) = block {
            if want != root {
                if !self.canonical.contains(&want) {
                    return Err(RpcError::new(rpc::BLOCK_NOT_FOUND, "`block` is not canonical on this node"));
                }
                let mut cur = checkpoint_header.parent;
                loop {
                    if ancestry.len() >= MAX_ANCESTRY {
                        return Err(RpcError::invalid_params(format!(
                            "`block` is more than {MAX_ANCESTRY} blocks below the checkpoint; use an older epoch"
                        )));
                    }
                    let h = self
                        .header_by_id(&cur)
                        .ok_or_else(|| RpcError::new(rpc::BLOCK_NOT_FOUND, "`block` is not an ancestor of the checkpoint"))?;
                    let done = cur == want;
                    let genesis = cur == *self.chain[0].1.as_bytes();
                    cur = h.parent;
                    ancestry.push(h);
                    if done {
                        break;
                    }
                    if genesis {
                        return Err(RpcError::new(rpc::BLOCK_NOT_FOUND, "`block` is not an ancestor of the checkpoint"));
                    }
                }
            }
        }

        let cert = Certificate { checkpoint_header, registry: (*registry).clone(), links: [l0, l1], ancestry };
        let bytes = cert.encode();
        let reply = Json::Obj(vec![
            ("epoch".into(), Json::u(e)),
            ("root".into(), Json::s(crate::codec::hex32(&root))),
            ("checkpoint_slot".into(), Json::u(cert.checkpoint_header.slot)),
            ("set_source_epoch".into(), Json::u(src_epoch)),
            ("set_source_root".into(), Json::s(crate::codec::hex32(&src_root))),
            ("justifying_source_epoch".into(), Json::u(source.0)),
            ("votes".into(), Json::Arr(vec![Json::u(cert.links[0].votes.len() as u64), Json::u(cert.links[1].votes.len() as u64)])),
            ("registry_records".into(), Json::u(cert.registry.records.len() as u64)),
            ("ancestry".into(), Json::u(cert.ancestry.len() as u64)),
            ("bytes".into(), Json::u(bytes.len() as u64)),
            ("format".into(), Json::s("BLOCHFC1")),
            ("certificate".into(), Json::s(crate::codec::hex(&bytes))),
        ]);
        self.finality_certs.cache.push_back((key, reply.clone()));
        while self.finality_certs.cache.len() > CERT_CACHE {
            self.finality_certs.cache.pop_front();
        }
        if set_source_epoch.is_none() && !self.finality_certs.default_source.iter().any(|(k, _)| *k == e) {
            self.finality_certs.default_source.push_back((e, src_epoch));
            while self.finality_certs.default_source.len() > CERT_CACHE {
                self.finality_certs.default_source.pop_front();
            }
        }
        Ok(reply)
    }

    /// `getlcproof`: the certificate of `epoch` with its extensions, as one
    /// `BLCLMP01` blob. The certificate comes from `finality_certificate`
    /// unchanged, apart from dropping votes its set source cannot judge.
    pub(super) fn lc_proof(
        &mut self,
        epoch: Option<u64>,
        set_source_epoch: Option<u64>,
        block: Option<[u8; 32]>,
    ) -> RpcResult {
        let e = epoch.unwrap_or(self.state.finality().finalized.epoch);
        let key = (e, block, set_source_epoch);
        if let Some((_, j)) = self.finality_certs.lc_cache.iter().find(|(k, _)| *k == key) {
            return Ok(j.clone());
        }
        let reply = self.finality_certificate(Some(e), block, set_source_epoch)?;
        let field = |name: &str| reply.get(name).cloned().ok_or_else(|| RpcError::unavailable(format!("certificate reply has no `{name}`")));
        let cert_hex = field("certificate")?;
        let cert_bytes = cert_hex
            .as_str()
            .and_then(bloch_finality_cert::from_hex)
            .ok_or_else(|| RpcError::unavailable("certificate reply is not hex"))?;
        let mut cert = Certificate::decode(&cert_bytes).map_err(|e| RpcError::unavailable(format!("own certificate: {e}")))?;
        let set_source_id = *bloch_pos_committee::header::BlockId::of(&cert.registry.header).as_bytes();
        lc_proof::retain_provable_votes(&mut cert);
        let voters: BTreeSet<u32> = cert.links.iter().flat_map(|l| l.votes.iter().map(|v| v.validator)).collect();
        let extensions_of = |id: &[u8; 32]| self.finality_certs.extensions.iter().find(|(x, _)| x == id).map(|(_, x)| x);
        let mut ext = extensions_of(&set_source_id).map(|x| x.for_voters(&voters)).unwrap_or_default();
        // While the set source commits no bind, the finalizing link is
        // judged by the checkpoint's own bind leaf (or its absence): see
        // `lc_proof::KesProofs`. Attached only from the KES gate on, so
        // earlier proofs keep the `BLCLMP01` encoding.
        let checkpoint_id = cert.root();
        let checkpoint_kes = extensions_of(&checkpoint_id).and_then(|x| x.kes.clone());
        ext.kes = ext.kes.take().map(|k| k.with_checkpoint_bind(checkpoint_kes.as_ref(), e.saturating_add(1)));
        // Static votes this set source cannot vouch for any more (the voter
        // may have registered a KES key since) would get the proof refused.
        if let Some(k) = &ext.kes {
            lc_proof::retain_fresh_static_votes(&mut cert, k);
        }
        let votes = [cert.links[0].votes.len() as u64, cert.links[1].votes.len() as u64];
        let has_set = |fs: &lc_proof::FinalitySetProof| {
            bloch_finality_cert::state::FinalityLeaf::decode(&fs.leaf).is_some_and(|l| l.finality_set.is_some())
        };
        let weights = if ext.finality_set.as_ref().is_some_and(has_set) { "frozen" } else { "bond" };
        let kes_json = match &ext.kes {
            None => Json::Null,
            Some(k) => Json::Obj(vec![
                ("enforced_from".into(), k.enforced.0.map_or(Json::Null, Json::u)),
                ("entries".into(), Json::u(k.entries.iter().filter(|(_, b, _)| b.is_some()).count() as u64)),
                ("absent".into(), Json::u(k.entries.iter().filter(|(_, b, _)| b.is_none()).count() as u64)),
            ]),
        };
        let proof = MainnetProof { cert, finality_set: ext.finality_set, kes: ext.kes };
        let bytes = proof.encode();
        let out = Json::Obj(vec![
            ("epoch".into(), Json::u(e)),
            ("root".into(), field("root")?),
            ("checkpoint_slot".into(), field("checkpoint_slot")?),
            ("set_source_epoch".into(), field("set_source_epoch")?),
            ("set_source_root".into(), field("set_source_root")?),
            ("justifying_source_epoch".into(), field("justifying_source_epoch")?),
            ("votes".into(), Json::Arr(votes.iter().map(|v| Json::u(*v)).collect())),
            ("weights".into(), Json::s(weights)),
            ("kes".into(), kes_json),
            ("ancestry".into(), field("ancestry")?),
            ("bytes".into(), Json::u(bytes.len() as u64)),
            ("format".into(), Json::s(if bytes.starts_with(lc_proof::PROOF_MAGIC_V2) { "BLCLMP02" } else { "BLCLMP01" })),
            ("proof".into(), Json::s(crate::codec::hex(&bytes))),
        ]);
        self.finality_certs.lc_cache.push_back((key, out.clone()));
        while self.finality_certs.lc_cache.len() > CERT_CACHE {
            self.finality_certs.lc_cache.pop_front();
        }
        Ok(out)
    }
}
