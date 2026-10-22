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

use super::*;
use bloch_finality_cert::{Certificate, Link, RegistryProof, Vote};

/// How many checkpoint registry proofs to retain. `0` disables the feature
/// (and its once-per-epoch cost) entirely.
pub(super) fn finality_cert_epochs() -> usize {
    static N: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *N.get_or_init(|| {
        std::env::var("BLOCH_FINALITY_CERT_EPOCHS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(16)
            .min(4096)
    })
}

/// Built certificates are immutable once their epoch is finalized (the
/// finality latch forbids rewinding below it), so a few are cached.
const CERT_CACHE: usize = 8;

/// Most ancestry headers one certificate may carry.
const MAX_ANCESTRY: usize = bloch_finality_cert::MAX_ANCESTRY;

#[derive(Default)]
pub(super) struct FinalityCertStore {
    /// `(checkpoint block id, registry proof)`, oldest first.
    registry: VecDeque<([u8; 32], Arc<RegistryProof>)>,
    /// `((epoch, block, set source epoch), reply)`, oldest first.
    cache: VecDeque<((u64, Option<[u8; 32]>, u64), Json)>,
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
        let Some(proof) = bloch_finality_cert::registry_proof(&state, header) else {
            // The retained post-state does not commit to the header's root
            // (e.g. an unbound genesis header). Nothing to serve; not an error.
            return;
        };
        self.finality_certs.registry.push_back((pid, Arc::new(proof)));
        while self.finality_certs.registry.len() > cap {
            self.finality_certs.registry.pop_front();
        }
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

    pub(super) fn finality_certificate(
        &mut self,
        epoch: Option<u64>,
        block: Option<[u8; 32]>,
        set_source_epoch: Option<u64>,
    ) -> RpcResult {
        let finalized = self.state.finality().finalized.epoch;
        let e = epoch.unwrap_or(finalized);
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
        let root = self.checkpoint_root(e);
        let next_root = self.checkpoint_root(e + 1);

        // Justifying link: the source with the most votes for (e, root).
        let v_e = self.canonical_votes(e)?;
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
        let v_next = self.canonical_votes(e + 1)?;
        let l1 = Self::link_from(&v_next, (e, root), (e + 1, next_root));
        if l1.votes.is_empty() {
            return Err(RpcError::new(
                rpc::BLOCK_NOT_FOUND,
                format!("epoch {e} was not finalized by the consecutive link {e}→{}; ask for a later finalized checkpoint", e + 1),
            ));
        }

        let src_root = self.checkpoint_root(src_epoch);
        let registry = self
            .finality_certs
            .registry
            .iter()
            .find(|(id, _)| *id == src_root)
            .map(|(_, p)| Arc::clone(p))
            .ok_or_else(|| {
                RpcError::unavailable(format!(
                    "the registry proof for set-source epoch {src_epoch} (block {}) is not retained \
                     on this node (it keeps the last {} checkpoints; BLOCH_FINALITY_CERT_EPOCHS)",
                    crate::codec::hex8(&src_root),
                    finality_cert_epochs()
                ))
            })?;

        let checkpoint_header = self
            .envelope_by_id(&root)
            .map(|e| e.header.clone())
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
                    let env = self
                        .envelope_by_id(&cur)
                        .ok_or_else(|| RpcError::new(rpc::BLOCK_NOT_FOUND, "`block` is not an ancestor of the checkpoint"))?;
                    let h = env.header.clone();
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
        Ok(reply)
    }
}
