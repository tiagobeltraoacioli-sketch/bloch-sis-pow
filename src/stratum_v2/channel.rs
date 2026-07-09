// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Sprint 10-beta: Mining channel state.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use crate::stratum::Template;

/// Sprint 10-epsilon Phase 2: maximum jobs cached per channel.
/// Each NewMiningJob push stores one Sv2CachedJob; when the ring
/// is full, the oldest is evicted. Late shares against evicted
/// jobs surface as ShareValidation::StaleJob (unchanged semantics).
pub const MAX_JOBS_PER_CHANNEL: usize = 16;

/// Sprint 10-epsilon Phase 2: per-channel cached job record.
///
/// Captured at NewMiningJob push time, consumed at SubmitShares
/// time to reconstruct the exact 80-byte mining header the miner
/// hashed against. The invariant is byte-identical reconstruction:
/// template + extranonce_prefix + (nonce, ntime, version) the miner
/// echoes back must rebuild the same merkle_root stored here.
///
/// `template` is held via Arc because all channels on the same
/// session share the same Template per tip event — only the
/// extranonce_prefix and derived merkle_root differ per channel.
///
/// Debug impl is manual and elides the Template body (which would
/// otherwise emit ~10 KB of coinbase bytes + mempool transactions
/// per log line). The logged shape is a one-liner with job_id,
/// extranonce prefix hex, merkle_root prefix, and template height.
#[derive(Clone)]
pub struct Sv2CachedJob {
    /// Server-assigned job_id, matching NewMiningJob.job_id
    /// and future SubmitSharesStandard.job_id.
    pub job_id: u32,

    /// The full V1-shape Template used to generate this job.
    /// Shared across channels on the same tip event.
    pub template: Arc<Template>,

    /// The 8-byte extranonce prefix used for merkle_root
    /// computation for this channel. Stored as [u8; 8]
    /// (post-CHECKME-4b-extranonce truncation) so
    /// reconstruction is deterministic.
    pub extranonce_prefix: [u8; 8],

    /// The merkle_root already shipped to the miner in
    /// NewMiningJob. Stored verbatim so ε.5 reconstruction
    /// can match byte-for-byte without recomputing.
    pub merkle_root: [u8; 32],
}

impl std::fmt::Debug for Sv2CachedJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sv2CachedJob")
            .field("job_id", &self.job_id)
            .field("extranonce_prefix", &format_args!("{:02x?}", self.extranonce_prefix))
            .field("merkle_root_prefix",
                   &format_args!("{:02x}{:02x}{:02x}{:02x}..",
                                 self.merkle_root[0], self.merkle_root[1],
                                 self.merkle_root[2], self.merkle_root[3]))
            .field("template_height", &self.template.height)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct ChannelState {
    pub channel_id:         u32,
    pub user_identity:      String,
    pub nominal_hash_rate:  f32,
    pub current_target:     [u8; 32],
    pub extranonce_prefix:  Vec<u8>,
    pub last_job_id:        Option<u32>,
    pub group_channel_id:   u32,
    /// Sprint 10-epsilon Phase 2: ring buffer of recent jobs
    /// pushed to this channel. Bounded by MAX_JOBS_PER_CHANNEL.
    /// Populated on NewMiningJob push, queried on SubmitShares.
    pub recent_jobs:        VecDeque<Sv2CachedJob>,
}

impl ChannelState {
    pub fn new(
        channel_id:         u32,
        user_identity:      String,
        nominal_hash_rate:  f32,
        current_target:     [u8; 32],
        extranonce_prefix:  Vec<u8>,
    ) -> Self {
        Self {
            channel_id,
            user_identity,
            nominal_hash_rate,
            current_target,
            extranonce_prefix,
            last_job_id:        None,
            group_channel_id:   0,
            recent_jobs:        VecDeque::with_capacity(MAX_JOBS_PER_CHANNEL),
        }
    }

    /// Sprint 10-epsilon Phase 2: record a newly-pushed job.
    /// Updates last_job_id and appends to the recent_jobs ring.
    /// Evicts the oldest entry when the ring is at capacity.
    pub fn push_job(&mut self, job: Sv2CachedJob) {
        self.last_job_id = Some(job.job_id);
        if self.recent_jobs.len() >= MAX_JOBS_PER_CHANNEL {
            self.recent_jobs.pop_front();
        }
        self.recent_jobs.push_back(job);
    }

    /// Sprint 10-epsilon Phase 2: look up a cached job by id.
    /// Used by the SubmitShares dispatch path to recover the
    /// exact Template + merkle_root used at job-push time, so
    /// the 80-byte header can be reconstructed byte-identically
    /// for PoW validation (ε.5).
    pub fn find_job(&self, job_id: u32) -> Option<&Sv2CachedJob> {
        self.recent_jobs.iter().find(|j| j.job_id == job_id)
    }
}

pub const MAX_CHANNELS_PER_SESSION: usize = 64;

#[derive(Debug, Default)]
pub struct ChannelRegistry {
    next_id:    AtomicU32,
    channels:   HashMap<u32, ChannelState>,
}

impl ChannelRegistry {
    pub fn new() -> Self {
        Self {
            next_id:    AtomicU32::new(1),
            channels:   HashMap::new(),
        }
    }

    pub fn allocate_id(&self) -> u32 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    pub fn insert(&mut self, channel: ChannelState) -> Result<(), ChannelError> {
        if self.channels.contains_key(&channel.channel_id) {
            return Err(ChannelError::DuplicateId(channel.channel_id));
        }
        if self.channels.len() >= MAX_CHANNELS_PER_SESSION {
            return Err(ChannelError::TooManyChannels(MAX_CHANNELS_PER_SESSION));
        }
        self.channels.insert(channel.channel_id, channel);
        Ok(())
    }

    pub fn get(&self, channel_id: u32) -> Option<&ChannelState> {
        self.channels.get(&channel_id)
    }

    pub fn get_mut(&mut self, channel_id: u32) -> Option<&mut ChannelState> {
        self.channels.get_mut(&channel_id)
    }

    pub fn len(&self) -> usize {
        self.channels.len()
    }

    pub fn is_empty(&self) -> bool {
        self.channels.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &ChannelState> {
        self.channels.values()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ChannelError {
    #[error("channel id {0} already exists in registry")]
    DuplicateId(u32),

    #[error("session reached max channel limit ({0})")]
    TooManyChannels(usize),

    #[error("channel id {0} not found")]
    NotFound(u32),

    #[error("max_target cannot be zero (would require infinite work)")]
    InvalidMaxTarget,
}

pub fn compute_initial_target(
    max_target:         &[u8; 32],
    _nominal_hash_rate: f32,
    _network_target:    &[u8; 32],
) -> [u8; 32] {
    if max_target.iter().all(|&b| b == 0) {
        let mut t = [0u8; 32];
        t[4] = 0xff;
        t[5] = 0xff;
        t[6] = 0xff;
        t[7] = 0xff;
        return t;
    }
    *max_target
}

pub fn derive_extranonce_prefix(channel_id: u32) -> Vec<u8> {
    let mut prefix = vec![0u8; 8];
    prefix[..4].copy_from_slice(&channel_id.to_be_bytes());
    prefix
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_allocates_unique_ids() {
        let reg = ChannelRegistry::new();
        let id1 = reg.allocate_id();
        let id2 = reg.allocate_id();
        assert_ne!(id1, id2);
    }

    #[test]
    fn registry_insert_rejects_duplicates() {
        let mut reg = ChannelRegistry::new();
        let ch = ChannelState::new(42, "test".into(), 1.0, [0; 32], vec![]);
        reg.insert(ch.clone()).unwrap();
        assert!(matches!(reg.insert(ch), Err(ChannelError::DuplicateId(42))));
    }

    #[test]
    fn extranonce_prefix_derived_from_channel_id() {
        let p1 = derive_extranonce_prefix(1);
        let p2 = derive_extranonce_prefix(2);
        assert_eq!(p1.len(), 8);
        assert_ne!(p1, p2);
        assert_eq!(&p1[..4], &[0, 0, 0, 1]);
    }

    #[test]
    fn zero_max_target_replaced_with_floor() {
        let result = compute_initial_target(&[0; 32], 0.0, &[0; 32]);
        assert_ne!(result, [0; 32]);
    }

    // ── Sprint 10-epsilon Phase 2.b: Sv2CachedJob ring buffer tests ──

    fn mk_template_stub(height: u64) -> Arc<Template> {
        use crate::stratum::Template;
        Arc::new(Template {
            job_id:        format!("t-{}", height),
            parents:       vec![],
            prev_hash:     [0u8; 32],
            merkle_branch: vec![],
            coinb1:        vec![],
            coinb2:        vec![],
            other_txs:     vec![],
            version:       1,
            bits:          0x1d00ffff,
            ntime:         0,
            blue_score:    height,
            height,
        })
    }

    fn mk_cached_job(job_id: u32) -> Sv2CachedJob {
        Sv2CachedJob {
            job_id,
            template:          mk_template_stub(100),
            extranonce_prefix: [0u8; 8],
            merkle_root:       [0u8; 32],
        }
    }

    #[test]
    fn push_job_updates_last_job_id() {
        let mut ch = ChannelState::new(1, "test".into(), 1.0, [0; 32], vec![]);
        assert_eq!(ch.last_job_id, None);
        ch.push_job(mk_cached_job(42));
        assert_eq!(ch.last_job_id, Some(42));
    }

    #[test]
    fn find_job_returns_cached_entry() {
        let mut ch = ChannelState::new(1, "test".into(), 1.0, [0; 32], vec![]);
        ch.push_job(mk_cached_job(7));
        ch.push_job(mk_cached_job(8));
        ch.push_job(mk_cached_job(9));
        assert!(ch.find_job(7).is_some());
        assert!(ch.find_job(8).is_some());
        assert!(ch.find_job(9).is_some());
        assert_eq!(ch.find_job(8).unwrap().job_id, 8);
    }

    #[test]
    fn find_job_returns_none_for_unknown_id() {
        let mut ch = ChannelState::new(1, "test".into(), 1.0, [0; 32], vec![]);
        ch.push_job(mk_cached_job(1));
        assert!(ch.find_job(999).is_none());
    }

    #[test]
    fn ring_evicts_oldest_at_capacity() {
        let mut ch = ChannelState::new(1, "test".into(), 1.0, [0; 32], vec![]);
        // Push MAX_JOBS_PER_CHANNEL + 2 jobs; the first 2 must be evicted.
        for i in 0..(MAX_JOBS_PER_CHANNEL as u32 + 2) {
            ch.push_job(mk_cached_job(i));
        }
        assert_eq!(ch.recent_jobs.len(), MAX_JOBS_PER_CHANNEL);
        // Oldest two (0, 1) are gone; newest is MAX+1.
        assert!(ch.find_job(0).is_none());
        assert!(ch.find_job(1).is_none());
        assert!(ch.find_job(2).is_some());
        assert_eq!(
            ch.last_job_id,
            Some(MAX_JOBS_PER_CHANNEL as u32 + 1),
        );
    }
}
