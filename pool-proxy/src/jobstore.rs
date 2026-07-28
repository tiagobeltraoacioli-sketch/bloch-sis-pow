//! jobstore — the full `mining.notify` cache the local share validator needs.
//!
//! `crate::types::Job` (the Sprint-1 keepalive cache) only remembers the
//! `job_id` + `clean_jobs` flag — enough to re-feed an idle miner, but NOT
//! enough to RECONSTRUCT a header. The mini-pool validates shares locally, so
//! it must cache every field of the job plus the precomputed network target.
//!
//! A [`FullJob`] stores the notify params with the two consensus-critical
//! transforms already applied AT PARSE TIME, so the hot submit path does no
//! per-share decoding of job fields:
//!   * `prevhash_raw` — the stratum word-swap UNDONE (see
//!     `validator::undo_prevhash_word_swap`), i.e. the raw consensus prev_hash
//!     that goes straight into header bytes 4..36;
//!   * `network_target` — `bits_to_target(nbits)`, cached once.
//!
//! `ntime` is deliberately NOT stored from the job: cpuminer/ASICs roll ntime,
//! so the authoritative ntime is the one in each `mining.submit`.

use std::collections::VecDeque;
use std::time::Instant;

use serde_json::Value;

use crate::validator::{bits_to_target, hex_to_bytes, parse_hex_u32, undo_prevhash_word_swap};

/// A fully-parsed `mining.notify` job, ready for header reconstruction.
#[derive(Clone, Debug)]
pub struct FullJob {
    pub job_id: String,
    pub version: u32,
    /// Raw consensus prev_hash — stratum word-swap ALREADY undone at parse time.
    pub prevhash_raw: [u8; 32],
    pub coinb1: Vec<u8>,
    pub coinb2: Vec<u8>,
    pub merkle_branch: Vec<[u8; 32]>,
    pub nbits: u32,
    /// `bits_to_target(nbits)`, cached once (the block/network target).
    pub network_target: [u8; 32],
    /// Block height this job templates, parsed from the node's `job_id`
    /// convention `"{sid:x}-{height}-{ctr:x}"` (see `stratum/submit.rs`'s
    /// `MAX_JOB_ID_LEN` doc comment on the node side). Drives the PER-JOB
    /// `SHA256D_LE_FORK_HEIGHT` gate (`validator::le_for_height`) — hardcoding
    /// `le=true` was correct while the chain was permanently past height 2400,
    /// but is WRONG on a fresh/replayed chain still below the fork (observed:
    /// a founder relaunch at height ~15 forwarded genuine solutions that the
    /// node's own height-gated `sha256d_pow_valid` correctly validates
    /// pre-fork BIG-ENDIAN, while this pool kept comparing LITTLE-ENDIAN —
    /// every real block candidate got forwarded and bounced as LowDifficulty).
    /// `u64::MAX` (permanently post-fork) when the id doesn't parse.
    pub height: u64,
    pub clean_jobs: bool,
    pub received_at: Instant,
}

/// Parse the block height out of the node's `job_id` convention
/// `"{sid:x}-{height}-{ctr:x}"` (see the node's `src/stratum/submit.rs`).
/// Returns `u64::MAX` (i.e. "assume post-fork") when the id doesn't match —
/// fails open to the LONG-STANDING default rather than silently mis-gating a
/// converged, permanently-past-2400 chain on a parse hiccup.
fn parse_job_height(job_id: &str) -> u64 {
    job_id
        .split('-')
        .nth(1)
        .and_then(|h| h.parse::<u64>().ok())
        .unwrap_or(u64::MAX)
}

/// Parse a raw `mining.notify` line into a [`FullJob`].
///
/// notify params: `[job_id, prevhash, coinb1, coinb2, merkle[], version, nbits,
/// ntime, clean_jobs]`. Returns `None` on any malformed field — the caller
/// simply forwards the job downstream without caching it (a later submit
/// against an uncached job is answered "job not found").
pub fn parse_notify_full(raw: &str) -> Option<FullJob> {
    let v: Value = serde_json::from_str(raw.trim()).ok()?;
    let arr = v.get("params")?.as_array()?;
    if arr.len() < 8 {
        return None;
    }

    let job_id = arr[0].as_str()?.to_string();

    // prevhash: hex-decode → undo the 8×4-byte word swap → raw consensus bytes.
    let prevhash_bytes = hex_to_bytes(arr[1].as_str()?)?;
    if prevhash_bytes.len() != 32 {
        return None;
    }
    let mut prev = [0u8; 32];
    prev.copy_from_slice(&prevhash_bytes);
    let prevhash_raw = undo_prevhash_word_swap(&prev);

    let coinb1 = hex_to_bytes(arr[2].as_str()?)?;
    let coinb2 = hex_to_bytes(arr[3].as_str()?)?;

    // merkle branch: array of 32-byte hex siblings (empty on this chain).
    let mut merkle_branch = Vec::new();
    for sib in arr[4].as_array()? {
        let b = hex_to_bytes(sib.as_str()?)?;
        if b.len() != 32 {
            return None;
        }
        let mut s = [0u8; 32];
        s.copy_from_slice(&b);
        merkle_branch.push(s);
    }

    // version / nbits are big-endian hex per stratum convention.
    let version = parse_hex_u32(arr[5].as_str()?)?;
    let nbits = parse_hex_u32(arr[6].as_str()?)?;
    // arr[7] is ntime — NOT stored (submit's ntime is authoritative).
    let clean_jobs = arr.get(8).and_then(Value::as_bool).unwrap_or(false);

    let network_target = bits_to_target(nbits);
    let height = parse_job_height(&job_id);

    Some(FullJob {
        job_id,
        version,
        prevhash_raw,
        coinb1,
        coinb2,
        merkle_branch,
        nbits,
        network_target,
        height,
        clean_jobs,
        received_at: Instant::now(),
    })
}

/// A bounded ring of recent [`FullJob`]s keyed by `job_id`, so late / stale /
/// ntime-rolled submits against a slightly older job still validate.
pub struct JobStore {
    jobs: VecDeque<FullJob>,
    cap: usize,
}

impl JobStore {
    /// A store keeping the last `cap` jobs (design default 16).
    pub fn new(cap: usize) -> Self {
        JobStore {
            jobs: VecDeque::with_capacity(cap.max(1)),
            cap: cap.max(1),
        }
    }

    /// Insert a job. On `clean_jobs`, older jobs are abandoned (the node told
    /// miners to drop in-flight work). Evicts the oldest when over capacity.
    pub fn insert(&mut self, job: FullJob) {
        if job.clean_jobs {
            // Abandon ONLY work built on a DIFFERENT tip. A clean_jobs=true that
            // repeats the SAME prevhash (the node re-templating on an unchanged
            // tip — e.g. while the height is stuck at a target) must NOT wipe
            // in-flight jobs, or every share races the next notify and is
            // rejected stale (observed: 7 ASICs → 983 submits, 100% stale).
            self.jobs.retain(|j| j.prevhash_raw == job.prevhash_raw);
        }
        // De-dup by job_id (a re-sent job replaces the old entry).
        if let Some(pos) = self.jobs.iter().position(|j| j.job_id == job.job_id) {
            self.jobs.remove(pos);
        }
        self.jobs.push_back(job);
        while self.jobs.len() > self.cap {
            self.jobs.pop_front();
        }
    }

    /// Look up a cached job by `job_id`.
    pub fn get(&self, job_id: &str) -> Option<&FullJob> {
        self.jobs.iter().find(|j| j.job_id == job_id)
    }

    /// The most recently inserted job — used as the fallback template when a
    /// downstream rig proxy (MRR/NiceHash) re-labels job_ids so the submitted
    /// id never matches ours. The hash check remains authoritative.
    pub fn latest(&self) -> Option<&FullJob> {
        self.jobs.back()
    }

    /// Iterate cached jobs (oldest→newest). Used to validate a re-labeled submit
    /// against every candidate template, identifying the mined job BY HASH.
    pub fn iter(&self) -> std::collections::vec_deque::Iter<'_, FullJob> {
        self.jobs.iter()
    }

    pub fn len(&self) -> usize {
        self.jobs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.jobs.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator::bits_to_target;

    fn notify_line(job_id: &str, clean: bool) -> String {
        notify_line_prev(job_id, clean, 0)
    }

    /// Like [`notify_line`] but with a tweakable first prevhash byte so tests
    /// can distinguish same-tip re-templates from genuine tip changes.
    fn notify_line_prev(job_id: &str, clean: bool, prev0: u8) -> String {
        // prevhash: 32 bytes of prev0,0x01..0x1f (word-swapped on the wire);
        // coinb1 "aabb", coinb2 "ccdd", empty branch, version 00000002, nbits
        // 1f00ffff, ntime 66000000.
        let prevhash: String = (0u8..32)
            .map(|b| format!("{:02x}", if b == 0 { prev0 } else { b }))
            .collect();
        format!(
            r#"{{"id":null,"method":"mining.notify","params":["{job_id}","{prevhash}","aabb","ccdd",[],"00000002","1f00ffff","66000000",{clean}]}}"#
        )
    }

    #[test]
    fn parses_all_fields_and_precomputes_target() {
        let job = parse_notify_full(&notify_line("j1", false)).expect("valid notify");
        assert_eq!(job.job_id, "j1");
        assert_eq!(job.version, 2);
        assert_eq!(job.nbits, 0x1f00ffff);
        assert_eq!(job.network_target, bits_to_target(0x1f00ffff));
        assert_eq!(job.coinb1, vec![0xaa, 0xbb]);
        assert_eq!(job.coinb2, vec![0xcc, 0xdd]);
        assert!(job.merkle_branch.is_empty());
        // Word-swap undone: wire word [00,01,02,03] → raw [03,02,01,00].
        assert_eq!(&job.prevhash_raw[0..4], &[0x03, 0x02, 0x01, 0x00]);
        // "j1" has no "-" separator ⇒ unparseable ⇒ fails open to u64::MAX
        // (assume post-fork), the long-standing default.
        assert_eq!(job.height, u64::MAX);
    }

    /// The node's real job_id convention (`stratum/submit.rs`):
    /// `"{sid:x}-{height}-{ctr:x}"`. This is what actually arrives on a live
    /// node, and is what `le_for_height` gates on — the whole point of this
    /// fix (a fresh/replayed chain's job_ids carry small heights, e.g. "15",
    /// which must compare LEGACY BIG-ENDIAN, not the LE that a permanently-
    /// converged chain's job_ids implied).
    #[test]
    fn parses_height_from_real_job_id_convention() {
        let job = parse_notify_full(&notify_line("7-15-8b", false)).expect("valid notify");
        assert_eq!(job.height, 15);

        let job2 = parse_notify_full(&notify_line("3-4000-2a1", false)).expect("valid notify");
        assert_eq!(job2.height, 4000);
    }

    #[test]
    fn malformed_job_id_height_fails_open_to_post_fork() {
        // No middle segment, or a non-numeric one — both must fail open to
        // u64::MAX rather than silently mis-gating a converged chain.
        assert_eq!(parse_notify_full(&notify_line("solo", false)).unwrap().height, u64::MAX);
        assert_eq!(
            parse_notify_full(&notify_line("7-abc-8b", false)).unwrap().height,
            u64::MAX
        );
    }

    #[test]
    fn store_evicts_and_looks_up() {
        let mut s = JobStore::new(2);
        s.insert(parse_notify_full(&notify_line("a", false)).unwrap());
        s.insert(parse_notify_full(&notify_line("b", false)).unwrap());
        s.insert(parse_notify_full(&notify_line("c", false)).unwrap());
        // Cap 2 ⇒ "a" evicted.
        assert!(s.get("a").is_none());
        assert!(s.get("b").is_some());
        assert!(s.get("c").is_some());
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn clean_jobs_clears_older_jobs_on_tip_change_only() {
        // clean_jobs=true with a NEW prevhash (a real tip change) abandons
        // older-tip jobs …
        let mut s = JobStore::new(16);
        s.insert(parse_notify_full(&notify_line_prev("a", false, 0x00)).unwrap());
        s.insert(parse_notify_full(&notify_line_prev("b", true, 0xff)).unwrap());
        assert!(
            s.get("a").is_none(),
            "clean_jobs on a tip change must abandon older-tip jobs"
        );
        assert!(s.get("b").is_some());

        // … but clean_jobs=true REPEATING the same prevhash (node re-template
        // on an unchanged tip) must NOT wipe in-flight jobs, or every share
        // races the next notify and reads as stale (observed live: 7 ASICs →
        // 983 submits, 100% stale).
        let mut s2 = JobStore::new(16);
        s2.insert(parse_notify_full(&notify_line_prev("c", false, 0x42)).unwrap());
        s2.insert(parse_notify_full(&notify_line_prev("d", true, 0x42)).unwrap());
        assert!(
            s2.get("c").is_some(),
            "same-tip clean_jobs must keep in-flight jobs valid"
        );
        assert!(s2.get("d").is_some());
    }

    #[test]
    fn malformed_notify_returns_none() {
        assert!(parse_notify_full("not json").is_none());
        assert!(parse_notify_full(r#"{"method":"mining.notify","params":[]}"#).is_none());
    }
}
