//! Bounded signed-operation admission for one local candidate, not a live mempool.
use crate::{
    dex_journal::{self, BaseVerifier, Checkpoint, Journal},
    BlochVerifier,
};
use bloch_pos_committee::transition::native_dex::{pool_batch, pool_candidate, pool_review, State};
use std::io::{self, Read};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

#[derive(Debug)]
pub enum Error {
    Journal(dex_journal::Error),
    StaleParent,
    HeightRegression,
    Closed,
    Duplicate,
    InvalidPrefix,
    ReviewContextChanged,
    Review(pool_review::Error),
    ResourceLimit,
    LengthMismatch,
    Io(io::Error),
    Batch(pool_batch::Error),
    Candidate(pool_candidate::Error),
}

/// Per-queue retained-review limit; transports still need global rate limits.
pub const MAX_ACCOUNT_REVIEWS: usize = 8;

struct ReviewSlot(Arc<AtomicUsize>);
impl ReviewSlot {
    fn acquire(slots: &Arc<AtomicUsize>) -> Result<Self, Error> {
        slots
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                if used < MAX_ACCOUNT_REVIEWS {
                    Some(used + 1)
                } else {
                    None
                }
            })
            .map_err(|_| Error::ResourceLimit)?;
        Ok(Self(Arc::clone(slots)))
    }
}
impl Drop for ReviewSlot {
    fn drop(&mut self) {
        let previous = self.0.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0);
    }
}

/// Local account review bound to an exact pending prefix and execution height.
/// Not user consent or a signing capability. Finishing consumes it on all paths.
/// Prefix storage is bounded by the existing candidate byte/operation limits.
/// ```compile_fail
/// use bloch_ustav::dex_admission::AccountReview;
/// fn duplicate(review: AccountReview) { let _copy = review.clone(); }
/// ```
pub struct AccountReview {
    slot: ReviewSlot,
    funding: pool_review::FundingReview,
    parent: Checkpoint,
    prefix: Vec<Vec<u8>>,
    height: u64,
}
impl AccountReview {
    pub fn funding(&self) -> &pool_review::FundingReview {
        &self.funding
    }
}

/// A volatile candidate queue bound to one trusted parent and host height.
/// Admission does not reserve balances, persist transactions or promise inclusion.
/// Only commit confirms the entire batch through the durable journal.
pub struct PendingBatch {
    review_slots: Arc<AtomicUsize>,
    parent: Checkpoint,
    height: u64,
    frames: Vec<Vec<u8>>,
    wire_bytes: u64,
    closed: bool,
}
impl PendingBatch {
    pub fn new(journal: &Journal, height: u64) -> Result<Self, Error> {
        journal.ensure_healthy().map_err(Error::Journal)?;
        let parent = journal.checkpoint();
        if height <= parent.height {
            return Err(Error::Journal(dex_journal::Error::NonIncreasingHeight));
        }
        Ok(Self {
            review_slots: Arc::new(AtomicUsize::new(0)),
            parent,
            height,
            frames: Vec::new(),
            wire_bytes: 0,
            closed: false,
        })
    }
    pub fn len(&self) -> usize {
        self.frames.len()
    }
    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }
    pub fn wire_bytes(&self) -> u64 {
        self.wire_bytes
    }
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Latest trusted host height observed for this parent, not a finalized height.
    pub fn height(&self) -> u64 {
        self.height
    }

    fn check_context(&mut self, journal: &Journal, height: u64) -> Result<(), Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        journal.ensure_healthy().map_err(Error::Journal)?;
        if journal.checkpoint() != self.parent {
            return Err(Error::StaleParent);
        }
        if height < self.height {
            return Err(Error::HeightRegression);
        }
        // Trusted execution height remains monotonic even when the request fails later.
        self.height = height;
        Ok(())
    }

    /// Fully verify the ordered prefix plus this signed frame with fixed PQ
    /// verifiers at the current trusted host height. Copy the new frame only
    /// after every validation succeeds; the height watermark advances even on rejection.
    pub fn admit(
        &mut self,
        journal: &Journal,
        frame: &[u8],
        height: u64,
    ) -> Result<pool_batch::Outcome, Error> {
        self.check_context(journal, height)?;
        let next_bytes = next_size(self.frames.len(), self.wire_bytes, frame.len() as u64)?;
        if self.frames.iter().any(|f| f.as_slice() == frame) {
            return Err(Error::Duplicate);
        }
        let mut refs: Vec<_> = self.frames.iter().map(Vec::as_slice).collect();
        refs.push(frame);
        let outcome = pool_batch::simulate(
            journal.state(),
            &self.parent.root,
            self.height,
            &refs,
            &BaseVerifier,
            &BlochVerifier,
        )
        .map_err(Error::Batch)?;
        self.frames.push(frame.to_vec());
        self.wire_bytes = next_bytes;
        Ok(outcome)
    }

    fn reviewed_prefix_state(&self, journal: &Journal) -> Result<State, Error> {
        let mut state = journal.state().clone();
        if !self.frames.is_empty() {
            let refs: Vec<_> = self.frames.iter().map(Vec::as_slice).collect();
            pool_batch::apply(
                &mut state,
                &self.parent.root,
                self.height,
                &refs,
                &BaseVerifier,
                &BlochVerifier,
            )
            .map_err(Error::Batch)?;
        }
        Ok(state)
    }

    /// Review against the state AFTER the pending prefix using fixed real PQ
    /// verifiers. No frame is admitted and no journal state is changed.
    /// The host supplies the selected wallet key and trusted execution height.
    pub fn prepare_account_review(
        &mut self,
        journal: &Journal,
        frame: &[u8],
        payer: &[u8],
        height: u64,
    ) -> Result<AccountReview, Error> {
        self.check_context(journal, height)?;
        next_size(self.frames.len(), self.wire_bytes, frame.len() as u64)?;
        // Reserve capacity before state cloning, decoding or PQ verification.
        // Every failure below releases it automatically.
        let slot = ReviewSlot::acquire(&self.review_slots)?;
        let state = self.reviewed_prefix_state(journal)?;
        let funding = pool_review::FundingReview::prepare(&state, frame, payer, height)
            .map_err(Error::Review)?;
        Ok(AccountReview {
            slot,
            funding,
            parent: self.parent,
            prefix: self.frames.clone(),
            height,
        })
    }

    /// Attach only the account's signature to its retained review and perform
    /// ordinary full-prefix admission. Other-party witnesses must already be
    /// valid. Does not invoke a signer, grant consent, broadcast or commit.
    pub fn admit_account_signature(
        &mut self,
        journal: &Journal,
        review: AccountReview,
        payer: &[u8],
        signature: &[u8],
        height: u64,
    ) -> Result<pool_batch::Outcome, Error> {
        self.check_context(journal, height)?;
        if !Arc::ptr_eq(&review.slot.0, &self.review_slots)
            || review.parent != self.parent
            || review.height != height
            || review.prefix != self.frames
        {
            return Err(Error::ReviewContextChanged);
        }
        let state = self.reviewed_prefix_state(journal)?;
        let signed = review
            .funding
            .finish_with_account_signature(&state, payer, height, signature, &BaseVerifier)
            .map_err(Error::Review)?;
        self.admit(journal, signed.canonical_bytes(), height)
    }

    /// Read one request BODY with a bounded allocation before PQ validation.
    /// The reader must end at the body boundary, not at connection shutdown.
    /// declared_length is untrusted; None supports bodies without a known length.
    /// The transport must enforce its own deadline and connection/rate limits.
    pub fn admit_from_reader(
        &mut self,
        journal: &Journal,
        reader: &mut impl Read,
        declared_length: Option<u64>,
        height: u64,
    ) -> Result<pool_batch::Outcome, Error> {
        self.check_context(journal, height)?;
        next_size(self.frames.len(), self.wire_bytes, 0)?;
        let remaining = pool_batch::MAX_BYTES - self.wire_bytes;
        let frame = read_body(reader, remaining, declared_length)?;
        self.admit(journal, &frame, height)
    }

    /// Retain an ordered prefix, discarding its entire dependent suffix.
    /// This is local queue editing, not transaction cancellation or validation.
    /// Even clearing the queue preserves its parent and monotonic height.
    pub fn retain_prefix(
        &mut self,
        journal: &Journal,
        keep: usize,
        height: u64,
    ) -> Result<(), Error> {
        self.check_context(journal, height)?;
        if keep > self.frames.len() {
            return Err(Error::InvalidPrefix);
        }
        self.frames.truncate(keep);
        // The retained subset is already bounded by MAX_BYTES.
        self.wire_bytes = self.frames.iter().map(|frame| frame.len() as u64).sum();
        Ok(())
    }

    /// Build at the current trusted host height without changing pending frames,
    /// the journal or State. The monotonic height watermark may advance.
    pub fn build(&mut self, journal: &Journal, height: u64) -> Result<Vec<u8>, Error> {
        self.check_context(journal, height)?;
        let refs: Vec<_> = self.frames.iter().map(Vec::as_slice).collect();
        pool_candidate::build(
            journal.state(),
            self.height,
            &refs,
            &BaseVerifier,
            &BlochVerifier,
        )
        .map_err(Error::Candidate)
    }

    /// Recheck expiry at the current trusted host height and commit only through
    /// the journal's verification/write/fsync boundary.
    /// Errors preserve pending frames; I/O errors also poison the journal.
    /// Success closes this batch and releases its buffered frames.
    pub fn commit(
        &mut self,
        journal: &mut Journal,
        height: u64,
    ) -> Result<pool_batch::Outcome, Error> {
        let candidate = self.build(journal, height)?;
        let result = journal
            .append(&candidate, self.height)
            .map_err(Error::Journal)?;
        self.frames.clear();
        self.wire_bytes = 0;
        self.closed = true;
        Ok(result)
    }
}

// At most quota+1 bytes are consumed. The extra byte detects an overlong body;
// a transport must discard/close rejected bodies before handling another request.
fn read_body(reader: &mut impl Read, quota: u64, declared: Option<u64>) -> Result<Vec<u8>, Error> {
    if quota == 0 || quota > pool_batch::MAX_BYTES {
        return Err(Error::ResourceLimit);
    }
    if let Some(length) = declared {
        if length > quota {
            return Err(Error::ResourceLimit);
        }
        if length == 0 {
            return Err(Error::LengthMismatch);
        }
    }
    let body_limit = declared.unwrap_or(quota);
    let read_limit = body_limit + 1;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(read_limit as usize)
        .map_err(|_| Error::ResourceLimit)?;
    let mut limited = reader.take(read_limit);
    let mut chunk = [0; 8192];
    loop {
        let count = match limited.read(&mut chunk) {
            Ok(0) => break,
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(Error::Io(error)),
        };
        bytes.extend_from_slice(&chunk[..count]);
    }
    if bytes.len() as u64 > quota {
        return Err(Error::ResourceLimit);
    }
    if declared.is_some_and(|n| bytes.len() as u64 != n) {
        return Err(Error::LengthMismatch);
    }
    if bytes.is_empty() {
        return Err(Error::LengthMismatch);
    }
    Ok(bytes)
}

fn next_size(count: usize, current: u64, incoming: u64) -> Result<u64, Error> {
    if count >= pool_batch::MAX_OPERATIONS {
        return Err(Error::ResourceLimit);
    }
    current
        .checked_add(incoming)
        .filter(|n| *n <= pool_batch::MAX_BYTES)
        .ok_or(Error::ResourceLimit)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn review_slots_release_capacity_on_drop() {
        let counter = Arc::new(AtomicUsize::new(0));
        let mut held: Vec<_> = (0..MAX_ACCOUNT_REVIEWS)
            .map(|_| ReviewSlot::acquire(&counter).unwrap())
            .collect();
        assert!(matches!(
            ReviewSlot::acquire(&counter),
            Err(Error::ResourceLimit)
        ));
        held.pop();
        let replacement = ReviewSlot::acquire(&counter).unwrap();
        assert_eq!(counter.load(Ordering::Acquire), MAX_ACCOUNT_REVIEWS);
        drop(held);
        drop(replacement);
        assert_eq!(counter.load(Ordering::Acquire), 0);
    }

    #[test]
    fn simultaneous_review_slot_requests_cannot_exceed_capacity() {
        let counter = Arc::new(AtomicUsize::new(0));
        let acquired = Arc::new(std::sync::Barrier::new(33));
        let release = Arc::new(std::sync::Barrier::new(33));
        let threads: Vec<_> = (0..32)
            .map(|_| {
                let counter = Arc::clone(&counter);
                let acquired = Arc::clone(&acquired);
                let release = Arc::clone(&release);
                std::thread::spawn(move || {
                    let slot = ReviewSlot::acquire(&counter).ok();
                    acquired.wait();
                    release.wait();
                    slot.is_some()
                })
            })
            .collect();
        acquired.wait();
        let used = counter.load(Ordering::Acquire);
        release.wait();
        let accepted = threads
            .into_iter()
            .map(|t| usize::from(t.join().unwrap()))
            .sum::<usize>();
        assert_eq!(used, MAX_ACCOUNT_REVIEWS);
        assert_eq!(accepted, MAX_ACCOUNT_REVIEWS);
        assert_eq!(counter.load(Ordering::Acquire), 0);
    }

    struct NoRead;
    impl Read for NoRead {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            panic!("body must not be read")
        }
    }
    #[test]
    fn invalid_declared_lengths_reject_before_reading() {
        for (quota, length) in [
            (0, None),
            (16, Some(17)),
            (16, Some(u64::MAX)),
            (16, Some(0)),
        ] {
            assert!(read_body(&mut NoRead, quota, length).is_err());
        }
    }
    #[test]
    fn known_and_unknown_lengths_consume_at_most_the_limit_plus_one() {
        let body = vec![7; 100];
        for declared in [None, Some(16)] {
            let mut reader = io::Cursor::new(&body);
            assert!(matches!(
                read_body(&mut reader, 16, declared),
                Err(Error::ResourceLimit)
            ));
            assert_eq!(reader.position(), 17);
        }
        let mut reader = io::Cursor::new(&body);
        assert!(matches!(
            read_body(&mut reader, 16, Some(8)),
            Err(Error::LengthMismatch)
        ));
        assert_eq!(reader.position(), 9);
        assert!(matches!(
            read_body(&mut io::Cursor::new([1; 7]), 16, Some(8)),
            Err(Error::LengthMismatch)
        ));
        assert!(matches!(
            read_body(&mut io::empty(), 16, None),
            Err(Error::LengthMismatch)
        ));
        for declared in [None, Some(16)] {
            assert_eq!(
                read_body(&mut io::Cursor::new([3; 16]), 16, declared).unwrap(),
                [3; 16]
            );
        }
    }
    struct InterruptedThenChunked {
        interrupted: bool,
        body: io::Cursor<Vec<u8>>,
    }
    impl Read for InterruptedThenChunked {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            if !self.interrupted {
                self.interrupted = true;
                return Err(io::ErrorKind::Interrupted.into());
            }
            let end = out.len().min(3);
            self.body.read(&mut out[..end])
        }
    }
    #[test]
    fn fragmented_body_and_interrupted_reads_preserve_exact_bytes() {
        let mut reader = InterruptedThenChunked {
            interrupted: false,
            body: io::Cursor::new(vec![9; 32]),
        };
        assert_eq!(read_body(&mut reader, 32, Some(32)).unwrap(), [9; 32]);
    }
    #[test]
    fn capacity_bounds_accept_the_exact_limit_and_reject_overflow() {
        assert_eq!(
            next_size(pool_batch::MAX_OPERATIONS - 1, pool_batch::MAX_BYTES - 1, 1).unwrap(),
            pool_batch::MAX_BYTES
        );
        for (count, current, incoming) in [
            (pool_batch::MAX_OPERATIONS, 0, 1),
            (usize::MAX, 0, 1),
            (0, pool_batch::MAX_BYTES, 1),
            (0, 1, u64::MAX),
            (0, 0, pool_batch::MAX_BYTES + 1),
        ] {
            assert!(matches!(
                next_size(count, current, incoming),
                Err(Error::ResourceLimit)
            ));
        }
    }
}
