//! Bounded signed-operation admission for one local candidate, not a live mempool.
use crate::{
    dex_journal::{self, BaseVerifier, Checkpoint, Journal},
    BlochVerifier,
};
use bloch_pos_committee::transition::native_dex::{pool_batch, pool_candidate};

#[derive(Debug)]
pub enum Error {
    Journal(dex_journal::Error),
    StaleParent,
    HeightRegression,
    Closed,
    Duplicate,
    ResourceLimit,
    Batch(pool_batch::Error),
    Candidate(pool_candidate::Error),
}

/// A volatile candidate queue bound to one trusted parent and host height.
/// Admission does not reserve balances, persist transactions or promise inclusion.
/// Only commit confirms the entire batch through the durable journal.
pub struct PendingBatch {
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
