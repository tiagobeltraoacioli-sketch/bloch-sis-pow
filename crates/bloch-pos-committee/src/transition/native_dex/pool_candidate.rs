//! Bounded candidate exchange and independent result verification for rehearsal.
//! Not a signed block, consensus admission, RPC registration or finality proof.
use super::{pool_batch, wire, State};
use crate::SignatureVerifier;
use bloch_euvm::ustav::Verifier;

const MAGIC: &[u8; 8] = b"BLCHPCAN";
const HEADER_BYTES: usize = 8 + 2 + 32 + 32 + 8 + 32 + 32 + 2;
/// Includes the fixed header and one u64 length for each bounded operation.
pub const MAX_ENCODED_BYTES: usize =
    HEADER_BYTES + pool_batch::MAX_OPERATIONS * 8 + pool_batch::MAX_BYTES as usize;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Wire(wire::Error),
    WrongHeight,
    InvalidCount,
    CommitmentMismatch,
    Batch(pool_batch::Error),
}
impl From<wire::Error> for Error {
    fn from(error: wire::Error) -> Self {
        Self::Wire(error)
    }
}

fn decode<'a>(
    bytes: &'a [u8],
    domain: &[u8; 32],
    height: u64,
) -> Result<(pool_batch::Expected, Vec<&'a [u8]>), Error> {
    if bytes.len() > MAX_ENCODED_BYTES {
        return Err(wire::Error::TooLarge.into());
    }
    let mut reader = wire::Reader { bytes, offset: 0 };
    if reader.take(8)? != MAGIC {
        return Err(wire::Error::InvalidHeader.into());
    }
    if u16::from_le_bytes(reader.fixed()?) != 1 {
        return Err(wire::Error::InvalidVersion.into());
    }
    let encoded_domain: [u8; 32] = reader.fixed()?;
    if encoded_domain == [0; 32] || encoded_domain != *domain {
        return Err(wire::Error::WrongDomain.into());
    }
    let parent = reader.fixed()?;
    let encoded_height = u64::from_le_bytes(reader.fixed()?);
    if encoded_height != height {
        return Err(Error::WrongHeight);
    }
    let post = reader.fixed()?;
    let commitment = reader.fixed()?;
    let count = u16::from_le_bytes(reader.fixed()?) as usize;
    if count == 0 || count > pool_batch::MAX_OPERATIONS {
        return Err(Error::InvalidCount);
    }
    // At most 128 borrowed slices; no untrusted payload is cloned here.
    let mut frames = Vec::with_capacity(count);
    let mut total = 0u64;
    for _ in 0..count {
        let frame = reader.section(pool_batch::MAX_BYTES)?;
        if frame.is_empty() {
            return Err(wire::Error::InvalidOperation.into());
        }
        total = total
            .checked_add(frame.len() as u64)
            .filter(|n| *n <= pool_batch::MAX_BYTES)
            .ok_or(wire::Error::TooLarge)?;
        frames.push(frame);
    }
    if reader.offset != bytes.len() {
        return Err(wire::Error::TrailingBytes.into());
    }
    if pool_batch::commitment(domain, &parent, height, &frames) != commitment {
        return Err(Error::CommitmentMismatch);
    }
    Ok((
        pool_batch::Expected {
            parent,
            post,
            commitment,
            height,
        },
        frames,
    ))
}

/// Simulate a candidate with real verifiers, then encode its computed claims.
/// The returned bytes convey no authority; acceptance independently reexecutes.
pub fn build(
    state: &State,
    height: u64,
    frames: &[&[u8]],
    base_verifier: &dyn SignatureVerifier,
    native_verifier: &dyn Verifier,
) -> Result<Vec<u8>, Error> {
    let parent = state.state_root();
    let outcome = pool_batch::simulate(
        state,
        &parent,
        height,
        frames,
        base_verifier,
        native_verifier,
    )
    .map_err(Error::Batch)?;
    let mut bytes =
        Vec::with_capacity(HEADER_BYTES + frames.len() * 8 + outcome.wire_bytes as usize);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&state.domain);
    bytes.extend_from_slice(&parent);
    bytes.extend_from_slice(&height.to_le_bytes());
    bytes.extend_from_slice(&outcome.post_root);
    bytes.extend_from_slice(&outcome.commitment);
    bytes.extend_from_slice(&(frames.len() as u16).to_le_bytes());
    for frame in frames {
        bytes.extend_from_slice(&(frame.len() as u64).to_le_bytes());
        bytes.extend_from_slice(frame);
    }
    Ok(bytes)
}

/// The host supplies the authenticated height; the State supplies the domain
/// and current parent. No result, fee claim or verifier is trusted from bytes.
pub fn apply(
    state: &mut State,
    bytes: &[u8],
    height: u64,
    base_verifier: &dyn SignatureVerifier,
    native_verifier: &dyn Verifier,
) -> Result<pool_batch::Outcome, Error> {
    Ok(prepare(state, bytes, height, base_verifier, native_verifier)?.commit())
}

/// Fully verified candidate whose exclusive State borrow prevents intervening
/// mutation. Dropping it aborts; commit consumes it exactly once. No executable
/// component can be extracted. The original bytes stay immutably borrowed.
///
/// ```compile_fail
/// use bloch_pos_committee::transition::native_dex::pool_candidate::Prepared;
/// fn extract(p: Prepared<'_, '_>) { let state = p.staged; }
/// ```
/// ```compile_fail
/// use bloch_pos_committee::transition::native_dex::pool_candidate::Prepared;
/// fn twice(p: Prepared<'_, '_>) { p.commit(); p.commit(); }
/// ```
/// ```compile_fail
/// use bloch_pos_committee::{SignatureVerifier, transition::native_dex::{State, pool_candidate}};
/// use bloch_euvm::ustav::Verifier;
/// fn change_state(s: &mut State, bytes: &[u8], base: &dyn SignatureVerifier, native: &dyn Verifier) {
///     let pending = pool_candidate::prepare(s, bytes, 1, base, native).unwrap();
///     let snapshot = s.snapshot();
///     pending.commit();
/// }
/// ```
/// ```compile_fail
/// use bloch_pos_committee::{SignatureVerifier, transition::native_dex::{State, pool_candidate}};
/// use bloch_euvm::ustav::Verifier;
/// fn change_bytes(s: &mut State, bytes: &mut Vec<u8>, base: &dyn SignatureVerifier, native: &dyn Verifier) {
///     let pending = pool_candidate::prepare(s, bytes, 1, base, native).unwrap();
///     bytes.clear();
///     pending.commit();
/// }
/// ```
#[must_use = "dropping a prepared candidate aborts the state update"]
pub struct Prepared<'state, 'bytes> {
    target: &'state mut State,
    staged: State,
    outcome: pool_batch::Outcome,
    bytes: &'bytes [u8],
}
impl Prepared<'_, '_> {
    /// Exact bytes that were validated; a persistence host must write these.
    pub fn candidate(&self) -> &[u8] {
        self.bytes
    }
    pub fn outcome(&self) -> &pool_batch::Outcome {
        &self.outcome
    }
    /// Install the complete validated state. A persistence host calls this only
    /// after successfully writing and synchronizing candidate().
    pub fn commit(self) -> pool_batch::Outcome {
        *self.target = self.staged;
        self.outcome
    }
}

/// Prepare once for a persistence boundary, without a second full-state clone.
/// The host still supplies trusted height/domain context and real verifiers.
pub fn prepare<'state, 'bytes>(
    state: &'state mut State,
    bytes: &'bytes [u8],
    height: u64,
    base_verifier: &dyn SignatureVerifier,
    native_verifier: &dyn Verifier,
) -> Result<Prepared<'state, 'bytes>, Error> {
    let (expected, frames) = decode(bytes, &state.domain, height)?;
    let (staged, outcome) =
        pool_batch::stage_expected(state, &expected, &frames, base_verifier, native_verifier)
            .map_err(Error::Batch)?;
    Ok(Prepared {
        target: state,
        staged,
        outcome,
        bytes,
    })
}

#[cfg(test)]
mod tests;
