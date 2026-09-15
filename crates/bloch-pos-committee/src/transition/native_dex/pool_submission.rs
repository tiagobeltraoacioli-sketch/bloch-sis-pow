//! Read-only preflight of a fully signed, single-payer native operation.
use super::{
    pool_intent::DecodedIntent, pool_review, pool_review::FundingReview, pool_wire, State,
};
use crate::SignatureVerifier;
use bloch_euvm::ustav::Verifier;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Review(pool_review::Error),
    Execution(super::wire::Error),
    HeightChanged,
}

/// Runs the actual executor on a private state copy. No state or funds are
/// committed, reserved or broadcast. Caller-supplied state and verifiers must
/// be trusted; permissive test verifiers do not establish valid signatures.
///
/// The receipt and predicted root are valid only for this exact signed packet,
/// parent state and execution height. The full executor must run again at
/// inclusion, through the host's durable commit path.
/// ```compile_fail
/// use bloch_pos_committee::transition::native_dex::{pool_submission::SubmissionReview, State};
/// fn reuse(review: SubmissionReview, state: &State, payer: &[u8], bytes: &[u8]) {
///     let _ = review.finish(state, payer, 1, bytes);
///     let _ = review.finish(state, payer, 1, bytes);
/// }
/// ```
#[derive(Debug)]
pub struct SubmissionReview {
    funding: FundingReview,
    receipt: pool_wire::Receipt,
    predicted_root: [u8; 32],
}

impl SubmissionReview {
    pub fn prepare(
        state: &State,
        bytes: &[u8],
        payer: &[u8],
        height: u64,
        base_verifier: &dyn SignatureVerifier,
        native_verifier: &dyn Verifier,
    ) -> Result<Self, Error> {
        // Reject malformed, expired or unsupported requests before copying state.
        let funding = FundingReview::prepare(state, bytes, payer, height).map_err(Error::Review)?;
        let mut candidate = state.clone();
        let receipt = pool_wire::apply_request(
            &mut candidate,
            funding.intent().request(),
            height,
            base_verifier,
            native_verifier,
        )
        .map_err(Error::Execution)?;
        Ok(Self {
            funding,
            receipt,
            predicted_root: candidate.state_root(),
        })
    }

    pub fn funding(&self) -> &FundingReview {
        &self.funding
    }

    /// Executor result from the private simulation, not an inclusion receipt.
    pub fn receipt(&self) -> &pool_wire::Receipt {
        &self.receipt
    }

    pub fn predicted_root(&self) -> [u8; 32] {
        self.predicted_root
    }

    /// Consume the preflight and recheck its exact context. Height equality is
    /// stricter than funding review expiry: execution effects can depend on height.
    /// Success is neither human consent nor permission to bypass execution.
    pub fn finish(
        self,
        state: &State,
        payer: &[u8],
        height: u64,
        bytes: &[u8],
    ) -> Result<DecodedIntent, Error> {
        if height != self.funding.height() {
            return Err(Error::HeightChanged);
        }
        self.funding
            .finish(state, payer, height, bytes)
            .map_err(Error::Review)
    }
}
