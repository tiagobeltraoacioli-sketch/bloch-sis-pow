//! Isolated typed signer. It accepts canonical native operations plus a trusted
//! state view, never a caller-selected digest. No network or broadcast code.
use bloch_crypto::crypto;
use bloch_euvm::ustav::Verifier;
use bloch_pos_committee::{
    transition::{
        native_dex::{pool_intent::Operation, pool_review::FundingReview, State},
        NativeTransferPayload, PosTransaction,
    },
    SignatureVerifier,
};
use sha3::{Digest, Sha3_256};
use zeroize::Zeroizing;

mod abi;
#[cfg(test)]
mod tests;
pub struct Hybrid;
impl SignatureVerifier for Hybrid {
    fn verify_with_key(&self, key: &[u8], message: &[u8; 32], signature: &[u8]) -> bool {
        crypto::valid_native_hybrid_key(key) && crypto::verify(key, message, signature)
    }
    fn valid_native_key(&self, key: &[u8]) -> bool {
        crypto::valid_native_hybrid_key(key)
    }
    fn verify_native_signature(&self, key: &[u8], message: &[u8; 32], signature: &[u8]) -> bool {
        self.verify_with_key(key, message, signature)
    }
}
impl Verifier for Hybrid {
    fn valid_pq_key(&self, key: &[u8]) -> bool {
        crypto::valid_native_hybrid_key(key)
    }
    fn verify_pq(&self, message: &[u8], key: &[u8], signature: &[u8]) -> bool {
        crypto::valid_native_hybrid_key(key) && crypto::verify(key, message, signature)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Review {
    pub id: [u8; 32],
    pub authorization: [u8; 32],
    pub state_root: [u8; 32],
    pub public_key: Vec<u8>,
    pub gas: u64,
    pub fee_sat: u128,
    pub expires: u64,
    pub funding_sats: u128,
    pub wallet_outputs_sats: u128,
    pub packet: Vec<u8>,
}
struct Pending {
    review: FundingReview,
    packet: Vec<u8>,
    tag: u8,
    id: [u8; 32],
}
pub struct Session {
    domain: [u8; 32],
    public: Vec<u8>,
    secret: Zeroizing<Vec<u8>>,
    pending: Option<Pending>,
}
impl Session {
    /// Seed comes from the host's isolated custody boundary, never a website.
    pub fn open(seed: &[u8; 32], domain: [u8; 32]) -> Result<Self, &'static str> {
        if domain == [0; 32] {
            return Err("zero laboratory domain");
        }
        let (public, secret) =
            crypto::generate_keypair_from_seed(seed).map_err(|_| "key derivation failed")?;
        if !crypto::valid_native_hybrid_key(&public) {
            return Err("noncanonical hybrid key");
        }
        Ok(Self {
            domain,
            public,
            secret: Zeroizing::new(secret),
            pending: None,
        })
    }
    pub fn public_key(&self) -> &[u8] {
        &self.public
    }
    pub fn cancel(&mut self) {
        self.pending = None;
    }
    pub fn prepare(
        &mut self,
        state: &State,
        transaction: &[u8],
        height: u64,
    ) -> Result<Review, &'static str> {
        self.pending = None;
        if transaction.len() > 262144 {
            return Err("packet limit");
        }
        let tx = PosTransaction::from_canonical_bytes(transaction)
            .map_err(|_| "invalid canonical packet")?;
        let (tag, payload) = match tx {
            PosTransaction::NativePool(p) => (0x12, p),
            PosTransaction::NativeWithdrawal(p) => (0x11, p),
            _ => return Err("unsupported signing operation"),
        };
        let funding = FundingReview::prepare(state, payload.as_bytes(), &self.public, height)
            .map_err(|_| "typed funding review refused")?;
        if funding.intent().domain() != self.domain
            || (tag == 0x11) != (funding.intent().operation() == Operation::Withdraw)
            || funding.intent().operation() == Operation::Import
        {
            return Err("operation/domain mismatch");
        }
        let mut binding = Sha3_256::new();
        binding.update(b"POSTERN-NATIVE-WALLET-REVIEW-v1");
        binding.update(self.domain);
        binding.update(funding.state_root());
        binding.update(height.to_le_bytes());
        binding.update(&self.public);
        binding.update(transaction);
        let id = binding.finalize().into();
        let charge = funding.charge();
        let review = Review {
            id,
            authorization: funding.intent().authorization(),
            state_root: funding.state_root(),
            public_key: self.public.clone(),
            gas: charge.gas,
            fee_sat: charge
                .base_fee_sat
                .checked_add(charge.priority_fee_sat)
                .ok_or("fee overflow")?,
            expires: funding.valid_until(),
            funding_sats: funding.funding_sats(),
            wallet_outputs_sats: funding.wallet_outputs_sats(),
            packet: transaction.to_vec(),
        };
        self.pending = Some(Pending {
            review: funding,
            packet: transaction.to_vec(),
            tag,
            id,
        });
        Ok(review)
    }
    /// Consumes the review even on refusal. Fresh state/height and exact packet
    /// must be supplied again immediately after explicit host confirmation.
    pub fn sign(
        &mut self,
        id: [u8; 32],
        state: &State,
        transaction: &[u8],
        height: u64,
        confirmed: bool,
    ) -> Result<Vec<u8>, &'static str> {
        let p = self.pending.take().ok_or("no pending review")?;
        if !confirmed || p.id != id || p.packet != transaction {
            return Err("confirmation or packet changed");
        }
        if state.state_root() != p.review.state_root()
            || height < p.review.height()
            || height > p.review.valid_until()
        {
            return Err("stale signing context");
        }
        let signature = Zeroizing::new(
            crypto::sign(&self.secret, &p.review.intent().authorization())
                .map_err(|_| "hybrid signature failed")?,
        );
        let intent = p
            .review
            .finish_with_account_signature(state, &self.public, height, &signature, &Hybrid)
            .map_err(|_| "signed ownership/context review refused")?;
        let payload = NativeTransferPayload::new(intent.canonical_bytes().to_vec())
            .map_err(|_| "signed packet too large")?;
        let signed = if p.tag == 0x12 {
            PosTransaction::NativePool(payload)
        } else {
            PosTransaction::NativeWithdrawal(payload)
        };
        Ok(signed.canonical_bytes())
    }
}
