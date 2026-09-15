//! Immutable decoding for a future wallet review, not an approval or signer.
//! The expected domain comes from independently authenticated configuration.
//! No balances, pool freshness, signatures, fees or source finality are verified.
use super::{pool_wire, wire::Error};
use bloch_euvm::ustav::gateway::wire::Operation as GatewayOperation;
use sha3::{Digest, Sha3_256};

/// Structural operation identity. Symbols/decimals must not be inferred from it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    Import,
    Withdraw,
    CreatePair,
    Initialize,
    Add,
    Swap,
    Remove,
    ClosePair,
}

/// One bounded, canonical packet and the operation decoded from those bytes.
/// Read every relevant field from `request()`, including both funding legs,
/// outputs, limits, expiry heights and witness identities. A website's separate
/// display labels are not a substitute for this decoded request.
///
/// The authorization digest is the existing executor's digest, not a grant to
/// sign. A wallet still needs verified deployment/state, an account-bound review,
/// explicit human approval and its own signing implementation. This type cannot
/// establish that an input belongs to the wallet or that a packet can execute.
///
/// No mutable request/byte access is exposed after decoding:
/// ```compile_fail
/// use bloch_pos_committee::transition::native_dex::{pool_intent::DecodedIntent, pool_wire};
/// fn mutate(intent: &mut DecodedIntent) -> &mut pool_wire::Request {
///     intent.request()
/// }
/// ```
#[derive(Clone, Debug)]
pub struct DecodedIntent {
    request: pool_wire::Request,
    bytes: Box<[u8]>,
    domain: [u8; 32],
    operation: Operation,
    authorization: [u8; 32],
    packet_hash: [u8; 32],
}

impl DecodedIntent {
    /// Applies the same size, shape, canonical encoding and domain checks as
    /// pool transport before allocating the retained packet. Unsigned or forged
    /// witnesses may pass decoding; only execution validates them.
    pub fn decode(bytes: &[u8], expected_domain: &[u8; 32]) -> Result<Self, Error> {
        let request = pool_wire::decode(bytes, expected_domain)?;
        let (operation, authorization) = match &request {
            pool_wire::Request::Gateway(r) => (
                match &r.gateway.operation {
                    GatewayOperation::Import(_) => Operation::Import,
                    GatewayOperation::Withdraw(_) => Operation::Withdraw,
                },
                r.authorization(expected_domain),
            ),
            pool_wire::Request::CreatePair(r) => {
                (Operation::CreatePair, r.authorization(expected_domain))
            }
            pool_wire::Request::Initialize(r) => {
                (Operation::Initialize, r.authorization(expected_domain))
            }
            pool_wire::Request::Add(r) => (Operation::Add, r.authorization(expected_domain)),
            pool_wire::Request::Swap(r) => (Operation::Swap, r.authorization(expected_domain)),
            pool_wire::Request::Remove(r) => (Operation::Remove, r.authorization(expected_domain)),
            pool_wire::Request::ClosePair(r) => {
                (Operation::ClosePair, r.authorization(expected_domain))
            }
        };
        Ok(Self {
            request,
            bytes: bytes.into(),
            domain: *expected_domain,
            operation,
            authorization: authorization.map_err(Error::Joint)?,
            packet_hash: Sha3_256::digest(bytes).into(),
        })
    }

    pub fn request(&self) -> &pool_wire::Request {
        &self.request
    }
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn domain(&self) -> [u8; 32] {
        self.domain
    }
    pub fn operation(&self) -> Operation {
        self.operation
    }
    /// Domain-separated digest already defined by this operation's executor.
    /// Signatures are excluded by that protocol; witness tables are not fully
    /// committed by this digest. Equality alone never authenticates a packet.
    pub fn authorization(&self) -> [u8; 32] {
        self.authorization
    }
    /// SHA3-256 of the entire canonical packet, including witness bytes.
    /// This is an off-chain review identifier, not a consensus txid or signature
    /// message. Filling any signature changes it and requires decoding anew.
    pub fn packet_hash(&self) -> [u8; 32] {
        self.packet_hash
    }
    /// Exact byte equality, not authorization/signature/freshness validation.
    pub fn matches_packet(&self, bytes: &[u8]) -> bool {
        self.canonical_bytes() == bytes
    }
}
