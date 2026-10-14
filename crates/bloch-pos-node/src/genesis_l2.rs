// SPDX-License-Identifier: AGPL-3.0-or-later
//! Fixed-size public policy input. Native network/genesis are derived locally.
use crate::codec::{DecodeErr, Reader};
use bloch_pos_committee::l2_settlement::Policy;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct L2Config {
    /// Domain, execution configuration, guest ELF, KoalaBear key, BN254 key.
    pub identities: [[u8; 32]; 5],
    pub proof_policy: [u8; 32],
    pub chain_id: u64,
    pub initial_l2_parent: [u8; 32],
    pub initial_l2_state: [u8; 32],
    /// M6 attestor set hash (`withdrawal::attestor_set_hash`); zero = none.
    /// Encoded as 32 trailing bytes only when set, so configs without it
    /// keep their 264 bytes.
    pub attestor_set: [u8; 32],
}
impl L2Config {
    pub const BYTES: usize = 264;
    /// With an attestor set.
    pub const BYTES_ATTESTED: usize = Self::BYTES + 32;
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::BYTES);
        for hash in self.identities { out.extend_from_slice(&hash); }
        out.extend_from_slice(&self.proof_policy);
        out.extend_from_slice(&self.chain_id.to_le_bytes());
        out.extend_from_slice(&self.initial_l2_parent);
        out.extend_from_slice(&self.initial_l2_state);
        if self.attestor_set != [0; 32] {
            out.extend_from_slice(&self.attestor_set);
        }
        out
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeErr> {
        if bytes.len() != Self::BYTES && bytes.len() != Self::BYTES_ATTESTED {
            return Err(DecodeErr("L2 config length"));
        }
        let mut r = Reader::new(bytes);
        let mut value = Self {
            identities: [r.h32()?, r.h32()?, r.h32()?, r.h32()?, r.h32()?],
            proof_policy: r.h32()?, chain_id: r.u64()?,
            initial_l2_parent: r.h32()?, initial_l2_state: r.h32()?,
            attestor_set: [0; 32],
        };
        if bytes.len() == Self::BYTES_ATTESTED {
            value.attestor_set = r.h32()?;
            // Attestors only gate user-transaction claims; an all-zero set
            // would be the unattested encoding written the long way.
            if value.attestor_set == [0; 32] || !bloch_pos_committee::l2_settlement::USER_TRANSACTIONS_ENABLED {
                return Err(DecodeErr("L2 attestor set needs devnet-l2-user-txs and a non-zero hash"));
            }
        }
        r.finish()?;
        if !value.policy([1;32], [2;32]).valid()
            // V2 (existing networks) or V3 (user transactions); exactly one is
            // pinned per genesis and the verifier admits only its own version.
            || (value.proof_policy != bloch_l2_proof::policy_commitment()
                && value.proof_policy != bloch_l2_proof::policy_commitment_v3()) {
            return Err(DecodeErr("invalid or unsupported L2 policy"));
        }
        Ok(value)
    }
    pub fn policy(&self, network: [u8;32], genesis: [u8;32]) -> Policy {
        Policy {
            identities: [network, genesis, self.identities[0], self.identities[1],
                self.identities[2], self.identities[3], self.identities[4]],
            proof_policy: self.proof_policy, chain_id: self.chain_id,
            initial_l2_parent: self.initial_l2_parent, initial_l2_state: self.initial_l2_state,
            attestor_set: self.attestor_set,
        }
    }
}
