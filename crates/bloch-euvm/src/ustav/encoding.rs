//! Streaming, length-prefixed signing encodings. No native usize or debug strings.
use super::{
    PolicyAction, PolicyUpdate, Registration, Transaction, KERNEL_VERSION, RULESET_VERSION,
};
use crate::modules::ModuleKind;
use sha2::{Digest, Sha256};

pub(super) struct HashWriter(Sha256);
impl HashWriter {
    pub(super) fn new(tag: &[u8]) -> Self {
        let mut h = Self(Sha256::new());
        h.bytes(tag);
        h
    }
    pub(super) fn fixed(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }
    pub(super) fn byte(&mut self, byte: u8) {
        self.fixed(&[byte]);
    }
    pub(super) fn u32(&mut self, n: u32) {
        self.fixed(&n.to_le_bytes());
    }
    pub(super) fn u64(&mut self, n: u64) {
        self.fixed(&n.to_le_bytes());
    }
    pub(super) fn bytes(&mut self, bytes: &[u8]) {
        self.u64(bytes.len() as u64);
        self.fixed(bytes);
    }
    pub(super) fn optional_hash(&mut self, hash: Option<[u8; 32]>) {
        match hash {
            Some(h) => {
                self.byte(1);
                self.fixed(&h);
            }
            None => self.byte(0),
        }
    }
    pub(super) fn finish(self) -> [u8; 32] {
        Sha256::digest(self.0.finalize()).into()
    }
}

pub(super) fn asset_hash(domain: &[u8; 32], registration: &Registration) -> [u8; 32] {
    let mut h = HashWriter::new(b"USTAV-ASSET-v3");
    h.fixed(domain);
    h.u32(KERNEL_VERSION);
    h.u32(RULESET_VERSION);
    h.fixed(&registration.nonce);
    h.bytes(&registration.charter.token_name);
    h.u64(registration.charter.modules.len() as u64);
    for module in &registration.charter.modules {
        match module {
            ModuleKind::Supply(c) => {
                h.byte(1);
                h.u64(c.cap);
                h.bytes(&c.issuer_pubkey);
            }
            ModuleKind::TransferPolicy(c) => {
                h.byte(2);
                h.bytes(&c.authority_pubkey);
            }
            ModuleKind::ComplianceKycGate(_) => h.byte(3),
            ModuleKind::Vesting(c) => {
                h.byte(4);
                h.fixed(&c.unlock_height.to_le_bytes());
                h.bytes(&c.beneficiary_pubkey);
            }
            ModuleKind::Governance(c) => {
                h.byte(5);
                h.u32(c.threshold);
                h.u64(c.signers.len() as u64);
                for key in &c.signers {
                    h.bytes(key);
                }
            }
            ModuleKind::Custody(c) => {
                h.byte(6);
                h.bytes(&c.btc_pubkey);
                h.bytes(&c.pq_pubkey);
            }
        }
    }
    h.finish()
}

pub(super) fn registration_hash(domain: &[u8; 32], registration: &Registration) -> [u8; 32] {
    let mut h = HashWriter::new(b"USTAV-REGISTER-v3");
    h.fixed(&asset_hash(domain, registration));
    h.optional_hash(registration.initial_kyc_root);
    h.finish()
}

pub(super) fn transaction_hash(domain: &[u8; 32], tx: &Transaction) -> [u8; 32] {
    let mut h = HashWriter::new(b"USTAV-TRANSACTION-v3");
    h.fixed(domain);
    h.u32(KERNEL_VERSION);
    h.fixed(&tx.asset);
    h.u64(tx.inputs.len() as u64);
    for id in &tx.inputs {
        h.fixed(&id.transaction);
        h.u32(id.index);
    }
    h.u64(tx.outputs.len() as u64);
    for output in &tx.outputs {
        h.bytes(&output.owner);
        h.u64(output.amount);
    }
    h.fixed(&tx.delta.to_le_bytes());
    h.u64(tx.mint_nonce);
    h.u64(tx.policy_revision);
    h.u64(tx.valid_until);
    h.finish()
}

pub(super) fn update_hash(domain: &[u8; 32], update: &PolicyUpdate) -> [u8; 32] {
    let mut h = HashWriter::new(b"USTAV-POLICY-UPDATE-v3");
    h.fixed(domain);
    h.u32(KERNEL_VERSION);
    h.fixed(&update.asset);
    h.u64(update.revision);
    h.u64(update.valid_until);
    match update.action {
        PolicyAction::SetFrozen(f) => {
            h.byte(1);
            h.byte(u8::from(f));
        }
        PolicyAction::SetKycRoot(root) => {
            h.byte(2);
            h.fixed(&root);
        }
    }
    h.finish()
}
