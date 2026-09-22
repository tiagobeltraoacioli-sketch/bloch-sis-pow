//! Internal canonical transaction/witness codec shared by bounded envelopes.
use super::pairs::wire::Error;
use super::{
    OutPoint, Output, Transaction, Witnesses, MAX_INPUTS, MAX_OUTPUTS, MAX_SIGNATURE_BYTES,
};
use crate::kirpich::limits;
use crate::state::{Proof, TREE_DEPTH};
use crate::Val;
pub(crate) fn check_native(
    tx: &Transaction,
    witness: &Witnesses,
    domain: &[u8; 32],
) -> Result<(), Error> {
    tx.signing_hash(domain).map_err(|_| Error::InvalidShape)?;
    if witness.modules.len() > limits::MAX_CHARTER_MODULES {
        return Err(Error::InvalidShape);
    }
    witness
        .check(witness.modules.len(), tx.inputs.len())
        .map_err(|_| Error::InvalidShape)?;
    if witness.eligibility.windows(2).any(|w| w[0].key >= w[1].key) {
        return Err(Error::InvalidShape);
    }
    Ok(())
}
fn count(out: &mut Vec<u8>, n: usize) {
    out.extend_from_slice(&(n as u32).to_le_bytes());
}
fn blob(out: &mut Vec<u8>, bytes: &[u8]) {
    count(out, bytes.len());
    out.extend_from_slice(bytes);
}

pub(crate) fn encode_native(
    out: &mut Vec<u8>,
    tx: &Transaction,
    witness: &Witnesses,
) -> Result<(), Error> {
    out.extend_from_slice(&tx.asset);
    count(out, tx.inputs.len());
    for input in &tx.inputs {
        out.extend_from_slice(&input.transaction);
        out.extend_from_slice(&input.index.to_le_bytes());
    }
    count(out, tx.outputs.len());
    for output in &tx.outputs {
        blob(out, &output.owner);
        out.extend_from_slice(&output.amount.to_le_bytes());
    }
    out.extend_from_slice(&tx.delta.to_le_bytes());
    out.extend_from_slice(&tx.mint_nonce.to_le_bytes());
    out.extend_from_slice(&tx.policy_revision.to_le_bytes());
    out.extend_from_slice(&tx.valid_until.to_le_bytes());
    count(out, witness.owners.len());
    for signature in &witness.owners {
        blob(out, signature);
    }
    count(out, witness.modules.len());
    for module in &witness.modules {
        count(out, module.len());
        for value in module {
            let Val::Bytes(bytes) = value else {
                return Err(Error::InvalidShape);
            };
            blob(out, bytes);
        }
    }
    count(out, witness.eligibility.len());
    for proof in &witness.eligibility {
        out.extend_from_slice(&proof.key);
        out.extend_from_slice(proof.value.as_ref().ok_or(Error::InvalidShape)?);
        for sibling in &proof.siblings {
            out.extend_from_slice(sibling);
        }
    }
    Ok(())
}
pub(crate) struct Reader<'a> {
    pub(crate) bytes: &'a [u8],
    pub(crate) offset: usize,
}
impl<'a> Reader<'a> {
    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.offset.checked_add(n).ok_or(Error::TooLarge)?;
        let bytes = self.bytes.get(self.offset..end).ok_or(Error::Truncated)?;
        self.offset = end;
        Ok(bytes)
    }
    pub(crate) fn fixed<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?.try_into().map_err(|_| Error::Truncated)
    }
    pub(crate) fn count(&mut self, max: usize) -> Result<usize, Error> {
        let n = u32::from_le_bytes(self.fixed()?) as usize;
        if n > max {
            return Err(Error::InvalidShape);
        }
        Ok(n)
    }
    pub(crate) fn blob(&mut self, max: usize) -> Result<Vec<u8>, Error> {
        let n = self.count(max)?;
        Ok(self.take(n)?.to_vec())
    }
    pub(crate) fn leg(&mut self) -> Result<(Transaction, Witnesses), Error> {
        let asset = self.fixed()?;
        let mut inputs = Vec::new();
        for _ in 0..self.count(MAX_INPUTS)? {
            inputs.push(OutPoint {
                transaction: self.fixed()?,
                index: u32::from_le_bytes(self.fixed()?),
            });
        }
        let mut outputs = Vec::new();
        for _ in 0..self.count(MAX_OUTPUTS)? {
            outputs.push(Output {
                owner: self.blob(limits::MAX_KEY_BYTES)?,
                amount: u64::from_le_bytes(self.fixed()?),
            });
        }
        let tx = Transaction {
            asset,
            inputs,
            outputs,
            delta: i128::from_le_bytes(self.fixed()?),
            mint_nonce: u64::from_le_bytes(self.fixed()?),
            policy_revision: u64::from_le_bytes(self.fixed()?),
            valid_until: u64::from_le_bytes(self.fixed()?),
        };
        let mut owners = Vec::new();
        for _ in 0..self.count(MAX_INPUTS)? {
            owners.push(self.blob(MAX_SIGNATURE_BYTES)?);
        }
        let mut modules = Vec::new();
        for _ in 0..self.count(limits::MAX_CHARTER_MODULES)? {
            let mut module = Vec::new();
            for _ in 0..self.count(253)? {
                module.push(Val::Bytes(self.blob(MAX_SIGNATURE_BYTES)?));
            }
            modules.push(module);
        }
        let mut eligibility = Vec::new();
        for _ in 0..self.count(MAX_INPUTS + MAX_OUTPUTS)? {
            // Validate the entire fixed-size proof before allocating any of it.
            let bytes = self.take(40 + TREE_DEPTH * 32)?;
            eligibility.push(Proof {
                key: bytes[..32].to_vec(),
                value: Some(bytes[32..40].to_vec()),
                siblings: bytes[40..]
                    .chunks_exact(32)
                    .map(|b| {
                        let mut sibling = [0u8; 32];
                        sibling.copy_from_slice(b);
                        sibling
                    })
                    .collect(),
            });
        }
        Ok((
            tx,
            Witnesses {
                owners,
                modules,
                eligibility,
            },
        ))
    }
}
