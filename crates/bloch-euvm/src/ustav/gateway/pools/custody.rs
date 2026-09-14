//! One-way authenticated reserve funding. No release or mutable ledger access.
use super::*;
pub const MAX_CUSTODY: usize = 128;
pub const FUNDING_GAS: u64 = 1000;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub id: [u8; 32],
    pub authorization: [u8; 32],
    pub asset: AssetId,
    pub owner: Vec<u8>,
    pub amount: u64,
    pub outpoint: OutPoint,
}
pub struct FundingPlan<'a> {
    transfer: TransferPlan<'a>,
    record: Record,
}
impl FundingPlan<'_> {
    pub fn commit(self) -> Receipt {
        let Self { transfer, record } = self;
        // Lock and record become part of the same exclusive commit as the transfer.
        transfer.ledger.locks.insert(record.outpoint, record.id);
        transfer.ledger.custody.insert(record.id, record);
        let mut receipt = transfer.commit();
        receipt.gas_used += FUNDING_GAS;
        receipt
    }
}
/// Owner consent commits to permanent custody, not merely an ordinary transfer.
pub fn signing_hash(
    record: &Record,
    transaction: &[u8; 32],
    domain: &[u8; 32],
) -> Result<[u8; 32], Error> {
    check_key_size(&record.owner)?;
    let mut h = HashWriter::new(b"USTAV-RESERVE-FUNDING-AUTH-v1");
    h.fixed(domain);
    h.fixed(transaction);
    h.fixed(&record.id);
    h.fixed(&record.authorization);
    h.fixed(&record.asset);
    h.bytes(&record.owner);
    h.u64(record.amount);
    point(&mut h, &record.outpoint);
    Ok(h.finish())
}
struct FundingVerifier<'a> {
    inner: &'a dyn Verifier,
    transaction: [u8; 32],
    custody: [u8; 32],
}
impl Verifier for FundingVerifier<'_> {
    fn valid_pq_key(&self, key: &[u8]) -> bool {
        self.inner.valid_pq_key(key)
    }
    fn verify_pq(&self, message: &[u8], key: &[u8], sig: &[u8]) -> bool {
        message == self.transaction && self.inner.verify_pq(&self.custody, key, sig)
    }
}
impl PoolLedger {
    pub fn custody(&self, id: &[u8; 32]) -> Option<&Record> {
        self.custody.get(id)
    }
    pub fn custody_records(&self) -> impl Iterator<Item = &Record> {
        self.custody.values()
    }
    /// Output zero is retained permanently. All inputs and outputs belong to the
    /// admitted owner, and ordinary transfer validation still verifies signatures.
    /// Owners sign `signing_hash(record, transaction_hash, domain)`, covering
    /// permanent lock consent and the host commitment. Ordinary signatures fail.
    pub fn plan_custody<'a>(
        &'a mut self,
        record: Record,
        tx: &Transaction,
        witnesses: &Witnesses,
        height: u64,
        verifier: &dyn Verifier,
        gas_limit: u64,
    ) -> Result<FundingPlan<'a>, Error> {
        self.asset(&tx.asset)?;
        check_key_size(&record.owner)?;
        if self.custody.len() >= MAX_CUSTODY
            || self.custody.contains_key(&record.id)
            || record.id == [0; 32]
            || record.authorization == [0; 32]
            || !verifier.valid_pq_key(&record.owner)
            || record.amount == 0
            || record.asset != tx.asset
            || record.outpoint.index != 0
            || record.outpoint.transaction != tx.signing_hash(self.gateway.native.domain())?
            || tx.outputs.first().is_none_or(|o| o.amount != record.amount)
            || tx.outputs.iter().any(|o| o.owner != record.owner)
            || tx.inputs.iter().any(|id| {
                self.gateway
                    .native
                    .output(id)
                    .is_none_or(|o| o.output.owner != record.owner)
            })
        {
            return Err(Error::InvalidFunding);
        }
        let gas = gas_limit
            .checked_sub(FUNDING_GAS)
            .ok_or(Error::ResourceLimit)?;
        let transaction = tx.signing_hash(self.gateway.native.domain())?;
        let scoped = FundingVerifier {
            inner: verifier,
            transaction,
            custody: signing_hash(&record, &transaction, self.gateway.native.domain())?,
        };
        let transfer = self.plan_transfer(tx, witnesses, height, &scoped, gas)?;
        Ok(FundingPlan { transfer, record })
    }
    pub(super) fn hash_custody(&self, h: &mut HashWriter) {
        h.u64(self.custody.len() as u64);
        for r in self.custody.values() {
            h.fixed(&r.id);
            h.fixed(&r.authorization);
            h.fixed(&r.asset);
            h.bytes(&r.owner);
            h.u64(r.amount);
            point(h, &r.outpoint);
        }
    }
    pub(super) fn restore_custody(
        &mut self,
        records: Vec<Record>,
        verifier: &dyn Verifier,
    ) -> Result<(), Error> {
        if records.len() > MAX_CUSTODY || records.windows(2).any(|w| w[0].id >= w[1].id) {
            return Err(Error::InvalidSnapshot);
        }
        for r in records {
            self.asset(&r.asset)?;
            check_key_size(&r.owner)?;
            let o = self
                .gateway
                .native
                .output(&r.outpoint)
                .ok_or(Error::InvalidSnapshot)?;
            if r.id == [0; 32]
                || r.authorization == [0; 32]
                || r.amount == 0
                || r.outpoint.index != 0
                || !verifier.valid_pq_key(&r.owner)
                || o.asset != r.asset
                || o.output.amount != r.amount
                || o.output.owner != r.owner
                || self.locks.insert(r.outpoint, r.id).is_some()
            {
                return Err(Error::InvalidSnapshot);
            }
            self.custody.insert(r.id, r);
        }
        Ok(())
    }
}
