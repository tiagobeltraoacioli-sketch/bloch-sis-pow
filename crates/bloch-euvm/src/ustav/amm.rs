//! Pure pool arithmetic reference. No reserves, keys, LP ownership or ledger custody.
//! A host must atomically authenticate/execute returned deltas and persist state.
use crate::AssetId;
use sha2::{Digest, Sha256};

pub const VERSION: u32 = 1;
pub const MINIMUM_LIQUIDITY: u64 = 1000;
const BPS: u128 = 10_000;
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidPool,
    InvalidSnapshot,
    InvalidAction,
    StaleRevision,
    Expired,
    Overflow,
    Slippage,
    InsufficientLiquidity,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoolState {
    domain: [u8; 32],
    seed: [u8; 32],
    id: [u8; 32],
    assets: [AssetId; 2],
    fee_bps: u16,
    reserves: [u64; 2],
    lp_supply: u64,
    revision: u64,
}
/// Untrusted serialized fields; restore only against an independently trusted root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub version: u32,
    pub domain: [u8; 32],
    pub seed: [u8; 32],
    pub id: [u8; 32],
    pub assets: [AssetId; 2],
    pub fee_bps: u16,
    pub reserves: [u64; 2],
    pub lp_supply: u64,
    pub revision: u64,
}
impl Snapshot {
    /// Computing a root does not authenticate this snapshot or establish backing.
    pub fn state_root(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"BLOCH-NATIVE-AMM-STATE-v1");
        hash.update(self.version.to_be_bytes());
        hash.update(self.domain);
        hash.update(self.seed);
        hash.update(self.id);
        hash.update(self.assets[0]);
        hash.update(self.assets[1]);
        hash.update(self.fee_bps.to_be_bytes());
        hash.update(self.reserves[0].to_be_bytes());
        hash.update(self.reserves[1].to_be_bytes());
        hash.update(self.lp_supply.to_be_bytes());
        hash.update(self.revision.to_be_bytes());
        hash.finalize().into()
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Add {
        maximum: [u64; 2],
        minimum_lp: u64,
    },
    SwapExactInput {
        input_index: u8,
        amount: u64,
        minimum_out: u64,
    },
    Remove {
        lp: u64,
        minimum: [u64; 2],
    },
}
/// Every action binds a particular pool, state revision and inclusive host height.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub pool: [u8; 32],
    pub revision: u64,
    pub valid_until: u64,
    pub action: Action,
}
impl Request {
    pub fn signing_hash(
        &self,
        pool: &PoolState,
        funding_commitment: [u8; 32],
    ) -> Result<[u8; 32], Error> {
        pool.signing_hash(self, funding_commitment)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transition {
    pub next: PoolState,
    /// Exact units the host must debit from/credit to authenticated user funding.
    pub user_debit: [u64; 2],
    pub user_credit: [u64; 2],
    /// Unused Add.maximum units; not an additional credit or reserve movement.
    pub unused_maximum: [u64; 2],
    /// LP units to issue to/burn from the authenticated user's sealed position.
    pub lp_mint: u64,
    pub lp_burn: u64,
}
impl PoolState {
    pub fn new(
        domain: [u8; 32],
        a: AssetId,
        b: AssetId,
        fee_bps: u16,
        seed: [u8; 32],
    ) -> Result<Self, Error> {
        if domain == [0; 32] || a == b || fee_bps >= 10_000 {
            return Err(Error::InvalidPool);
        }
        let assets = if a < b { [a, b] } else { [b, a] };
        let mut hash = Sha256::new();
        hash.update(b"BLOCH-NATIVE-AMM-v1");
        hash.update(domain);
        hash.update(assets[0]);
        hash.update(assets[1]);
        hash.update(fee_bps.to_be_bytes());
        hash.update(seed);
        Ok(Self {
            domain,
            seed,
            id: hash.finalize().into(),
            assets,
            fee_bps,
            reserves: [0; 2],
            lp_supply: 0,
            revision: 0,
        })
    }
    pub fn domain(&self) -> [u8; 32] {
        self.domain
    }
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            version: VERSION,
            domain: self.domain,
            seed: self.seed,
            id: self.id,
            assets: self.assets,
            fee_bps: self.fee_bps,
            reserves: self.reserves,
            lp_supply: self.lp_supply,
            revision: self.revision,
        }
    }
    pub fn state_root(&self) -> [u8; 32] {
        self.snapshot().state_root()
    }
    pub fn restore(snapshot: Snapshot, trusted_root: [u8; 32]) -> Result<Self, Error> {
        if snapshot.version != VERSION
            || snapshot.assets[0] >= snapshot.assets[1]
            || snapshot.state_root() != trusted_root
        {
            return Err(Error::InvalidSnapshot);
        }
        let mut pool = Self::new(
            snapshot.domain,
            snapshot.assets[0],
            snapshot.assets[1],
            snapshot.fee_bps,
            snapshot.seed,
        )
        .map_err(|_| Error::InvalidSnapshot)?;
        if pool.id != snapshot.id {
            return Err(Error::InvalidSnapshot);
        }
        if snapshot.lp_supply == 0 {
            if snapshot.reserves != [0; 2] || snapshot.revision != 0 {
                return Err(Error::InvalidSnapshot);
            }
        } else {
            let product = u128::from(snapshot.reserves[0]) * u128::from(snapshot.reserves[1]);
            if snapshot.reserves.contains(&0)
                || snapshot.revision == 0
                || snapshot.lp_supply < MINIMUM_LIQUIDITY
                || product < u128::from(snapshot.lp_supply) * u128::from(snapshot.lp_supply)
                || (snapshot.revision == 1
                    && (snapshot.lp_supply <= MINIMUM_LIQUIDITY
                        || snapshot.lp_supply != sqrt(product)))
            {
                return Err(Error::InvalidSnapshot);
            }
        }
        pool.reserves = snapshot.reserves;
        pool.lp_supply = snapshot.lp_supply;
        pool.revision = snapshot.revision;
        Ok(pool)
    }
    /// An unsigned commitment, not an ownership proof. Funding hash must commit
    /// resolved input IDs, recipients and LP owner/position under the host format.
    pub fn signing_hash(
        &self,
        request: &Request,
        funding_commitment: [u8; 32],
    ) -> Result<[u8; 32], Error> {
        if request.pool != self.id {
            return Err(Error::InvalidPool);
        }
        if request.revision != self.revision {
            return Err(Error::StaleRevision);
        }
        if funding_commitment == [0; 32] {
            return Err(Error::InvalidAction);
        }
        let mut hash = Sha256::new();
        hash.update(b"BLOCH-NATIVE-AMM-AUTH-v1");
        hash.update(VERSION.to_be_bytes());
        hash.update(self.domain);
        hash.update(self.state_root());
        hash.update(request.pool);
        hash.update(request.revision.to_be_bytes());
        hash.update(request.valid_until.to_be_bytes());
        match request.action {
            Action::Add {
                maximum,
                minimum_lp,
            } => {
                hash.update([0]);
                hash.update(maximum[0].to_be_bytes());
                hash.update(maximum[1].to_be_bytes());
                hash.update(minimum_lp.to_be_bytes());
            }
            Action::SwapExactInput {
                input_index,
                amount,
                minimum_out,
            } => {
                hash.update([1, input_index]);
                hash.update(amount.to_be_bytes());
                hash.update(minimum_out.to_be_bytes());
            }
            Action::Remove { lp, minimum } => {
                hash.update([2]);
                hash.update(lp.to_be_bytes());
                hash.update(minimum[0].to_be_bytes());
                hash.update(minimum[1].to_be_bytes());
            }
        }
        hash.update(funding_commitment);
        Ok(hash.finalize().into())
    }
    pub fn id(&self) -> [u8; 32] {
        self.id
    }
    pub fn assets(&self) -> [AssetId; 2] {
        self.assets
    }
    pub fn reserves(&self) -> [u64; 2] {
        self.reserves
    }
    pub fn lp_supply(&self) -> u64 {
        self.lp_supply
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn fee_bps(&self) -> u16 {
        self.fee_bps
    }
    pub fn transition(&self, request: &Request, height: u64) -> Result<Transition, Error> {
        if request.pool != self.id {
            return Err(Error::InvalidPool);
        }
        if request.revision != self.revision {
            return Err(Error::StaleRevision);
        }
        if height > request.valid_until {
            return Err(Error::Expired);
        }
        let mut t = Transition {
            next: self.clone(),
            user_debit: [0; 2],
            user_credit: [0; 2],
            unused_maximum: [0; 2],
            lp_mint: 0,
            lp_burn: 0,
        };
        match request.action {
            Action::Add {
                maximum,
                minimum_lp,
            } => {
                if maximum.contains(&0) {
                    return Err(Error::InvalidAction);
                }
                if self.lp_supply == 0 {
                    let root = sqrt(u128::from(maximum[0]) * u128::from(maximum[1]));
                    t.lp_mint = root
                        .checked_sub(MINIMUM_LIQUIDITY)
                        .filter(|v| *v > 0)
                        .ok_or(Error::InsufficientLiquidity)?;
                    t.next.lp_supply = root;
                    t.user_debit = maximum;
                } else {
                    // Only the limiting side must fit LP accounting; a large
                    // unused maximum on the other side must not reject an add.
                    let candidates = [
                        u128::from(maximum[0]) * u128::from(self.lp_supply)
                            / u128::from(self.reserves[0]),
                        u128::from(maximum[1]) * u128::from(self.lp_supply)
                            / u128::from(self.reserves[1]),
                    ];
                    t.lp_mint = u64::try_from(candidates[0].min(candidates[1]))
                        .map_err(|_| Error::Overflow)?;
                    if t.lp_mint == 0 {
                        return Err(Error::InsufficientLiquidity);
                    }
                    for (i, max) in maximum.iter().enumerate() {
                        t.user_debit[i] =
                            mul_div_ceil(t.lp_mint, self.reserves[i], self.lp_supply)?;
                        t.unused_maximum[i] =
                            max.checked_sub(t.user_debit[i]).ok_or(Error::Overflow)?;
                    }
                    t.next.lp_supply = self
                        .lp_supply
                        .checked_add(t.lp_mint)
                        .ok_or(Error::Overflow)?;
                }
                if t.lp_mint < minimum_lp {
                    return Err(Error::Slippage);
                }
                for i in 0..2 {
                    t.next.reserves[i] = self.reserves[i]
                        .checked_add(t.user_debit[i])
                        .ok_or(Error::Overflow)?;
                }
            }
            Action::SwapExactInput {
                input_index,
                amount,
                minimum_out,
            } => {
                if input_index > 1 || amount == 0 {
                    return Err(Error::InvalidAction);
                }
                let i = usize::from(input_index);
                let o = 1 - i;
                if self.reserves.contains(&0) {
                    return Err(Error::InsufficientLiquidity);
                }
                let effective = u128::from(amount) * (BPS - u128::from(self.fee_bps));
                // Full u64 triple products can exceed u128; reject instead of wrapping.
                let numerator = effective
                    .checked_mul(u128::from(self.reserves[o]))
                    .ok_or(Error::Overflow)?;
                let denominator = u128::from(self.reserves[i]) * BPS + effective;
                let out = u64::try_from(numerator / denominator).map_err(|_| Error::Overflow)?;
                if out == 0 || out >= self.reserves[o] {
                    return Err(Error::InsufficientLiquidity);
                }
                if out < minimum_out {
                    return Err(Error::Slippage);
                }
                t.user_debit[i] = amount;
                t.user_credit[o] = out;
                t.next.reserves[i] = self.reserves[i]
                    .checked_add(amount)
                    .ok_or(Error::Overflow)?;
                t.next.reserves[o] = self.reserves[o] - out;
                if u128::from(t.next.reserves[0]) * u128::from(t.next.reserves[1])
                    < u128::from(self.reserves[0]) * u128::from(self.reserves[1])
                {
                    return Err(Error::InvalidAction);
                }
            }
            Action::Remove { lp, minimum } => {
                if lp == 0 || lp > self.lp_supply.saturating_sub(MINIMUM_LIQUIDITY) {
                    return Err(Error::InsufficientLiquidity);
                }
                for (i, min) in minimum.iter().enumerate() {
                    let out = mul_div(lp, self.reserves[i], self.lp_supply)?;
                    if out == 0 {
                        return Err(Error::InsufficientLiquidity);
                    }
                    if out < *min {
                        return Err(Error::Slippage);
                    }
                    t.user_credit[i] = out;
                    t.next.reserves[i] = self.reserves[i] - out;
                }
                t.lp_burn = lp;
                t.next.lp_supply = self.lp_supply - lp;
            }
        }
        t.next.revision = self.revision.checked_add(1).ok_or(Error::Overflow)?;
        Ok(t)
    }
}
fn mul_div(a: u64, b: u64, d: u64) -> Result<u64, Error> {
    if d == 0 {
        return Err(Error::InsufficientLiquidity);
    }
    u64::try_from(u128::from(a) * u128::from(b) / u128::from(d)).map_err(|_| Error::Overflow)
}
fn mul_div_ceil(a: u64, b: u64, d: u64) -> Result<u64, Error> {
    if d == 0 {
        return Err(Error::InsufficientLiquidity);
    }
    let product = u128::from(a) * u128::from(b);
    let divisor = u128::from(d);
    u64::try_from(product / divisor + u128::from(product % divisor != 0))
        .map_err(|_| Error::Overflow)
}
fn sqrt(n: u128) -> u64 {
    let mut low = 0u128;
    let mut high = u128::from(u64::MAX);
    while low < high {
        let mid = low + (high - low + 1) / 2;
        if mid * mid <= n {
            low = mid;
        } else {
            high = mid - 1;
        }
    }
    low as u64
}
