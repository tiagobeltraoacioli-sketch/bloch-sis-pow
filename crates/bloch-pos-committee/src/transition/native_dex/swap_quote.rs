//! Read-only exact-input quotes over verified BLCH/native custody.
//! A quote is neither a reserve-spend capability nor a signed execution intent.
use super::{Error, PoolError, State};
use bloch_euvm::{ustav::amm, AssetId};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub domain: [u8; 32],
    pub pool: [u8; 32],
    pub revision: u64,
    pub input_asset: AssetId,
    /// Raw integer asset units, without decimal conversion.
    pub amount: u64,
    pub minimum_out: u64,
    /// Inclusive host height, not wall-clock time.
    pub valid_until: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Quote {
    pub request: Request,
    pub height: u64,
    /// Identifies the pool state used for this calculation; not a finality proof.
    pub pool_state_root: [u8; 32],
    pub output_asset: AssetId,
    pub amount_out: u64,
    pub fee_bps: u16,
    /// Asset order is given by State::blch_pool(...).assets().
    pub reserves_before: [u64; 2],
    pub reserves_after: [u64; 2],
}

impl State {
    /// Rechecks actual custody and sealed LP accounting before quoting.
    /// No balances, fee escrow, locks or revisions are changed. Network fees
    /// and user funding are not quoted or verified by this method.
    pub fn quote_blch_swap(&self, request: &Request, height: u64) -> Result<Quote, Error> {
        if request.domain != self.domain {
            return Err(Error::WrongDomain);
        }
        let record = self
            .initial_pools
            .get(&request.pool)
            .ok_or(Error::InvalidReserve)?;
        if self.reserve_pools.get(&record.reserve) != Some(&request.pool) {
            return Err(Error::InvalidReserve);
        }
        self.validate_blch_pool(record)?;
        let assets = record.pool.assets();
        let input_index = assets
            .iter()
            .position(|asset| *asset == request.input_asset)
            .ok_or(Error::InvalidShape)?;
        let transition = record
            .pool
            .transition(
                &amm::Request {
                    pool: request.pool,
                    revision: request.revision,
                    valid_until: request.valid_until,
                    action: amm::Action::SwapExactInput {
                        input_index: input_index as u8,
                        amount: request.amount,
                        minimum_out: request.minimum_out,
                    },
                },
                height,
            )
            .map_err(|error| Error::Native(PoolError::Amm(error)))?;
        Ok(Quote {
            request: request.clone(),
            height,
            pool_state_root: record.pool.state_root(),
            output_asset: assets[1 - input_index],
            amount_out: transition.user_credit[1 - input_index],
            fee_bps: record.pool.fee_bps(),
            reserves_before: record.pool.reserves(),
            reserves_after: transition.next.reserves(),
        })
    }
}
