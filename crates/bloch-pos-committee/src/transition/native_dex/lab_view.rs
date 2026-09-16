//! Bounded canonical committed route accounting.
use super::NativeState;
use crate::transition::native_wallet::RouteReport;
impl NativeState {
    pub(in crate::transition) fn lab_route_report(
        &self,
        asset: &[u8; 32],
        route: &[u8; 32],
    ) -> Option<RouteReport> {
        let ledger = self.native.gateway();
        let state = ledger.route(route)?;
        if &state.config.route.native_asset != asset {
            return None;
        }
        Some(RouteReport {
            supply: ledger.native().supply(asset)?,
            imported: state.imported,
            burned: state.burned,
            next_release_nonce: state.next_release_nonce,
            commitment: self.commitment(),
            first_release_burn: ledger.release_record(route, 0).map(|r| r.native_burn),
        })
    }
}

impl NativeState {
    pub(in crate::transition) fn lab_pool_report(
        &self,
        id: &[u8; 32],
    ) -> Option<crate::transition::native_wallet::PoolReport> {
        let record = self.initial_pools.get(id)?;
        Some(crate::transition::native_wallet::PoolReport {
            pool_id: record.pool.id(),
            reserve_id: record.reserve,
            assets: record.pool.assets(),
            reserves: record.pool.reserves(),
            pool_root: record.pool.state_root(),
            revision: record.pool.revision(),
            lp_total: record.pool.lp_supply(),
            fee_bps: record.pool.fee_bps(),
        })
    }
}
#[cfg(test)]
mod tests {
    use super::super::{
        consensus_pool, pool_wire,
        tests::{BoundVerifier, DOMAIN},
    };
    #[test]
    fn committed_pool_view_tracks_canonical_swap_without_exposing_spendable_balance() {
        let fee = crate::fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS;
        let (mut base, bytes, _) = consensus_pool::tests::fixtures(fee)
            .into_iter()
            .find(|(_, bytes, _)| {
                matches!(
                    pool_wire::decode(bytes, &DOMAIN),
                    Ok(pool_wire::Request::Swap(_))
                )
            })
            .unwrap();
        let pool_wire::Request::Swap(request) = pool_wire::decode(&bytes, &DOMAIN).unwrap() else {
            unreachable!()
        };
        assert!(base.native_lab_pool_report(&[0; 32]).is_none());
        let before = base.native_lab_pool_report(&request.quote.pool).unwrap();
        assert_eq!(before.pool_id, request.quote.pool);
        assert_eq!(before.revision, request.quote.revision);
        assert_eq!(before.pool_root, request.pool_state_root);
        consensus_pool::apply_pool(&mut base, &bytes, 1, fee, &BoundVerifier, &BoundVerifier)
            .unwrap();
        let after = base.native_lab_pool_report(&request.quote.pool).unwrap();
        assert_eq!(after.reserve_id, before.reserve_id);
        assert_eq!(after.assets, before.assets);
        assert_eq!(after.revision, before.revision + 1);
        assert_eq!(after.lp_total, before.lp_total);
        assert_ne!(after.reserves, before.reserves);
        assert_ne!(after.pool_root, before.pool_root);
    }
}
