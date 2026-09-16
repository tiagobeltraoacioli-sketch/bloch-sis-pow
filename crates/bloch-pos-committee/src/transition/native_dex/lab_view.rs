//! Bounded laboratory-only committed route accounting.
use super::NativeState;
use crate::transition::native_lab::RouteReport;
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
