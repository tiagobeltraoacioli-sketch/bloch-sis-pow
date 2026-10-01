// SPDX-License-Identifier: AGPL-3.0-or-later
//! Offline qualification of the requested batch against the production resolver.
//! No keys, network calls, signatures, or transactions are involved.

use bloch_pos_committee::delegation::{Delegation, Registry};

fn main() {
    const AMOUNT: u128 = 10_000_000 * 100_000_000;
    const START: u64 = 4_330;
    for count in [1u32, 30, 31, 35, 36, 37, 38, 95, 100] {
        let positions: Vec<_> = (0..count)
            .map(|index| Delegation {
                delegator: index,
                validator: index,
                amount_sat: AMOUNT,
                requested_epoch: START,
                deactivate_epoch: None,
                eligible: true,
            })
            .collect();
        let total = AMOUNT * u128::from(count);
        let mut low = START;
        let mut high = START + 10_000;
        assert_eq!(Registry::resolve(&positions, high).total_active(), total);
        while low < high {
            let middle = low + (high - low) / 2;
            if Registry::resolve(&positions, middle).total_active() == total {
                high = middle;
            } else {
                low = middle + 1;
            }
        }
        let epoch = low;
        let registry = Registry::resolve(&positions, epoch);
        assert_eq!(registry.total_active(), total);
        assert!(epoch == START || Registry::resolve(&positions, epoch - 1).total_active() < total);
        let weights = registry.validators();
        let min = weights.iter().map(|v| v.effective_stake).min().unwrap();
        let max = weights.iter().map(|v| v.effective_stake).max().unwrap();
        println!(
            "{{\"positions\":{count},\"amount_per_position_sat\":\"{AMOUNT}\",\"warmup_epochs\":{},\"total_activated_sat\":\"{}\",\"computed_cap_sat\":\"{}\",\"min_delegated_consensus_weight_sat\":\"{min}\",\"max_delegated_consensus_weight_sat\":\"{max}\",\"production_ready\":false}}",
            epoch - START + 1,
            registry.total_active(),
            registry.cap_sat(),
        );
    }
}
