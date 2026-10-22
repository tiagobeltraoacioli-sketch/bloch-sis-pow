// SPDX-License-Identifier: AGPL-3.0-or-later
//! Offline qualification of the requested batch against the production resolver.
//! No keys, network calls, signatures, or transactions are involved.

use bloch_pos_committee::delegation::{Delegation, Registry};
use bloch_pos_committee::transition::funded_delegation::MAX_FUNDED_DELEGATION_PER_VALIDATOR_SAT;

fn main() {
    let amount_blch: u128 = std::env::args()
        .nth(1)
        .map_or(Ok(10_000_000), |value| value.parse())
        .expect("expected an integer BLCH amount per validator");
    assert!((10..=1_000_000_000).contains(&amount_blch));
    let amount = amount_blch * 100_000_000;
    const START: u64 = 4_330;
    for count in [1u32, 30, 31, 35, 36, 37, 38, 95, 100] {
        let positions: Vec<_> = (0..count)
            .map(|index| Delegation {
                delegator: index,
                validator: index,
                amount_sat: amount,
                requested_epoch: START,
                deactivate_epoch: None,
                eligible: true,
            })
            .collect();
        let total = amount * u128::from(count);
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
        let fixed = registry.validators_with_absolute_cap(MAX_FUNDED_DELEGATION_PER_VALIDATOR_SAT);
        let fixed_min = fixed.iter().map(|v| v.effective_stake).min().unwrap();
        let fixed_max = fixed.iter().map(|v| v.effective_stake).max().unwrap();
        let within_limit = amount <= MAX_FUNDED_DELEGATION_PER_VALIDATOR_SAT;
        println!(
            "{{\"positions\":{count},\"amount_per_position_sat\":\"{amount}\",\"warmup_epochs\":{},\"total_activated_sat\":\"{}\",\"legacy_percentage_cap_sat\":\"{}\",\"legacy_min_weight_sat\":\"{min}\",\"legacy_max_weight_sat\":\"{max}\",\"funded_min_weight_sat\":\"{fixed_min}\",\"funded_max_weight_sat\":\"{fixed_max}\",\"principal_within_fixed_limit\":{within_limit},\"production_ready\":false}}",
            epoch - START + 1,
            registry.total_active(),
            registry.cap_sat(),
        );
    }
}
