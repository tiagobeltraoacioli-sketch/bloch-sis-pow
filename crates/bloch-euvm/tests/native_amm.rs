use bloch_euvm::ustav::amm::{Action, Error, PoolState, Request, Transition, MINIMUM_LIQUIDITY};
use bloch_euvm::BLCH;
fn empty() -> PoolState {
    PoolState::new([1; 32], BLCH, [2; 32], 30, [3; 32]).unwrap()
}
fn run(p: &PoolState, action: Action) -> Result<Transition, Error> {
    p.transition(
        &Request {
            pool: p.id(),
            revision: p.revision(),
            valid_until: 100,
            action,
        },
        100,
    )
}
fn funded() -> PoolState {
    run(
        &empty(),
        Action::Add {
            maximum: [1_000_000, 2_000_000],
            minimum_lp: 1,
        },
    )
    .unwrap()
    .next
}
#[test]
fn full_width_swaps_match_independent_arbitrary_precision_vectors() {
    // Expected floor(a*(10000-f)*y / (x*10000+a*(10000-f))) values
    // calculated independently with Python arbitrary-precision integers.
    let max = u64::MAX;
    for (x, y, amount, fee, expected) in [
        (max / 2, max, max / 2, 30, 9_209_516_195_036_766_630),
        (max - 1, max, 1, 0, 1),
        (1, max, max - 1, 9999, 18_446_744_073_709_541_615),
        (max / 4, max / 3, max / 2, 30, 4_095_168_969_380_633_035),
        (
            1_000_000_000_000_000_000,
            1_000_000_000_000_000_000,
            1_000_000_000_000_000_000,
            30,
            499_248_873_309_964_947,
        ),
    ] {
        for direction in 0..2 {
            let reserves = if direction == 0 { [x, y] } else { [y, x] };
            let pool = PoolState::new([1; 32], BLCH, [2; 32], fee, [3; 32]).unwrap();
            let pool = run(
                &pool,
                Action::Add {
                    maximum: reserves,
                    minimum_lp: 1,
                },
            )
            .unwrap()
            .next;
            let t = run(
                &pool,
                Action::SwapExactInput {
                    input_index: direction as u8,
                    amount,
                    minimum_out: expected,
                },
            )
            .unwrap();
            assert_eq!(t.user_credit[1 - direction], expected);
            assert_eq!(t.next.reserves()[direction], x + amount);
            assert_eq!(t.next.reserves()[1 - direction], y - expected);
            assert_eq!(t.next.lp_supply(), pool.lp_supply());
            assert!(
                u128::from(t.next.reserves()[0]) * u128::from(t.next.reserves()[1])
                    >= u128::from(x) * u128::from(y)
            );
            assert_eq!(
                run(
                    &pool,
                    Action::SwapExactInput {
                        input_index: direction as u8,
                        amount,
                        minimum_out: expected + 1,
                    }
                ),
                Err(Error::Slippage)
            );
        }
    }
}

#[test]
fn bounded_fraction_arithmetic_matches_direct_formula_when_product_fits() {
    for fee in [0, 1, 30, 100, 9999] {
        let pool = PoolState::new([1; 32], BLCH, [2; 32], fee, [3; 32]).unwrap();
        let pool = run(
            &pool,
            Action::Add {
                maximum: [1_000_003, 9_000_019],
                minimum_lp: 1,
            },
        )
        .unwrap()
        .next;
        for direction in 0..2 {
            for amount in [1, 2, 31, 10_000, 100_003, 1_000_000_000] {
                let r = pool.reserves();
                let effective = u128::from(amount) * u128::from(10_000 - fee);
                let expected = effective * u128::from(r[1 - direction])
                    / (u128::from(r[direction]) * 10_000 + effective);
                let result = run(
                    &pool,
                    Action::SwapExactInput {
                        input_index: direction as u8,
                        amount,
                        minimum_out: 0,
                    },
                );
                if expected == 0 {
                    assert_eq!(result, Err(Error::InsufficientLiquidity));
                } else {
                    assert_eq!(
                        u128::from(result.unwrap().user_credit[1 - direction]),
                        expected
                    );
                }
            }
        }
    }
}
#[test]
fn canonical_identity_commits_domain_fee_seed_and_allows_real_blch() {
    let p = empty();
    assert_eq!(
        p.id(),
        PoolState::new([1; 32], [2; 32], BLCH, 30, [3; 32])
            .unwrap()
            .id()
    );
    assert_ne!(
        p.id(),
        PoolState::new([9; 32], BLCH, [2; 32], 30, [3; 32])
            .unwrap()
            .id()
    );
    assert_ne!(
        p.id(),
        PoolState::new([1; 32], BLCH, [2; 32], 31, [3; 32])
            .unwrap()
            .id()
    );
    assert_ne!(
        p.id(),
        PoolState::new([1; 32], BLCH, [2; 32], 30, [9; 32])
            .unwrap()
            .id()
    );
    assert!(PoolState::new([1; 32], BLCH, BLCH, 30, [3; 32]).is_err());
    assert!(PoolState::new([0; 32], BLCH, [2; 32], 30, [3; 32]).is_err());
    assert!(PoolState::new([1; 32], BLCH, [2; 32], 10_000, [3; 32]).is_err());
}
#[test]
fn add_swap_remove_conserves_reserves_and_permanent_shares() {
    let p = empty();
    let initial = run(
        &p,
        Action::Add {
            maximum: [1_000_000, 2_000_000],
            minimum_lp: 1,
        },
    )
    .unwrap();
    assert_eq!(
        initial.lp_mint + MINIMUM_LIQUIDITY,
        initial.next.lp_supply()
    );
    let added = run(
        &initial.next,
        Action::Add {
            maximum: [100_000, 400_000],
            minimum_lp: 1,
        },
    )
    .unwrap();
    for i in 0..2 {
        assert_eq!(
            added.user_debit[i] + added.unused_maximum[i],
            [100_000, 400_000][i]
        );
    }
    assert!(added.unused_maximum[1] > 0);
    let swapped = run(
        &added.next,
        Action::SwapExactInput {
            input_index: 0,
            amount: 10_000,
            minimum_out: 1,
        },
    )
    .unwrap();
    assert!(swapped.user_credit[1] > 0 && swapped.user_credit[1] < added.next.reserves()[1]);
    let removed = run(
        &swapped.next,
        Action::Remove {
            lp: swapped.next.lp_supply() - MINIMUM_LIQUIDITY,
            minimum: [1, 1],
        },
    )
    .unwrap();
    assert_eq!(removed.next.lp_supply(), MINIMUM_LIQUIDITY);
    assert!(removed.next.reserves().iter().all(|n| *n > 0));
    assert!(run(
        &removed.next,
        Action::Remove {
            lp: 1,
            minimum: [0, 0]
        }
    )
    .is_err());
    for (before, t) in [
        (&p, &initial),
        (&initial.next, &added),
        (&added.next, &swapped),
        (&swapped.next, &removed),
    ] {
        for i in 0..2 {
            assert_eq!(
                u128::from(before.reserves()[i]) + u128::from(t.user_debit[i]),
                u128::from(t.next.reserves()[i]) + u128::from(t.user_credit[i])
            );
        }
        assert_eq!(t.next.revision(), before.revision() + 1);
    }
}
#[test]
fn replay_wrong_pool_expiry_and_slippage_preserve_input_state() {
    let p = funded();
    let before = p.clone();
    let request = Request {
        pool: p.id(),
        revision: p.revision(),
        valid_until: 100,
        action: Action::SwapExactInput {
            input_index: 0,
            amount: 1000,
            minimum_out: 1,
        },
    };
    let accepted = p.transition(&request, 100).unwrap();
    assert_eq!(
        accepted.next.transition(&request, 100),
        Err(Error::StaleRevision)
    );
    assert_eq!(p.transition(&request, 101), Err(Error::Expired));
    let mut wrong = request.clone();
    wrong.pool = [0; 32];
    assert_eq!(p.transition(&wrong, 100), Err(Error::InvalidPool));
    assert_eq!(
        run(
            &p,
            Action::SwapExactInput {
                input_index: 0,
                amount: 1,
                minimum_out: u64::MAX
            }
        ),
        Err(Error::Slippage)
    );
    assert_eq!(
        run(
            &p,
            Action::Add {
                maximum: [1000, 1000],
                minimum_lp: u64::MAX
            }
        ),
        Err(Error::Slippage)
    );
    assert_eq!(
        run(
            &p,
            Action::Remove {
                lp: 1000,
                minimum: [u64::MAX, 1]
            }
        ),
        Err(Error::Slippage)
    );
    assert_eq!(p, before);
}
#[test]
fn invalid_dust_and_full_width_overflow_fail_closed() {
    assert!(run(
        &empty(),
        Action::Add {
            maximum: [1000, 1000],
            minimum_lp: 0
        }
    )
    .is_err());
    assert!(run(
        &empty(),
        Action::SwapExactInput {
            input_index: 0,
            amount: 10,
            minimum_out: 0
        }
    )
    .is_err());
    let p = funded();
    for index in [2, 255] {
        assert!(run(
            &p,
            Action::SwapExactInput {
                input_index: index,
                amount: 1,
                minimum_out: 0
            }
        )
        .is_err());
    }
    assert!(run(
        &p,
        Action::SwapExactInput {
            input_index: 0,
            amount: 0,
            minimum_out: 0
        }
    )
    .is_err());
    assert!(run(
        &p,
        Action::Remove {
            lp: p.lp_supply(),
            minimum: [0, 0]
        }
    )
    .is_err());
    let big = run(
        &empty(),
        Action::Add {
            maximum: [u64::MAX, u64::MAX],
            minimum_lp: 1,
        },
    )
    .unwrap()
    .next;
    assert_eq!(big.lp_supply(), u64::MAX);
    assert_eq!(
        run(
            &big,
            Action::SwapExactInput {
                input_index: 0,
                amount: u64::MAX,
                minimum_out: 0
            }
        ),
        Err(Error::Overflow)
    );
    assert_eq!(
        run(
            &big,
            Action::Add {
                maximum: [1, 1],
                minimum_lp: 0
            }
        ),
        Err(Error::Overflow)
    );
}
#[test]
fn deterministic_campaign_checks_invariant_rounding_and_no_free_lp() {
    let mut p = funded();
    for i in 1..=512u64 {
        let old = p.reserves();
        let t = run(
            &p,
            Action::SwapExactInput {
                input_index: (i % 2) as u8,
                amount: i * 31,
                minimum_out: 1,
            },
        )
        .unwrap();
        assert!(
            u128::from(t.next.reserves()[0]) * u128::from(t.next.reserves()[1])
                >= u128::from(old[0]) * u128::from(old[1])
        );
        p = t.next;
        let add = run(
            &p,
            Action::Add {
                maximum: [10_003 + i, 30_001 + i],
                minimum_lp: 1,
            },
        )
        .unwrap();
        let remove = run(
            &add.next,
            Action::Remove {
                lp: add.lp_mint,
                minimum: [1, 1],
            },
        )
        .unwrap();
        for j in 0..2 {
            assert!(remove.user_credit[j] <= add.user_debit[j]);
        }
        p = remove.next;
    }
}

#[test]
fn asymmetric_maximum_is_narrowed_only_after_limiting_side_selection() {
    for amounts in [[10_000, 1_000_000], [1_000_000, 10_000]] {
        let pool = run(
            &empty(),
            Action::Add {
                maximum: amounts,
                minimum_lp: 1,
            },
        )
        .unwrap()
        .next;
        assert_eq!(pool.lp_supply(), 100_000);
        let mut maximum = amounts;
        let excess_index = if amounts[0] < amounts[1] { 0 } else { 1 };
        maximum[excess_index] = u64::MAX;
        let added = run(
            &pool,
            Action::Add {
                maximum,
                minimum_lp: 100_000,
            },
        )
        .unwrap();
        assert_eq!(added.lp_mint, 100_000);
        assert_eq!(added.user_debit, amounts);
        assert_eq!(
            added.unused_maximum[excess_index],
            u64::MAX - amounts[excess_index]
        );
        assert_eq!(added.unused_maximum[1 - excess_index], 0);
        assert_eq!(added.next.lp_supply(), 200_000);
    }
}

#[test]
fn snapshots_restore_reachable_states_and_reject_tampering() {
    let mut p = empty();
    for action in [
        Action::Add {
            maximum: [10_000, 1_000_000],
            minimum_lp: 1,
        },
        Action::SwapExactInput {
            input_index: 0,
            amount: 1000,
            minimum_out: 1,
        },
        Action::Add {
            maximum: [20_000, 20_000],
            minimum_lp: 1,
        },
    ] {
        assert_eq!(PoolState::restore(p.snapshot(), p.state_root()).unwrap(), p);
        p = run(&p, action).unwrap().next;
    }
    p = run(
        &p,
        Action::Remove {
            lp: p.lp_supply() - MINIMUM_LIQUIDITY,
            minimum: [1, 1],
        },
    )
    .unwrap()
    .next;
    assert_eq!(PoolState::restore(p.snapshot(), p.state_root()).unwrap(), p);
    let original = p.snapshot();
    let mut changed = Vec::new();
    let mut s = original.clone();
    s.domain[0] ^= 1;
    changed.push(s);
    let mut s = original.clone();
    s.seed[0] ^= 1;
    changed.push(s);
    let mut s = original.clone();
    s.id[0] ^= 1;
    changed.push(s);
    let mut s = original.clone();
    s.fee_bps += 1;
    changed.push(s);
    let mut s = original.clone();
    s.assets.swap(0, 1);
    changed.push(s);
    let mut s = original.clone();
    s.reserves[0] += 1;
    changed.push(s);
    let mut s = original.clone();
    s.lp_supply += 1;
    changed.push(s);
    let mut s = original.clone();
    s.revision += 1;
    changed.push(s);
    let mut s = original.clone();
    s.version += 1;
    changed.push(s);
    for s in changed {
        assert_eq!(
            PoolState::restore(s, p.state_root()),
            Err(Error::InvalidSnapshot)
        );
    }
    // A self-consistent hash does not make malformed state acceptable.
    for (reserve, supply, revision) in [
        ([0, 0], 1, 0),
        ([1, 0], 0, 0),
        ([0, 0], 0, 1),
        ([1, 1], 1000, 2),
        ([1000, 1000], 999, 2),
        ([1000, 1000], 1000, 1),
        ([2000, 2000], 1001, 1),
    ] {
        let mut s = original.clone();
        s.reserves = reserve;
        s.lp_supply = supply;
        s.revision = revision;
        let hash = s.state_root();
        assert_eq!(PoolState::restore(s, hash), Err(Error::InvalidSnapshot));
    }
    for field in 0..3 {
        let mut s = original.clone();
        match field {
            0 => s.domain[0] ^= 1,
            1 => s.seed[0] ^= 1,
            _ => s.assets.swap(0, 1),
        }
        let hash = s.state_root();
        assert_eq!(PoolState::restore(s, hash), Err(Error::InvalidSnapshot));
    }
}

#[test]
fn signing_commitment_binds_entire_request_state_and_funding() {
    let p = funded();
    let request = Request {
        pool: p.id(),
        revision: p.revision(),
        valid_until: 100,
        action: Action::Add {
            maximum: [100, 200],
            minimum_lp: 7,
        },
    };
    let expected = request.signing_hash(&p, [4; 32]).unwrap();
    assert_eq!(expected, p.signing_hash(&request, [4; 32]).unwrap());
    assert_ne!(expected, p.signing_hash(&request, [5; 32]).unwrap());
    assert_eq!(p.signing_hash(&request, [0; 32]), Err(Error::InvalidAction));
    for action in [
        Action::Add {
            maximum: [101, 200],
            minimum_lp: 7,
        },
        Action::Add {
            maximum: [100, 201],
            minimum_lp: 7,
        },
        Action::Add {
            maximum: [100, 200],
            minimum_lp: 8,
        },
        Action::SwapExactInput {
            input_index: 0,
            amount: 100,
            minimum_out: 7,
        },
        Action::Remove {
            lp: 100,
            minimum: [200, 7],
        },
    ] {
        let mut changed = request.clone();
        changed.action = action;
        assert_ne!(expected, changed.signing_hash(&p, [4; 32]).unwrap());
    }
    let mut changed = request.clone();
    changed.valid_until += 1;
    assert_ne!(expected, changed.signing_hash(&p, [4; 32]).unwrap());
    changed = request.clone();
    changed.revision += 1;
    assert_eq!(changed.signing_hash(&p, [4; 32]), Err(Error::StaleRevision));
    changed = request.clone();
    changed.pool[0] ^= 1;
    assert_eq!(changed.signing_hash(&p, [4; 32]), Err(Error::InvalidPool));
    let mut snapshot = p.snapshot();
    snapshot.reserves[0] += 1000;
    snapshot.revision = 2;
    let altered = PoolState::restore(snapshot.clone(), snapshot.state_root()).unwrap();
    changed = request.clone();
    changed.revision = 2;
    assert_ne!(expected, changed.signing_hash(&altered, [4; 32]).unwrap());
}
