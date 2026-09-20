//! Deterministic key-bound test verifier; actual hybrid crypto is tested in bloch-ustav.
use bloch_euvm::modules::{ModuleKind, SupplyConfig, TokenCharter};
use bloch_euvm::ustav::amm::{Action, PoolState, Request};
use bloch_euvm::ustav::gateway::pools::wire::{self, Envelope, Error};
use bloch_euvm::ustav::gateway::pools::{creation_hash, PoolAction, PoolLedger};
use bloch_euvm::ustav::{OutPoint, Output, Registration, Transaction, Verifier, Witnesses};
use bloch_euvm::Val;
use sha2::{Digest, Sha256};
const DOMAIN: [u8; 32] = [51; 32];
const GAS: u64 = 10_000_000;
struct V;
fn sign(hash: &[u8], key: &[u8]) -> Vec<u8> {
    Sha256::digest([key, hash].concat()).to_vec()
}
impl Verifier for V {
    fn valid_pq_key(&self, k: &[u8]) -> bool {
        k.len() == 32 && k[0] > 0
    }
    fn verify_pq(&self, m: &[u8], k: &[u8], s: &[u8]) -> bool {
        self.valid_pq_key(k) && sign(m, k) == s
    }
}
fn envelope(action: Action) -> Envelope {
    Envelope {
        domain: DOMAIN,
        action: PoolAction {
            request: Request {
                pool: [9; 32],
                revision: 7,
                valid_until: 100,
                action,
            },
            owner: vec![8; 32],
            funding: [
                vec![OutPoint {
                    transaction: [1; 32],
                    index: 2,
                }],
                vec![],
            ],
        },
        signature: vec![6; 32],
    }
}
#[test]
fn all_actions_roundtrip_truncation_and_canonical_bytes() {
    for action in [
        Action::Add {
            maximum: [100, 200],
            minimum_lp: 1,
        },
        Action::SwapExactInput {
            input_index: 1,
            amount: 10,
            minimum_out: 2,
        },
        Action::Remove {
            lp: 5,
            minimum: [2, 3],
        },
    ] {
        let e = envelope(action);
        let bytes = wire::encode(&e).unwrap();
        assert_eq!(wire::decode(&bytes).unwrap(), e);
        assert_eq!(wire::encode(&wire::decode(&bytes).unwrap()).unwrap(), bytes);
        for end in 0..bytes.len() {
            assert!(wire::decode(&bytes[..end]).is_err(), "truncation {end}");
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(wire::decode(&trailing), Err(Error::TrailingBytes));
    }
}
#[test]
fn bad_header_counts_lengths_and_order_rejected() {
    let e = envelope(Action::Add {
        maximum: [100, 200],
        minimum_lp: 1,
    });
    let bytes = wire::encode(&e).unwrap();
    for offset in [0, 8, 10] {
        let mut bad = bytes.clone();
        bad[offset] = 255;
        assert!(wire::decode(&bad).is_err());
    }
    // Header91 + Add payload24 = owner length offset115; owner32 then funding count151.
    for offset in [115, 151] {
        let mut bad = bytes.clone();
        bad[offset..offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(wire::decode(&bad).is_err());
    }
    let mut bad = e.clone();
    bad.action.funding[0].push(bad.action.funding[0][0]);
    assert_eq!(wire::encode(&bad), Err(Error::InvalidShape));
    bad = e.clone();
    bad.action.owner = vec![1; 8193];
    assert_eq!(wire::encode(&bad), Err(Error::InvalidShape));
    bad = e.clone();
    bad.signature.clear();
    assert_eq!(wire::encode(&bad), Err(Error::InvalidShape));
    assert_eq!(
        wire::decode(&vec![0; wire::MAX_ENCODED_BYTES + 1]),
        Err(Error::TooLarge)
    );
}
fn fixture() -> (PoolLedger, Envelope) {
    let mut ledger = PoolLedger::new(DOMAIN);
    let owner = vec![8; 32];
    let mut minted = Vec::new();
    for i in 0..2 {
        let r = Registration {
            charter: TokenCharter {
                token_name: vec![65, i],
                modules: vec![ModuleKind::Supply(SupplyConfig {
                    cap: 10_000_000,
                    issuer_pubkey: owner.clone(),
                })],
            },
            nonce: [i; 32],
            initial_kyc_root: None,
        };
        let sig = sign(&r.signing_hash(&DOMAIN).unwrap(), &owner);
        let asset = ledger.register(r, &sig, &V, GAS).unwrap();
        let tx = Transaction {
            asset,
            inputs: vec![],
            outputs: vec![Output {
                owner: owner.clone(),
                amount: 1_000_000,
            }],
            delta: 1_000_000,
            mint_nonce: 0,
            policy_revision: 0,
            valid_until: 100,
        };
        let w = Witnesses {
            modules: vec![vec![Val::Bytes(sign(
                &tx.signing_hash(&DOMAIN).unwrap(),
                &owner,
            ))]],
            ..Witnesses::default()
        };
        let receipt = ledger.apply(&tx, &w, 1, &V, GAS).unwrap();
        minted.push((asset, receipt.outputs[0]));
    }
    minted.sort_by_key(|a| a.0);
    let pool = PoolState::new(DOMAIN, minted[0].0, minted[1].0, 30, [12; 32]).unwrap();
    let sig = sign(&creation_hash(&pool, &owner).unwrap(), &owner);
    let id = ledger.create(pool, &owner, &sig, &V, GAS).unwrap();
    let action = PoolAction {
        request: Request {
            pool: id,
            revision: 0,
            valid_until: 100,
            action: Action::Add {
                maximum: [100_000, 200_000],
                minimum_lp: 1,
            },
        },
        owner: owner.clone(),
        funding: [vec![minted[0].1], vec![minted[1].1]],
    };
    let signature = sign(&ledger.signing_hash(&action).unwrap(), &owner);
    (
        ledger,
        Envelope {
            domain: DOMAIN,
            action,
            signature,
        },
    )
}
#[test]
fn encoded_execution_gas_domain_signature_and_lock_boundary() {
    let (mut ledger, e) = fixture();
    let bytes = wire::encode(&e).unwrap();
    let before = ledger.snapshot();
    assert_eq!(
        wire::apply_encoded(&mut ledger, &bytes, 2, &V, 0),
        Err(Error::OutOfGas)
    );
    assert_eq!(ledger.snapshot(), before);
    let mut wrong = e.clone();
    wrong.domain = [52; 32];
    assert_eq!(
        wire::apply_encoded(&mut ledger, &wire::encode(&wrong).unwrap(), 2, &V, GAS),
        Err(Error::WrongDomain)
    );
    assert_eq!(ledger.snapshot(), before);
    let mut forged = e.clone();
    forged.signature[0] ^= 1;
    assert!(wire::apply_encoded(&mut ledger, &wire::encode(&forged).unwrap(), 2, &V, GAS).is_err());
    assert_eq!(ledger.snapshot(), before);
    let parse_only = 100 + (bytes.len() as u64).div_ceil(32);
    assert!(wire::apply_encoded(&mut ledger, &bytes, 2, &V, parse_only).is_err());
    assert_eq!(ledger.snapshot(), before);
    let mut direct = ledger.clone();
    let expected = direct.execute(&e.action, &e.signature, 2, &V, GAS).unwrap();
    let receipt = wire::apply_encoded(&mut ledger, &bytes, 2, &V, GAS).unwrap();
    assert_eq!(ledger.state_root(), direct.state_root());
    assert_eq!(
        receipt.gas_used,
        expected.gas_used + 100 + (bytes.len() as u64).div_ceil(32)
    );
    assert!(receipt.reserves.iter().all(|p| ledger.is_locked(p)));
    let mut locked = e.clone();
    locked.action.request.revision = 1;
    locked.action.request.action = Action::SwapExactInput {
        input_index: 0,
        amount: 10,
        minimum_out: 1,
    };
    locked.action.funding = [vec![receipt.reserves[0]], vec![]];
    locked.signature = sign(
        &ledger.signing_hash(&locked.action).unwrap(),
        &locked.action.owner,
    );
    let before = ledger.snapshot();
    assert!(wire::apply_encoded(&mut ledger, &wire::encode(&locked).unwrap(), 3, &V, GAS).is_err());
    assert_eq!(ledger.snapshot(), before);
    assert!(wire::apply_encoded(&mut ledger, &bytes, 3, &V, GAS).is_err());
    assert_eq!(ledger.snapshot(), before);
}

#[test]
fn maximum_bounded_shape_fits_documented_limit() {
    let mut e = envelope(Action::Add {
        maximum: [1, 1],
        minimum_lp: 1,
    });
    e.action.owner = vec![1; 8192];
    e.signature = vec![2; 8192];
    e.action.funding = std::array::from_fn(|side| {
        (0..128)
            .map(|index| OutPoint {
                transaction: [side as u8 + 1; 32],
                index,
            })
            .collect()
    });
    let encoded = wire::encode(&e).unwrap();
    assert_eq!(encoded.len(), 25_731);
    assert_eq!(wire::decode(&encoded).unwrap(), e);
}
