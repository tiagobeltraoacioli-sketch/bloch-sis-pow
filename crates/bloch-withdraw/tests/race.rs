// SPDX-License-Identifier: AGPL-3.0-or-later

//! The tests this crate exists for: the double-payment race, closed — and,
//! first, demonstrated.
//!
//! The fake chain below is not a mock that answers what the test wants to
//! hear. It holds a real eUTXO map and re-runs the same admission arithmetic
//! consensus runs — `fee_market::charge` for the price, `owns` for
//! authorisation shape, real hybrid signature verification, conservation as
//! an equality — against transactions decoded from the exact bytes the
//! client submits. What it fakes is only the scheduler: WHICH bytes get
//! included WHEN, and at WHAT base fee, is the adversary's choice, which is
//! precisely the power a real network has over a withdrawal client.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::sync::OnceLock;

use bloch_pos_committee::fee_market::{self, TxClass};
use bloch_pos_committee::params::SLOTS_PER_EPOCH;
use bloch_pos_committee::transition::PosTransaction;
use sha3::{Digest, Sha3_256};

use bloch_withdraw::json::Json;
use bloch_withdraw::rpc::{Node, RpcFailure, SubmitOutcome};
use bloch_withdraw::store::{AttemptKind, MemStore, Status, Store};
use bloch_withdraw::{Config, KeyMaterial, Withdrawer};

// ─── One expensive key for the whole suite ──────────────────────────────────

fn wallet_key() -> &'static KeyMaterial {
    static KEY: OnceLock<KeyMaterial> = OnceLock::new();
    KEY.get_or_init(|| KeyMaterial::from_seed(&[0x57; 32]).unwrap())
}

/// A recipient's `script_hash`: 32 bytes, the native Genesis-4 shape.
///
/// It used to be twenty 0xEE bytes and twelve zeroes — the carried shape —
/// because the client derived every payee from an address. It does not any
/// more, and a test that kept building the carried shape would have been the
/// last place the old convention survived.
fn recipient_script() -> [u8; 32] {
    [0xEE; 32]
}

/// The payee, in the form Genesis-4 actually uses: a 64-hex `script_hash`.
///
/// This used to be the `bloch1q…` address whose 20 bytes matched
/// `recipient_script`. It is now the hash itself, because the client no longer
/// derives one from the other — see `address.rs`.
fn recipient_address() -> String {
    hex_of(&recipient_script())
}

fn hex_of(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// ─── The fake chain ─────────────────────────────────────────────────────────

#[derive(Clone)]
struct Entry {
    value: u64,
    script_hash: [u8; 32],
}

struct FakeChain {
    eutxos: BTreeMap<([u8; 32], u32), Entry>,
    /// The price the next included block charges — reported to the client as
    /// `next_base_fee_millisat_per_gas`, enforced by `include`.
    base_fee: u128,
    slot: u64,
    finalized_epoch: u64,
    /// Canonical bytes accepted by `sendrawtransaction`, in arrival order.
    mempool: Vec<Vec<u8>>,
}

impl FakeChain {
    fn new(base_fee: u128, slot: u64) -> FakeChain {
        FakeChain { eutxos: BTreeMap::new(), base_fee, slot, finalized_epoch: 0, mempool: Vec::new() }
    }

    fn fund(&mut self, tag: u8, vout: u32, value: u64, script_hash: [u8; 32]) -> ([u8; 32], u32) {
        let txid = [tag; 32];
        self.eutxos.insert((txid, vout), Entry { value, script_hash });
        (txid, vout)
    }

    fn balance(&self, script_hash: &[u8; 32]) -> u128 {
        self.eutxos
            .values()
            .filter(|e| &e.script_hash == script_hash)
            .map(|e| u128::from(e.value))
            .sum()
    }

    /// Apply one transaction the way `transition::apply_transfer*` would:
    /// same checks, same order of ideas, same arithmetic — at THIS chain's
    /// current base fee. Advances the slot on success (a block happened).
    fn include(&mut self, bytes: &[u8]) -> Result<[u8; 32], String> {
        let tx = PosTransaction::from_canonical_bytes(bytes).map_err(|e| format!("{e:?}"))?;
        let (spends, witnesses, outputs, tx_bytes, tip, n_verifies): (
            Vec<([u8; 32], u32)>,
            Vec<(Vec<u8>, Vec<u8>)>,
            _,
            u64,
            u128,
            u32,
        ) = match &tx {
            PosTransaction::Transfer { inputs, outputs, tx_bytes, tip_millisat_per_gas } => (
                inputs.iter().map(|i| (i.txid, i.vout)).collect(),
                inputs.iter().map(|i| (i.pubkey.clone(), i.signature.clone())).collect(),
                outputs.clone(),
                *tx_bytes,
                *tip_millisat_per_gas,
                inputs.len() as u32,
            ),
            PosTransaction::TransferV2 { keys, inputs, outputs, tx_bytes, tip_millisat_per_gas } => (
                inputs.iter().map(|i| (i.txid, i.vout)).collect(),
                inputs
                    .iter()
                    .map(|i| {
                        let k = &keys[i.key_index as usize];
                        (k.pubkey.clone(), k.signature.clone())
                    })
                    .collect(),
                outputs.clone(),
                *tx_bytes,
                *tip_millisat_per_gas,
                keys.len() as u32,
            ),
            other => return Err(format!("not a transfer: {other:?}")),
        };
        if spends.is_empty() {
            return Err("NoInputs".into());
        }
        if tx_bytes < bytes.len() as u64 {
            return Err("UnderdeclaredSize".into());
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut spent_value: u128 = 0;
        for (outpoint, (pubkey, _)) in spends.iter().zip(&witnesses) {
            if !seen.insert(*outpoint) {
                return Err("DuplicateInput".into());
            }
            let Some(entry) = self.eutxos.get(outpoint) else {
                return Err("UnknownInput".into());
            };
            let key_hash: [u8; 32] = Sha3_256::digest(pubkey).into();
            let owns = key_hash == entry.script_hash
                || (entry.script_hash[20..] == [0u8; 12]
                    && key_hash[..20] == entry.script_hash[..20]);
            if !owns {
                return Err("ScriptMismatch".into());
            }
            spent_value += u128::from(entry.value);
        }
        let charge =
            fee_market::charge(TxClass::Eutxo { inputs: n_verifies }, tx_bytes, self.base_fee, tip);
        let created: u128 = outputs.iter().map(|o| u128::from(o.value)).sum();
        if spent_value != created + charge.base_fee_sat + charge.priority_fee_sat {
            return Err("ValueNotConserved".into());
        }
        let txid = tx.txid();
        for vout in 0..outputs.len() as u32 {
            if self.eutxos.contains_key(&(txid, vout)) {
                return Err("OutputExists".into());
            }
        }
        let root = tx.spend_signing_root();
        for (pubkey, signature) in &witnesses {
            if !bloch_crypto::crypto::verify(pubkey, &root, signature) {
                return Err("BadSignature".into());
            }
        }
        for outpoint in &spends {
            self.eutxos.remove(outpoint);
        }
        for (vout, o) in outputs.iter().enumerate() {
            self.eutxos
                .insert((txid, vout as u32), Entry { value: o.value, script_hash: o.script_hash });
        }
        self.slot += 1;
        Ok(txid)
    }

    /// Finalize everything up to and including `slot`: the boundary the
    /// client reads becomes `> slot`.
    fn finalize_past(&mut self, slot: u64) {
        self.finalized_epoch = slot / SLOTS_PER_EPOCH + 1;
        if self.slot < self.finalized_epoch * SLOTS_PER_EPOCH {
            self.slot = self.finalized_epoch * SLOTS_PER_EPOCH;
        }
    }
}

/// `Node` over the fake chain — the same JSON the real node serves, so the
/// client's parsing is exercised too (amounts as decimal strings, etc).
struct FakeNode {
    chain: RefCell<FakeChain>,
}

impl FakeNode {
    fn new(chain: FakeChain) -> FakeNode {
        FakeNode { chain: RefCell::new(chain) }
    }
}

fn sat(v: u128) -> Json {
    Json::s(v.to_string())
}

impl Node for FakeNode {
    fn call(&self, method: &str, params: Json) -> Result<Json, RpcFailure> {
        let mut chain = self.chain.borrow_mut();
        let hexpar = |i: usize| -> Option<[u8; 32]> {
            let s = params.at(i)?.as_str()?;
            if s.len() != 64 {
                return None;
            }
            let mut out = [0u8; 32];
            for (k, pair) in s.as_bytes().chunks_exact(2).enumerate() {
                let hi = (pair[0] as char).to_digit(16)?;
                let lo = (pair[1] as char).to_digit(16)?;
                out[k] = (hi * 16 + lo) as u8;
            }
            Some(out)
        };
        match method {
            "getchaininfo" => Ok(Json::Obj(vec![
                ("slot".into(), Json::u(chain.slot)),
                ("epoch".into(), Json::u(chain.slot / SLOTS_PER_EPOCH)),
                ("height".into(), Json::u(chain.slot)),
                ("finalized_height".into(), Json::u(chain.finalized_epoch * SLOTS_PER_EPOCH)),
                (
                    "finalized".into(),
                    Json::Obj(vec![("epoch".into(), Json::u(chain.finalized_epoch))]),
                ),
                ("base_fee_millisat_per_gas".into(), sat(chain.base_fee)),
                ("next_base_fee_millisat_per_gas".into(), sat(chain.base_fee)),
                ("behind_by_slots".into(), Json::u(0)),
            ])),
            "gettxout" => {
                let txid = hexpar(0).ok_or(RpcFailure::Transport("bad txid".into()))?;
                let vout = params.at(1).and_then(Json::as_u64).unwrap_or(0) as u32;
                let (unspent, utxo) = match chain.eutxos.get(&(txid, vout)) {
                    Some(e) => (
                        true,
                        Json::Obj(vec![("value_sat".into(), sat(u128::from(e.value)))]),
                    ),
                    None => (false, Json::Null),
                };
                Ok(Json::Obj(vec![
                    ("unspent".into(), Json::Bool(unspent)),
                    ("utxo".into(), utxo),
                    ("at_slot".into(), Json::u(chain.slot)),
                ]))
            }
            "listunspent" => {
                let script = hexpar(0).ok_or(RpcFailure::Transport("bad script".into()))?;
                let limit = params.at(1).and_then(Json::as_u64).unwrap_or(100) as usize;
                let matching: Vec<Json> = chain
                    .eutxos
                    .iter()
                    .filter(|(_, e)| e.script_hash == script)
                    .take(limit)
                    .map(|((txid, vout), e)| {
                        Json::Obj(vec![
                            ("txid".into(), Json::hex(txid)),
                            ("vout".into(), Json::u(u64::from(*vout))),
                            ("value_sat".into(), sat(u128::from(e.value))),
                        ])
                    })
                    .collect();
                Ok(Json::Obj(vec![
                    ("truncated".into(), Json::Bool(false)),
                    ("utxos".into(), Json::Arr(matching)),
                ]))
            }
            "getbalance" => {
                let script = hexpar(0).ok_or(RpcFailure::Transport("bad script".into()))?;
                let bal = chain.balance(&script);
                Ok(Json::Obj(vec![
                    ("balance_sat".into(), sat(bal)),
                    ("utxo_count".into(), Json::u(0)),
                ]))
            }
            "sendrawtransaction" => {
                let hex = params
                    .at(0)
                    .and_then(Json::as_str)
                    .ok_or(RpcFailure::Transport("missing hex".into()))?;
                let mut bytes = Vec::with_capacity(hex.len() / 2);
                for pair in hex.as_bytes().chunks_exact(2) {
                    let hi = (pair[0] as char).to_digit(16).unwrap();
                    let lo = (pair[1] as char).to_digit(16).unwrap();
                    bytes.push((hi * 16 + lo) as u8);
                }
                // Structural admission only, like the real node: full
                // validity is judged at inclusion, silently.
                if PosTransaction::from_canonical_bytes(&bytes).is_err() {
                    return Err(RpcFailure::Rpc {
                        code: bloch_withdraw::rpc::TX_DECODE_FAILED,
                        message: "not canonical".into(),
                    });
                }
                let duplicate = chain.mempool.iter().any(|b| b == &bytes);
                if !duplicate {
                    chain.mempool.push(bytes);
                }
                Ok(Json::Obj(vec![(
                    "status".into(),
                    Json::s(if duplicate { "duplicate" } else { "accepted" }),
                )]))
            }
            other => Err(RpcFailure::Rpc { code: -32601, message: format!("no {other}") }),
        }
    }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/// A slot inside an epoch where TransferV2 is active, so the default build
/// path (single witness) is the one exercised.
fn v2_era_slot() -> u64 {
    (bloch_pos_committee::params::TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH + 100) * SLOTS_PER_EPOCH
}

fn outpoints_of(bytes: &[u8]) -> Vec<([u8; 32], u32)> {
    match PosTransaction::from_canonical_bytes(bytes).unwrap() {
        PosTransaction::Transfer { inputs, .. } => {
            inputs.iter().map(|i| (i.txid, i.vout)).collect()
        }
        PosTransaction::TransferV2 { inputs, .. } => {
            inputs.iter().map(|i| (i.txid, i.vout)).collect()
        }
        _ => panic!("not a transfer"),
    }
}

fn attempt_bytes(store: &dyn Store, id: &str, index: usize) -> Vec<u8> {
    let rec = store.load(id).unwrap().unwrap();
    let hex = &rec.attempts[index].canonical_hex;
    let mut out = Vec::with_capacity(hex.len() / 2);
    for pair in hex.as_bytes().chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16).unwrap();
        let lo = (pair[1] as char).to_digit(16).unwrap();
        out.push((hi * 16 + lo) as u8);
    }
    out
}

const AMOUNT: u64 = 40_000_000;

// ─── The tests ──────────────────────────────────────────────────────────────

/// FIRST, the hazard, demonstrated against consensus arithmetic: a naive
/// client that rebuilds with FRESH coins produces two transactions the chain
/// happily includes both of. This is the behaviour every retry loop written
/// against a txid-bearing chain would exhibit here, and it is real money out
/// the door twice.
#[test]
fn naive_rebuild_with_fresh_coins_pays_twice() {
    let key = wallet_key();
    let mut chain = FakeChain::new(10, v2_era_slot());
    let c1 = chain.fund(1, 0, 100_000_000, key.script_hash());
    let c2 = chain.fund(2, 0, 100_000_000, key.script_hash());

    let build = |coin: ([u8; 32], u32), value: u64, base_fee: u128| {
        bloch_withdraw::build::build_transfer(&bloch_withdraw::build::BuildRequest {
            key,
            coins: &[bloch_withdraw::store::Coin { txid: coin.0, vout: coin.1, value_sat: value }],
            payment: Some((recipient_script(), AMOUNT)),
            change_script: key.script_hash(),
            base_fee_msat_per_gas: base_fee,
            tip_msat_per_gas: 0,
            dust_floor_sat: 546,
            format: bloch_withdraw::build::TransferFormat::V2,
        })
        .unwrap()
    };

    // The naive loop: build at fee 10; the fee moves; assume the first try
    // is dead; rebuild over whatever coins the wallet offers next.
    let first = build(c1, 100_000_000, 10);
    let second = build(c2, 100_000_000, 11);

    // But the first was included after all (the fee oscillated back)...
    chain.base_fee = 10;
    chain.include(&first.canonical).unwrap();
    // ...and the second is ALSO valid, at the fee it was built for.
    chain.base_fee = 11;
    chain.include(&second.canonical).unwrap();

    // The recipient was paid twice. This is the disaster.
    assert_eq!(chain.balance(&recipient_script()), 2 * u128::from(AMOUNT));
}

/// THE SAME adversarial schedule against the real client: fee moves, client
/// rebuilds, adversary includes the FIRST attempt anyway — and the rebuild
/// is a double-spend the chain rejects. Exactly one payment lands, and the
/// machine settles on `Paid` only after finality.
#[test]
fn pinned_rebuild_cannot_double_pay() {
    let key = wallet_key();
    let mut chain = FakeChain::new(10, v2_era_slot());
    chain.fund(1, 0, 100_000_000, key.script_hash());
    let node = FakeNode::new(chain);
    let store = MemStore::new();
    let w = Withdrawer::new(&node, &store, key);

    w.create("wd-1", &recipient_address(), AMOUNT).unwrap();
    let t1 = w.tick("wd-1").unwrap();
    assert!(matches!(t1.submit, Some(SubmitOutcome::Accepted { .. })));

    // The base fee moves before inclusion: attempt 0 is now permanently
    // invalid, and the mempool (in real life) has dropped it silently.
    node.chain.borrow_mut().base_fee = 11;
    let t2 = w.tick("wd-1").unwrap();
    assert!(matches!(t2.submit, Some(SubmitOutcome::Accepted { .. })));

    let a0 = attempt_bytes(&store, "wd-1", 0);
    let a1 = attempt_bytes(&store, "wd-1", 1);
    assert_eq!(
        outpoints_of(&a0),
        outpoints_of(&a1),
        "every rebuild must spend the pinned inputs"
    );

    // Adversary: the fee oscillates back and attempt 0 — the one the client
    // has already replaced — is included.
    {
        let mut chain = node.chain.borrow_mut();
        chain.base_fee = 10;
        chain.include(&a0).unwrap();
        // The replacement, at its own fee, is now a double-spend. Refused.
        chain.base_fee = 11;
        assert_eq!(chain.include(&a1), Err("UnknownInput".into()));
        assert_eq!(chain.balance(&recipient_script()), u128::from(AMOUNT), "paid exactly once");
    }

    // The client observes the spend and waits for finality — not head.
    let t3 = w.tick("wd-1").unwrap();
    let observed = match t3.status {
        Status::AwaitingFinality { landed: Some(0), observed_slot } => observed_slot,
        other => panic!("expected AwaitingFinality on attempt 0, got {other:?}"),
    };
    // Still not credited before the boundary passes.
    let t4 = w.tick("wd-1").unwrap();
    assert!(matches!(t4.status, Status::AwaitingFinality { .. }));

    node.chain.borrow_mut().finalize_past(observed);
    let t5 = w.tick("wd-1").unwrap();
    assert_eq!(t5.status, Status::Paid { attempt: Some(0) });

    // Terminal is terminal: further ticks change nothing and submit nothing.
    let t6 = w.tick("wd-1").unwrap();
    assert_eq!(t6.status, Status::Paid { attempt: Some(0) });
    assert!(t6.submit.is_none());
}

/// Crash-and-restart: a fresh process over the same store resumes the same
/// withdrawal — same id, same pinned coins — instead of paying it again.
#[test]
fn restart_resumes_instead_of_repaying() {
    let key = wallet_key();
    let mut chain = FakeChain::new(10, v2_era_slot());
    chain.fund(3, 0, 100_000_000, key.script_hash());
    let node = FakeNode::new(chain);
    let store = MemStore::new();

    {
        let w = Withdrawer::new(&node, &store, key);
        w.create("wd-crash", &recipient_address(), AMOUNT).unwrap();
        w.tick("wd-crash").unwrap();
    } // "crash"

    node.chain.borrow_mut().base_fee = 12;
    let w2 = Withdrawer::new(&node, &store, key);
    // Idempotent create: same terms come back, changed terms are refused.
    w2.create("wd-crash", &recipient_address(), AMOUNT).unwrap();
    assert!(matches!(
        w2.create("wd-crash", &recipient_address(), AMOUNT + 1),
        Err(bloch_withdraw::WithdrawError::IdMismatch(_))
    ));
    w2.tick("wd-crash").unwrap();

    let rec = store.load("wd-crash").unwrap().unwrap();
    assert_eq!(rec.attempts.len(), 2);
    assert_eq!(
        outpoints_of(&attempt_bytes(&store, "wd-crash", 0)),
        outpoints_of(&attempt_bytes(&store, "wd-crash", 1)),
        "the restarted process rebuilt over the SAME pinned inputs"
    );
}

/// A reorg that un-spends the pinned coins after the spend was observed:
/// the machine walks back to Submitted, resubmits, and still ends Paid
/// exactly once.
#[test]
fn reorg_walks_back_and_recovers() {
    let key = wallet_key();
    let mut chain = FakeChain::new(10, v2_era_slot());
    chain.fund(4, 0, 100_000_000, key.script_hash());
    let node = FakeNode::new(chain);
    let store = MemStore::new();
    let w = Withdrawer::new(&node, &store, key);

    w.create("wd-reorg", &recipient_address(), AMOUNT).unwrap();
    w.tick("wd-reorg").unwrap();
    let a0 = attempt_bytes(&store, "wd-reorg", 0);

    // Include, observe...
    let snapshot = node.chain.borrow().eutxos.clone();
    node.chain.borrow_mut().include(&a0).unwrap();
    let t = w.tick("wd-reorg").unwrap();
    assert!(matches!(t.status, Status::AwaitingFinality { .. }));

    // ...then the block is reorganised out before finality.
    node.chain.borrow_mut().eutxos = snapshot;
    let t = w.tick("wd-reorg").unwrap();
    assert_eq!(t.status, Status::Submitted, "walked back, not credited");
    assert!(
        matches!(t.submit, Some(SubmitOutcome::Accepted { .. })),
        "resubmitted the still-priced attempt"
    );

    // It lands again on the new branch; finality settles it.
    node.chain.borrow_mut().include(&a0).unwrap();
    let t = w.tick("wd-reorg").unwrap();
    let observed = match t.status {
        Status::AwaitingFinality { observed_slot, .. } => observed_slot,
        other => panic!("{other:?}"),
    };
    node.chain.borrow_mut().finalize_past(observed);
    let t = w.tick("wd-reorg").unwrap();
    assert_eq!(t.status, Status::Paid { attempt: Some(0) });
    assert_eq!(node.chain.borrow().balance(&recipient_script()), u128::from(AMOUNT));
}

/// Fee growth that outruns the pinned coins: the set GROWS (never swaps),
/// so later attempts still conflict with every earlier one.
#[test]
fn pinned_set_grows_and_never_swaps() {
    let key = wallet_key();
    // First coin barely covers amount + fee at fee 10; a large fee jump
    // forces a second coin in.
    let mut chain = FakeChain::new(10, v2_era_slot());
    chain.fund(5, 0, AMOUNT + 3_000_000, key.script_hash());
    chain.fund(6, 0, 50_000_000, key.script_hash());
    let node = FakeNode::new(chain);
    let store = MemStore::new();
    let w = Withdrawer::new(&node, &store, key);

    w.create("wd-grow", &recipient_address(), AMOUNT).unwrap();
    w.tick("wd-grow").unwrap();

    // A 6,000x fee spike (~13M sat on this shape): the 50M coin picked first
    // can no longer cover amount + fee, so the set must grow.
    node.chain.borrow_mut().base_fee = 60_000;
    w.tick("wd-grow").unwrap();

    let rec = store.load("wd-grow").unwrap().unwrap();
    assert_eq!(rec.attempts.len(), 2);
    let o0 = outpoints_of(&attempt_bytes(&store, "wd-grow", 0));
    let o1 = outpoints_of(&attempt_bytes(&store, "wd-grow", 1));
    assert!(o1.len() > o0.len(), "the pinned set grew");
    for op in &o0 {
        assert!(o1.contains(op), "growth is append-only: old pins stay in every rebuild");
    }

    // Whichever attempt lands, the other is dead. Include the SECOND this
    // time; the first must then be rejected.
    {
        let mut chain = node.chain.borrow_mut();
        chain.include(&attempt_bytes(&store, "wd-grow", 1)).unwrap();
        chain.base_fee = 10;
        assert_eq!(chain.include(&attempt_bytes(&store, "wd-grow", 0)), Err("UnknownInput".into()));
    }
    let t = w.tick("wd-grow").unwrap();
    let observed = match t.status {
        Status::AwaitingFinality { landed: Some(1), observed_slot } => observed_slot,
        other => panic!("{other:?}"),
    };
    node.chain.borrow_mut().finalize_past(observed);
    assert_eq!(w.tick("wd-grow").unwrap().status, Status::Paid { attempt: Some(1) });
    assert_eq!(node.chain.borrow().balance(&recipient_script()), u128::from(AMOUNT));
}

/// Cancellation is a conflicting sweep, not a deletion: it races the payment
/// on the same pinned inputs, and whichever finalizes is the answer.
#[test]
fn cancel_races_the_payment_with_a_sweep() {
    let key = wallet_key();
    let mut chain = FakeChain::new(10, v2_era_slot());
    chain.fund(7, 0, 100_000_000, key.script_hash());
    let node = FakeNode::new(chain);
    let store = MemStore::new();
    let w = Withdrawer::new(&node, &store, key);

    w.create("wd-cancel", &recipient_address(), AMOUNT).unwrap();
    w.tick("wd-cancel").unwrap();
    w.cancel("wd-cancel").unwrap();
    w.tick("wd-cancel").unwrap();

    let rec = store.load("wd-cancel").unwrap().unwrap();
    assert_eq!(rec.attempts.len(), 2);
    assert_eq!(rec.attempts[1].kind, AttemptKind::Sweep);
    assert_eq!(
        outpoints_of(&attempt_bytes(&store, "wd-cancel", 0)),
        outpoints_of(&attempt_bytes(&store, "wd-cancel", 1)),
        "the sweep conflicts with the payment by construction"
    );

    // The sweep wins the race.
    node.chain.borrow_mut().include(&attempt_bytes(&store, "wd-cancel", 1)).unwrap();
    let t = w.tick("wd-cancel").unwrap();
    let observed = match t.status {
        Status::AwaitingFinality { landed: Some(1), observed_slot } => observed_slot,
        other => panic!("{other:?}"),
    };
    node.chain.borrow_mut().finalize_past(observed);
    let t = w.tick("wd-cancel").unwrap();
    assert_eq!(t.status, Status::Cancelled { attempt: 1 });
    // Nobody was paid; the wallet holds everything minus the sweep fee.
    let chain = node.chain.borrow();
    assert_eq!(chain.balance(&recipient_script()), 0);
    assert!(chain.balance(&key.script_hash()) > 99_000_000);
}

/// Every output every attempt ever emits clears the dust floor — across the
/// whole suite's records. (The build module tests the exact-burn arithmetic;
/// this pins the policy end-to-end through the state machine.)
#[test]
fn no_attempt_ever_emits_dust() {
    let key = wallet_key();
    let mut chain = FakeChain::new(10, v2_era_slot());
    chain.fund(8, 0, 100_000_000, key.script_hash());
    let node = FakeNode::new(chain);
    let store = MemStore::new();
    let w = Withdrawer::new(&node, &store, key);
    w.create("wd-dust", &recipient_address(), AMOUNT).unwrap();
    for fee in [10u128, 11, 13, 200] {
        node.chain.borrow_mut().base_fee = fee;
        w.tick("wd-dust").unwrap();
    }
    let rec = store.load("wd-dust").unwrap().unwrap();
    assert!(rec.attempts.len() >= 4);
    for (i, _) in rec.attempts.iter().enumerate() {
        let tx = PosTransaction::from_canonical_bytes(&attempt_bytes(&store, "wd-dust", i)).unwrap();
        let outputs = match tx {
            PosTransaction::TransferV2 { outputs, .. } => outputs,
            PosTransaction::Transfer { outputs, .. } => outputs,
            _ => panic!(),
        };
        for o in outputs {
            assert!(o.value >= 546, "attempt {i} emitted {} sat", o.value);
        }
    }
}

/// The stale-node guard: a node that admits it is behind cannot drive
/// decisions.
#[test]
fn stale_node_is_refused() {
    let key = wallet_key();
    let mut chain = FakeChain::new(10, v2_era_slot());
    chain.fund(9, 0, 100_000_000, key.script_hash());
    let node = FakeNode::new(chain);
    let store = MemStore::new();
    let mut w = Withdrawer::new(&node, &store, key);
    w.cfg = Config { max_behind_slots: 0, ..Config::default() };
    w.create("wd-stale", &recipient_address(), AMOUNT).unwrap();
    // FakeNode reports behind_by_slots: 0, so this passes...
    w.tick("wd-stale").unwrap();
    // ...and a stricter-than-possible bound is how we prove the guard fires.
    struct Behind<'a>(&'a FakeNode);
    impl Node for Behind<'_> {
        fn call(&self, method: &str, params: Json) -> Result<Json, RpcFailure> {
            let v = self.0.call(method, params)?;
            if method == "getchaininfo" {
                if let Json::Obj(mut fields) = v {
                    for f in fields.iter_mut() {
                        if f.0 == "behind_by_slots" {
                            f.1 = Json::u(50);
                        }
                    }
                    return Ok(Json::Obj(fields));
                }
                unreachable!()
            }
            Ok(v)
        }
    }
    let behind = Behind(&node);
    let w2 = Withdrawer::new(&behind, &store, key);
    assert!(matches!(
        w2.tick("wd-stale"),
        Err(bloch_withdraw::WithdrawError::NodeStale { behind_by_slots: 50 })
    ));
}
