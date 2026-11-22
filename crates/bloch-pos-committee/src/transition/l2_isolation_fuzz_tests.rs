// SPDX-License-Identifier: AGPL-3.0-or-later
//
// ── Fault isolation of the L2 / bridge / settlement handlers ──────────────
//
// Included into `l2_tests` (l2_settlement_tests.rs), so it drives the REAL
// transition through real blocks, on an L2 installed by the running-network
// flag day (the mainnet shape: deposits, data availability, asynchronous V3
// settlements and claims admitted on every build, attestor set configured).
//
// WHAT IS ASSERTED, for every generated transaction and block body:
//
// 1. Decoding never panics, and what decodes in the L2 family encodes back to
//    the bytes it came from.
// 2. `CommittedState::apply_transaction` never panics. When it refuses, the
//    state is equal to the state before the call (every field, so the state
//    root too). When it accepts, the bridge escrow is conserved, the accounted
//    supply drops by exactly the fee charged, and the state root computes.
// 3. The node-local preflights never panic and agree with the transition: a
//    transaction the transition accepts is never refused by its preflight, and
//    one the preflight passes is refused by the transition only for a
//    signature.
// 4. `Transition::compute_post_state` never panics on a block carrying such
//    transactions, and a body it accepts applies through `apply_block`.
// 5. The gated fault boundary (`params::L2_FAULT_ISOLATION_ACTIVATION_EPOCH`)
//    changes no verdict and no state root while nothing faults.
//
// HOW. A deterministic walk (xorshift, no external crate) advances a chain
// block by block. Each block gets a candidate body from the generators
// (deposit, DA batch, V3 settlement with withdrawals, claim, several at once),
// sometimes spoiled; the walk does not assume it is valid, it asks the
// transition and falls back to an empty block. Around every block, hostile
// transactions are thrown at the state the block's transactions see: valid
// ones with one field set to an edge value (re-signed and re-balanced part of
// the time, so they pass the cheap checks and reach the deep ones), mutated
// encodings, and in-memory shapes the decoder cannot produce.
//
// The walk folds every verdict and every post-state root into one digest
// (`trace`). It is printed, and compared with `BLOCH_L2_ISOLATION_TRACE_EXPECT`
// when that is set, so two builds can be shown to judge the same chain alike.

use crate::transition::funded::{ADMISSION_PQ_KEY_BYTES, ADMISSION_PQ_SIGNATURE_MAX};
use std::panic::{catch_unwind, AssertUnwindSafe};

/// Opening coins of the funding key, and one coin of another key.
const COINS: u32 = 6;
const COIN_SAT: u64 = 500 * BLCH;
const FOREIGN_COIN: ([u8; 32], u32) = ([0x34; 32], 0);
const DOMAIN: [u8; 32] = [0x91; 32];
const CHAIN: u64 = 700771;

/// The transaction types of the L2 / bridge / settlement family
/// (`crate::isolation::is_non_l1` is checked against it below).
fn l2_family(tx: &PosTransaction) -> bool {
    matches!(
        tx,
        PosTransaction::L2Settlement(_)
            | PosTransaction::L2SettlementAsync(_)
            | PosTransaction::L2Deposit(_)
            | PosTransaction::L2DataAvailability(_)
            | PosTransaction::L2WithdrawClaim(_)
            | PosTransaction::L2ForcedTransaction(_)
    )
}

struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1)
    }
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }
    fn chance(&mut self, num: u64, den: u64) -> bool {
        self.below(den) < num
    }
    fn bytes<const N: usize>(&mut self) -> [u8; N] {
        std::array::from_fn(|_| self.next() as u8)
    }
    fn vec(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next() as u8).collect()
    }
    fn edge64(&mut self) -> u64 {
        const EDGES: [u64; 14] = [
            0,
            1,
            2,
            255,
            999_999,
            1_000_000,
            u32::MAX as u64,
            1 << 32,
            50 * BLCH,
            i64::MAX as u64,
            1 << 63,
            u64::MAX - 1,
            u64::MAX,
            CHAIN,
        ];
        if self.chance(1, 4) {
            self.next()
        } else {
            EDGES[self.below(EDGES.len() as u64) as usize]
        }
    }
    fn edge128(&mut self) -> u128 {
        match self.below(6) {
            0 => 0,
            1 => fee_market::MAX_TIP_MILLISAT_PER_GAS,
            2 => fee_market::MAX_TIP_MILLISAT_PER_GAS + 1,
            3 => u128::MAX,
            4 => u128::from(self.edge64()),
            _ => u128::from(self.next()) << 64 | u128::from(self.next()),
        }
    }
}

/// The funded network after its flag day, as `activated_fixture`, with
/// several coins, a coin of another key and (optionally) the attestor set.
fn fuzz_fixture(attested: bool) -> (CommittedState, Vec<RandaoChain>) {
    let key = depositor();
    let mut coins: Vec<crate::state_root::EutxoEntry> = (0..COINS)
        .map(|vout| crate::state_root::EutxoEntry { txid: [0x33; 32], vout, value: COIN_SAT, script_hash: script_of(&key) })
        .collect();
    coins.push(crate::state_root::EutxoEntry {
        txid: FOREIGN_COIN.0,
        vout: FOREIGN_COIN.1,
        value: COIN_SAT,
        script_hash: script_of(&[0x6b; 40]),
    });
    let (_, mut genesis, mut chains) = setup_with(4, ToyVerifier, &coins);
    genesis.admission_network_domain = Some(DOMAIN);
    let (_, mut policy) = running_without_l2();
    policy.identities[1] = *genesis.head.as_bytes();
    if attested {
        policy.attestor_set = wd::attestor_set_hash(2, &attestors());
    }
    let pre = apply(&genesis, 1, &[], &mut chains).unwrap();
    let _gate = crate::params::l2_settlement_rehearsal::open();
    let _policy = crate::l2_settlement::activation_rehearsal::set(activation(policy, true));
    let opened = apply(&pre, crate::params::SLOTS_PER_EPOCH, &[], &mut chains).unwrap();
    assert!(opened.l2_settlement().is_some_and(|l2| l2.deposits_enabled() && l2.user_transactions()));
    (opened, chains)
}

/// The fields the three funded L2 transactions share.
struct Funded<'a> {
    domain: &'a mut [u8; 32],
    key: &'a mut Vec<u8>,
    inputs: &'a mut Vec<FundingInput>,
    change: &'a mut TransferOutput,
    tx_bytes: &'a mut u64,
    tip: &'a mut u128,
    signature: &'a mut Vec<u8>,
}
fn funded(tx: &mut PosTransaction) -> Option<Funded<'_>> {
    Some(match tx {
        PosTransaction::L2Deposit(t) => Funded {
            domain: &mut t.network_domain,
            key: &mut t.funding_pubkey,
            inputs: &mut t.inputs,
            change: &mut t.change,
            tx_bytes: &mut t.tx_bytes,
            tip: &mut t.tip_millisat_per_gas,
            signature: &mut t.signature,
        },
        PosTransaction::L2DataAvailability(t) => Funded {
            domain: &mut t.network_domain,
            key: &mut t.funding_pubkey,
            inputs: &mut t.inputs,
            change: &mut t.change,
            tx_bytes: &mut t.tx_bytes,
            tip: &mut t.tip_millisat_per_gas,
            signature: &mut t.signature,
        },
        PosTransaction::L2WithdrawClaim(t) => Funded {
            domain: &mut t.network_domain,
            key: &mut t.funding_pubkey,
            inputs: &mut t.inputs,
            change: &mut t.change,
            tx_bytes: &mut t.tx_bytes,
            tip: &mut t.tip_millisat_per_gas,
            signature: &mut t.signature,
        },
        _ => return None,
    })
}
fn intent_root(tx: &PosTransaction) -> Option<[u8; 32]> {
    match tx {
        PosTransaction::L2Deposit(t) => Some(t.intent_root()),
        PosTransaction::L2DataAvailability(t) => Some(t.intent_root()),
        PosTransaction::L2WithdrawClaim(t) => Some(t.intent_root()),
        _ => None,
    }
}
fn sign(tx: &mut PosTransaction) {
    if let Some(root) = intent_root(tx) {
        let f = funded(tx).unwrap();
        *f.signature = toy_sign(f.key, &root);
    }
}
/// Declare the size (unless `keep_declared`), set the change that conserves
/// value at `base_fee` and sign. False when the inputs do not cover it.
fn balance_and_sign(tx: &mut PosTransaction, state: &CommittedState, base_fee: u128, keep_declared: bool) -> bool {
    let outflow = match tx {
        PosTransaction::L2Deposit(t) => u128::from(t.amount_sat),
        _ => 0,
    };
    let Some(f) = funded(tx) else { return false };
    *f.signature = vec![0; 32];
    let (inputs, tip) = (f.inputs.clone(), *f.tip);
    if !keep_declared {
        let encoded = tx.canonical_bytes().len() as u64;
        *funded(tx).unwrap().tx_bytes = encoded;
    }
    let f = funded(tx).unwrap();
    let mut spent = 0u128;
    for input in &inputs {
        let Some(coin) = state.eutxos.get(&(input.txid, input.vout)) else { return false };
        spent += u128::from(coin.value);
    }
    let charge = fee_market::charge(fee_market::TxClass::Eutxo { inputs: inputs.len() as u32 }, *f.tx_bytes, base_fee, tip);
    let Some(change) = charge
        .base_fee_sat
        .checked_add(charge.priority_fee_sat)
        .and_then(|fees| fees.checked_add(outflow))
        .and_then(|out| spent.checked_sub(out))
        .and_then(|change| u64::try_from(change).ok())
    else {
        return false;
    };
    f.change.value = change;
    sign(tx);
    true
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Stats {
    blocks: u32,
    bodies_applied: u32,
    deposits: u32,
    batches: u32,
    settlements: u32,
    withdrawals: u32,
    claims: u32,
    attested_claims: u32,
    tx_accepted: u32,
    tx_refused: u32,
    bodies_refused: u32,
    decoded: u32,
    undecodable: u32,
}

struct Walk {
    rng: Rng,
    state: CommittedState,
    chains: Vec<RandaoChain>,
    slot: u64,
    attested: bool,
    /// Spendable outputs of the funding key.
    coins: Vec<(([u8; 32], u32), u64)>,
    /// Withdrawals the accepted settlements published: `(recipient, sats)`,
    /// the leaf index is the position.
    outbox: Vec<([u8; 32], u64)>,
    trace: Sha3_256,
    stats: Stats,
}

struct Body {
    txs: Vec<PosTransaction>,
    /// Withdrawals a settlement in `txs` would publish.
    staged: Vec<([u8; 32], u64)>,
}

impl Walk {
    fn new(seed: u64, attested: bool) -> Self {
        let (state, chains) = fuzz_fixture(attested);
        Walk {
            rng: Rng::new(seed),
            slot: state.slot + 1,
            state,
            chains,
            attested,
            coins: (0..COINS).map(|vout| (([0x33; 32], vout), COIN_SAT)).collect(),
            outbox: Vec::new(),
            trace: Sha3_256::new(),
            stats: Stats::default(),
        }
    }

    fn l2(&self) -> &crate::l2_settlement::State {
        self.state.l2_settlement().unwrap()
    }
    fn leaves(&self, outbox: &[([u8; 32], u64)]) -> Vec<[u8; 32]> {
        outbox.iter().enumerate().map(|(i, (r, sats))| wd::leaf(CHAIN, i as u64, r, *sats)).collect()
    }
    /// A coin not yet taken by this body (an unknown one when none is left).
    fn coin(&mut self, taken: &mut Vec<([u8; 32], u32)>) -> FundingInput {
        let free: Vec<_> = self.coins.iter().map(|c| c.0).filter(|c| !taken.contains(c)).collect();
        if free.is_empty() {
            return FundingInput { txid: self.rng.bytes(), vout: 0 };
        }
        let pick = free[self.rng.below(free.len() as u64) as usize];
        taken.push(pick);
        FundingInput { txid: pick.0, vout: pick.1 }
    }
    fn tip(&mut self) -> u128 {
        [0, 0, 1_000, 50_000][self.rng.below(4) as usize]
    }

    fn deposit(&mut self, base_fee: u128, taken: &mut Vec<([u8; 32], u32)>) -> PosTransaction {
        let key = depositor();
        let mut recipient: [u8; 20] = self.rng.bytes();
        recipient[0] |= 1;
        let mut tx = PosTransaction::L2Deposit(L2Deposit {
            network_domain: DOMAIN,
            funding_pubkey: key.clone(),
            inputs: vec![self.coin(taken)],
            amount_sat: 1_000_000 + self.rng.below(60 * BLCH),
            recipient,
            change: TransferOutput { value: 0, script_hash: script_of(&key) },
            tx_bytes: 0,
            tip_millisat_per_gas: self.tip(),
            signature: Vec::new(),
        });
        balance_and_sign(&mut tx, &self.state, base_fee, false);
        tx
    }

    fn batch_tx(&mut self, base_fee: u128, taken: &mut Vec<([u8; 32], u32)>) -> PosTransaction {
        let key = depositor();
        let parts: Vec<Vec<u8>> = (0..1 + self.rng.below(3)).map(|_| { let n = 1 + self.rng.below(40) as usize; self.rng.vec(n) }).collect();
        let payload = batch(&parts.iter().map(Vec::as_slice).collect::<Vec<_>>());
        let ahead = if self.rng.chance(1, 5) { self.rng.below(4) } else { 0 };
        let mut tx = PosTransaction::L2DataAvailability(L2DataAvailability {
            network_domain: DOMAIN,
            funding_pubkey: key.clone(),
            inputs: vec![self.coin(taken)],
            l2_chain_id: CHAIN,
            l2_block_number: self.l2().settled_number() + 1 + ahead,
            payload,
            change: TransferOutput { value: 0, script_hash: script_of(&key) },
            tx_bytes: 0,
            tip_millisat_per_gas: self.tip(),
            signature: Vec::new(),
        });
        balance_and_sign(&mut tx, &self.state, base_fee, false);
        tx
    }

    /// The V3 settlement of the next L2 block on the source this state pins:
    /// it mints the pending deposits, settles user transactions when a batch
    /// for the block is on L1, and publishes zero to three new withdrawals.
    fn settlement_tx(&mut self) -> (Transaction, Vec<([u8; 32], u64)>) {
        let l2 = self.state.l2_settlement().unwrap();
        let source = l2.source(*self.state.head.as_bytes(), self.state.slot);
        let consumed = l2.pending_for(&source).to_vec();
        let number = l2.settled_number() + 1;
        let on_l1 = l2.data_availability().iter().find(|r| r.l2_number == number && r.height <= l2.height()).map(|r| r.commitment);
        let users = if on_l1.is_some() && self.rng.chance(3, 4) { 1 + self.rng.below(5) } else { 0 };
        let empty = crate::l2_settlement::expected_body_commitment(&[]);
        let mut tx = to_v3(settlement(&self.state, empty), crate::l2_settlement::deposits_hash(&consumed), users);
        if let (Some(commitment), true) = (on_l1, users != 0) {
            tx.statement[S + v3::DA_COMMITMENT..S + v3::DA_COMMITMENT + 32].copy_from_slice(&commitment);
        }
        let staged: Vec<([u8; 32], u64)> = (0..[0, 0, 1, 2, 3][self.rng.below(5) as usize])
            .map(|_| {
                let sats = if self.rng.chance(1, 5) { 50 * BLCH + self.rng.below(30 * BLCH) } else { 1_000_000 + self.rng.below(3 * BLCH) };
                (self.rng.bytes(), sats)
            })
            .collect();
        let mut published = self.outbox.clone();
        published.extend_from_slice(&staged);
        tx.statement[S + v3::WITHDRAWAL_ROOT..S + v3::WITHDRAWAL_ROOT + 32].copy_from_slice(&wd::root(&self.leaves(&published)));
        tx.statement[S + v3::WITHDRAWAL_COUNT..S + v3::WITHDRAWAL_COUNT + 8].copy_from_slice(&(published.len() as u64).to_be_bytes());
        (tx, staged)
    }

    /// A claim of one published withdrawal against a retained root, matured
    /// when one is; attested when the leaf is large and the policy has a set.
    fn claim_tx(&mut self, base_fee: u128, taken: &mut Vec<([u8; 32], u32)>) -> Option<PosTransaction> {
        let l2 = self.state.l2_settlement().unwrap();
        let records = l2.withdrawal_roots().to_vec();
        let at = l2.height() + 1;
        let matured: Vec<_> = records.iter().filter(|r| r.height + PINNED.delay_blocks <= at).copied().collect();
        let pool = if matured.is_empty() || self.rng.chance(1, 8) { &records } else { &matured };
        let record = *pool.get(self.rng.below(pool.len().max(1) as u64) as usize)?;
        let unclaimed: Vec<u64> = (0..record.count).filter(|i| !l2.claimed().contains(*i)).collect();
        let index = if unclaimed.is_empty() || self.rng.chance(1, 8) {
            self.rng.below(self.outbox.len() as u64 + 2)
        } else {
            unclaimed[self.rng.below(unclaimed.len() as u64) as usize]
        };
        let (l1_recipient, sats) = self.outbox.get(index as usize).copied().unwrap_or(([9; 32], 1_000_000));
        let tree = self.leaves(&self.outbox[..record.count as usize]);
        let attestation = (self.attested && sats >= PINNED.large_claim_sat && self.rng.chance(7, 8)).then(|| {
            let digest = wd::attestation_digest(&DOMAIN, CHAIN, &record.root);
            let skip = self.rng.below(3) as u8;
            Attestation {
                threshold: 2,
                keys: attestors(),
                signatures: (0..3u8).filter(|i| *i != skip).map(|i| (i, toy_sign(&attestor(i), &digest))).collect(),
            }
        });
        let key = depositor();
        let mut tx = PosTransaction::L2WithdrawClaim(L2WithdrawClaim {
            network_domain: DOMAIN,
            funding_pubkey: key.clone(),
            inputs: vec![self.coin(taken)],
            l2_chain_id: CHAIN,
            index,
            l1_recipient,
            sats,
            siblings: wd::proof(&tree, index).unwrap_or([[7; 32]; 32]),
            release: TransferOutput { value: sats, script_hash: l1_recipient },
            change: TransferOutput { value: 0, script_hash: script_of(&key) },
            tx_bytes: 0,
            tip_millisat_per_gas: self.tip(),
            attestation,
            signature: Vec::new(),
        });
        balance_and_sign(&mut tx, &self.state, base_fee, false);
        Some(tx)
    }

    fn funded_tx(&mut self, base_fee: u128, taken: &mut Vec<([u8; 32], u32)>) -> PosTransaction {
        match self.rng.below(5) {
            0 | 1 => self.deposit(base_fee, taken),
            2 => self.batch_tx(base_fee, taken),
            _ => match self.claim_tx(base_fee, taken) {
                Some(tx) => tx,
                None => self.deposit(base_fee, taken),
            },
        }
    }

    /// The body the walk would like this block to carry.
    fn body(&mut self, base_fee: u128) -> Body {
        let mut taken = Vec::new();
        let mut body = Body { txs: Vec::new(), staged: Vec::new() };
        match self.rng.below(20) {
            0..=3 => body.txs.push(self.deposit(base_fee, &mut taken)),
            4..=5 => body.txs.push(self.batch_tx(base_fee, &mut taken)),
            6..=10 => {
                let (tx, staged) = self.settlement_tx();
                body.txs.push(PosTransaction::L2SettlementAsync(Box::new(tx)));
                body.staged = staged;
            }
            11..=16 => {
                let tx = self.claim_tx(base_fee, &mut taken).unwrap_or_else(|| self.deposit(base_fee, &mut taken));
                body.txs.push(tx);
            }
            17..=18 => {
                for _ in 0..2 + self.rng.below(3) {
                    let tx = self.funded_tx(base_fee, &mut taken);
                    body.txs.push(tx);
                }
            }
            _ => {}
        }
        // Part of the time the body is spoiled: the transition must refuse it
        // whole, and the walk falls back to an empty block.
        if !body.txs.is_empty() && self.rng.chance(1, 4) {
            match self.rng.below(5) {
                0 => {
                    let again = body.txs[0].clone();
                    body.txs.push(again);
                }
                1 => {
                    let (tx, _) = self.settlement_tx();
                    body.txs.push(PosTransaction::L2SettlementAsync(Box::new(tx)));
                }
                2 => {
                    for _ in 0..5 {
                        let mut none = Vec::new();
                        body.txs.push(self.batch_tx(base_fee, &mut none));
                    }
                }
                _ => {
                    let at = self.rng.below(body.txs.len() as u64) as usize;
                    let spoiled = self.hostile_from(body.txs[at].clone(), base_fee);
                    body.txs[at] = spoiled;
                }
            }
        }
        body
    }

    /// One field of `tx` set to something a wallet would never send.
    fn mutate(&mut self, tx: &mut PosTransaction) {
        let rng = &mut self.rng;
        if rng.chance(1, 2) {
            if let Some(f) = funded(tx) {
                match rng.below(12) {
                    0 => f.domain[rng.below(32) as usize] ^= 1 << rng.below(8),
                    1 => {
                        *f.key = match rng.below(4) {
                            0 => Vec::new(),
                            1 => rng.vec(ADMISSION_PQ_KEY_BYTES),
                            2 => f.key.get(1..).unwrap_or_default().to_vec(),
                            _ => [f.key.as_slice(), &[0]].concat(),
                        }
                    }
                    2 => f.inputs.clear(),
                    3 => {
                        if let Some(first) = f.inputs.first().cloned() {
                            f.inputs.push(first);
                        }
                    }
                    4 => f.inputs.push(FundingInput { txid: rng.bytes(), vout: rng.below(3) as u32 }),
                    5 => *f.inputs = vec![FundingInput { txid: FOREIGN_COIN.0, vout: FOREIGN_COIN.1 }],
                    6 => *f.inputs = (0..1 + rng.below(200) as u32).map(|vout| FundingInput { txid: [0x33; 32], vout }).collect(),
                    7 => f.change.value = rng.edge64(),
                    8 => *f.tx_bytes = rng.edge64(),
                    9 => *f.tip = rng.edge128(),
                    10 => {
                        *f.signature = match rng.below(4) {
                            0 => Vec::new(),
                            1 => rng.vec(32),
                            2 => vec![0; ADMISSION_PQ_SIGNATURE_MAX + 1],
                            _ => rng.vec(ADMISSION_PQ_SIGNATURE_MAX),
                        }
                    }
                    _ => f.change.script_hash = rng.bytes(),
                }
                return;
            }
        }
        match tx {
            PosTransaction::L2Deposit(t) => match rng.below(4) {
                0 => t.amount_sat = rng.edge64(),
                1 => t.recipient = [0; 20],
                2 => t.amount_sat = t.amount_sat.wrapping_add(1),
                _ => t.recipient = rng.bytes(),
            },
            PosTransaction::L2DataAvailability(t) => match rng.below(7) {
                0 => t.l2_chain_id = rng.edge64(),
                1 => t.l2_block_number = rng.edge64(),
                2 => {
                    let n = rng.below(64) as usize;
                    t.payload = rng.vec(n);
                }
                3 => t.payload.truncate(rng.below(t.payload.len() as u64 + 1) as usize),
                4 => {
                    let count = (rng.edge64() as u32).to_be_bytes();
                    let end = 4.min(t.payload.len());
                    let _ = t.payload.splice(..end, count);
                }
                5 => {
                    let len = (rng.edge64() as u32).to_be_bytes();
                    let end = 8.min(t.payload.len());
                    let _ = t.payload.splice(4.min(end)..end, len);
                }
                _ => t.payload = vec![0; da::MAX_PAYLOAD_BYTES + 1],
            },
            PosTransaction::L2WithdrawClaim(t) => match rng.below(12) {
                0 => t.index = rng.edge64(),
                1 => t.index = t.index.wrapping_add(1),
                2 => t.sats = rng.edge64(),
                3 => t.sats = t.sats.wrapping_sub(1),
                4 => t.l1_recipient = rng.bytes(),
                5 => t.siblings[rng.below(32) as usize][rng.below(32) as usize] ^= 1,
                6 => t.release.value = rng.edge64(),
                7 => t.release.script_hash = rng.bytes(),
                8 => t.l2_chain_id = rng.edge64(),
                9 => t.attestation = None,
                10 => t.index = (1 << 32) + rng.below(4),
                _ => {
                    // Shapes the decoder bounds, and shapes it cannot produce.
                    let n = rng.below(10) as usize;
                    let keys = (0..n)
                        .map(|i| match rng.below(4) {
                            0 => attestor(0),
                            1 => {
                                let n = rng.below(48) as usize;
                                rng.vec(n)
                            }
                            _ => attestor(i as u8),
                        })
                        .collect();
                    let signatures = (0..rng.below(10))
                        .map(|_| {
                            let n = [0, 1, 32, 33][rng.below(4) as usize];
                            (rng.below(12) as u8, rng.vec(n))
                        })
                        .collect();
                    t.attestation = Some(Attestation { threshold: rng.below(10) as u8, keys, signatures });
                }
            },
            PosTransaction::L2Settlement(t) | PosTransaction::L2SettlementAsync(t) => match rng.below(8) {
                0 => {
                    let at = rng.below(t.statement.len().max(1) as u64) as usize;
                    if let Some(byte) = t.statement.get_mut(at) {
                        *byte ^= 1 << rng.below(8);
                    }
                }
                1 => {
                    // The big-endian counters of the statement.
                    const FIELDS: [usize; 9] = [256, 264, 432, 440, 512, 520, 528, v3::USER_TX_COUNT, v3::WITHDRAWAL_COUNT];
                    let at = S + FIELDS[rng.below(FIELDS.len() as u64) as usize];
                    let value = rng.edge64().to_be_bytes();
                    if let Some(field) = t.statement.get_mut(at..at + 8) {
                        field.copy_from_slice(&value);
                    }
                }
                2 => {
                    // Lengths the decoder refuses; only an in-memory value has them.
                    let len = [0, 1, S, S + 100, 589, 591, 765, 767, 2_000][rng.below(9) as usize];
                    t.statement.resize(len, 0x5a);
                }
                3 => {
                    let tag = if rng.chance(1, 2) { STATEMENT_TAG } else { STATEMENT_V3_TAG };
                    if let Some(head) = t.statement.get_mut(..S) {
                        head.copy_from_slice(tag);
                    }
                }
                4 => t.proof = rng.bytes(),
                5 => t.proof[rng.below(356) as usize] ^= 1,
                6 => t.proof_policy[rng.below(32) as usize] ^= 1,
                _ => {
                    let at = S + 32 * rng.below(23) as usize;
                    if let Some(field) = t.statement.get_mut(at..at + 32) {
                        field.copy_from_slice(&[0; 32]);
                    }
                }
            },
            _ => {}
        }
    }

    fn mutate_bytes(&mut self, bytes: &mut Vec<u8>) {
        let rng = &mut self.rng;
        let at = rng.below(bytes.len().max(1) as u64) as usize;
        match rng.below(8) {
            0 => {
                if let Some(byte) = bytes.get_mut(at) {
                    *byte ^= 1 << rng.below(8);
                }
            }
            1 => bytes.truncate(at),
            2 => {
                let n = 1 + rng.below(40) as usize;
                bytes.extend(rng.vec(n));
            }
            3 => {
                // Where a length or a count may sit.
                let value = (rng.edge64() as u32).to_le_bytes();
                if let Some(field) = bytes.get_mut(at..at + 4) {
                    field.copy_from_slice(&value);
                }
            }
            4 => {
                let value = rng.edge64().to_le_bytes();
                if let Some(field) = bytes.get_mut(at..at + 8) {
                    field.copy_from_slice(&value);
                }
            }
            5 => {
                let n = 1 + rng.below(8) as usize;
                let insert = rng.vec(n);
                let _ = bytes.splice(at..at, insert);
            }
            6 => {
                if let Some(first) = bytes.first_mut() {
                    *first = [0x12, 0x13, 0x14, 0x15, 0x16][rng.below(5) as usize];
                }
            }
            _ => {
                // The version byte of a claim, or the first field of the others.
                if let Some(byte) = bytes.get_mut(1) {
                    *byte = rng.below(4) as u8;
                }
            }
        }
    }

    /// Decode `bytes` as the network would. Never a panic; in the L2 family,
    /// what decodes is canonical.
    fn decode(&mut self, bytes: &[u8]) -> Option<PosTransaction> {
        let decoded = catch_unwind(|| PosTransaction::from_canonical_bytes(bytes))
            .unwrap_or_else(|_| panic!("the decoder panicked on {}", hex::encode(bytes)));
        match decoded {
            Ok(tx) => {
                self.stats.decoded += 1;
                if l2_family(&tx) {
                    assert_eq!(tx.canonical_bytes(), bytes, "a decoded L2 transaction is not canonical: {tx:?}");
                }
                Some(tx)
            }
            Err(_) => {
                self.stats.undecodable += 1;
                None
            }
        }
    }

    /// A hostile variant of `tx`.
    fn hostile_from(&mut self, mut tx: PosTransaction, base_fee: u128) -> PosTransaction {
        match self.rng.below(10) {
            0..=5 => {
                for _ in 0..1 + self.rng.below(2) {
                    self.mutate(&mut tx);
                }
                // Part of the time the mutated transaction is made whole again
                // (value conserved, signed), so that it passes the cheap checks.
                match self.rng.below(4) {
                    0 => {
                        balance_and_sign(&mut tx, &self.state, base_fee, false);
                    }
                    1 => {
                        balance_and_sign(&mut tx, &self.state, base_fee, true);
                    }
                    2 => sign(&mut tx),
                    _ => {}
                }
                if self.rng.chance(1, 8) {
                    tx = match tx {
                        PosTransaction::L2Settlement(t) => PosTransaction::L2SettlementAsync(t),
                        PosTransaction::L2SettlementAsync(t) => PosTransaction::L2Settlement(t),
                        other => other,
                    };
                }
                tx
            }
            6..=8 => {
                let mut bytes = tx.canonical_bytes();
                for _ in 0..1 + self.rng.below(3) {
                    self.mutate_bytes(&mut bytes);
                }
                match self.decode(&bytes) {
                    Some(decoded) => decoded,
                    None => {
                        self.mutate(&mut tx);
                        tx
                    }
                }
            }
            _ => {
                // Noise behind every tag the wire knows (and a few it does not).
                let n = 1 + self.rng.below(200) as usize;
                let mut bytes = self.rng.vec(n);
                bytes[0] = self.rng.below(0x21) as u8;
                self.decode(&bytes).unwrap_or(tx)
            }
        }
    }

    fn hostile(&mut self, base_fee: u128) -> PosTransaction {
        let mut taken = Vec::new();
        let tx = match self.rng.below(7) {
            0 | 1 => self.deposit(base_fee, &mut taken),
            2 => self.batch_tx(base_fee, &mut taken),
            3 | 4 => {
                let (tx, _) = self.settlement_tx();
                PosTransaction::L2SettlementAsync(Box::new(tx))
            }
            _ => self.claim_tx(base_fee, &mut taken).unwrap_or_else(|| self.deposit(base_fee, &mut taken)),
        };
        if self.rng.chance(1, 10) {
            tx
        } else {
            self.hostile_from(tx, base_fee)
        }
    }

    /// Properties 2 and 3 on `inblock`, the state a block's transactions see.
    fn probe_tx(&mut self, inblock: &CommittedState, tx: &PosTransaction, base_fee: u128) {
        let verifier = ProofDouble;
        let mut st = inblock.clone();
        let result = catch_unwind(AssertUnwindSafe(|| st.apply_transaction(tx, 0, base_fee, &verifier)))
            .unwrap_or_else(|_| panic!("a handler panicked on {tx:?}"));
        match &result {
            Err(_) => {
                self.stats.tx_refused += 1;
                assert!(st == *inblock, "a refused transaction changed the state: {tx:?}");
            }
            Ok(charge) => {
                self.stats.tx_accepted += 1;
                assert!(charge.gas <= fee_market::BLOCK_GAS_LIMIT, "{tx:?}");
                assert!(st.l2_settlement().is_none_or(|l2| l2.escrow_conserved()), "escrow not conserved by {tx:?}");
                if l2_family(tx) {
                    assert_eq!(
                        st.accounted_supply_sat() + charge.base_fee_sat + charge.priority_fee_sat,
                        inblock.accounted_supply_sat(),
                        "the supply moved by more than the fee: {tx:?}"
                    );
                }
                catch_unwind(AssertUnwindSafe(|| st.state_root())).unwrap_or_else(|_| panic!("the state root panicked after {tx:?}"));
            }
        }
        self.trace.update(format!("{result:?}").as_bytes());
        // The preflight agrees: it never refuses what the transition takes,
        // and what it passes the transition refuses only for a signature.
        let agree = |refusal: bool, signature: bool| {
            assert!(!(result.is_ok() && refusal), "the preflight refuses what the transition accepts: {tx:?}");
            assert!(result.is_ok() || refusal || signature, "the preflight passes what the transition refuses ({result:?}): {tx:?}");
        };
        let preflight = catch_unwind(AssertUnwindSafe(|| match tx {
            PosTransaction::L2Deposit(t) => {
                agree(inblock.l2_deposit_refusal_at(t, base_fee).is_some(), result == Err(TxReject::L2Deposit(L2DepositReject::Signature)));
            }
            PosTransaction::L2DataAvailability(t) => {
                agree(
                    inblock.l2_data_availability_refusal_at(t, base_fee).is_some(),
                    result == Err(TxReject::L2DataAvailability(DaReject::Signature)),
                );
            }
            PosTransaction::L2WithdrawClaim(t) => {
                let refusal = inblock.l2_withdraw_claim_refusal_at(t, base_fee);
                agree(
                    refusal.is_some(),
                    matches!(result, Err(TxReject::L2WithdrawClaim(ClaimReject::Signature | ClaimReject::Attestation))),
                );
                let before_finality = inblock.l2_withdraw_claim_refusal_before_finality_at(t, base_fee);
                assert_ne!(before_finality, Some(ClaimReject::NotFinalized));
                assert!(refusal == before_finality || refusal == Some(ClaimReject::NotFinalized), "{tx:?}");
                // State-free checks the mempool door runs on its own.
                let _ = (t.validate_shape(), t.proven_root(), t.verify_attestation(&verifier), t.nullifier());
            }
            PosTransaction::L2SettlementAsync(t) => {
                if let Some(l2) = inblock.l2_settlement() {
                    assert_eq!(l2.validate_async(t, &verifier).is_ok(), result.is_ok(), "{tx:?}");
                    let pending = l2.pending_async_refusal(t, *inblock.head.as_bytes(), inblock.slot);
                    assert!(!(result.is_ok() && pending.is_some()), "{tx:?}");
                }
            }
            _ => {}
        }));
        if let Err(panic) = preflight {
            std::panic::resume_unwind(panic);
        }
    }

    /// Property 4: `txs` as the body of the block `empty` was built for.
    fn probe_body(
        &mut self,
        t: &Transition<ProofDouble>,
        empty: &ProposalEnvelope,
        txs: &[PosTransaction],
    ) -> Result<(CommittedState, ProposalEnvelope), TransitionError> {
        let mut block = empty.clone();
        block.header.body_root = crate::derive::body_root(&txs.iter().map(PosTransaction::canonical_bytes).collect::<Vec<_>>());
        let key = crate::attestation::KeyLookup::pubkey(&self.state, block.header.proposer_index).unwrap().to_vec();
        block.proposer_sig = toy_sign(&key, &block.header.proposal_signing_root());
        let pre = &self.state;
        let result = catch_unwind(AssertUnwindSafe(|| t.compute_post_state(pre, &block, &[], txs)))
            .unwrap_or_else(|_| panic!("the block transition panicked on the body {txs:?}"));
        self.trace.update(format!("{:?}", result.as_ref().map(|_| ())).as_bytes());
        let post = result?;
        assert!(post.l2_settlement().is_none_or(|l2| l2.escrow_conserved()), "escrow not conserved by the body {txs:?}");
        block.header.state_root = post.state_root();
        block.proposer_sig = toy_sign(&key, &block.header.proposal_signing_root());
        Ok((post, block))
    }

    /// What an accepted body did to the funding key's coins and the outbox.
    fn account(&mut self, body: &Body) {
        self.stats.bodies_applied += 1;
        for tx in &body.txs {
            let (inputs, change, vout) = match tx {
                PosTransaction::L2Deposit(t) => {
                    self.stats.deposits += 1;
                    (&t.inputs, &t.change, 0)
                }
                PosTransaction::L2DataAvailability(t) => {
                    self.stats.batches += 1;
                    (&t.inputs, &t.change, 0)
                }
                PosTransaction::L2WithdrawClaim(t) => {
                    self.stats.claims += 1;
                    self.stats.attested_claims += u32::from(t.attestation.is_some());
                    (&t.inputs, &t.change, CHANGE_VOUT)
                }
                PosTransaction::L2SettlementAsync(_) => {
                    self.stats.settlements += 1;
                    self.stats.withdrawals += body.staged.len() as u32;
                    self.outbox.extend_from_slice(&body.staged);
                    continue;
                }
                _ => continue,
            };
            self.coins.retain(|(coin, _)| !inputs.iter().any(|i| (i.txid, i.vout) == *coin));
            if change.value > 0 && change.script_hash == script_of(&depositor()) {
                self.coins.push(((tx.txid(), vout), change.value));
            }
        }
    }

    fn step(&mut self, probes: usize) {
        let slot = self.slot;
        self.slot += if self.rng.chance(1, 8) { 1 + self.rng.below(3) } else { 1 };
        let t = Transition::new(ProofDouble);
        let empty = build_block(&t, &self.state, slot, &[], &[], &mut self.chains);
        let base_fee = self.state.next_base_fee_at(crate::epoch_of(slot));
        // The state the block's transactions see: the parent rolled to the
        // block's epoch, with the L2 source pinned.
        let mut inblock = self.state.clone();
        while inblock.epoch < crate::epoch_of(slot) {
            inblock = inblock.close_epoch();
        }
        if let Some(l2) = inblock.l2_settlement.as_mut() {
            l2.prepare_source(*self.state.head.as_bytes(), self.state.slot);
        }
        let root = self.state.state_root();
        for _ in 0..probes {
            let tx = self.hostile(base_fee);
            self.probe_tx(&inblock, &tx, base_fee);
        }
        for _ in 0..2 {
            let txs: Vec<PosTransaction> = (0..1 + self.rng.below(4))
                .map(|_| {
                    if self.rng.chance(1, 2) {
                        self.hostile(base_fee)
                    } else {
                        let mut taken = Vec::new();
                        self.funded_tx(base_fee, &mut taken)
                    }
                })
                .collect();
            if self.probe_body(&t, &empty, &txs).is_err() {
                self.stats.bodies_refused += 1;
            }
        }
        assert_eq!(self.state.state_root(), root, "judging transactions and bodies changed the parent state");
        let body = self.body(base_fee);
        self.state = match self.probe_body(&t, &empty, &body.txs) {
            Ok((post, block)) => {
                let applied = t.apply_block(&self.state, &block, &[], &body.txs).expect("the body the transition accepted applies");
                // The head is the block id, which commits to the state root the
                // probe did not have yet; everything the root commits is equal.
                assert_eq!(applied.state_root(), post.state_root());
                self.account(&body);
                applied
            }
            Err(_) => {
                self.stats.bodies_refused += 1;
                t.apply_block(&self.state, &empty, &[], &[]).expect("the empty block applies")
            }
        };
        self.stats.blocks += 1;
        self.trace.update(self.state.state_root());
        // The blocks carry no attestations; claims need finalized
        // settlements, so finality is granted from outside now and then: the
        // previous epoch's checkpoint, which leaves the finality engine's
        // cursor on the epoch being run (nothing out of order at the next
        // boundary).
        let epoch = crate::epoch_of(self.state.slot);
        if epoch > 0 && self.rng.chance(1, 3) {
            self.state.finality_engine = crate::finality::FinalityState::relaunch(crate::finality::Checkpoint {
                epoch: epoch - 1,
                root: *self.state.head.as_bytes(),
            });
        }
    }
}

/// The walk of `seed`: its trace and what it reached.
fn walk(seed: u64, blocks: u32, probes: usize) -> ([u8; 32], Stats) {
    let mut walk = Walk::new(seed, seed % 2 == 1);
    for _ in 0..blocks {
        walk.step(probes);
    }
    let l2 = walk.l2();
    assert!(l2.escrow_conserved());
    assert_eq!(l2.claimed().claims(), u64::from(walk.stats.claims));
    assert_eq!(l2.inbox().len() as u32, walk.stats.deposits);
    (walk.trace.finalize().into(), walk.stats)
}

const WALK_BLOCKS: u32 = 170;
const WALK_PROBES: usize = 10;

/// The property test (properties 1 to 4), bounded: four walks of 170 blocks.
#[test]
fn malformed_l2_transactions_never_panic_and_refusals_leave_the_state_unchanged() {
    let mut total = Stats::default();
    let mut digest = Sha3_256::new();
    for seed in 1..=4u64 {
        let (trace, stats) = walk(seed, WALK_BLOCKS, WALK_PROBES);
        eprintln!("l2 isolation walk {seed}: trace {} {stats:?}", hex::encode(trace));
        digest.update(trace);
        // Every walk goes deep, not only the sum of them.
        assert!(stats.deposits > 0 && stats.settlements > 0 && stats.tx_accepted > 0, "walk {seed} stayed shallow: {stats:?}");
        for (sum, part) in [
            (&mut total.blocks, stats.blocks),
            (&mut total.bodies_applied, stats.bodies_applied),
            (&mut total.deposits, stats.deposits),
            (&mut total.batches, stats.batches),
            (&mut total.settlements, stats.settlements),
            (&mut total.withdrawals, stats.withdrawals),
            (&mut total.claims, stats.claims),
            (&mut total.attested_claims, stats.attested_claims),
            (&mut total.tx_accepted, stats.tx_accepted),
            (&mut total.tx_refused, stats.tx_refused),
            (&mut total.bodies_refused, stats.bodies_refused),
            (&mut total.decoded, stats.decoded),
            (&mut total.undecodable, stats.undecodable),
        ] {
            *sum += part;
        }
    }
    let digest = hex::encode(digest.finalize());
    eprintln!("l2 isolation walks: digest {digest} {total:?}");
    // The generators reach every handler's accepting path and its refusals.
    assert!(
        total.deposits >= 20
            && total.batches >= 4
            && total.settlements >= 20
            && total.withdrawals >= 10
            && total.claims >= 6
            && total.attested_claims >= 1
            && total.tx_accepted >= 100
            && total.tx_refused >= 2_000
            && total.bodies_refused >= 400
            && total.decoded >= 50
            && total.undecodable >= 200,
        "the walks no longer reach what they are meant to: {total:?}"
    );
    if let Ok(expected) = std::env::var("BLOCH_L2_ISOLATION_TRACE_EXPECT") {
        assert_eq!(digest, expected, "this build judges the walks differently");
    }
}

/// What a settlement costs the L1 beyond its own verification, pinned so that
/// a change to it is a decision: it charges the whole block gas budget, so no
/// gas-paying transaction shares its block, and the fee controller reads that
/// block as full (the next base fee rises by one eighth).
#[test]
fn a_settlement_takes_the_whole_block_and_reads_as_a_full_block_to_the_fee_controller() {
    let mut walk = Walk::new(3, false);
    let (tx, _) = walk.settlement_tx();
    let settlement = PosTransaction::L2SettlementAsync(Box::new(tx));
    let t = Transition::new(ProofDouble);
    let slot = walk.slot;
    let epoch = crate::epoch_of(slot);
    let empty = build_block(&t, &walk.state, slot, &[], &[], &mut walk.chains);
    let base_fee = walk.state.next_base_fee_at(epoch);
    let (alone, _) = walk.probe_body(&t, &empty, std::slice::from_ref(&settlement)).expect("a settlement alone applies");
    assert_eq!((alone.block_gas_used, alone.base_fee_millisat_per_gas), (fee_market::BLOCK_GAS_LIMIT, base_fee));
    assert_eq!(alone.next_base_fee_at(epoch), base_fee + base_fee / 8);
    let (quiet, _) = walk.probe_body(&t, &empty, &[]).expect("the empty block applies");
    assert_eq!(quiet.block_gas_used, 0);
    assert!(quiet.next_base_fee_at(epoch) <= base_fee);
    let mut taken = Vec::new();
    let deposit = walk.deposit(base_fee, &mut taken);
    assert!(walk.probe_body(&t, &empty, std::slice::from_ref(&deposit)).is_ok());
    for body in [[settlement.clone(), deposit.clone()], [deposit, settlement]] {
        assert_eq!(walk.probe_body(&t, &empty, &body).err(), Some(TransitionError::BlockGasLimitExceeded));
    }
}

// ── The gated boundary (`params::L2_FAULT_ISOLATION_ACTIVATION_EPOCH`) ──

#[test]
fn l2_fault_isolation_gate_is_inert() {
    assert_eq!(crate::params::L2_FAULT_ISOLATION_ACTIVATION_EPOCH, u64::MAX);
    for epoch in [0, 5_850, 8_620, 8_735, 1 << 40, u64::MAX - 1, u64::MAX] {
        assert!(!crate::params::l2_fault_isolation_active(epoch));
    }
    let _gate = crate::params::l2_fault_isolation_rehearsal::open();
    assert!(crate::params::l2_fault_isolation_active(0));
}

/// Property 5: with the boundary armed, a chain on which nothing faults is
/// judged exactly as with it inert (every verdict, every state root).
#[test]
fn the_fault_boundary_changes_no_verdict_and_no_root_while_nothing_faults() {
    for seed in [1u64, 2] {
        let inert = walk(seed, 60, 6);
        let armed = {
            let _gate = crate::params::l2_fault_isolation_rehearsal::open();
            walk(seed, 60, 6)
        };
        assert!(inert.1.settlements > 0 && inert.1.deposits > 0, "{:?}", inert.1);
        assert_eq!(inert, armed, "seed {seed}");
    }
}

/// The L2 family the boundary applies to, and nothing of the L1 core.
#[test]
fn the_fault_boundary_covers_the_l2_family_only() {
    let mut walk = Walk::new(7, true);
    let mut taken = Vec::new();
    let (settlement, _) = walk.settlement_tx();
    for tx in [
        walk.deposit(1, &mut taken),
        walk.batch_tx(1, &mut taken),
        PosTransaction::L2Settlement(Box::new(settlement.clone())),
        PosTransaction::L2SettlementAsync(Box::new(settlement)),
    ] {
        assert!(crate::isolation::is_non_l1(&tx) && l2_family(&tx), "{tx:?}");
    }
    for tx in [PosTransaction::Withdraw { validator: 0 }, PosTransaction::Exit { validator: 0 }] {
        assert!(!crate::isolation::is_non_l1(&tx) && !l2_family(&tx), "{tx:?}");
    }
    // Whatever the walk generates or decodes, the two definitions agree.
    for _ in 0..200 {
        let tx = walk.hostile(1);
        assert_eq!(crate::isolation::is_non_l1(&tx), l2_family(&tx), "{tx:?}");
    }
}

/// A verifier that faults on one marked signature and one marked proof: a
/// defect in code a handler calls, planted where a test can reach it.
struct Faulty;
const FAULT_SIGNATURE: [u8; 32] = [0xfa; 32];
const FAULT_PROOF: [u8; 356] = [0xfa; 356];
impl SignatureVerifier for Faulty {
    fn verify_with_key(&self, pk: &[u8], root: &[u8; 32], sig: &[u8]) -> bool {
        assert!(sig != FAULT_SIGNATURE, "planted fault in an L2 handler (signature)");
        ToyVerifier.verify_with_key(pk, root, sig)
    }
    fn verify_l2_settlement(&self, _: &[u8; 32], _: &[u8; 32], _: &[u8], proof: &[u8]) -> bool {
        assert!(proof != FAULT_PROOF, "planted fault in an L2 handler (proof)");
        proof == [1; 356]
    }
}

/// Below the gate a fault in an L2 handler unwinds the block transition (the
/// node stops). Behind it the block is refused like any block carrying an
/// invalid transaction, the parent state is untouched and the fault counted.
#[test]
fn a_handler_fault_stops_the_transition_below_the_gate_and_refuses_the_block_behind_it() {
    let mut walk = Walk::new(11, true);
    for _ in 0..3 {
        walk.step(0);
    }
    let t = Transition::new(Faulty);
    let slot = walk.slot;
    let empty = build_block(&t, &walk.state, slot, &[], &[], &mut walk.chains);
    let base_fee = walk.state.next_base_fee_at(crate::epoch_of(slot));
    let mut taken = Vec::new();
    let good = walk.deposit(base_fee, &mut taken);
    // Whole, so that the handler reaches the signature; then the marked one.
    let mut deposit = walk.deposit(base_fee, &mut taken);
    funded(&mut deposit).unwrap().signature.copy_from_slice(&FAULT_SIGNATURE);
    let mut claim_like = walk.batch_tx(base_fee, &mut taken);
    funded(&mut claim_like).unwrap().signature.copy_from_slice(&FAULT_SIGNATURE);
    let (mut settlement, _) = walk.settlement_tx();
    settlement.proof = FAULT_PROOF;
    let settlement = PosTransaction::L2SettlementAsync(Box::new(settlement));
    let bodies: [(Vec<PosTransaction>, u32); 4] = [
        (vec![deposit.clone()], 0),
        (vec![good.clone(), deposit], 1),
        (vec![good, claim_like], 1),
        (vec![settlement], 0),
    ];
    let key = crate::attestation::KeyLookup::pubkey(&walk.state, empty.header.proposer_index).unwrap().to_vec();
    let before = walk.state.clone();
    for (txs, culprit) in &bodies {
        let mut block = empty.clone();
        block.header.body_root = crate::derive::body_root(&txs.iter().map(PosTransaction::canonical_bytes).collect::<Vec<_>>());
        block.proposer_sig = toy_sign(&key, &block.header.proposal_signing_root());
        // Inert: the fault is a panic of the transition.
        let unwound = catch_unwind(AssertUnwindSafe(|| t.compute_post_state(&walk.state, &block, &[], txs)));
        assert!(unwound.is_err(), "the planted fault did not fire: {txs:?}");
        // Armed: the transaction is refused, and with it the block.
        let faults = crate::isolation::contained_faults();
        let _gate = crate::params::l2_fault_isolation_rehearsal::open();
        assert_eq!(t.compute_post_state(&walk.state, &block, &[], txs).err(), Some(TransitionError::Transaction(*culprit)));
        assert_eq!(t.apply_block(&walk.state, &block, &[], txs).err(), Some(TransitionError::Transaction(*culprit)));
        assert!(crate::isolation::contained_faults() >= faults + 2);
        assert!(walk.state == before);
    }
    // Armed, the empty block still applies, and the chain goes on.
    let _gate = crate::params::l2_fault_isolation_rehearsal::open();
    assert!(t.apply_block(&walk.state, &empty, &[], &[]).is_ok());
}

/// Node-local, always on: a preflight that faults refuses the transaction.
#[test]
fn a_faulting_preflight_refuses_the_settlement() {
    let mut walk = Walk::new(13, false);
    walk.step(0);
    let mut inblock = walk.state.clone();
    inblock.l2_settlement.as_mut().unwrap().prepare_source(*walk.state.head.as_bytes(), walk.state.slot);
    let l2 = inblock.l2_settlement().unwrap();
    let (mut tx, _) = walk.settlement_tx();
    assert_eq!(l2.validate_async(&tx, &Faulty), Ok(()));
    tx.proof = FAULT_PROOF;
    let faults = crate::isolation::contained_faults();
    assert_eq!(l2.validate_async(&tx, &Faulty), Err(Reject::Height));
    assert!(crate::isolation::contained_faults() > faults);
    // Not `Reject::Proof`: the node bars the bytes of a failed proof for good.
    assert_ne!(l2.validate_async(&tx, &Faulty), Err(Reject::Proof));
}

/// The SP1 Groth16 verifier behind `verify_l2_settlement` is the one piece
/// of the settlement path this crate does not own. Malformed proofs for a
/// statement that passes every check before the pairing must be refused, not
/// panic: 356 attacker-chosen bytes reach it from the mempool door.
#[test]
fn the_real_proof_verifier_refuses_malformed_proofs_without_panicking() {
    let values = include_bytes!("../../../bloch-l2-proof/tests/fixtures/source-contract.values");
    let valid = *include_bytes!("../../../bloch-l2-proof/tests/fixtures/source-contract.proof");
    let key = hash_at(values, S + 6 * 32);
    let policy = bloch_l2_proof::policy_commitment();
    let verify = |proof: &[u8]| {
        catch_unwind(|| bloch_l2_proof::verify(&policy, &key, values, proof))
            .unwrap_or_else(|_| panic!("the proof verifier panicked on {}", hex::encode(proof)))
    };
    assert!(verify(&valid));
    let mut rng = Rng::new(0x51);
    let mut cases: Vec<[u8; 356]> = Vec::new();
    // Past the 4-byte key prefix: all zero, all ones, field-sized values.
    for fill in [0x00, 0xff, 0x30, 0x7f, 0x80] {
        let mut proof = valid;
        proof[4..].fill(fill);
        cases.push(proof);
    }
    // One coordinate at a time replaced by an edge value (32-byte words).
    for word in 0..11 {
        for fill in [0x00, 0xff] {
            let mut proof = valid;
            proof[4 + 32 * word..4 + 32 * (word + 1)].fill(fill);
            cases.push(proof);
        }
    }
    for _ in 0..24 {
        let mut proof = valid;
        match rng.below(3) {
            0 => proof[4 + rng.below(352) as usize] ^= 1 << rng.below(8),
            1 => proof[4..].copy_from_slice(&rng.bytes::<352>()),
            _ => {
                let at = 4 + 32 * rng.below(11) as usize;
                proof[at..at + 32].copy_from_slice(&rng.bytes::<32>());
            }
        }
        cases.push(proof);
    }
    // A zero fill leaves a word that is already zero as it was.
    cases.retain(|proof| *proof != valid);
    assert!(cases.len() >= 40);
    for proof in &cases {
        assert!(!verify(proof), "a mutated proof verified: {}", hex::encode(proof));
    }
    // Wrong lengths and a wrong key prefix never reach the pairing.
    assert!(!verify(&valid[..355]) && !verify(&[]) && !verify(&[valid.as_slice(), &[0]].concat()));
    let mut prefix = valid;
    prefix[0] ^= 1;
    assert!(!verify(&prefix));
}
