// AUDIT-L1L2-20261123: fixtures shared by the regression tests of the audit
// fixes. Every test runs the consensus code on an L2 installed by the
// flag-day path with the MAINNET withdrawal limits.
use crate::l2_settlement::mainnet as mn;

/// The outpoint of funded coin `i` of [`funded_l2`].
fn coin(i: u32) -> ([u8; 32], u32) {
    let mut txid = [0x44; 32];
    txid[..4].copy_from_slice(&i.to_be_bytes());
    (txid, 0)
}

/// Funded network with `coins` outputs of 2 BLCH owned by the depositor key
/// and the L2 installed at the boundary with the mainnet limits.
fn funded_l2(coins: u32) -> (CommittedState, Vec<RandaoChain>) {
    let key = depositor();
    let utxos: Vec<crate::state_root::EutxoEntry> = (0..coins)
        .map(|i| crate::state_root::EutxoEntry { txid: coin(i).0, vout: 0, value: 2 * BLCH, script_hash: script_of(&key) })
        .collect();
    let (_, mut genesis, mut chains) = setup_with(4, ToyVerifier, &utxos);
    genesis.admission_network_domain = Some([0x91; 32]);
    let (_, mut policy) = running_without_l2();
    policy.identities[1] = *genesis.head.as_bytes();
    let pre = apply(&genesis, 1, &[], &mut chains).unwrap();
    let _gate = crate::params::l2_settlement_rehearsal::open();
    let _policy = crate::l2_settlement::activation_rehearsal::set(Activation {
        policy,
        asynchronous: mn::ASYNCHRONOUS,
        limits: mn::LIMITS,
    });
    let opened = apply(&pre, crate::params::SLOTS_PER_EPOCH, &[], &mut chains).unwrap();
    assert!(opened.l2_settlement().unwrap().deposits_enabled());
    (opened, chains)
}

/// A minimum (0.01 BLCH) deposit spending coin `i`.
fn min_deposit(pre: &CommittedState, i: u32) -> PosTransaction {
    let key = depositor();
    let mut tx = crate::transition::L2Deposit {
        network_domain: [0x91; 32],
        funding_pubkey: key.clone(),
        inputs: vec![crate::transition::FundingInput { txid: coin(i).0, vout: 0 }],
        amount_sat: crate::transition::l2_deposit::MIN_L2_DEPOSIT_SAT,
        recipient: [0x66; 20],
        change: TransferOutput { value: 0, script_hash: script_of(&key) },
        tx_bytes: 0,
        tip_millisat_per_gas: 0,
        signature: vec![0; 32],
    };
    tx.tx_bytes = tx.canonical_bytes().len() as u64;
    let charge = fee_market::charge(fee_market::TxClass::Eutxo { inputs: 1 }, tx.tx_bytes, pre.next_base_fee(), 0);
    tx.change.value = (u128::from(2 * BLCH) - u128::from(tx.amount_sat) - charge.base_fee_sat - charge.priority_fee_sat) as u64;
    tx.signature = toy_sign(&key, &tx.intent_root());
    PosTransaction::L2Deposit(tx)
}

/// Verdict of `block` (a valid block on `pre`) with its body replaced by
/// `txs` and re-signed: one RANDAO reveal serves every body judged.
fn body_verdict(pre: &CommittedState, block: &ProposalEnvelope, txs: &[PosTransaction]) -> Result<CommittedState, TransitionError> {
    let t = Transition::new(ProofDouble);
    let mut graft = block.clone();
    graft.header.body_root = crate::derive::body_root(&txs.iter().map(PosTransaction::canonical_bytes).collect::<Vec<_>>());
    let pk = crate::attestation::KeyLookup::pubkey(pre, graft.header.proposer_index).unwrap();
    graft.proposer_sig = toy_sign(pk, &graft.header.proposal_signing_root());
    t.compute_post_state(pre, &graft, &[], txs)
}
