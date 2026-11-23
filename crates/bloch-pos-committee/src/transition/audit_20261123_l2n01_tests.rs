// AUDIT-L1L2-20261123 L2N-01, the L1 stop-gap: behind
// `params::L2_SETTLER_AUTHORIZATION_ACTIVATION_EPOCH` an L2 with a settler
// set installed accepts a settlement only with an authorization signed by a
// registered settler key. Inert as shipped: no set, settlement permissionless.
use crate::l2_settlement::settler;

fn settler_key(tag: u8) -> Vec<u8> {
    vec![tag; crate::transition::funded::ADMISSION_PQ_KEY_BYTES]
}

/// The next (empty, deposit-only) V3 settlement of `pre`. `variant` flips a
/// bit of the L2 header hash: the field the L1 cannot check, i.e. the
/// prover-chosen block context of the finding.
fn next_settlement(pre: &CommittedState, variant: u8) -> Transaction {
    let mut tx = to_v3(settlement(pre, crate::l2_settlement::expected_body_commitment(&[])), no_deposits(), 0);
    tx.statement[S + 337] ^= variant;
    tx
}

fn authorize(pre: &CommittedState, mut tx: Transaction, key: &[u8], signer: u8, next_set: Option<Vec<Vec<u8>>>) -> Transaction {
    let policy = pre.l2_settlement().unwrap().policy();
    let digest = settler::digest(&policy.identities[0], policy.chain_id, &tx.commitment(), next_set.as_deref());
    tx.authorization = Some(settler::Authorization { signer, signature: toy_sign(key, &digest), next_set });
    tx
}

fn wire(tx: &Transaction) -> PosTransaction {
    PosTransaction::L2SettlementAsync(Box::new(tx.clone()))
}

/// An activated L2 one block past the epoch boundary that follows the
/// installation, so the source of L2 block 1 is frozen. With `keys` the
/// settler gate is open at that boundary and the set is installed there.
fn settler_fixture(keys: Option<Vec<Vec<u8>>>) -> (CommittedState, Vec<RandaoChain>) {
    settler_fixture_with(1, keys)
}

/// [`settler_fixture`] with `coins` funded outputs of the depositor key.
fn settler_fixture_with(coins: u32, keys: Option<Vec<Vec<u8>>>) -> (CommittedState, Vec<RandaoChain>) {
    let (opened, mut chains) = funded_l2(coins);
    let boundary = 2 * crate::params::SLOTS_PER_EPOCH;
    let rolled = match keys {
        None => apply(&opened, boundary, &[], &mut chains).unwrap(),
        Some(keys) => {
            let _gate = crate::params::l2_settler_authorization_rehearsal::open();
            let _set = crate::l2_settlement::settler_rehearsal::set(keys);
            apply(&opened, boundary, &[], &mut chains).unwrap()
        }
    };
    let next = apply(&rolled, boundary + 1, &[], &mut chains).unwrap();
    assert!(next.l2_settlement().unwrap().frozen_source().is_some());
    (next, chains)
}

/// An empty block on `pre`: every settlement judged on `pre` is grafted
/// into it (one RANDAO reveal serves them all).
fn template(pre: &CommittedState, chains: &mut Vec<RandaoChain>) -> ProposalEnvelope {
    build_block(&Transition::new(ProofDouble), pre, pre.slot + 1, &[], &[], chains)
}

fn judged(pre: &CommittedState, block: &ProposalEnvelope, tx: &Transaction) -> Result<CommittedState, TransitionError> {
    body_verdict(pre, block, std::slice::from_ref(&wire(tx)))
}

#[test]
fn l2n01_the_settler_gate_is_inert_and_unset() {
    assert_eq!(crate::params::L2_SETTLER_AUTHORIZATION_ACTIVATION_EPOCH, u64::MAX);
    assert!(!crate::params::l2_settler_authorization_active(u64::MAX - 1));
    assert!(crate::l2_settlement::mainnet::SETTLER_SET.is_none());
    // The pinned text format: hex keys, one per line, 1 to MAX_KEYS, distinct.
    let line = |tag: u8| hex::encode(settler_key(tag));
    assert_eq!(
        crate::l2_settlement::mainnet::settler_keys(&format!("{}\n{}\n", line(1), line(2))),
        Some(vec![settler_key(1), settler_key(2)])
    );
    assert_eq!(crate::l2_settlement::mainnet::settler_keys(&format!("{}\n{}\n", line(1), line(1))), None);
    assert_eq!(crate::l2_settlement::mainnet::settler_keys(""), None);
    assert_eq!(crate::l2_settlement::mainnet::settler_keys(&[line(1), line(2), line(3), line(4)].join("\n")), None);
}

/// As shipped: no set is installed at any boundary, the committed bytes are
/// unchanged, anyone with a valid proof settles (two statements that differ
/// only in the L2 header hash are both acceptable: the finding's L1 half),
/// and a settlement carrying an authorization is refused.
#[test]
fn l2n01_inert_settlement_stays_permissionless_and_refuses_a_trailer() {
    let (pre, mut chains) = settler_fixture(None);
    let block = template(&pre, &mut chains);
    let l2 = pre.l2_settlement().unwrap();
    assert!(l2.settlers().is_empty());
    assert!(!l2.committed_bytes().windows(26).any(|w| w == b"BLOCH:NATIVE:L2:SETTLERS:1"));
    for variant in [0, 1] {
        let tx = next_settlement(&pre, variant);
        assert_eq!(l2.validate_async(&tx, &ProofDouble), Ok(()));
        assert_eq!(judged(&pre, &block, &tx).unwrap().l2_settlement().unwrap().settled_number(), 1);
    }
    let signed = authorize(&pre, next_settlement(&pre, 0), &settler_key(1), 0, None);
    assert_eq!(l2.validate_async(&signed, &ProofDouble), Err(Reject::Settler));
    assert_eq!(l2.pending_async_refusal(&signed, *pre.head.as_bytes(), pre.slot), Some(Reject::Settler));
    assert!(judged(&pre, &block, &signed).is_err());
    // Review item C1: with the gate inert the DECODER is the base decoder.
    // A settlement followed by a trailer is not a transaction for the block
    // door, the mempool or the RPC, under either wire tag, and every length
    // other than the two exact settlement lengths is refused as before.
    assert!(!crate::params::l2_settler_trailer_decodable());
    let plain = next_settlement(&pre, 0);
    let bytes = signed.encode_async();
    assert_eq!(Transaction::decode_async(&bytes), None);
    assert_eq!(PosTransaction::from_canonical_bytes(&bytes), Err(TxDecodeError::Truncated));
    let mut sync = bytes.clone();
    sync[0] = crate::l2_settlement::WIRE_TAG;
    assert_eq!(Transaction::decode(&sync), None);
    assert_eq!(PosTransaction::from_canonical_bytes(&sync), Err(TxDecodeError::Truncated));
    let exact = plain.encode_async();
    assert_eq!(exact.len(), crate::l2_settlement::TRANSACTION_V3_BYTES);
    assert_eq!(Transaction::decode_async(&exact), Some(plain.clone()));
    for extra in [1usize, 2, 5, 100, settler::MAX_AUTHORIZATION_BYTES, settler::MAX_AUTHORIZATION_BYTES + 1] {
        let mut longer = exact.clone();
        longer.resize(exact.len() + extra, 0);
        assert_eq!(Transaction::decode_async(&longer), None, "{extra} bytes after the proof");
    }
    // The same bytes decode only for a build that arms the gate, and are
    // then refused by the transition on an L2 without a set (the test above).
    let _decoder = crate::params::l2_settler_trailer_rehearsal::open();
    assert_eq!(Transaction::decode_async(&bytes), Some(signed.clone()));
    assert_eq!(PosTransaction::from_canonical_bytes(&bytes), Ok(wire(&signed)));
}

/// Review item I7: the bytes a settlement is charged are a consensus value
/// (they are the block's `block_tx_bytes`, committed in the fee leaf of the
/// state root and read by the next block's base fee). Nothing pinned them:
/// an off-by-one in the charge passed every suite. As shipped, a V3
/// settlement block commits exactly the encoded length every release has
/// charged, 1 + 32 + statement + proof, and the full block gas; the value is
/// written out here, not taken from `wire_len`.
#[test]
fn l2n01_a_settlement_block_commits_its_exact_byte_charge_in_the_fee_leaf() {
    let (pre, mut chains) = settler_fixture(None);
    let block = template(&pre, &mut chains);
    let tx = next_settlement(&pre, 0);
    let charged = (1 + 32 + crate::l2_settlement::STATEMENT_V3_BYTES + crate::l2_settlement::PROOF_BYTES) as u64;
    assert_eq!(charged, 1_155, "tag, proof policy, 766-byte V3 statement, 356-byte proof");
    assert_eq!(tx.encode_async().len() as u64, charged);
    let post = judged(&pre, &block, &tx).expect("the settlement block");
    assert_eq!(post.block_tx_bytes, charged);
    assert_eq!(post.block_gas_used, fee_market::BLOCK_GAS_LIMIT);
    // The same block without the settlement commits no bytes and no gas.
    let empty = body_verdict(&pre, &block, &[]).expect("the empty block");
    assert_eq!((empty.block_tx_bytes, empty.block_gas_used), (0, 0));
    // The leaf is part of the state root: one byte more is another root.
    let mut off_by_one = post.clone();
    off_by_one.block_tx_bytes += 1;
    assert_ne!(off_by_one.compute_root(), post.compute_root());
    // Behind the gate an authorized settlement is charged its encoded
    // length too, trailer included (never reachable while the gate is inert:
    // the decoder knows no trailer and `apply` refuses one).
    let keys = vec![settler_key(1)];
    let (armed, mut armed_chains) = settler_fixture(Some(keys));
    let armed_block = template(&armed, &mut armed_chains);
    let signed = authorize(&armed, next_settlement(&armed, 0), &settler_key(1), 0, None);
    let settled = judged(&armed, &armed_block, &signed).expect("the settler's settlement");
    assert_eq!(settled.block_tx_bytes, signed.encode_async().len() as u64);
    assert!(settled.block_tx_bytes > charged);
}

/// Armed: the set is installed at the boundary and committed; the finding's
/// foreign settlement (a valid proof, no registered key) is refused by the
/// transition and by the mempool preflight before any proof is verified; the
/// registered settler's settlement is accepted; an authorization is bound to
/// its settlement and to its signer.
#[test]
fn l2n01_only_a_registered_settler_settles_behind_the_gate() {
    let (plain, _) = settler_fixture(None);
    let keys = vec![settler_key(1), settler_key(2)];
    let (pre, mut chains) = settler_fixture(Some(keys.clone()));
    let block = template(&pre, &mut chains);
    let l2 = pre.l2_settlement().unwrap();
    assert_eq!(l2.settlers(), keys.as_slice());
    assert!(l2.committed_bytes().windows(26).any(|w| w == b"BLOCH:NATIVE:L2:SETTLERS:1"));
    assert_ne!(pre.compute_root(), plain.compute_root(), "the set is part of the state root");

    // The outsider of the finding: a proof that verifies, no authorization.
    struct NoProof;
    impl SignatureVerifier for NoProof {
        fn verify_with_key(&self, pk: &[u8], root: &[u8; 32], sig: &[u8]) -> bool {
            ToyVerifier.verify_with_key(pk, root, sig)
        }
        fn verify_l2_settlement(&self, _: &[u8; 32], _: &[u8; 32], _: &[u8], _: &[u8]) -> bool {
            panic!("the proof must not be reached without a settler authorization")
        }
    }
    let foreign = next_settlement(&pre, 1);
    assert_eq!(l2.validate_async(&foreign, &NoProof), Err(Reject::Settler));
    assert_eq!(l2.pending_async_refusal(&foreign, *pre.head.as_bytes(), pre.slot), Some(Reject::Settler));
    let before = pre.clone();
    assert!(judged(&pre, &block, &foreign).is_err(), "a block carrying it is invalid");
    assert_eq!(pre, before);
    // Signed by a key that is not registered, or naming the wrong signer.
    let outsider = authorize(&pre, next_settlement(&pre, 1), &settler_key(9), 0, None);
    assert_eq!(l2.validate_async(&outsider, &NoProof), Err(Reject::Settler));
    let wrong_index = authorize(&pre, next_settlement(&pre, 0), &settler_key(1), 1, None);
    assert_eq!(l2.validate_async(&wrong_index, &NoProof), Err(Reject::Settler));
    let out_of_range = authorize(&pre, next_settlement(&pre, 0), &settler_key(1), 2, None);
    assert_eq!(l2.validate_async(&out_of_range, &NoProof), Err(Reject::Settler));
    // An authorization lifted from the settler's settlement onto another one.
    let honest = authorize(&pre, next_settlement(&pre, 0), &settler_key(1), 0, None);
    let mut lifted = next_settlement(&pre, 1);
    lifted.authorization = honest.authorization.clone();
    assert_eq!(l2.validate_async(&lifted, &NoProof), Err(Reject::Settler));
    // ...or kept on the same statement with a re-randomized proof.
    let mut reproven = honest.clone();
    reproven.proof[0] ^= 1;
    assert_eq!(l2.validate_async(&reproven, &NoProof), Err(Reject::Settler));

    // The registered settler, through the wire and the transition.
    assert_eq!(l2.validate_async(&honest, &ProofDouble), Ok(()));
    assert_eq!(l2.pending_async_refusal(&honest, *pre.head.as_bytes(), pre.slot), None);
    let encoded = wire(&honest).canonical_bytes();
    assert_eq!(encoded.len(), honest.wire_len());
    // The trailer is wire format only for a build that arms the gate.
    assert_eq!(PosTransaction::from_canonical_bytes(&encoded), Err(TxDecodeError::Truncated));
    {
        let _decoder = crate::params::l2_settler_trailer_rehearsal::open();
        assert_eq!(PosTransaction::from_canonical_bytes(&encoded), Ok(wire(&honest)));
    }
    let post = judged(&pre, &block, &honest).expect("the settler's settlement");
    let settled = post.l2_settlement().unwrap();
    assert_eq!(settled.settled_number(), 1);
    assert_eq!(settled.head().unwrap().0, honest.commitment(), "the head commitment is the unsigned one, as before");
    assert_eq!(settled.settlers(), keys.as_slice());
    // The standby key settles too.
    let standby = authorize(&pre, next_settlement(&pre, 0), &settler_key(2), 1, None);
    assert!(judged(&pre, &block, &standby).is_ok());
}

/// Rotation and key loss: any registered key (here the standby, the
/// settler's own key being lost) installs the next set with one settlement;
/// the old keys stop working from the next settlement on.
#[test]
fn l2n01_a_registered_key_rotates_the_set_with_a_settlement() {
    let (pre, mut chains) = settler_fixture(Some(vec![settler_key(1), settler_key(2)]));
    let block = template(&pre, &mut chains);
    let next = vec![settler_key(3)];
    // The next set is covered by the signature: it cannot be added or changed.
    let plain = authorize(&pre, next_settlement(&pre, 0), &settler_key(2), 1, None);
    let mut grafted = plain.clone();
    grafted.authorization.as_mut().unwrap().next_set = Some(next.clone());
    assert_eq!(pre.l2_settlement().unwrap().validate_async(&grafted, &ProofDouble), Err(Reject::Settler));
    let rotating = authorize(&pre, next_settlement(&pre, 0), &settler_key(2), 1, Some(next.clone()));
    {
        let _decoder = crate::params::l2_settler_trailer_rehearsal::open();
        assert_eq!(PosTransaction::from_canonical_bytes(&wire(&rotating).canonical_bytes()), Ok(wire(&rotating)));
    }
    let post = judged(&pre, &block, &rotating).expect("rotation");
    assert_eq!(post.l2_settlement().unwrap().settlers(), next.as_slice());

    // After it (anchor the next source first): old keys are refused.
    let after = apply(&post, post.slot + 1, &[], &mut chains).unwrap();
    let l2 = after.l2_settlement().unwrap();
    let old = authorize(&after, next_settlement(&after, 0), &settler_key(1), 0, None);
    assert_eq!(l2.validate_async(&old, &ProofDouble), Err(Reject::Settler));
    let new = authorize(&after, next_settlement(&after, 0), &settler_key(3), 0, None);
    assert_eq!(l2.validate_async(&new, &ProofDouble), Ok(()));
    // The set survives later boundaries (it is installed once).
    let _gate = crate::params::l2_settler_authorization_rehearsal::open();
    let _set = crate::l2_settlement::settler_rehearsal::set(vec![settler_key(7)]);
    let later = apply(&after, 4 * crate::params::SLOTS_PER_EPOCH, &[], &mut chains).unwrap();
    assert_eq!(later.l2_settlement().unwrap().settlers(), next.as_slice());

    #[cfg(feature = "local-state-cache")]
    {
        let (restored, bytes, _) = local_cache_round_trip(&after);
        assert!(bytes.windows(16).any(|w| w == b"BPOSST01:L2ST:v1"));
        assert_eq!(restored.l2_settlement().unwrap().settlers(), next.as_slice());
    }
}

/// The trailer has one encoding and strict bounds; a V2 settlement cannot
/// carry one.
#[test]
fn l2n01_the_authorization_trailer_is_canonical() {
    let (pre, _) = settler_fixture(None);
    let signed = authorize(&pre, next_settlement(&pre, 0), &settler_key(1), 0, Some(vec![settler_key(3), settler_key(4)]));
    let bytes = signed.encode_async();
    // Inert build: the consensus decoder knows no trailer; only the tooling
    // decoder reads one.
    assert_eq!(Transaction::decode_async(&bytes), None);
    assert_eq!(Transaction::decode_async_with_authorization(&bytes), Some(signed.clone()));
    let _decoder = crate::params::l2_settler_trailer_rehearsal::open();
    assert_eq!(Transaction::decode_async(&bytes), Some(signed.clone()));
    // Trailing or missing bytes, an empty signature, too many or repeated keys.
    let mut long = bytes.clone();
    long.push(0);
    assert_eq!(Transaction::decode_async(&long), None);
    assert_eq!(Transaction::decode_async(&bytes[..bytes.len() - 1]), None);
    let variant = |edit: &dyn Fn(&mut settler::Authorization)| {
        let mut tx = signed.clone();
        edit(tx.authorization.as_mut().unwrap());
        Transaction::decode_async(&tx.encode_async())
    };
    assert_eq!(variant(&|a| a.signature.clear()), None);
    assert_eq!(variant(&|a| a.signer = settler::MAX_KEYS as u8), None);
    assert_eq!(variant(&|a| a.next_set = Some(vec![settler_key(3), settler_key(3)])), None);
    assert_eq!(variant(&|a| a.next_set = Some((0..4).map(settler_key).collect())), None);
    // V2 statement + trailer: not a settlement.
    let mut v2 = settlement(&pre, crate::l2_settlement::expected_body_commitment(&[]));
    v2.authorization = signed.authorization.clone();
    assert_eq!(Transaction::decode_async(&v2.encode_async()), None);
}
