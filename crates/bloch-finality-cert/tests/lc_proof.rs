//! `BLCLMP01` proofs across the hard forks, built with the consensus
//! serializers and real hybrid keys at the compiled mainnet gates (no post-HF
//! mainnet block exists yet): HF1 frozen set, HF2 bound signatures, KES leaves
//! and the 0x22 entries, all proven against one state root. Ported from the
//! light-client branch's `tests/post_hf.rs`, whose rule this crate shares.

use bloch_finality_cert::lc_proof::{self as ffg, Config, FinalitySetProof, HybridConsensusVerifier, KesProofs, MainnetProof, Refusal, Weights};
use bloch_finality_cert::state::{decode_kes_entry, FinalityLeaf};
use bloch_finality_cert::{Certificate, CompressedProof, Link, RegistryProof, Vote};
use bloch_pos_committee::attestation::AttestationData;
use bloch_pos_committee::header::{BlockHeaderV4, BlockId, VERSION_G4};
use bloch_pos_committee::kes::{self, KesEntry, KesPublic, KesSignature, RetiredKes};
use bloch_pos_committee::state_root::{
    empty_subtree_hashes, finality_leaf_key, kes_enforced_leaf_key, kes_leaf_key, leaf_value_hash, validator_leaf_key,
    CheckpointRecord, FinalityRecord, FinalitySetRecord, LeakRecord, Smt, ValidatorRecord,
};
use bloch_pos_committee::{params, SLOTS_PER_EPOCH};
use sha3::{Digest, Sha3_256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, OnceLock};

const DOMAIN: [u8; 32] = ffg::MAINNET_NETWORK_DOMAIN;
const KES_DEPTH: u8 = 8;
type Kp = (Vec<u8>, Vec<u8>);

/// Deterministic hybrid keypair `kind` (0 static, 1 KES leaf 0) of
/// validator `v`, generated once per process.
fn kp(v: u32, kind: u8) -> Kp {
    static K: OnceLock<Mutex<BTreeMap<(u32, u8), Kp>>> = OnceLock::new();
    let m = K.get_or_init(Default::default);
    if let Some(k) = m.lock().unwrap().get(&(v, kind)) {
        return k.clone();
    }
    let mut seed = [0x5Au8; 32];
    seed[..4].copy_from_slice(&v.to_le_bytes());
    seed[4] = kind;
    let k = bloch_crypto::crypto::generate_keypair_from_seed(&seed).unwrap();
    m.lock().unwrap().insert((v, kind), k.clone());
    k
}

fn node(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"BLOCH-KES-v1/node");
    h.update(l);
    h.update(r);
    h.finalize().into()
}

/// A depth-8 KES tree whose leaf 0 is `leaf_pk` (other leaves are filler
/// hashes): `(root, path of leaf 0)`.
fn kes_tree(leaf_pk: &[u8], salt: u8) -> ([u8; 32], Vec<[u8; 32]>) {
    let mut level: Vec<[u8; 32]> =
        (0..1usize << KES_DEPTH).map(|i| if i == 0 { kes::leaf_hash(leaf_pk) } else { [salt ^ (i as u8); 32] }).collect();
    let mut path = Vec::new();
    while level.len() > 1 {
        path.push(level[1]);
        level = level.chunks(2).map(|c| node(&c[0], &c[1])).collect();
    }
    (level[0], path)
}

fn kes_public(v: u32) -> (KesPublic, Vec<[u8; 32]>) {
    let (root, path) = kes_tree(&kp(v, 1).0, v as u8);
    (KesPublic::new(KES_DEPTH, root, 0), path)
}

fn record(v: u32, stake: u64) -> ValidatorRecord {
    ValidatorRecord {
        index: v,
        pubkey: kp(v, 0).0,
        stake,
        activation_epoch: 0,
        exit_epoch: u64::MAX,
        slashed: false,
        randao_commitment: [v as u8; 32],
        reveals_used: 0,
        withdrawable_epoch: u64::MAX,
        withdrawal_credentials: vec![0xC0, v as u8],
        commission_bps: 500,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Sig {
    /// What consensus demands at the epoch (KES leaf if registered and
    /// bound, else the static key under the epoch's policy).
    Proper,
    /// The static key, v2 bound form, even when KES is bound.
    StaticBound,
    /// The static key, v1 (context-free) form.
    StaticV1,
}

struct World {
    /// Bond stakes (registry) and frozen-set weights.
    bond: Vec<u64>,
    frozen: Vec<(u32, u64)>,
    pending: Option<Vec<(u32, u64)>>,
    /// Validators with a KES entry.
    kes: Vec<u32>,
    enforced: Option<u64>,
    /// The checkpoint epoch E (links E-1 -> E, E -> E+1).
    epoch: u64,
    /// The bind is committed by the checkpoint's state, not the set source's.
    bind_in_checkpoint: bool,
    /// The finality leaf commits no frozen set yet.
    no_set_in_leaf: bool,
    /// Epochs between the set-source block's epoch and E (2: the block that
    /// closes E-2, which is the checkpoint of E-1).
    src_gap: u64,
    /// Serve the checkpoint's own bind proof when the set source has none.
    second_proof: bool,
}

struct Built {
    proof: MainnetProof,
    src_id: [u8; 32],
}

/// The committed state of world `w`: registry, finality leaf, KES entries
/// and, when this state commits it, the bind epoch.
fn state_smt(w: &World) -> Smt {
    let mut smt = Smt::new();
    for v in 0..w.bond.len() as u32 {
        let r = record(v, w.bond[v as usize]);
        smt.insert(validator_leaf_key(r.index), leaf_value_hash(&r.canonical_bytes()));
    }
    smt.insert(finality_leaf_key(), leaf_value_hash(&finality_record(w).committed_bytes()));
    for v in &w.kes {
        smt.insert(kes_leaf_key(*v), leaf_value_hash(&KesEntry::from(kes_public(*v).0).committed_bytes()));
    }
    if let Some(b) = w.enforced.filter(|_| !w.bind_in_checkpoint) {
        smt.insert(kes_enforced_leaf_key(), leaf_value_hash(&b.to_le_bytes()));
    }
    smt
}

/// The world one epoch later, whose state the checkpoint block of `w`
/// commits: the same registry and keys, and the bind if there is one.
fn next_world(w: &World) -> World {
    World {
        bond: w.bond.clone(),
        frozen: w.frozen.clone(),
        pending: w.pending.clone(),
        kes: w.kes.clone(),
        enforced: w.enforced,
        epoch: w.epoch + 1,
        bind_in_checkpoint: false,
        no_set_in_leaf: w.no_set_in_leaf,
        src_gap: 2,
        second_proof: w.second_proof,
    }
}

fn compress(p: &bloch_pos_committee::state_root::InclusionProof) -> CompressedProof {
    CompressedProof::compress(p, &empty_subtree_hashes())
}

fn finality_record(w: &World) -> FinalityRecord {
    let cp = |e: u64| CheckpointRecord { epoch: e, root: [e as u8; 32] };
    FinalityRecord {
        justified: vec![cp(w.epoch - 2), cp(w.epoch - 3)],
        current_justified: cp(w.epoch - 2),
        previous_justified: cp(w.epoch - 3),
        finalized: cp(w.epoch - 3),
        leaked: vec![LeakRecord { validator: 2, leaked_sat: 7 }],
        next_epoch: w.epoch - 1,
        finality_set: (!w.no_set_in_leaf).then(|| FinalitySetRecord {
            current_epoch: w.epoch - 4,
            current: w.frozen.clone(),
            pending: w.pending.clone().map(|p| (w.epoch - 3, p)),
            last_seen: (0..w.bond.len() as u32).map(|v| (v, w.epoch - 2)).collect(),
        }),
        own_checkpoints: vec![cp(w.epoch - 1), cp(w.epoch - 2)],
    }
}

fn header(slot: u64, parent: [u8; 32], state_root: [u8; 32]) -> BlockHeaderV4 {
    BlockHeaderV4 {
        version: VERSION_G4,
        parent,
        state_root,
        body_root: [1; 32],
        slot,
        proposer_index: 0,
        randao_reveal: [2; 32],
        randao_mix: [3; 32],
        justified_root: [4; 32],
        finalized_root: [5; 32],
        attestation_root: [6; 32],
        coherence_root: [7; 32],
    }
}

fn sign_vote(v: u32, data: &AttestationData, how: Sig, w: &World) -> Vec<u8> {
    let root = data.signing_root();
    let (_, sk) = &kp(v, 0);
    let kes_bound = params::kes_period(data.target_epoch).is_some()
        && w.enforced.is_some_and(|b| data.target_epoch >= b)
        && w.kes.contains(&v);
    match how {
        Sig::StaticV1 => bloch_crypto::crypto::sign(sk, &root).unwrap(),
        Sig::StaticBound => bloch_crypto::crypto::sign_bound(sk, &root).unwrap(),
        Sig::Proper if !kes_bound => {
            if params::sig_canonical_active(data.target_epoch) {
                bloch_crypto::crypto::sign_bound(sk, &root).unwrap()
            } else {
                bloch_crypto::crypto::sign(sk, &root).unwrap()
            }
        }
        Sig::Proper => {
            let period = params::kes_period(data.target_epoch).unwrap();
            let (public, path) = kes_public(v);
            let msg = kes::leaf_message(Some(DOMAIN), v, &public, period, &root).unwrap();
            let (leaf_pk, leaf_sk) = &kp(v, 1);
            KesSignature {
                index: 0,
                leaf_pk: leaf_pk.clone(),
                sig: bloch_crypto::crypto::sign_bound(leaf_sk, &msg).unwrap(),
                path,
            }
            .encode()
        }
    }
}

fn build(w: &World, voters: &[(u32, Sig)], with_set: bool, with_kes: bool) -> Built {
    build_on(w, voters, with_set, with_kes, None)
}

/// [`build`] on a given set-source header (the checkpoint header of the
/// previous step of a chain), which must commit `state_smt(w)`.
fn build_on(w: &World, voters: &[(u32, Sig)], with_set: bool, with_kes: bool, on: Option<BlockHeaderV4>) -> Built {
    let smt = state_smt(w);
    let n = w.bond.len() as u32;
    let records: Vec<ValidatorRecord> = (0..n).map(|v| record(v, w.bond[v as usize])).collect();
    let fin = finality_record(w).committed_bytes();
    let entries: BTreeMap<u32, KesEntry> = w.kes.iter().map(|v| (*v, KesEntry::from(kes_public(*v).0))).collect();
    // The checkpoint's own state: the next epoch's, which commits the bind
    // from the checkpoint on when the set source did not.
    let cp_smt = state_smt(&next_world(w));
    let e = w.epoch;
    let src = on.unwrap_or_else(|| header((e - w.src_gap + 1) * SLOTS_PER_EPOCH - 1, [9; 32], smt.root()));
    assert_eq!(src.state_root, smt.root(), "the set source commits this world's state");
    let src_id = *BlockId::of(&src).as_bytes();
    let cp = header(e * SLOTS_PER_EPOCH - 1, src_id, cp_smt.root());
    let cp_id = *BlockId::of(&cp).as_bytes();
    let link = |source: (u64, [u8; 32]), target: (u64, [u8; 32])| {
        let votes = voters
            .iter()
            .map(|(v, how)| {
                let slot = target.0 * SLOTS_PER_EPOCH + *v as u64 % SLOTS_PER_EPOCH;
                let data = AttestationData {
                    slot,
                    head: [0xEE; 32],
                    source_epoch: source.0,
                    source_root: source.1,
                    target_epoch: target.0,
                    target_root: target.1,
                };
                Vote { validator: *v, slot, head: [0xEE; 32], signature: sign_vote(*v, &data, *how, w) }
            })
            .collect();
        Link { source_epoch: source.0, source_root: source.1, target_epoch: target.0, target_root: target.1, votes }
    };
    let links = [link((e - 1, src_id), (e, cp_id)), link((e, cp_id), (e + 1, [0x77; 32]))];
    let registry = RegistryProof {
        header: src,
        records: records
            .iter()
            .map(|r| (r.canonical_bytes(), compress(&smt.prove(&validator_leaf_key(r.index)).unwrap())))
            .collect(),
        absent: vec![(n, compress(&smt.prove_absence(&validator_leaf_key(n)).unwrap()))],
    };
    let finality_set = with_set
        .then(|| FinalitySetProof { leaf: fin.clone(), proof: compress(&smt.prove(&finality_leaf_key()).unwrap()) });
    // What the set source commits about the bind, and what the checkpoint does.
    let at_source = w.enforced.filter(|_| !w.bind_in_checkpoint);
    let kes = with_kes.then(|| KesProofs {
        enforced: (
            at_source,
            compress(&match at_source {
                Some(_) => smt.prove(&kes_enforced_leaf_key()).unwrap(),
                None => smt.prove_absence(&kes_enforced_leaf_key()).unwrap(),
            }),
        ),
        // As the node does: only from the KES gate on, so that earlier
        // proofs keep the `BLCLMP01` encoding.
        enforced_at_checkpoint: (at_source.is_none() && w.second_proof && params::kes_period(e + 1).is_some()).then(|| {
            (
                w.enforced,
                compress(&match w.enforced {
                    Some(_) => cp_smt.prove(&kes_enforced_leaf_key()).unwrap(),
                    None => cp_smt.prove_absence(&kes_enforced_leaf_key()).unwrap(),
                }),
            )
        }),
        entries: voters
            .iter()
            .map(|(v, _)| match entries.get(v) {
                Some(e) => (*v, Some(e.committed_bytes()), compress(&smt.prove(&kes_leaf_key(*v)).unwrap())),
                None => (*v, None, compress(&smt.prove_absence(&kes_leaf_key(*v)).unwrap())),
            })
            .collect(),
    });
    Built {
        proof: MainnetProof {
            cert: Certificate { checkpoint_header: cp, registry, links, ancestry: vec![] },
            finality_set,
            kes,
        },
        src_id,
    }
}

fn run(b: &Built) -> Result<ffg::Verified, Refusal> {
    let trusted: BTreeSet<[u8; 32]> = [b.src_id].into_iter().collect();
    ffg::verify(&b.proof, &trusted, &Config::mainnet(), &HybridConsensusVerifier)
}

fn kes_world(epoch: u64) -> World {
    World {
        bond: vec![25, 25, 25, 25],
        frozen: vec![(0, 40), (1, 30), (2, 20), (3, 10)],
        pending: None,
        kes: vec![0, 1, 2],
        enforced: Some(params::HF3_KES_ENFORCE_EPOCH),
        epoch,
        bind_in_checkpoint: false,
        no_set_in_leaf: false,
        src_gap: 2,
        second_proof: true,
    }
}

const ALL: [(u32, Sig); 4] = [(0, Sig::Proper), (1, Sig::Proper), (2, Sig::Proper), (3, Sig::Proper)];

#[test]
fn the_shipped_gates_are_the_ones_these_fixtures_cross() {
    assert_eq!(params::HF1_FROZEN_FINALITY_SET_EPOCH, 7180);
    assert_eq!(params::SIG_CANONICAL_ACTIVATION_EPOCH, 7270);
    assert_eq!(params::HF3_KES_ENFORCE_EPOCH, 8620);
    assert_eq!(params::kes_period(8701), Some(0));
}

#[test]
fn finality_leaf_round_trips_through_the_consensus_serializer() {
    let w = kes_world(8700);
    let rec = finality_record(&w);
    let leaf = FinalityLeaf::decode(&rec.committed_bytes()).expect("decodes");
    let set = leaf.finality_set.as_ref().unwrap();
    assert_eq!(set.current.members.iter().map(|(a, b)| (*a, *b)).collect::<Vec<_>>(), w.frozen);
    assert_eq!(set.current.total(), 100);
    assert_eq!(leaf.own_checkpoints.len(), 2);
    assert_eq!(leaf.finalized.epoch, 8697);
    // A pre-HF1 leaf (no extension) still decodes, with no set.
    let mut legacy = rec.clone();
    legacy.finality_set = None;
    legacy.own_checkpoints.clear();
    assert!(FinalityLeaf::decode(&legacy.committed_bytes()).unwrap().finality_set.is_none());
    // Trailing bytes are refused.
    let mut bytes = rec.committed_bytes();
    bytes.push(0);
    assert!(FinalityLeaf::decode(&bytes).is_none());
}

#[test]
fn kes_entries_round_trip_through_the_consensus_serializer() {
    let a = KesPublic::new(8, [1; 32], 0);
    let b = KesPublic::new(9, [2; 32], 200);
    let c = KesPublic::new(8, [3; 32], 40);
    for e in [
        KesEntry::from(a),
        KesEntry { current: a, next: Some(b), retired: vec![] },
        KesEntry { current: b, next: None, retired: vec![RetiredKes { public: c, end_period: 199 }] },
        KesEntry { current: a, next: Some(b), retired: vec![RetiredKes { public: c, end_period: 10 }] },
    ] {
        assert_eq!(decode_kes_entry(&e.committed_bytes()), Some(e.clone()));
    }
    let mut bad = KesEntry::from(a).committed_bytes();
    bad.push(0xFF);
    assert_eq!(decode_kes_entry(&bad), None);
}

#[test]
fn post_kes_step_verifies_with_frozen_weights_and_kes_votes() {
    let b = build(&kes_world(8700), &ALL, true, true);
    let v = run(&b).expect("verifies");
    assert_eq!(v.weights, Weights::Frozen { with_pending: false });
    assert_eq!(v.stake, [(100, 100), (100, 100)]);
    assert_eq!(v.kes_votes, 6, "validators 0..2 sign with KES leaves on both links");
}

#[test]
fn past_the_kes_gate_kes_proofs_are_required() {
    let b = build(&kes_world(8700), &ALL, true, false);
    assert!(matches!(run(&b).unwrap_err(), Refusal::Kes(_)));
}

#[test]
fn a_static_signature_from_a_kes_registered_validator_is_refused() {
    let voters = [(0, Sig::StaticBound), (1, Sig::Proper), (2, Sig::Proper), (3, Sig::Proper)];
    assert_eq!(run(&build(&kes_world(8700), &voters, true, true)).unwrap_err(), Refusal::BadSignature(0));
}

#[test]
fn after_hf2_a_v1_signature_is_refused() {
    let voters = [(0, Sig::Proper), (1, Sig::Proper), (2, Sig::Proper), (3, Sig::StaticV1)];
    assert_eq!(run(&build(&kes_world(8700), &voters, true, true)).unwrap_err(), Refusal::BadSignature(3));
}

#[test]
fn a_kes_vote_bound_to_another_network_is_refused() {
    let b = build(&kes_world(8700), &ALL, true, true);
    let trusted: BTreeSet<[u8; 32]> = [b.src_id].into_iter().collect();
    let mut cfg = Config::mainnet();
    cfg.network_domain[0] ^= 1;
    assert_eq!(ffg::verify(&b.proof, &trusted, &cfg, &HybridConsensusVerifier).unwrap_err(), Refusal::BadSignature(0));
}

#[test]
fn a_voter_without_a_kes_proof_is_refused() {
    let mut b = build(&kes_world(8700), &ALL, true, true);
    b.proof.kes.as_mut().unwrap().entries.retain(|(v, _, _)| *v != 1);
    assert!(matches!(run(&b).unwrap_err(), Refusal::Kes(_)));
}

#[test]
fn a_forged_kes_entry_is_refused() {
    let mut b = build(&kes_world(8700), &ALL, true, true);
    let e = &mut b.proof.kes.as_mut().unwrap().entries[0];
    e.1.as_mut().unwrap()[5] ^= 1;
    assert!(matches!(run(&b).unwrap_err(), Refusal::Kes(_)));
}

/// The frozen set, not the bond, decides: 0+1 hold 70 % of the frozen set
/// but 50 % of the bond; 1+2+3 hold 60 % of the set but 75 % of the bond.
#[test]
fn frozen_weights_decide_where_bond_weights_would_differ() {
    let w = kes_world(8700);
    let a = [(0, Sig::Proper), (1, Sig::Proper)];
    assert!(run(&build(&w, &a, true, true)).is_ok());
    let b = [(1, Sig::Proper), (2, Sig::Proper), (3, Sig::Proper)];
    assert!(matches!(run(&build(&w, &b, true, true)).unwrap_err(), Refusal::InsufficientWeight { .. }));
}

/// A prover must not choose the weight rule by omitting the leaf: these voters
/// reach 2/3 of bond but not of the frozen set.
#[test]
fn a_prover_cannot_choose_the_bond_rule_past_the_frozen_gate() {
    let w = kes_world(8700);
    let b = [(1, Sig::Proper), (2, Sig::Proper), (3, Sig::Proper)];
    assert!(matches!(run(&build(&w, &b, false, true)).unwrap_err(), Refusal::FinalitySet(_)));
}

/// The fold of an epoch runs at its closing boundary, so the set source of the
/// gate epoch's last block commits no set yet. That block must still prove its
/// leaf; only then, and only there, the bond rule applies.
#[test]
fn only_the_gate_epochs_set_source_may_prove_a_leaf_without_a_set() {
    let voters: Vec<(u32, Sig)> = (0..4).map(|v| (v, Sig::StaticV1)).collect();
    let gate = params::HF1_FROZEN_FINALITY_SET_EPOCH;
    let world = |epoch| {
        let mut w = kes_world(epoch);
        w.kes = vec![];
        w.enforced = None;
        w
    };
    // Set source's block in the last pre-gate epoch: the leaf is optional.
    assert_eq!(run(&build(&world(gate + 1), &voters, false, false)).unwrap().weights, Weights::Bond);
    // In the gate epoch: omission is refused, a proven set-less leaf is bond.
    let mut w = world(gate + 2);
    assert!(matches!(run(&build(&w, &voters, false, false)).unwrap_err(), Refusal::FinalitySet(_)));
    w.no_set_in_leaf = true;
    assert_eq!(run(&build(&w, &voters, true, false)).unwrap().weights, Weights::Bond);
    // Past it, a state with no set is not a state of this chain.
    let mut w = world(gate + 3);
    w.no_set_in_leaf = true;
    assert!(matches!(run(&build(&w, &voters, true, false)).unwrap_err(), Refusal::FinalitySet(_)));
}

#[test]
fn a_pending_handoff_set_must_also_be_reached() {
    let mut w = kes_world(8700);
    w.pending = Some(vec![(0, 10), (1, 10), (2, 40), (3, 40)]);
    let voters = [(0, Sig::Proper), (1, Sig::Proper), (2, Sig::Proper)];
    // current: 90 % ; pending: 60 %.
    assert!(matches!(run(&build(&w, &voters, true, true)).unwrap_err(), Refusal::InsufficientWeight { .. }));
    let v = run(&build(&w, &ALL, true, true)).unwrap();
    assert_eq!(v.weights, Weights::Frozen { with_pending: true });
}

#[test]
fn a_forged_frozen_set_is_refused() {
    let mut b = build(&kes_world(8700), &ALL, true, true);
    let fs = b.proof.finality_set.as_mut().unwrap();
    let at = fs.leaf.len() - 30;
    fs.leaf[at] ^= 1;
    assert!(matches!(run(&b).unwrap_err(), Refusal::FinalitySet(_)));
}

/// Between HF2 and the KES gate: static keys, v2 bound signatures, no KES
/// proofs needed; v1 refused.
#[test]
fn between_hf2_and_kes_static_bound_votes_verify() {
    let mut w = kes_world(7300);
    w.enforced = None;
    let v = run(&build(&w, &ALL, true, false)).expect("verifies");
    assert_eq!(v.kes_votes, 0);
    let voters = [(0, Sig::StaticV1), (1, Sig::Proper), (2, Sig::Proper), (3, Sig::Proper)];
    assert_eq!(run(&build(&w, &voters, true, false)).unwrap_err(), Refusal::BadSignature(0));
}

/// Between HF1 and HF2: frozen weights, v1 signatures.
#[test]
fn between_hf1_and_hf2_v1_votes_verify_with_frozen_weights() {
    let mut w = kes_world(7200);
    w.enforced = None;
    let v = run(&build(&w, &ALL, true, false)).expect("verifies");
    assert_eq!(v.weights, Weights::Frozen { with_pending: false });
}

/// KES registered (HF3) but not yet bound: static keys still sign.
#[test]
fn registered_but_unbound_kes_keys_do_not_sign_yet() {
    let mut w = kes_world(8700);
    w.enforced = None;
    let v = run(&build(&w, &ALL, true, true)).expect("verifies");
    assert_eq!(v.kes_votes, 0);
}

#[test]
fn step_proofs_round_trip_through_their_wire_format() {
    let b = build(&kes_world(8700), &ALL, true, true);
    let bytes = b.proof.encode();
    let back = MainnetProof::decode(&bytes).expect("decodes");
    assert_eq!(back.encode(), bytes);
    assert!(run(&Built { proof: back, src_id: b.src_id }).is_ok());
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(MainnetProof::decode(&trailing).is_none());
    assert!(MainnetProof::decode(&bytes[..bytes.len() - 1]).is_none());
}

/// The released certificate verifier (`bloch-finality-verify`, the static
/// key of each registry record) cannot judge KES votes: once KES binds, a
/// certificate with only the registry is refused, while the light client
/// with the 0x22 proofs accepts the same votes. Any consumer of
/// `getfinalitycertificate` needs the KES extension before the bind.
#[test]
fn the_released_certificate_verifier_refuses_kes_votes() {
    let b = build(&kes_world(8700), &ALL, false, true);
    let anchors = bloch_finality_cert::TrustAnchors::new([b.src_id]);
    let err = bloch_finality_cert::verify(&b.proof.cert, &anchors, &bloch_finality_cert::HybridSigCheck).unwrap_err();
    // FC-6: refused by epoch before any vote is read (it used to fail on the
    // first KES signature), naming the verifier that can judge it.
    assert!(matches!(err, bloch_finality_cert::Refusal::UseLcProofVerifier { target_epoch: 8701, .. }), "{err:?}");
    assert!(run(&build(&kes_world(8700), &ALL, true, true)).is_ok());
}

/// The second step of the same finding, reached first on the calendar: from
/// HF2 votes are in the bound form, and the released check is the v1 form. A
/// bare certificate needs no extension for this, only the epoch's policy.
#[test]
fn the_released_certificate_verifier_refuses_hf2_votes_and_this_one_does_not() {
    let mut w = kes_world(params::SIG_CANONICAL_ACTIVATION_EPOCH + 10);
    w.enforced = None;
    let b = build(&w, &ALL, false, false);
    let anchors = bloch_finality_cert::TrustAnchors::new([b.src_id]);
    let err = bloch_finality_cert::verify(&b.proof.cert, &anchors, &bloch_finality_cert::HybridSigCheck).unwrap_err();
    // FC-6: HF2 is past the frozen-set gate, so the epoch ceiling refuses
    // first (it used to fail on the first bound-form signature).
    assert!(matches!(err, bloch_finality_cert::Refusal::UseLcProofVerifier { .. }), "{err:?}");
    assert!(run(&build(&w, &ALL, true, false)).is_ok(), "policy-aware");
}

/// FC-6. The bare certificate verifier counts bond weights and v1 static
/// signatures. From the frozen-set gate the chain's quorum is the frozen
/// set's, so a certificate with a link target at or past the gate is refused
/// outright, with an error naming `lc_proof::verify`; below it the bare
/// verifier still accepts, with the bond verdict `lc_proof` gives.
#[test]
fn the_bare_verifier_refuses_targets_from_the_frozen_set_gate() {
    use bloch_finality_cert::{HybridSigCheck, Refusal as Bare, TrustAnchors};
    let gate = params::HF1_FROZEN_FINALITY_SET_EPOCH;
    let voters: Vec<(u32, Sig)> = (0..4).map(|v| (v, Sig::StaticV1)).collect();
    let world = |epoch| {
        let mut w = kes_world(epoch);
        w.kes = vec![];
        w.enforced = None;
        w
    };
    let bare = |b: &Built| bloch_finality_cert::verify(&b.proof.cert, &TrustAnchors::new([b.src_id]), &HybridSigCheck);

    // Both link targets below the gate (E = gate-2, E+1 = gate-1): accepted,
    // and it is the verdict the gate-aware verifier reaches under bonds.
    let below = build(&world(gate - 2), &voters, false, false);
    let v = bare(&below).expect("below the gate the bare verifier still verifies");
    let lc = run(&below).unwrap();
    assert_eq!(lc.weights, Weights::Bond);
    assert_eq!((v.epoch, v.root, v.stake, v.votes), (lc.epoch, lc.root, lc.stake, lc.votes));

    // The finalizing link's target is the gate epoch (E = gate-1), the
    // checkpoint itself is (E = gate), and well past it: all refused, even
    // though these v1 votes would pass the bond rule.
    for e in [gate - 1, gate, gate + 1, gate + 500] {
        let b = build(&world(e), &voters, false, false);
        let err = bare(&b).unwrap_err();
        assert_eq!(err, Bare::UseLcProofVerifier { target_epoch: e + 1, gate_epoch: gate }, "E = {e}");
        let text = err.to_string();
        assert!(text.contains("bloch_finality_cert::lc_proof::verify"), "{text}");
        assert!(text.contains("bloch-finality-verify"), "{text}");
        // The chain mode refuses the same way, at the offending certificate.
        let mut anchors = TrustAnchors::new([b.src_id]);
        let chained = bloch_finality_cert::verify_chain(&[b.proof.cert.clone()], &mut anchors, &HybridSigCheck);
        assert_eq!(chained.unwrap_err(), (0, err));
    }

    // The ceiling is an epoch rule, not a verdict on the contents: a
    // malformed certificate is still reported as malformed.
    let mut b = build(&world(gate), &voters, false, false);
    b.proof.cert.links[1].target_epoch += 1;
    assert!(matches!(bare(&b).unwrap_err(), Bare::LinkShape(_)));
}

/// A voter the set source does not know, or one already out at the target,
/// weighs nothing but would refuse the whole certificate: the builder drops it.
#[test]
fn votes_the_set_source_cannot_judge_are_dropped_by_the_builder() {
    let mut b = build(&kes_world(8700), &ALL, true, true);
    let vote = b.proof.cert.links[0].votes[0].clone();
    b.proof.cert.links[0].votes.push(Vote { validator: 99, ..vote });
    assert_eq!(run(&b).unwrap_err(), Refusal::UnknownValidator(99));
    ffg::retain_provable_votes(&mut b.proof.cert);
    assert_eq!(b.proof.cert.links[0].votes.len(), ALL.len());
    assert!(run(&b).is_ok());
}

/// Real certificates, read-only from public RPCs: the tool's path gives the
/// released verifier's verdict, chaining from one anchor.
#[test]
fn real_mainnet_certificates_keep_their_verdict() {
    let load = |e: u64| {
        let path = format!("{}/tests/fixtures/mainnet-cert-e{e}.bin", env!("CARGO_MANIFEST_DIR"));
        Certificate::decode(&std::fs::read(path).unwrap()).unwrap()
    };
    let anchor: [u8; 32] = bloch_finality_cert::from_hex("b5d5118b16e97fd8ee587c600fab6fbaa949f9d7a3cca9a26b455195e66924c2")
        .unwrap()
        .try_into()
        .unwrap();
    let certs = [load(7018), load(7019)];
    let mut anchors = bloch_finality_cert::TrustAnchors::new([anchor]);
    let released = bloch_finality_cert::verify_chain(&certs, &mut anchors, &bloch_finality_cert::HybridSigCheck).unwrap();
    let proofs: Vec<MainnetProof> =
        certs.iter().map(|c| MainnetProof { cert: c.clone(), finality_set: None, kes: None }).collect();
    let mut trusted: BTreeSet<[u8; 32]> = [anchor].into_iter().collect();
    let ours = ffg::verify_chain(&proofs, &mut trusted, &Config::mainnet(), &HybridConsensusVerifier).unwrap();
    for (r, o) in released.iter().zip(&ours) {
        assert_eq!((r.epoch, r.root, r.votes, r.stake), (o.epoch, o.root, o.votes, o.stake));
        assert_eq!(o.weights, Weights::Bond);
    }
    // And through the wire format.
    let wire = MainnetProof::decode(&proofs[0].encode()).unwrap();
    assert_eq!(wire.cert, certs[0]);
    // A tampered vote is refused.
    let mut bad = proofs[0].clone();
    let v = bad.cert.links[1].votes[7].validator;
    let sig = &mut bad.cert.links[1].votes[7].signature;
    let at = sig.len() / 2;
    sig[at] ^= 1;
    let mut trusted: BTreeSet<[u8; 32]> = [anchor].into_iter().collect();
    assert_eq!(ffg::verify(&bad, &mut trusted, &Config::mainnet(), &HybridConsensusVerifier).unwrap_err(), Refusal::BadSignature(v));
}

/// With `LC_PROOF_DUMP_DIR` set, writes a post-KES proof for wire-compatibility
/// checks against the light-client crate.
#[test]
fn dump_a_post_kes_proof_when_asked() {
    let Ok(dir) = std::env::var("LC_PROOF_DUMP_DIR") else { return };
    let b = build(&kes_world(8700), &ALL, true, true);
    std::fs::write(format!("{dir}/post-kes-e8700.bin"), b.proof.encode()).unwrap();
    std::fs::write(format!("{dir}/post-kes-e8700.src"), bloch_finality_cert::to_hex(&b.src_id)).unwrap();
}

/// The bind crossing, found on a forced-KES private chain: the last checkpoint
/// before the bind has a set source that cannot commit it, yet its finalizing
/// link is KES-signed. Without the checkpoint-state rule a proof chain stops here.
#[test]
fn the_last_checkpoint_before_the_bind_verifies_from_its_own_state_root() {
    let mut w = kes_world(8700);
    w.enforced = Some(8701);
    w.bind_in_checkpoint = true;
    // The set source (epoch 8698) commits no bind and no later registration:
    // its "no KES entry" for validator 3 is not evidence for epoch 8701, so
    // that static vote is refused on the finalizing link...
    assert_eq!(run(&build(&w, &ALL, true, true)).unwrap_err(), Refusal::Kes("voter absence too old"));
    // ...and the three registered validators (90% of the weight) carry it.
    let registered = [(0, Sig::Proper), (1, Sig::Proper), (2, Sig::Proper)];
    // The builder drops it from the finalizing link only: the justifying
    // link is not bound yet, and there the static vote is the right one.
    let mut dropped = build(&w, &ALL, true, true);
    let kes = dropped.proof.kes.clone().unwrap();
    ffg::retain_fresh_static_votes(&mut dropped.proof.cert, &kes);
    assert_eq!(dropped.proof.cert.links.iter().map(|l| l.votes.len()).collect::<Vec<_>>(), [4, 3]);
    assert_eq!(run(&dropped).expect("crosses the bind").kes_votes, 3);
    let b = build(&w, &registered, true, true);
    assert_eq!(&b.proof.encode()[..8], b"BLCLMP02");
    let v = run(&b).expect("crosses the bind");
    assert_eq!(v.kes_votes, 3, "validators 0..2 sign only the finalizing link with KES leaves");
    // The justifying link still decides the checkpoint: below 2/3 it is refused.
    let few = [(2, Sig::Proper)];
    assert!(matches!(run(&build(&w, &few, true, true)).unwrap_err(), Refusal::InsufficientWeight { link: 0, .. }));
    // Without the checkpoint's proof the finalizing link has nothing to be
    // judged under: the set source's absence does not reach its target.
    w.second_proof = false;
    assert_eq!(
        run(&build(&w, &registered, true, true)).unwrap_err(),
        Refusal::Kes("bind absence too old for this target")
    );
    // The checkpoint's state may not stand in for the set source's: a bind
    // offered in the first slot must be committed by the set source.
    w.second_proof = true;
    let mut legacy = build(&w, &registered, true, true);
    let k = legacy.proof.kes.as_mut().unwrap();
    k.enforced = k.enforced_at_checkpoint.take().unwrap();
    assert_eq!(run(&legacy).unwrap_err(), Refusal::Kes("bind epoch not proven"));
    // Nor may it sit beside a bind the set source does commit.
    let mut both = build(&kes_world(8700), &ALL, true, true);
    let spare = build(&w, &registered, true, true).proof.kes.unwrap().enforced_at_checkpoint;
    both.proof.kes.as_mut().unwrap().enforced_at_checkpoint = spare;
    assert_eq!(
        run(&both).unwrap_err(),
        Refusal::Kes("checkpoint bind proof beside a bind at the set source")
    );
}

// ── Security review round 2, CRY-2 / FC-5: KES freshness ────────────────────

/// The attack the rule exists for: the chain bound KES at B, and a holder of
/// old static keys shows a set source from before the bind decision, whose
/// "no bind" is true, to have a target past B judged under static keys.
#[test]
fn an_old_bind_absence_does_not_reach_a_target_past_the_delay() {
    let bind = params::HF3_KES_ENFORCE_EPOCH;
    // Target B+5, set source at B-10: every vote is static, as a forger's
    // would be, and every proof in it is genuine.
    let mut forged = kes_world(bind + 5);
    forged.enforced = None;
    forged.src_gap = 15;
    for second_proof in [true, false] {
        forged.second_proof = second_proof;
        assert_eq!(
            run(&build(&forged, &ALL, true, true)).unwrap_err(),
            Refusal::Kes("bind absence too old for this target")
        );
    }
    // The distance itself is not the problem: before the KES gate the same
    // hop verifies, as it always did.
    let mut early = kes_world(params::KES_ACTIVATION_EPOCH - 20);
    early.enforced = None;
    early.src_gap = 15;
    let v = run(&build(&early, &ALL, true, true)).expect("static epochs keep the long hop");
    assert_eq!(v.kes_votes, 0);
    // The same target from a set source that commits the bind verifies,
    // under KES, near or far.
    for src_gap in [2, 3] {
        let mut w = kes_world(bind + 5);
        w.src_gap = src_gap;
        let v = run(&build(&w, &ALL, true, true)).expect("bind committed by the set source");
        assert_eq!(v.kes_votes, 6);
    }
    // One epoch further than the delay covers is already refused.
    let mut edge = kes_world(bind + 5);
    edge.enforced = None;
    edge.src_gap = 3;
    assert_eq!(
        run(&build(&edge, &ALL, true, true)).unwrap_err(),
        Refusal::Kes("bind absence too old for this target")
    );
}

/// While the chain has not bound, a step is still possible: the justifying
/// link is within the delay of the set source, and the finalizing link takes
/// the (absent) bind from the checkpoint's own state.
#[test]
fn before_the_bind_a_step_needs_the_checkpoints_own_absence_proof() {
    let mut w = kes_world(8700);
    w.enforced = None;
    let b = build(&w, &ALL, true, true);
    assert!(b.proof.kes.as_ref().unwrap().enforced_at_checkpoint.is_some());
    assert_eq!(run(&b).expect("verifies").kes_votes, 0);
    w.second_proof = false;
    assert_eq!(
        run(&build(&w, &ALL, true, true)).unwrap_err(),
        Refusal::Kes("bind absence too old for this target")
    );
    // A second proof that the checkpoint's state does not commit is refused.
    w.second_proof = true;
    let mut wrong = build(&w, &ALL, true, true);
    wrong.proof.kes.as_mut().unwrap().enforced_at_checkpoint.as_mut().unwrap().0 = Some(8_750);
    assert_eq!(run(&wrong).unwrap_err(), Refusal::Kes("checkpoint bind epoch not proven"));
}

/// A voter with no KES entry at the set source may have registered since.
/// Its static vote counts only while the set source is itself bound and in
/// the target's KES period.
#[test]
fn a_voters_absence_at_the_set_source_must_be_fresh() {
    let period = params::KES_PERIOD_EPOCHS;
    let start = params::KES_ACTIVATION_EPOCH;
    let registered = [(0, Sig::Proper), (1, Sig::Proper), (2, Sig::Proper)];
    // Bound set source, same period: validator 3 (never registered) signs
    // with its static key, as on chain.
    assert_eq!(run(&build(&kes_world(start + 40), &ALL, true, true)).expect("fresh absence").kes_votes, 6);

    // The bind is committed by the set source but starts after it: a
    // validator absent there may have registered before the bind and would
    // sign with KES from the bind on.
    let mut w = kes_world(start + 40);
    w.enforced = Some(start + 39);
    assert_eq!(run(&build(&w, &ALL, true, true)).unwrap_err(), Refusal::Kes("voter absence too old"));
    // The same certificate without that vote verifies: the quorum holds.
    assert_eq!(run(&build(&w, &registered, true, true)).expect("without the stale vote").kes_votes, 6);
    // The builder drops exactly that vote, on both links, and nothing when
    // the absence is fresh.
    let mut stale = build(&w, &ALL, true, true);
    let kes = stale.proof.kes.clone().unwrap();
    ffg::retain_fresh_static_votes(&mut stale.proof.cert, &kes);
    for link in &stale.proof.cert.links {
        assert_eq!(link.votes.iter().map(|v| v.validator).collect::<Vec<_>>(), [0, 1, 2]);
    }
    assert_eq!(run(&stale).expect("after the builder dropped it").kes_votes, 6);
    let mut fresh = build(&kes_world(start + 40), &ALL, true, true);
    let kes = fresh.proof.kes.clone().unwrap();
    ffg::retain_fresh_static_votes(&mut fresh.proof.cert, &kes);
    assert!(fresh.proof.cert.links.iter().all(|l| l.votes.len() == 4));

    // Another KES period than the set source's: a registration made after
    // the set source is in force by then. (Nobody is registered here, so
    // every vote is static and the fixture needs no second-period leaf.)
    let mut unregistered = kes_world(start + period);
    unregistered.kes = vec![];
    assert_eq!(
        run(&build(&unregistered, &ALL, true, true)).unwrap_err(),
        Refusal::Kes("voter absence too old")
    );
    unregistered.epoch = start + period - 2;
    assert_eq!(run(&build(&unregistered, &ALL, true, true)).expect("same period").kes_votes, 0);
}

/// Three steps, each standing on the one before; afterwards only the newest
/// checkpoint is trusted, so an older root cannot be a set source again and
/// a client cannot be stepped backwards.
#[test]
fn a_chain_keeps_only_its_newest_checkpoint_as_a_set_source() {
    let cfg = Config::mainnet();
    let first = build(&kes_world(8700), &ALL, true, true);
    let second = build_on(&kes_world(8701), &ALL, true, true, Some(first.proof.cert.checkpoint_header));
    let third = build_on(&kes_world(8702), &ALL, true, true, Some(second.proof.cert.checkpoint_header));
    let fourth = build_on(&kes_world(8703), &ALL, true, true, Some(third.proof.cert.checkpoint_header));
    let root = |b: &Built| b.proof.cert.links[0].target_root;

    let mut trusted: BTreeSet<[u8; 32]> = [first.src_id].into_iter().collect();
    let steps = [first.proof.clone(), second.proof.clone(), third.proof.clone()];
    let verified = ffg::verify_chain(&steps, &mut trusted, &cfg, &HybridConsensusVerifier).expect("three steps");
    assert_eq!(verified.iter().map(|v| v.epoch).collect::<Vec<_>>(), [8700, 8701, 8702]);
    assert_eq!(trusted, [root(&third)].into_iter().collect());

    // A fourth proof whose set source is the first root: no longer trusted.
    let stale = [second.proof.clone()];
    assert_eq!(
        ffg::verify_chain(&stale, &mut trusted, &cfg, &HybridConsensusVerifier).unwrap_err(),
        (0, Refusal::UntrustedSetSource)
    );
    assert_eq!(trusted, [root(&third)].into_iter().collect(), "a refusal leaves the trusted set alone");
    // The genuine next step still verifies.
    let next = ffg::verify_next(&fourth.proof, &mut trusted, Some(8702), &cfg, &HybridConsensusVerifier).unwrap();
    assert_eq!((next.epoch, trusted.len()), (8703, 1));

    // A caller that manages its own set gets the same rule from the same
    // function: a target at or before the checkpoint it stands on is refused
    // even if an old root is still in the set.
    let mut wide: BTreeSet<[u8; 32]> = [first.src_id, root(&first), root(&second)].into_iter().collect();
    let before = wide.clone();
    assert_eq!(
        ffg::verify_next(&second.proof, &mut wide, Some(8701), &cfg, &HybridConsensusVerifier).unwrap_err(),
        Refusal::Shape("target not after the trusted checkpoint")
    );
    assert_eq!(wide, before);
    ffg::verify_next(&third.proof, &mut wide, Some(8701), &cfg, &HybridConsensusVerifier).unwrap();
    assert_eq!(wide, [root(&third)].into_iter().collect());
}

/// The wire format: a proof without the second bind proof is `BLCLMP01`,
/// byte for byte as before; with it, `BLCLMP02`; and neither magic decodes
/// the other's body.
#[test]
fn the_second_bind_proof_has_its_own_wire_version() {
    // Before the KES gate: no second proof, the released encoding.
    let mut early = kes_world(params::SIG_CANONICAL_ACTIVATION_EPOCH + 10);
    early.enforced = None;
    let b = build(&early, &ALL, true, true);
    let bytes = b.proof.encode();
    assert_eq!(&bytes[..8], b"BLCLMP01");
    let back = MainnetProof::decode(&bytes).expect("decodes");
    assert!(back.kes.as_ref().unwrap().enforced_at_checkpoint.is_none());
    assert_eq!(back.encode(), bytes);
    assert!(run(&Built { proof: back, src_id: b.src_id }).is_ok());

    // With the second proof.
    let mut w = kes_world(8700);
    w.enforced = None;
    let b = build(&w, &ALL, true, true);
    let bytes = b.proof.encode();
    assert_eq!(&bytes[..8], b"BLCLMP02");
    let back = MainnetProof::decode(&bytes).expect("decodes");
    assert_eq!(back.kes, b.proof.kes);
    assert_eq!(back.encode(), bytes);
    assert!(run(&Built { proof: back, src_id: b.src_id }).is_ok());
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(MainnetProof::decode(&trailing).is_none());
    assert!(MainnetProof::decode(&bytes[..bytes.len() - 1]).is_none());

    // One proof, one encoding.
    let mut relabelled = bytes.clone();
    relabelled[..8].copy_from_slice(b"BLCLMP01");
    assert!(MainnetProof::decode(&relabelled).is_none(), "01 never carries the second proof");
    w.second_proof = false;
    let mut plain = build(&w, &ALL, true, true).proof.encode();
    assert_eq!(&plain[..8], b"BLCLMP01");
    plain[..8].copy_from_slice(b"BLCLMP02");
    assert!(MainnetProof::decode(&plain).is_none(), "02 always carries it");
}
