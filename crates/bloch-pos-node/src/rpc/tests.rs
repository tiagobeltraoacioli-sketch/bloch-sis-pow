// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tests for the JSON-RPC surface.
//!
//! Three layers, tested where each one actually lives:
//!
//! 1. **Formatting** — free functions over a real `CommittedState` built here,
//!    with no node, no threads and no sockets. This is where "does `getbalance`
//!    read the eUTXO set" is answered.
//! 2. **Routing and the JSON-RPC envelope** — `handle_body` against a stub
//!    backend that records what it was asked. This is where "does the wire
//!    contract hold" is answered, including every malformed-input path.
//! 3. **HTTP** — one real TCP round trip against a real listener.
//!
//! What is *not* covered is stated in the report rather than implied here: the
//! engine's own `serve_rpc` lookups (which block is at which slot, what height
//! a block has) need a running engine, and standing one up requires a
//! keystore, a genesis manifest and a mesh listener.

use super::*;
use bloch_pos_committee::attestation::{Attestation, AttestationData};
use bloch_pos_committee::header::{BlockHeaderV4, Body, VERSION_G4};
use bloch_pos_committee::state_root::{EutxoEntry, EvmCommitment};
use bloch_pos_committee::transition::GenesisValidator;

// ─── Fixtures ───────────────────────────────────────────────────────────────

fn entry(txid: u8, vout: u32, value: u64, script: u8) -> EutxoEntry {
    EutxoEntry { txid: [txid; 32], vout, value, script_hash: [script; 32] }
}

/// A committed genesis state with two validators and four outputs across two
/// script hashes.
///
/// The values are deliberately enormous: `18_000_000_000_000_000_000` is above
/// `u64::MAX / 2`, so any code that sums balances in `u64` overflows on this
/// fixture instead of on mainnet.
fn state_with_balances() -> CommittedState {
    let validators = vec![
        GenesisValidator {
            index: 0,
            pubkey: vec![0xAA; 64],
            staked_sat: 200_000 * 100_000_000,
            randao_commitment: [1u8; 32],
            withdrawal_credentials: vec![],
            commission_bps: 500,
        },
        GenesisValidator {
            index: 1,
            pubkey: vec![0xBB; 64],
            staked_sat: 400_000 * 100_000_000,
            randao_commitment: [2u8; 32],
            withdrawal_credentials: vec![],
            commission_bps: 1_250,
        },
    ];
    let balances = vec![
        entry(0x11, 0, 9_000_000_000_000_000_000, 0xAB),
        entry(0x11, 1, 9_000_000_000_000_000_000, 0xAB),
        entry(0x22, 0, 500, 0xAB),
        entry(0x33, 7, 12_345, 0xCD),
    ];
    CommittedState::genesis(
        BlockId::of(&genesis_header()),
        [9u8; 32],
        &validators,
        &[0],
        [0u8; 32],
        [0u8; 32],
        [0u8; 32],
        EvmCommitment {
            account_root: [0u8; 32],
            receipts_root: [0u8; 32],
            gas_used: 0,
            base_fee_per_gas: 0,
        },
        &balances,
    )
}

fn genesis_header() -> BlockHeaderV4 {
    BlockHeaderV4 {
        version: VERSION_G4,
        parent: [0u8; 32],
        state_root: [0u8; 32],
        body_root: [0u8; 32],
        slot: 0,
        proposer_index: 0,
        randao_reveal: [0u8; 32],
        randao_mix: [9u8; 32],
        justified_root: [0u8; 32],
        finalized_root: [0u8; 32],
        attestation_root: [0u8; 32],
        coherence_root: [0u8; 32],
    }
}

fn sample_block(slot: u64, txs: usize) -> BlockEnvelope {
    let header = BlockHeaderV4 {
        version: VERSION_G4,
        parent: [7u8; 32],
        state_root: [8u8; 32],
        body_root: [9u8; 32],
        slot,
        proposer_index: 3,
        randao_reveal: [0xA1; 32],
        randao_mix: [0xA2; 32],
        justified_root: [0xA3; 32],
        finalized_root: [0xA4; 32],
        attestation_root: [0xA5; 32],
        coherence_root: [0xA6; 32],
    };
    let attestations = vec![Attestation {
        validator: 1,
        data: AttestationData {
            slot,
            head: [7u8; 32],
            source_epoch: 0,
            source_root: [0u8; 32],
            target_epoch: 1,
            target_root: [7u8; 32],
        },
        signature: vec![0u8; 8],
    }];
    let transactions = (0..txs)
        .map(|i| {
            test_transfer(1, 250 + i as u64, 1_000).canonical_bytes()
        })
        .collect();
    BlockEnvelope { header, proposer_sig: vec![0u8; 4], body: Body { transactions, attestations } }
}

/// A backend that records the request and answers with a marker, so a routing
/// test can assert what the dispatcher decoded without any node behind it.
struct Spy {
    seen: Mutex<Vec<RpcRequest>>,
    answer: RpcResult,
}

impl Spy {
    fn new() -> Arc<Self> {
        Arc::new(Spy { seen: Mutex::new(Vec::new()), answer: Ok(Json::s("ok")) })
    }
    fn failing(err: RpcError) -> Arc<Self> {
        Arc::new(Spy { seen: Mutex::new(Vec::new()), answer: Err(err) })
    }
    fn last(&self) -> Option<RpcRequest> {
        self.seen.lock().unwrap().last().cloned()
    }
}

impl RpcBackend for Spy {
    fn call(&self, req: RpcRequest) -> RpcResult {
        self.seen.lock().unwrap().push(req);
        self.answer.clone()
    }
}

/// Send a body through the dispatcher and parse the response back into `Json`.
fn call(backend: &dyn RpcBackend, body: &str) -> Json {
    let text = handle_body(body, backend);
    parse_json(&text).expect("every response this module emits must be valid JSON")
}

fn request(method: &str, params: &str) -> String {
    format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":{params}}}"#)
}

fn error_code(v: &Json) -> Option<i64> {
    v.get("error")?.get("code")?.as_u64().map(|u| u as i64).or_else(|| {
        match v.get("error")?.get("code")? {
            Json::Num(raw) => raw.parse().ok(),
            _ => None,
        }
    })
}

// ─── 1. Formatting, over real committed state ───────────────────────────────


/// A transfer in the shape the consensus layer now takes: real spend points
/// and real outputs, not the gas terms the variant carried before value
/// moved. These tests exercise the RPC's framing of a transaction, not its
/// validity, so the witness bytes are placeholders — nothing here submits to
/// a state transition.
fn test_transfer(inputs: u32, tx_bytes: u64, tip: u128) -> PosTransaction {
    PosTransaction::Transfer {
        inputs: (0..inputs)
            .map(|i| bloch_pos_committee::transition::TransferInput {
                txid: [i as u8; 32],
                vout: i,
                pubkey: vec![0xAB; 8],
                signature: vec![0xCD; 8],
            })
            .collect(),
        outputs: vec![bloch_pos_committee::transition::TransferOutput {
            value: 1_000,
            script_hash: [0xEE; 32],
        }],
        tx_bytes,
        tip_millisat_per_gas: tip,
    }
}

#[test]
fn getchaininfo_reports_slot_epoch_head_root_and_both_checkpoints() {
    let st = state_with_balances();
    let head = st.head();
    // Handed in, as `Engine::head_state_root` hands it in — and pinned below
    // against `st.state_root()`, so this test still fails if the field ever
    // stops being the committed root of the state the rest of the object
    // describes.
    // A wall slot of 12 with the head at slot 0: behind by 12, which is
    // inside the normal cadence gap — the health verdict must say so.
    let health = Health::assess(12, 0, 3_000, 30_000);
    let v = chain_info_json(&st, &head, st.state_root(), 0, Some(0), 12, &health, 2, 3, 0);

    assert_eq!(v.get("slot").unwrap().as_u64(), Some(0));
    assert_eq!(v.get("epoch").unwrap().as_u64(), Some(0));
    assert_eq!(v.get("slot_in_epoch").unwrap().as_u64(), Some(0));
    assert_eq!(v.get("block_id").unwrap().as_str(), Some(crate::codec::hex32(head.as_bytes()).as_str()));
    assert_eq!(
        v.get("state_root").unwrap().as_str(),
        Some(crate::codec::hex32(&st.state_root()).as_str())
    );

    // Genesis is justified and finalized by definition — finality needs a root
    // of trust, and epoch 0's checkpoint is it.
    assert_eq!(v.get("justified").unwrap().get("epoch").unwrap().as_u64(), Some(0));
    assert_eq!(v.get("finalized").unwrap().get("epoch").unwrap().as_u64(), Some(0));
    assert_eq!(
        v.get("finalized").unwrap().get("root").unwrap().as_str(),
        Some(crate::codec::hex32(head.as_bytes()).as_str())
    );

    assert_eq!(v.get("validators").unwrap().get("total").unwrap().as_u64(), Some(2));
    assert_eq!(v.get("wall_slot").unwrap().as_u64(), Some(12));
    assert_eq!(v.get("behind_by_slots").unwrap().as_u64(), Some(12));
    assert_eq!(v.get("mempool").unwrap().as_u64(), Some(3));

    // The health object rides along, field for field, and this near-head
    // node reads as neither syncing nor stalled.
    let h = v.get("health").unwrap();
    assert_eq!(h.get("behind_by_slots").unwrap().as_u64(), Some(12));
    assert_eq!(h.get("secs_since_last_block").unwrap().as_u64(), Some(3));
    assert_eq!(h.get("syncing").unwrap().as_bool(), Some(false));
    assert_eq!(h.get("stalled").unwrap().as_bool(), Some(false));
}

// ─── The liveness verdict ───────────────────────────────────────────────────
//
// `Health::assess` is the one place the "am I making progress" judgement is
// made — `getchaininfo` and the slot loop's periodic line both read it — so
// these cases ARE the defended behaviour of the post-replay stall's safety
// net. Slot cadence in all of them is the production 30s.

const SLOT_MS: u64 = 30_000;

/// The measured incident, as a test: ~480 slots behind, nothing applied for
/// minutes, RPC answering. The verdict must be STALLED — this is the node
/// that used to look like an ordinary laggard.
#[test]
fn far_behind_and_silent_is_stalled() {
    let h = Health::assess(50_010, 49_530, 5 * 60 * 1_000, SLOT_MS);
    assert_eq!(h.behind_by_slots, 480);
    assert!(h.stalled, "480 behind with five minutes of apply-silence is a stall");
    assert!(!h.syncing, "stalled and syncing are mutually exclusive verdicts");
}

/// The same lag while blocks are being applied is a node CATCHING UP — the
/// recovery path the 90–130-slot laggards took — and must not alarm.
#[test]
fn far_behind_but_applying_is_syncing_not_stalled() {
    let h = Health::assess(50_010, 49_530, 2_000, SLOT_MS);
    assert!(h.syncing);
    assert!(!h.stalled, "a node applying blocks two seconds ago is progressing");
}

/// A healthy node between blocks on a sparse chain: a dozen empty slots and
/// six minutes since the last block are ORDINARY on a 13%-cadence chain, and
/// must raise nothing — silence alone is not a stall.
#[test]
fn ordinary_cadence_gaps_are_healthy() {
    let h = Health::assess(1_012, 1_000, 6 * 60 * 1_000, SLOT_MS);
    assert!(!h.syncing);
    assert!(!h.stalled, "behind by less than HEALTH_BEHIND_SLOTS is never a stall");
}

/// The thresholds are the contract integrators alert on; pin the boundary on
/// both sides so a casual retune shows up as a failing test.
#[test]
fn the_stall_boundary_sits_exactly_at_the_documented_thresholds() {
    let silence = HEALTH_SILENCE_SLOTS * SLOT_MS;
    // One slot / one millisecond inside the line: not stalled.
    assert!(!Health::assess(HEALTH_BEHIND_SLOTS - 1 + 100, 100, silence, SLOT_MS).stalled);
    assert!(!Health::assess(HEALTH_BEHIND_SLOTS + 100, 100, silence - 1, SLOT_MS).stalled);
    // At the line on both axes: stalled.
    assert!(Health::assess(HEALTH_BEHIND_SLOTS + 100, 100, silence, SLOT_MS).stalled);
}

/// A wall clock behind the head (clock skew, or a freshly proposed block in
/// the current slot) must saturate to zero, never wrap.
#[test]
fn a_head_ahead_of_the_wall_clock_is_zero_behind() {
    let h = Health::assess(99, 100, 0, SLOT_MS);
    assert_eq!(h.behind_by_slots, 0);
    assert!(!h.syncing && !h.stalled);
}

/// A zero `slot_ms` from a hand-edited manifest must not panic the health
/// check (the same guard `Engine::wall_slot` carries for its division).
#[test]
fn a_zero_slot_ms_manifest_does_not_panic_the_verdict() {
    let h = Health::assess(1_000, 0, 1_000, 0);
    assert!(h.stalled || h.syncing); // behind either way; no panic is the point
}

#[test]
fn getblockbyslot_and_getblockbyid_share_one_block_shape() {
    let env = sample_block(41_290, 2);
    let v = block_json(&env, Some(41_230), Finality::Finalized, 1_790_000_000);

    assert_eq!(
        v.get("block_id").unwrap().as_str(),
        Some(crate::codec::hex32(env.block_id().as_bytes()).as_str())
    );
    assert_eq!(v.get("slot").unwrap().as_u64(), Some(41_290));
    // 41290 / 32 = 1290 — the epoch is derived, never carried in the header.
    assert_eq!(v.get("epoch").unwrap().as_u64(), Some(1_290));
    assert_eq!(v.get("height").unwrap().as_u64(), Some(41_230));
    assert_eq!(v.get("proposer_index").unwrap().as_u64(), Some(3));
    assert_eq!(v.get("tx_count").unwrap().as_u64(), Some(2));
    assert_eq!(v.get("attestation_count").unwrap().as_u64(), Some(1));
    assert_eq!(v.get("timestamp").unwrap().as_u64(), Some(1_790_000_000));

    // Every commitment in the header is exposed, so a client can verify the
    // block id itself rather than trusting this node's arithmetic.
    for field in [
        "parent",
        "state_root",
        "body_root",
        "randao_reveal",
        "randao_mix",
        "justified_root",
        "finalized_root",
        "attestation_root",
        "coherence_root",
    ] {
        assert!(
            matches!(v.get(field), Some(Json::Str(s)) if s.len() == 64),
            "{field} must be 32 bytes of hex"
        );
    }

    // A block off the canonical chain has no height, and says so with null
    // rather than with a plausible number.
    let orphan = block_json(&env, None, Finality::NotCanonical, 0);
    assert_eq!(orphan.get("height"), Some(&Json::Null));
    assert_eq!(orphan.get("finality").unwrap().as_str(), Some("not_canonical"));
}

/// The field an exchange credits a deposit on. Under PoS the guarantee is
/// Casper finalisation, not depth, so exactly one of the four states may report
/// `finalized: true`.
#[test]
fn only_a_finalized_block_reports_finalized_true() {
    let env = sample_block(100, 0);
    let cases = [
        (Finality::Finalized, "finalized", true),
        (Finality::Justified, "justified", false),
        (Finality::Canonical, "canonical", false),
        (Finality::NotCanonical, "not_canonical", false),
    ];
    for (f, label, expect_final) in cases {
        let v = block_json(&env, Some(1), f, 0);
        assert_eq!(v.get("finality").unwrap().as_str(), Some(label));
        assert_eq!(
            v.get("finalized"),
            Some(&Json::Bool(expect_final)),
            "{label}: `finalized` must be true only for a finalized block — an \
             integrator branches a deposit credit on this boolean"
        );
        assert_eq!(f.is_final(), expect_final);
    }
}

#[test]
fn getblockcount_carries_the_finalized_height_beside_the_head() {
    let v = block_count_json(41_230, 41_290, Some(41_100), 1_289, 1_288);
    assert_eq!(v.get("height").unwrap().as_u64(), Some(41_230));
    assert_eq!(v.get("slot").unwrap().as_u64(), Some(41_290));
    assert_eq!(v.get("epoch").unwrap().as_u64(), Some(1_290));
    assert_eq!(v.get("finalized_height").unwrap().as_u64(), Some(41_100));
    assert_eq!(v.get("justified_epoch").unwrap().as_u64(), Some(1_289));
    assert_eq!(v.get("finalized_epoch").unwrap().as_u64(), Some(1_288));
}

#[test]
fn getvalidator_reports_the_record_with_commission_and_lifecycle() {
    let st = state_with_balances();
    let rec = st.validator_record(1).expect("validator 1 is in the genesis registry");
    let effective =
        st.active_validators().iter().find(|v| v.index == 1).map(|v| v.effective_stake);
    let v = validator_json(&rec, effective, 0);

    assert_eq!(v.get("index").unwrap().as_u64(), Some(1));
    assert_eq!(v.get("state").unwrap().as_str(), Some("active"));
    assert_eq!(v.get("own_stake_sat").unwrap().as_str(), Some("40000000000000"));
    // R5: the rate rides on the response, because tokenomics leaves commission
    // uncapped on the bet that clients show it.
    assert_eq!(v.get("commission_bps").unwrap().as_str(), Some("1250"));
    assert_eq!(v.get("slashed"), Some(&Json::Bool(false)));
    assert_eq!(v.get("activation_epoch").unwrap().as_u64(), Some(0));
    // Never-scheduled epochs are null, not u64::MAX leaking onto the wire.
    assert_eq!(v.get("exit_epoch"), Some(&Json::Null));
    assert_eq!(v.get("withdrawable_epoch"), Some(&Json::Null));
    assert!(v.get("effective_stake_sat").unwrap().as_str().is_some());
}

#[test]
fn validator_state_orders_slashed_above_every_other_condition() {
    let st = state_with_balances();
    let base = st.validator_record(0).unwrap();

    let mut slashed_and_exiting = base.clone();
    slashed_and_exiting.slashed = true;
    slashed_and_exiting.exit_epoch = 5;
    assert_eq!(
        validator_state(&slashed_and_exiting, 0),
        "slashed",
        "a slashed validator must never be displayed as merely exiting"
    );

    let mut exiting = base.clone();
    exiting.exit_epoch = 5;
    assert_eq!(validator_state(&exiting, 0), "exiting");
    assert_eq!(validator_state(&exiting, 5), "exited");

    let mut queued = base.clone();
    queued.activation_epoch = 9;
    assert_eq!(validator_state(&queued, 0), "queued");
    assert_eq!(validator_state(&queued, 9), "active");
}

#[test]
fn getvalidator_count_matches_the_committed_registry() {
    let st = state_with_balances();
    assert_eq!(st.validator_count(), 2);
    assert_eq!(st.active_validators().len(), 2);
}

#[test]
fn getbalance_sums_the_eutxo_set_for_one_script_hash() {
    let st = state_with_balances();
    let v = balance_json(&st, &[0xAB; 32]);

    // 9e18 + 9e18 + 500 — a sum that wraps u64 and does not wrap u128.
    assert_eq!(v.get("balance_sat").unwrap().as_str(), Some("18000000000000000500"));
    assert_eq!(v.get("utxo_count").unwrap().as_u64(), Some(3));

    let other = balance_json(&st, &[0xCD; 32]);
    assert_eq!(other.get("balance_sat").unwrap().as_str(), Some("12345"));

    // An address with nothing is a zero balance, not an error: an exchange
    // polling a fresh deposit address must not have to treat "no outputs yet"
    // as a failure.
    let empty = balance_json(&st, &[0xEE; 32]);
    assert_eq!(empty.get("balance_sat").unwrap().as_str(), Some("0"));
    assert_eq!(empty.get("utxo_count").unwrap().as_u64(), Some(0));
}

/// The reason `balance_sat` is `u128` and the wire form is a string. This
/// balance is 1,997x JavaScript's exact-integer limit; as a JSON number it
/// would be silently wrong in every browser that read it.
#[test]
fn amounts_are_decimal_strings_not_json_numbers() {
    let st = state_with_balances();
    let v = balance_json(&st, &[0xAB; 32]);
    let raw = v.to_string();

    assert!(
        raw.contains(r#""balance_sat":"18000000000000000500""#),
        "R3: satoshi amounts must be quoted decimal strings — got {raw}"
    );
    match v.get("balance_sat") {
        Some(Json::Str(s)) => {
            assert_eq!(s.parse::<u128>().unwrap(), 18_000_000_000_000_000_500);
            assert!(18_000_000_000_000_000_500u128 > 9_007_199_254_740_991);
        }
        other => panic!("balance_sat must be a JSON string, got {other:?}"),
    }

    // The same rule holds for every satoshi field, not only the large ones —
    // "strings once they get big" is a latent bug in every client.
    let u = utxos_json(&st, &[0xCD; 32], 10);
    let first = u.get("utxos").unwrap().at(0).unwrap();
    assert!(matches!(first.get("value_sat"), Some(Json::Str(s)) if s == "12345"));
}

#[test]
fn getutxos_lists_the_outputs_and_reports_truncation() {
    let st = state_with_balances();
    let v = utxos_json(&st, &[0xAB; 32], 10);
    assert_eq!(v.get("total").unwrap().as_u64(), Some(3));
    assert_eq!(v.get("returned").unwrap().as_u64(), Some(3));
    assert_eq!(v.get("truncated"), Some(&Json::Bool(false)));

    let entries = match v.get("utxos") {
        Some(Json::Arr(a)) => a.clone(),
        other => panic!("utxos must be an array, got {other:?}"),
    };
    assert_eq!(entries.len(), 3);
    // Every returned output belongs to the requested script hash.
    for e in &entries {
        assert_eq!(e.get("script_hash").unwrap().as_str(), Some(crate::codec::hex32(&[0xAB; 32]).as_str()));
        assert!(e.get("txid").is_some() && e.get("vout").is_some());
    }

    // A short page says it was cut rather than pretending it was the whole set.
    let page = utxos_json(&st, &[0xAB; 32], 2);
    assert_eq!(page.get("total").unwrap().as_u64(), Some(3));
    assert_eq!(page.get("returned").unwrap().as_u64(), Some(2));
    assert_eq!(page.get("truncated"), Some(&Json::Bool(true)));
}

#[test]
fn getmempoolinfo_reports_size_capacity_and_the_next_price() {
    let v = mempool_info_json(7, 4_096, 1_750, 1_000);
    assert_eq!(v.get("size").unwrap().as_u64(), Some(7));
    assert_eq!(v.get("max").unwrap().as_u64(), Some(4_096));
    assert_eq!(v.get("bytes").unwrap().as_u64(), Some(1_750));
    assert_eq!(v.get("next_base_fee_millisat_per_gas").unwrap().as_str(), Some("1000"));
}

#[test]
fn sendrawtransaction_reply_names_the_kind_and_disclaims_the_hash() {
    let tx = test_transfer(2, 400, 5);
    let v = submitted_json(&tx, Admitted::New);
    assert_eq!(v.get("accepted"), Some(&Json::Bool(true)));
    assert_eq!(v.get("status").unwrap().as_str(), Some("accepted"));
    assert_eq!(v.get("kind").unwrap().as_str(), Some("transfer"));
    assert_eq!(v.get("bytes").unwrap().as_u64(), Some(tx.canonical_bytes().len() as u64));
    assert!(matches!(v.get("tx_hash"), Some(Json::Str(s)) if s.len() == 64));
    // The handle must not be mistaken for a consensus txid — there is none.
    assert!(v.get("tx_hash_note").unwrap().as_str().unwrap().contains("not a consensus"));

    let dup = submitted_json(&tx, Admitted::Duplicate);
    assert_eq!(dup.get("status").unwrap().as_str(), Some("duplicate"));
    assert_eq!(dup.get("accepted"), Some(&Json::Bool(true)));
}

// ─── 2. Routing and the JSON-RPC envelope ───────────────────────────────────

#[test]
fn every_method_routes_to_its_request() {
    let spy = Spy::new();
    let b = spy.as_ref();
    let script = "ab".repeat(32);

    call(b, &request("getchaininfo", "[]"));
    assert_eq!(spy.last(), Some(RpcRequest::ChainInfo));

    call(b, &request("getblockcount", "[]"));
    assert_eq!(spy.last(), Some(RpcRequest::BlockCount));

    call(b, &request("getblockbyslot", "[41290]"));
    assert_eq!(spy.last(), Some(RpcRequest::BlockBySlot(41_290)));

    call(b, &request("getblockbyid", &format!("[\"{}\"]", "cd".repeat(32))));
    assert_eq!(spy.last(), Some(RpcRequest::BlockById([0xCD; 32])));

    call(b, &request("getvalidator", "[7]"));
    assert_eq!(spy.last(), Some(RpcRequest::Validator(7)));

    call(b, &request("getvalidatorcount", "[]"));
    assert_eq!(spy.last(), Some(RpcRequest::ValidatorCount));

    call(b, &request("getbalance", &format!("[\"{script}\"]")));
    assert_eq!(spy.last(), Some(RpcRequest::Balance([0xAB; 32])));

    call(b, &request("getutxos", &format!("[\"{script}\"]")));
    assert_eq!(
        spy.last(),
        Some(RpcRequest::Utxos { script_hash: [0xAB; 32], limit: UTXO_PAGE_DEFAULT })
    );

    call(b, &request("getmempoolinfo", "[]"));
    assert_eq!(spy.last(), Some(RpcRequest::MempoolInfo));

    let tx = test_transfer(1, 250, 1_000);
    let hex: String = tx.canonical_bytes().iter().map(|b| format!("{b:02x}")).collect();
    call(b, &request("sendrawtransaction", &format!("[\"{hex}\"]")));
    assert_eq!(spy.last(), Some(RpcRequest::SendRawTransaction(tx)));
}

/// `gettxout` routes one outpoint, and refuses what it cannot answer.
///
/// The refusals matter more than the happy path here. This method exists so a
/// go/no-go check before the vesting-lock flag day can be a query instead of an
/// assumption, and a check that silently accepts a malformed outpoint is worse
/// than no check: it would answer about an output nobody asked about.
#[test]
fn gettxout_routes_an_outpoint_and_refuses_a_malformed_one() {
    let spy = Spy::new();
    let b = spy.as_ref();
    let txid = "cd".repeat(32);

    // Control: a well-formed call must reach the backend as the outpoint asked
    // for. Without this half, the refusals below would pass against a method
    // that refuses everything.
    call(b, &request("gettxout", &format!("[\"{txid}\", 3]")));
    assert_eq!(spy.last(), Some(RpcRequest::TxOut { txid: [0xCD; 32], vout: 3 }));

    // vout defaults to 0 rather than erroring: an outpoint's index is almost
    // always zero for the allocation outputs this was written for, and a
    // required argument that is nearly always the same value invites being
    // typed wrong.
    call(b, &request("gettxout", &format!("[\"{txid}\"]")));
    assert_eq!(spy.last(), Some(RpcRequest::TxOut { txid: [0xCD; 32], vout: 0 }));

    let before = spy.last();
    call(b, &request("gettxout", "[]"));
    assert_eq!(spy.last(), before, "a missing txid must not reach the backend");
    call(b, &request("gettxout", "[\"ab\"]"));
    assert_eq!(spy.last(), before, "a short txid must not reach the backend");
    call(b, &request("gettxout", &format!("[\"{txid}\", -1]")));
    assert_eq!(spy.last(), before, "a negative vout must not reach the backend");
    call(b, &request("gettxout", &format!("[\"{txid}\", 4294967296]")));
    assert_eq!(spy.last(), before, "a vout past 32 bits must not reach the backend");
}

/// `listunspent` is the exchange-facing name for `getutxos`. Two names, one
/// request — a second semantics for the second name is how a client ends up
/// with two balances that disagree.
#[test]
fn listunspent_is_the_same_request_as_getutxos() {
    let spy = Spy::new();
    let script = "ab".repeat(32);
    call(spy.as_ref(), &request("getutxos", &format!("[\"{script}\", 5]")));
    let a = spy.last();
    call(spy.as_ref(), &request("listunspent", &format!("[\"{script}\", 5]")));
    assert_eq!(a, spy.last());
    assert_eq!(a, Some(RpcRequest::Utxos { script_hash: [0xAB; 32], limit: 5 }));
}

#[test]
fn named_params_work_as_well_as_positional() {
    let spy = Spy::new();
    call(spy.as_ref(), &request("getblockbyslot", r#"{"slot":99}"#));
    assert_eq!(spy.last(), Some(RpcRequest::BlockBySlot(99)));

    call(spy.as_ref(), &request("getvalidator", r#"{"index":4}"#));
    assert_eq!(spy.last(), Some(RpcRequest::Validator(4)));
}

#[test]
fn getutxos_limit_is_clamped_rather_than_trusted() {
    let spy = Spy::new();
    let script = "ab".repeat(32);
    call(spy.as_ref(), &request("getutxos", &format!("[\"{script}\", 99999999]")));
    assert_eq!(
        spy.last(),
        Some(RpcRequest::Utxos { script_hash: [0xAB; 32], limit: UTXO_PAGE_MAX }),
        "an unbounded page size is a memory amplification on an unauthenticated port"
    );
}

/// `gettransaction` and `getnewaddress` are the two methods the integration
/// asked for that this build cannot honestly serve. Each answers with its own
/// code and an explanation, rather than with an approximation or a bare
/// "method not found" that would send someone hunting for a newer binary.
#[test]
fn unsupported_capabilities_refuse_with_their_own_codes_and_reasons() {
    let spy = Spy::new();

    let v = call(spy.as_ref(), &request("gettransaction", r#"["ab"]"#));
    assert_eq!(error_code(&v), Some(NO_TRANSACTION_INDEX));
    let msg = v.get("error").unwrap().get("message").unwrap().as_str().unwrap();
    assert!(msg.contains("no id"), "the message must say why, not just no: {msg}");
    assert!(msg.contains("do not retry"), "a permanent answer must say it is permanent");
    assert!(spy.last().is_none(), "a refused method must never reach the node");

    let v = call(spy.as_ref(), &request("getnewaddress", "[]"));
    assert_eq!(error_code(&v), Some(NO_WALLET));
    let msg = v.get("error").unwrap().get("message").unwrap().as_str().unwrap();
    assert!(
        msg.contains("never mint key material"),
        "the refusal must name the key-generation rule: {msg}"
    );
    assert!(spy.last().is_none(), "a node RPC must not generate keys, ever");
}

/// Bytes that are not a canonical transaction are refused **before** the node
/// sees them, with a code distinct from a hex-encoding mistake.
#[test]
fn sendrawtransaction_rejects_bytes_that_do_not_decode() {
    let spy = Spy::new();

    // Unknown discriminant.
    let v = call(spy.as_ref(), &request("sendrawtransaction", r#"["ff00"]"#));
    assert_eq!(error_code(&v), Some(TX_DECODE_FAILED));
    assert!(spy.last().is_none(), "undecodable bytes must never reach the mempool");

    // Truncated mid-field: the tag is a valid Transfer, the fields are missing.
    let v = call(spy.as_ref(), &request("sendrawtransaction", r#"["0101"]"#));
    assert_eq!(error_code(&v), Some(TX_DECODE_FAILED));
    assert!(spy.last().is_none());

    // Trailing bytes past a complete transaction. Injectivity is what makes
    // `body_root` meaningful, so two encodings of one transaction must not both
    // be accepted.
    let mut trailing = PosTransaction::Exit { validator: 3 }.canonical_bytes();
    trailing.push(0);
    let hex: String = trailing.iter().map(|b| format!("{b:02x}")).collect();
    let v = call(spy.as_ref(), &request("sendrawtransaction", &format!("[\"{hex}\"]")));
    assert_eq!(error_code(&v), Some(TX_DECODE_FAILED));
    assert!(spy.last().is_none());

    // Slashing evidence is one-way by construction — it folds its nested
    // messages in through signing roots, which nothing recovers an envelope
    // from. It must be refused here rather than half-accepted.
    let v = call(spy.as_ref(), &request("sendrawtransaction", r#"["05"]"#));
    assert_eq!(error_code(&v), Some(TX_DECODE_FAILED));
    assert!(spy.last().is_none());

    // Bad hex is a DIFFERENT cause and gets a different code: the client made
    // an encoding mistake rather than submitting a malformed transaction.
    let v = call(spy.as_ref(), &request("sendrawtransaction", r#"["zz"]"#));
    assert_eq!(error_code(&v), Some(-32602));
    let v = call(spy.as_ref(), &request("sendrawtransaction", r#"["010"]"#));
    assert_eq!(error_code(&v), Some(-32602), "odd-length hex is not a partial decode");
    assert!(spy.last().is_none());

    // And a transaction that DOES decode reaches the node, so the tests above
    // are not passing because everything is refused.
    let good = PosTransaction::Exit { validator: 3 };
    let hex: String = good.canonical_bytes().iter().map(|b| format!("{b:02x}")).collect();
    call(spy.as_ref(), &request("sendrawtransaction", &format!("[\"{hex}\"]")));
    assert_eq!(spy.last(), Some(RpcRequest::SendRawTransaction(good)));
}

/// The property that matters most on an unauthenticated port: no input, however
/// malformed, can panic the process. A panic here is a validator that anyone
/// can stop with one HTTP request.
#[test]
fn malformed_input_never_panics_and_always_answers_json_rpc() {
    let spy = Spy::new();
    let b = spy.as_ref();

    let cases: Vec<(&str, i64)> = vec![
        // Not JSON at all.
        ("", -32700),
        ("{", -32700),
        ("not json", -32700),
        ("{\"method\":}", -32700),
        (r#"{"method":"getchaininfo",}"#, -32700),
        (r#"{"a":1}{"b":2}"#, -32700),
        ("\"unterminated", -32700),
        (r#"{"a":01}"#, -32700),
        (r#"{"a":1e}"#, -32700),
        // JSON, but not a JSON-RPC request.
        ("null", -32600),
        ("42", -32600),
        (r#""a string""#, -32600),
        ("[]", -32600),
        (r#"[{"method":"getchaininfo"}]"#, -32600),
        ("{}", -32600),
        (r#"{"method":42}"#, -32600),
        (r#"{"jsonrpc":"1.0","method":"getchaininfo"}"#, -32600),
        // Real method, wrong arguments.
        (r#"{"method":"getblockbyslot"}"#, -32602),
        (r#"{"method":"getblockbyslot","params":[]}"#, -32602),
        (r#"{"method":"getblockbyslot","params":["abc"]}"#, -32602),
        (r#"{"method":"getblockbyslot","params":[-1]}"#, -32602),
        (r#"{"method":"getblockbyslot","params":[1.5]}"#, -32602),
        (r#"{"method":"getblockbyid","params":["xyz"]}"#, -32602),
        (r#"{"method":"getblockbyid","params":["aabb"]}"#, -32602),
        (r#"{"method":"getblockbyid","params":[123]}"#, -32602),
        (r#"{"method":"getbalance","params":[null]}"#, -32602),
        (r#"{"method":"getvalidator","params":[4294967296]}"#, -32602),
        (r#"{"method":"sendrawtransaction","params":[""]}"#, -32602),
        // No such method.
        (r#"{"method":"getblocktemplate"}"#, -32601),
        (r#"{"method":"submitblock","params":[1]}"#, -32601),
        (r#"{"method":""}"#, -32601),
    ];

    for (body, expected) in cases {
        let v = call(b, body);
        assert_eq!(
            error_code(&v),
            Some(expected),
            "body {body:?} should have produced error {expected}, got {}",
            v.to_string()
        );
        assert_eq!(v.get("jsonrpc").unwrap().as_str(), Some("2.0"));
        assert!(v.get("result").is_none(), "R4: a failure must not carry a result");
        assert!(
            !v.get("error").unwrap().get("message").unwrap().as_str().unwrap().is_empty(),
            "every error must explain itself"
        );
    }
}

/// A hostile body must not be able to exhaust the stack. Without a depth limit
/// the recursive parser aborts the process, which on a validator is a remote
/// kill switch.
#[test]
fn deeply_nested_json_is_refused_not_fatal() {
    let spy = Spy::new();
    let body = format!("{}{}", "[".repeat(50_000), "]".repeat(50_000));
    let v = call(spy.as_ref(), &body);
    assert_eq!(error_code(&v), Some(-32700));

    // Just inside the limit still parses, so the bound is a real boundary and
    // not an accidental rejection of everything nested.
    let ok = format!("{}{}", "[".repeat(60), "]".repeat(60));
    assert!(parse_json(&ok).is_ok());
}

#[test]
fn the_request_id_comes_back_unchanged_including_on_errors() {
    let spy = Spy::new();
    let b = spy.as_ref();

    let v = call(b, r#"{"jsonrpc":"2.0","id":7,"method":"getchaininfo"}"#);
    assert_eq!(v.get("id"), Some(&Json::Num("7".into())));

    let v = call(b, r#"{"jsonrpc":"2.0","id":"abc-123","method":"nosuch"}"#);
    assert_eq!(v.get("id").unwrap().as_str(), Some("abc-123"));

    // An id past 2^53 must survive: it is a client's correlation key, and a
    // parser that routed it through a double would hand back a different one.
    let v = call(b, r#"{"jsonrpc":"2.0","id":9007199254740993,"method":"getchaininfo"}"#);
    assert_eq!(v.get("id"), Some(&Json::Num("9007199254740993".into())));

    // Absent id is echoed as null rather than invented.
    let v = call(b, r#"{"jsonrpc":"2.0","method":"getchaininfo"}"#);
    assert_eq!(v.get("id"), Some(&Json::Null));
}

#[test]
fn a_backend_failure_becomes_a_top_level_error_object() {
    let spy = Spy::failing(RpcError::new(BLOCK_NOT_FOUND, "no block 0xdead is known"));
    let v = call(spy.as_ref(), &request("getblockbyslot", "[5]"));
    assert_eq!(error_code(&v), Some(BLOCK_NOT_FOUND));
    assert_eq!(
        v.get("error").unwrap().get("message").unwrap().as_str(),
        Some("no block 0xdead is known")
    );
    // R4 again, at the seam where V3 got it wrong: never a string under
    // `result` with a 200.
    assert!(v.get("result").is_none());
}

#[test]
fn a_successful_call_carries_result_and_no_error() {
    let spy = Spy::new();
    let v = call(spy.as_ref(), &request("getchaininfo", "[]"));
    assert_eq!(v.get("result").unwrap().as_str(), Some("ok"));
    assert!(v.get("error").is_none());
    assert_eq!(v.get("jsonrpc").unwrap().as_str(), Some("2.0"));
}

#[test]
fn an_unreachable_engine_is_reported_not_hung() {
    // A backend whose engine channel is already closed: this is what every
    // in-flight request sees when the node stops.
    let (tx, rx) = mpsc::channel::<crate::engine::EngineEvent>();
    drop(rx);
    let backend = EngineBackend::new(tx);
    let err = backend.call(RpcRequest::ChainInfo).expect_err("a dead engine must not look healthy");
    assert_eq!(err.code, NODE_UNAVAILABLE);
    assert!(err.message.contains("shutting down"));
}

// ─── 3. JSON round-trips ────────────────────────────────────────────────────

#[test]
fn json_strings_round_trip_through_escaping() {
    for original in [
        "plain",
        "with \"quotes\"",
        "back\\slash",
        "new\nline\ttab\r",
        "control\u{0001}char",
        "unicode: ação, 日本語, \u{1F600}",
        "",
    ] {
        let encoded = Json::s(original).to_string();
        let decoded = parse_json(&encoded).expect("our own output must parse");
        assert_eq!(decoded.as_str(), Some(original), "round trip failed for {original:?}");
    }
}

#[test]
fn json_escape_sequences_decode() {
    let v = parse_json(r#"{"k":"aAb\n\\\"é😀"}"#).unwrap();
    assert_eq!(v.get("k").unwrap().as_str(), Some("aAb\n\\\"é😀"));

    // A lone surrogate is not a character; substituting is the non-panicking
    // answer, and the parse still succeeds.
    let v = parse_json(r#"{"k":"\ud800"}"#).unwrap();
    assert_eq!(v.get("k").unwrap().as_str(), Some("\u{FFFD}"));
}

#[test]
fn json_numbers_keep_their_exact_text() {
    let v = parse_json(r#"[0,-1,1.5,1e10,9007199254740993,18000000000000000500]"#).unwrap();
    assert_eq!(v.at(4).unwrap().as_u64(), Some(9_007_199_254_740_993));
    // Beyond u64 the token is preserved even though it does not fit — the
    // parser's job is fidelity, not coercion.
    assert_eq!(v.at(5), Some(&Json::Num("18000000000000000500".into())));
    // Non-integers are refused by `as_u64` rather than truncated to 1.
    assert_eq!(v.at(2).unwrap().as_u64(), None);
    assert_eq!(v.at(1).unwrap().as_u64(), None);
}

#[test]
fn hex_decoding_refuses_malformed_input() {
    assert_eq!(from_hex("00ff"), Some(vec![0x00, 0xff]));
    assert_eq!(from_hex("0x00ff"), Some(vec![0x00, 0xff]));
    assert_eq!(from_hex(""), Some(vec![]));
    assert_eq!(from_hex("f"), None, "odd length");
    assert_eq!(from_hex("zz"), None, "not hex");
    assert_eq!(from_hex("00 ff"), None, "embedded space");
    // Multi-byte characters must not panic a byte-pair walk.
    assert_eq!(from_hex("ação"), None);
}

// ─── 4. HTTP, over a real socket ────────────────────────────────────────────

/// Send a raw HTTP request to `addr` and return the full response text.
fn http(addr: SocketAddr, raw: &str) -> String {
    use std::io::{Read as _, Write as _};
    let mut sock = TcpStream::connect(addr).expect("connect to the test server");
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    sock.write_all(raw.as_bytes()).unwrap();
    let mut out = String::new();
    let _ = sock.read_to_string(&mut out);
    out
}

fn post(addr: SocketAddr, body: &str) -> String {
    http(
        addr,
        &format!(
            "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\n\r\n{body}",
            body.len()
        ),
    )
}

fn test_server() -> (SocketAddr, Arc<Spy>) {
    let spy = Spy::new();
    let addr = serve("127.0.0.1", 0, spy.clone()).expect("bind an ephemeral port");
    (addr, spy)
}

#[test]
fn a_real_post_gets_a_real_json_rpc_response() {
    let (addr, spy) = test_server();
    let response = post(addr, &request("getchaininfo", "[]"));

    assert!(response.starts_with("HTTP/1.1 200 OK"), "got {response}");
    assert!(response.contains("Content-Type: application/json"));
    let body = response.split("\r\n\r\n").nth(1).expect("a response body");
    let v = parse_json(body).expect("the body must be JSON");
    assert_eq!(v.get("result").unwrap().as_str(), Some("ok"));
    assert_eq!(spy.last(), Some(RpcRequest::ChainInfo));

    // Content-Length must match the body exactly, or a client blocks waiting
    // for bytes that never come.
    let declared: usize = response
        .split("Content-Length: ")
        .nth(1)
        .and_then(|s| s.split("\r\n").next())
        .and_then(|s| s.parse().ok())
        .expect("a Content-Length header");
    assert_eq!(declared, body.len());
}

#[test]
fn the_server_binds_loopback_when_asked_for_loopback() {
    let (addr, _spy) = test_server();
    assert!(
        addr.ip().is_loopback(),
        "the default bind must be loopback — this port has no authentication"
    );
}

#[test]
fn http_that_is_not_a_json_rpc_post_is_answered_not_dropped() {
    let (addr, _) = test_server();

    // GET is refused with a status, not a hang or a panic.
    let r = http(addr, "GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    assert!(r.starts_with("HTTP/1.1 405"), "got {r}");

    // POST with no Content-Length cannot be read.
    let r = http(addr, "POST / HTTP/1.1\r\nHost: x\r\n\r\n{}");
    assert!(r.starts_with("HTTP/1.1 411"), "got {r}");

    // An over-large declared body is refused before it is read.
    let r = http(
        addr,
        &format!("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n", MAX_BODY_BYTES + 1),
    );
    assert!(r.starts_with("HTTP/1.1 413"), "got {r}");

    // Chunked encoding is not implemented and says so rather than parsing
    // chunk headers as JSON.
    let r = http(addr, "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n");
    assert!(r.starts_with("HTTP/1.1 411"), "got {r}");

    // Every refusal still carries a JSON-RPC error body, so a client that only
    // reads bodies still learns what happened.
    let body = r.split("\r\n\r\n").nth(1).unwrap_or("");
    let v = parse_json(body).expect("even an HTTP-level refusal answers JSON-RPC");
    assert_eq!(error_code(&v), Some(-32600));
}

#[test]
fn a_body_that_is_not_utf8_is_a_parse_error_not_a_dropped_connection() {
    let (addr, _) = test_server();
    use std::io::{Read as _, Write as _};
    let mut sock = TcpStream::connect(addr).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let head = "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\n";
    sock.write_all(head.as_bytes()).unwrap();
    sock.write_all(&[0xff, 0xfe, 0xfd]).unwrap();
    let mut out = String::new();
    let _ = sock.read_to_string(&mut out);

    assert!(out.starts_with("HTTP/1.1 200"), "got {out}");
    let v = parse_json(out.split("\r\n\r\n").nth(1).unwrap()).unwrap();
    assert_eq!(error_code(&v), Some(-32700));
}

#[test]
fn a_body_split_across_packets_is_reassembled() {
    let (addr, spy) = test_server();
    use std::io::{Read as _, Write as _};
    let body = request("getblockbyslot", "[41290]");
    let mut sock = TcpStream::connect(addr).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    sock.write_all(
        format!("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n", body.len()).as_bytes(),
    )
    .unwrap();
    // Deliberately dribble the body in two writes: a reader that assumed one
    // read per request would truncate the JSON here.
    let (a, b) = body.split_at(body.len() / 2);
    sock.write_all(a.as_bytes()).unwrap();
    std::thread::sleep(Duration::from_millis(50));
    sock.write_all(b.as_bytes()).unwrap();

    let mut out = String::new();
    let _ = sock.read_to_string(&mut out);
    assert!(out.starts_with("HTTP/1.1 200"), "got {out}");
    assert_eq!(spy.last(), Some(RpcRequest::BlockBySlot(41_290)));
}
