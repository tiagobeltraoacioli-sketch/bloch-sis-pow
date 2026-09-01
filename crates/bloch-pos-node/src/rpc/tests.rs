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
    // The roster summary is handed in as the engine hands it in. Taken from
    // `active_roster_summary` and NOT from a literal, so this test reads the
    // same numbers a live node publishes; `active_roster_summary_matches_the_two_accessors`
    // is what pins those to `active_validators()` / `total_active_stake_sat()`.
    let (count, total_stake_sat) = st.active_roster_summary();
    let v = chain_info_json(
        &st,
        &head,
        st.state_root(),
        0,
        Some(0),
        12,
        2,
        crate::rpc::ActiveRoster { count, total_stake_sat },
        3,
        0,
    );

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

// ─── 2b. The frozen namespace ───────────────────────────────────────────────
//
// `docs/WIRE-NAMESPACE-REGISTRY.md` §5 allocates RPC method names, and §7 gap 2
// records that the allocation was not frozen by anything. These three tests are
// that freeze. They exist because the compiler will not do it: a `match` on
// `&str` has no exhaustiveness to check, and a duplicate literal is at most an
// `unreachable_patterns` warning — one that fires only after the merge that
// puts both arms in the same file, which is precisely the case the registry
// says has already gone wrong four times in adjacent namespaces.

/// The dispatcher's own source, so the test can read the arms rather than
/// guess at them. Relative to `src/rpc/tests.rs`, this is `src/rpc.rs`.
const ROUTE_SOURCE: &str = include_str!("../rpc.rs");

/// Every method-name literal that appears as a `match` arm inside `route`,
/// extracted from the source.
///
/// The rule is positional and deliberately strict: an arm of the `Ok(match
/// method {` block is indented exactly eight spaces and begins with a quote.
/// Anything more clever (a real parser, a proc macro) buys nothing here, and
/// anything looser would sweep up the argument-name literals inside the arm
/// bodies. If a future refactor changes the indentation, this returns a short
/// list and the assertions below fail loudly — which is the correct outcome for
/// a freeze that has stopped being able to see what it froze.
fn dispatch_arm_names() -> Vec<String> {
    let body = ROUTE_SOURCE
        .split_once("pub fn route(")
        .expect("route() must exist")
        .1
        .split_once("Ok(match method {")
        .expect("route() must dispatch with `Ok(match method {`")
        .1;
    let end = body.find("\n    })\n}").expect("route()'s match must close at `    })`");

    let mut names = Vec::new();
    for line in body[..end].lines() {
        let Some(rest) = line.strip_prefix("        ") else { continue };
        if !rest.starts_with('"') {
            continue;
        }
        // Collect every literal to the left of `=>`, so an aliased arm
        // (`"getutxos" | "listunspent" =>`) contributes both of its names.
        let head = rest.split_once("=>").map(|(h, _)| h).unwrap_or(rest);
        let mut i = 0;
        while let Some(open) = head[i..].find('"') {
            let open = i + open;
            let close = open + 1 + head[open + 1..].find('"').expect("unterminated arm literal");
            names.push(head[open + 1..close].to_string());
            i = close + 1;
        }
    }
    names
}

/// The namespace, frozen in both directions.
///
/// A method wired into `route` but missing from [`RPC_SURFACE`] fails here, and
/// so does a name in `RPC_SURFACE` that nothing dispatches. That two-way check
/// is the whole value: it means the table is not documentation that can drift
/// from the code, it is the code's index, and an agent adding a method cannot
/// do it without touching the line the PMO registry points at.
#[test]
fn the_rpc_method_namespace_is_frozen() {
    // The golden list, written out. Not derived from `RPC_SURFACE` — deriving
    // it would make an accidental edit to the table invisible, and the point of
    // a golden list is that changing the surface shows up as a diff a reviewer
    // must approve and register with the PMO before it can go green.
    let golden = [
        "getbalance",
        "getblockbyid",
        "getblockbyslot",
        "getblockcount",
        "getcapabilities",
        "getchaininfo",
        "getmempoolinfo",
        "getnewaddress",
        "getstakedistribution",
        "getsupply",
        "gettransaction",
        "gettxout",
        "getutxos",
        "getvalidator",
        "getvalidatorcount",
        "getvalidators",
        "listunspent",
        "sendrawtransaction",
    ];

    let table: Vec<&str> = RPC_SURFACE.iter().map(|m| m.name).collect();
    assert_eq!(
        table, golden,
        "RPC_SURFACE changed. This is a shared namespace: claim the name from the \
         PMO (docs/WIRE-NAMESPACE-REGISTRY.md, section 5) and update the golden \
         list here in the same commit."
    );

    // A registry has to be sorted and unique to be readable as one.
    let mut sorted = table.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted, table, "RPC_SURFACE must be sorted and free of duplicates");

    // What the dispatcher actually accepts, read out of its own source.
    let raw = dispatch_arm_names();
    assert!(
        raw.len() >= golden.len(),
        "the arm extractor found only {} names — it has stopped seeing the \
         dispatch table and is no longer freezing anything: {raw:?}",
        raw.len()
    );

    // Duplicates in the source, which a `match` would only warn about, and only
    // after the merge that creates them.
    let mut seen: Vec<&str> = Vec::new();
    for name in &raw {
        assert!(
            !seen.contains(&name.as_str()),
            "`{name}` is dispatched twice; the second arm is dead and the \
             compiler's `unreachable_patterns` warning is not an error"
        );
        seen.push(name);
    }

    let mut arms: Vec<&str> = raw.iter().map(String::as_str).collect();
    arms.sort_unstable();
    assert_eq!(
        arms, golden,
        "the dispatcher and RPC_SURFACE disagree. Every name `route` answers must \
         be in the table with a stability class, and every name in the table must \
         be dispatched."
    );

    // The wildcard must be the typed refusal, not a silent fallthrough.
    assert!(
        ROUTE_SOURCE.contains("other => return Err(RpcError::method_not_found(other)),"),
        "an unknown method must answer -32601 by name; a `_ => ...` that swallowed \
         it would make a typo look like a working call"
    );
}

/// Every frozen name routes, and nothing else does.
///
/// The negative half is the one that matters. `-32601` is the only answer a
/// name outside the namespace may give: an integrator's probe of a name this
/// build does not serve must not accidentally reach a handler, and the names
/// listed in [`RPC_ABSENT`] — each of which a real integrator has sent — must
/// stay absent rather than being quietly re-added under their Genesis-3
/// meaning.
#[test]
fn only_the_frozen_names_route() {
    for m in RPC_SURFACE {
        let err = route(m.name, None).err();
        assert_ne!(
            err.as_ref().map(|e| e.code),
            Some(-32601),
            "`{}` is in RPC_SURFACE but the dispatcher does not know it",
            m.name
        );
        // A refused method must answer with its own permanent code, and must
        // do so at the dispatcher — never by reaching the node.
        if m.stability == Stability::Refused {
            let code = err.as_ref().map(|e| e.code);
            assert!(
                code == Some(NO_TRANSACTION_INDEX) || code == Some(NO_WALLET),
                "`{}` is classed Refused but answered {code:?}; a refusal must \
                 carry the code that says which capability is missing",
                m.name
            );
        }
    }

    let outside = [
        // The names an integrator probed on the live endpoint that are still
        // absent. `getsupply` and `getvalidators` left this list when they were
        // built; `getissuance`, `getstakinginfo` and `getsupplyinfo` stay,
        // because a near-synonym that silently works is how two names for one
        // number end up in two clients.
        "getblockbyheight",
        "getcirculatingsupply",
        "getissuance",
        "getpeers",
        "getstakinginfo",
        "getsupplyinfo",
        "help",
        // Genesis-3 names that must not silently come back with PoW meanings.
        "getblock",
        "getblockhash",
        "getdaginfo",
        "getdifficultyhistory",
        "gethashrate",
        "getnetworkinfo",
        "getrawmempool",
        "getsupplydistribution",
        "gettxstatus",
        "validateaddress",
        // Near misses: a method name is an exact string, not a fuzzy match.
        "GetBalance",
        "getbalance ",
        " getbalance",
        "getBalance",
        "get_balance",
        "",
    ];
    for name in outside {
        assert_eq!(
            route(name, None).err().map(|e| e.code),
            Some(-32601),
            "`{name}` must answer -32601; if this build now serves it, claim the \
             name from the PMO and add it to RPC_SURFACE"
        );
    }

    // Every name the capability document calls absent really is absent — the
    // two lists cannot drift into telling a client something untrue.
    for (name, _) in RPC_ABSENT {
        assert_eq!(
            route(name, None).err().map(|e| e.code),
            Some(-32601),
            "`{name}` is advertised as absent but the dispatcher serves it"
        );
        assert!(
            !RPC_SURFACE.iter().any(|m| m.name == *name),
            "`{name}` is in both RPC_SURFACE and RPC_ABSENT"
        );
    }
}

/// `getcapabilities` answers the questions probing was being used to answer,
/// at constant cost.
#[test]
fn getcapabilities_describes_the_surface_without_reading_state() {
    let spy = Spy::new();
    call(spy.as_ref(), &request("getcapabilities", "[]"));
    assert_eq!(spy.last(), Some(RpcRequest::Capabilities));

    let genesis = [0x11u8; 32];
    let v = capabilities_json("0.1.0-test", &genesis, 0xB10C_0005);

    assert_eq!(v.get("rpc_surface_version"), Some(&Json::s(RPC_SURFACE_VERSION)));
    assert_eq!(v.get("node_version"), Some(&Json::s("0.1.0-test")));
    assert_eq!(v.get("genesis_block_id"), Some(&Json::hex(&genesis)));
    // The raw header magic, not a friendlier `4`: a client recomputing a block
    // id hashes this value.
    assert_eq!(v.get("block_version"), Some(&Json::u(0xB10C_0005)));

    // Every method, with its class, in the order the table declares.
    let Some(Json::Arr(methods)) = v.get("methods") else { panic!("no methods array") };
    assert_eq!(methods.len(), RPC_SURFACE.len());
    for (entry, m) in methods.iter().zip(RPC_SURFACE) {
        assert_eq!(entry.get("name"), Some(&Json::s(m.name)));
        assert_eq!(entry.get("stability"), Some(&Json::s(m.stability.as_str())));
    }

    // The alias is declared as one, so a client does not have to discover that
    // two names are one question by comparing two answers.
    let listunspent = methods
        .iter()
        .find(|m| m.get("name") == Some(&Json::s("listunspent")))
        .expect("listunspent must be listed");
    assert_eq!(listunspent.get("alias_of"), Some(&Json::s("getutxos")));

    // The absent list is the substitute for probing.
    let Some(Json::Arr(absent)) = v.get("absent") else { panic!("no absent array") };
    for want in ["getblockbyheight", "getissuance", "getstakinginfo", "getpeers", "help"] {
        assert!(
            absent.iter().any(|a| a.get("name") == Some(&Json::s(want))),
            "`{want}` was probed by a real integrator and must be answered here"
        );
    }

    // The three names an integrator probed and got -32601 for, which this
    // build now serves. They must have MOVED from `absent` to `methods`, not
    // been added to one and left in the other: a client that reads `absent`
    // and short-circuits would never call a method that works.
    for moved in ["getsupply", "getvalidators", "getstakedistribution"] {
        assert!(
            methods.iter().any(|m| m.get("name") == Some(&Json::s(moved))),
            "`{moved}` is served but getcapabilities does not list it"
        );
        assert!(
            !absent.iter().any(|a| a.get("name") == Some(&Json::s(moved))),
            "`{moved}` is served AND advertised as absent; the two lists are \
             telling a client opposite things"
        );
    }

    // Every code this surface can return, so a client builds its branch table
    // from the node rather than from a document describing another build.
    let Some(Json::Arr(codes)) = v.get("error_codes") else { panic!("no error_codes") };
    for want in [NO_TRANSACTION_INDEX, NO_WALLET, SLOT_EMPTY, TX_REFUSED, MEMPOOL_FULL] {
        assert!(
            codes.iter().any(|c| c.get("code") == Some(&Json::Num(want.to_string()))),
            "code {want} is reachable but undocumented in getcapabilities"
        );
    }

    // R3, stated in the capability document because parsing an amount as a JSON
    // number is the most common integration bug on this chain.
    assert_eq!(
        v.get("encoding").and_then(|e| e.get("amounts")),
        Some(&Json::s("decimal_string"))
    );
    // Batch is refused by `handle_body`; a client must be able to learn that
    // without sending one.
    assert_eq!(
        v.get("transport").and_then(|t| t.get("batch")),
        Some(&Json::Bool(false))
    );
    // The limits a client must respect are numbers, not prose in a README.
    assert_eq!(
        v.get("limits").and_then(|l| l.get("utxo_page_max")),
        Some(&Json::u(UTXO_PAGE_MAX as u64))
    );
    assert_eq!(
        v.get("limits").and_then(|l| l.get("max_body_bytes")),
        Some(&Json::u(MAX_BODY_BYTES as u64))
    );
    // The port's honest description of itself.
    assert_eq!(
        v.get("authentication").and_then(|a| a.get("scheme")),
        Some(&Json::s("none"))
    );
    // R1: there is no confirmation count to report, and the field says so
    // rather than being absent, which a client would read as "unknown".
    assert_eq!(
        v.get("settlement").and_then(|s| s.get("confirmations")),
        Some(&Json::Null)
    );
}

/// What the read surface costs at carryover scale — a measurement, not an
/// assertion, which is why it is `#[ignore]`d.
///
/// Run it with `cargo test -p bloch-pos-node --bins --ignored
/// what_a_read_costs_at_carryover_scale -- --nocapture`.
///
/// # Why this exists
///
/// The RPC port has no authentication, no authorisation and no rate limit, and
/// every read is serviced **on the consensus thread**. So the price of a method
/// is not a performance footnote: it is the size of the lever an anonymous
/// caller has on block production. Two of the methods here walk the whole eUTXO
/// set — `getbalance` walks it twice, once to sum and once to count — and that
/// set is 452,726 entries at the Genesis-4 carryover and only grows.
///
/// The numbers this prints are the input to §4 and §5 of
/// `docs/specs/BLOCH-RPC-STABILITY-V4.md`, which is why any proposed method
/// that would add a third scan has to justify itself against them.
///
/// Measured 2026-08-31, release build, 452,726 entries — BEFORE the one-pass
/// rewrite of `balance_json` and the bounded page in `utxos_json`:
///
/// ```text
/// getbalance          18.2 ms    (two full scans)
/// getutxos limit=100  10.7 ms    (one full scan, collects every match)
/// getutxos limit=1000 30.8 ms
/// gettxout            28 µs      (one map lookup)
/// getcapabilities     100 µs     (constants only)
/// ```
///
/// Reads are serialised onto the consensus thread, so ~55 `getbalance` calls a
/// second were 100% of a validator's consensus thread — on a port with no
/// authentication and no rate limit.
///
/// The test now prints BOTH the old body and the new one on the same state, so
/// the comparison is reproduced rather than remembered.
///
/// **THIS TEST HAS NOT BEEN RUN TO COMPLETION.** It was attempted on
/// 2026-09-01 and abandoned: the box was running several agents' release
/// builds, and the LTO link alone ran over half an hour. Run it on a quiet
/// machine before quoting any number from it.
///
/// The sibling bench in the node crate (`engine::bench::bench_balance_and_utxos`)
/// DID complete, and settles the `getbalance` half: 13.454 ms for the old
/// two-walk body against 6.592 ms for the new one-walk body, min of 15
/// interleaved reps at 452,726 outputs with 425,563 on one script hash —
/// **2.04x**, which is precisely "two walks became one". Its absolute values
/// are ~8x the live-chain figure for the same shape and should be ignored; the
/// ratio is the result.
///
/// It does NOT settle the `getutxos` half, and the reason is worth keeping:
/// that bench's first `getutxos` comparison put the new body 2.6-2.7x SLOWER,
/// twice. Both times it was the same measurement bug — a BEFORE closure that
/// collected references and stopped, against an AFTER that went on to build
/// 1,000 `eutxo_json` objects and the response, roughly 2,000 hex encodings
/// the BEFORE never paid for. The gap WAS the missing half of the function.
///
/// What is not in doubt, because it is a property of the code rather than of a
/// stopwatch: both `utxos_json` bodies do one filtered walk and exactly `limit`
/// `eutxo_json` calls, and the old one additionally allocated and freed one
/// reference per match (425,563 of them, 3.2 MB). The new body does strictly
/// less work and cannot be slower. This test is the place to confirm that with
/// a number, because it is the only one with the module access to reconstruct
/// the old body verbatim. The old bodies are
/// written out below under `# the old bodies, kept as the reference`; if the
/// production bodies are ever changed again, change those to match what they
/// replaced, or this stops measuring a delta and starts measuring noise.
///
/// **What the improvement does and does not buy.** It removes one walk of the
/// eUTXO set per `getbalance`, which on the corrected numbers is worth about
/// 1.7 ms a call, not nine. A duplicate walk for a number you already have is
/// not defensible at any cost, so the change stands on its own — but it is not
/// a denial-of-service fix and must not be reported as one. The walk that
/// remains is still linear in the whole set because there is no index by
/// script hash. The durable fix is that index, in committed state; the fix in
/// front of it today is not serving this port to the world at all.
#[test]
#[ignore = "a measurement of the read surface, not a pass/fail assertion"]
fn what_a_read_costs_at_carryover_scale() {
    use std::time::Instant;

    // The live carryover, to the entry.
    const CARRYOVER_N: u32 = 452_726;

    let mut balances = Vec::with_capacity(CARRYOVER_N as usize);
    for i in 0..CARRYOVER_N {
        let mut txid = [0u8; 32];
        txid[..4].copy_from_slice(&i.to_le_bytes());
        let mut script_hash = [0u8; 32];
        // A hundred distinct holders, so the filter matches a realistic slice
        // rather than everything or nothing.
        script_hash[0] = (i % 100) as u8;
        balances.push(EutxoEntry { txid, vout: 0, value: 100_000, script_hash });
    }

    let validators = vec![GenesisValidator {
        index: 0,
        pubkey: vec![0xAA; 64],
        staked_sat: 200_000 * 100_000_000,
        randao_commitment: [1u8; 32],
        withdrawal_credentials: vec![],
        commission_bps: 500,
    }];

    let built = Instant::now();
    let state = CommittedState::genesis(
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
    );
    println!("built {CARRYOVER_N} entries in {:?}", built.elapsed());

    let script = [0u8; 32];
    let matches = state.eutxos().filter(|e| e.script_hash == script).count();
    println!("{matches} of {CARRYOVER_N} outputs match the probed script hash");

    // ── the old bodies, kept as the reference the new ones are measured
    // ── against. These are what `balance_json` and `utxos_json` used to be,
    // ── verbatim; they are not paraphrases and must not become paraphrases.
    let old_balance = |st: &CommittedState| {
        let count = st.eutxos().filter(|e| e.script_hash == script).count();
        let bal = st.balance_sat(&script);
        (count, bal)
    };
    let old_utxos = |st: &CommittedState, limit: usize| {
        let matching: Vec<&EutxoEntry> =
            st.eutxos().filter(|e| e.script_hash == script).collect();
        let total = matching.len();
        let page: Vec<Json> = matching.iter().take(limit).map(|e| eutxo_json(e)).collect();
        (total, page.len())
    };

    let t = Instant::now();
    let before = old_balance(&state);
    let bal_before = t.elapsed();
    let t = Instant::now();
    let after = balance_json(&state, &script);
    let bal_after = t.elapsed();
    println!("getbalance BEFORE   {bal_before:?}  (two full scans)");
    println!("getbalance AFTER    {bal_after:?}  (one fold)");
    // Same answer, or the measurement is of a different function.
    assert_eq!(after.get("utxo_count").unwrap().as_u64(), Some(before.0 as u64));
    assert_eq!(
        after.get("balance_sat").unwrap().as_str().map(str::to_string),
        Some(before.1.to_string()),
        "the one-pass fold disagreed with the two-scan body it replaced"
    );

    for limit in [UTXO_PAGE_DEFAULT, UTXO_PAGE_MAX] {
        let t = Instant::now();
        let b = old_utxos(&state, limit);
        let u_before = t.elapsed();
        let t = Instant::now();
        let a = utxos_json(&state, &script, limit);
        let u_after = t.elapsed();
        println!("getutxos limit={limit:<4} BEFORE {u_before:?}  (collects every match)");
        println!("getutxos limit={limit:<4} AFTER  {u_after:?}  (keeps at most `limit`)");
        assert_eq!(a.get("total").unwrap().as_u64(), Some(b.0 as u64));
        assert_eq!(a.get("returned").unwrap().as_u64(), Some(b.1 as u64));
        println!(
            "  peak refs BEFORE {} x {} B = {:.2} MB   AFTER {} entries",
            b.0,
            std::mem::size_of::<&EutxoEntry>(),
            (b.0 * std::mem::size_of::<&EutxoEntry>()) as f64 / 1_048_576.0,
            b.1
        );
    }

    let t = Instant::now();
    let _ = txout_json(&state, &balances[0].txid, 0);
    println!("gettxout            {:?}  (one map lookup)", t.elapsed());

    let t = Instant::now();
    let _ = capabilities_json("0.1.0-test", &[0u8; 32], VERSION_G4);
    println!("getcapabilities     {:?}  (constants only)", t.elapsed());
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

// ─── The three reads the chain could not answer ─────────────────────────────

/// `getsupply` reports the counter, the cap, and the two things a reader gets
/// wrong — in the payload, not in a document.
#[test]
fn getsupply_ships_its_caveats_as_fields_not_as_documentation() {
    use bloch_pos_committee::tokenomics_v4::{GENESIS_ISSUED_SAT, TOTAL_SUPPLY_SAT};

    let issued = GENESIS_ISSUED_SAT + 777_000;
    let v = supply_json(issued, TOTAL_SUPPLY_SAT, GENESIS_ISSUED_SAT, 54_547, 1_704, 1_702);

    // R3 everywhere: every satoshi field is a decimal string, never a number.
    for field in [
        "issued_sat",
        "cap_sat",
        "remaining_sat",
        "genesis_issued_sat",
        "emitted_since_genesis_sat",
    ] {
        assert!(
            matches!(v.get(field), Some(Json::Str(_))),
            "`{field}` must be a decimal string; 10^19 sat does not survive a double"
        );
    }

    assert_eq!(v.get("issued_sat").unwrap().as_str(), Some(issued.to_string().as_str()));
    assert_eq!(
        v.get("cap_sat").unwrap().as_str(),
        Some(TOTAL_SUPPLY_SAT.to_string().as_str())
    );
    // The number that actually grows, which is the headline for issuance.
    assert_eq!(v.get("emitted_since_genesis_sat").unwrap().as_str(), Some("777000"));

    // The identity that makes `remaining_sat` mean what it means. If this ever
    // fails, `remaining_sat` has stopped being the validator emission budget
    // and the note below it has become a lie.
    let remaining: u128 = v.get("remaining_sat").unwrap().as_str().unwrap().parse().unwrap();
    assert_eq!(
        remaining,
        bloch_pos_committee::tokenomics_v4::VALIDATOR_EMISSION_SAT - 777_000,
        "`remaining_sat` is the UNMINTED VALIDATOR EMISSION, not unissued supply"
    );

    // Both caveats travel with the answer. An integrator who reads `issued_sat`
    // as circulating supply is wrong by however much has been burned, and the
    // one who most needs to be told is the one who never opened the spec.
    let issued_note = v.get("issued_note").unwrap().as_str().unwrap();
    assert!(issued_note.contains("GROSS"), "the monotone/gross caveat must ship");
    assert!(
        issued_note.contains("not circulating supply"),
        "the response must refuse the label a Bitcoin-shaped audit will apply"
    );
    let rem_note = v.get("remaining_note").unwrap().as_str().unwrap();
    assert!(rem_note.contains("VALIDATOR EMISSION"), "the budget caveat must ship");

    // Head state sits above the finalized checkpoint, so the counter can still
    // move. An audit wanting a figure nobody can take back waits for this.
    assert_eq!(v.get("at_epoch").unwrap().as_u64(), Some(1_704));
    assert_eq!(v.get("finalized_epoch").unwrap().as_u64(), Some(1_702));
    assert_eq!(v.get("finalized"), Some(&Json::Bool(false)));

    let settled = supply_json(issued, TOTAL_SUPPLY_SAT, GENESIS_ISSUED_SAT, 32, 1, 9);
    assert_eq!(settled.get("finalized"), Some(&Json::Bool(true)));
}

/// The two subtractions cannot panic, even on a state that violates the
/// one-sided invariant they rest on.
///
/// `issued_sat <= TOTAL_SUPPLY_SAT` is enforced in `compute_post_state`, so a
/// state this node accepted cannot get here. But a query surface that panics
/// when an invariant it does not own is broken turns a consensus bug into a
/// dead node — on an unauthenticated port, that is the whole attack.
#[test]
fn getsupply_does_not_panic_when_the_supply_invariant_is_violated() {
    use bloch_pos_committee::tokenomics_v4::{GENESIS_ISSUED_SAT, TOTAL_SUPPLY_SAT};

    let over = supply_json(TOTAL_SUPPLY_SAT + 1, TOTAL_SUPPLY_SAT, GENESIS_ISSUED_SAT, 0, 0, 0);
    assert_eq!(over.get("remaining_sat").unwrap().as_str(), Some("0"));

    let under = supply_json(0, TOTAL_SUPPLY_SAT, GENESIS_ISSUED_SAT, 0, 0, 0);
    assert_eq!(under.get("emitted_since_genesis_sat").unwrap().as_str(), Some("0"));
}

/// `getvalidators` pages by registry index, and `next_start` is an index.
#[test]
fn getvalidators_pages_by_index_and_stops_without_looping() {
    let st = state_with_balances();
    let effective: Vec<(u32, u64)> =
        st.active_validators().iter().map(|v| (v.index, v.effective_stake)).collect();

    // A page shorter than the limit is the end of the registry. `next_start`
    // must be null: a client that kept paging on a non-null cursor here would
    // poll this method forever, on a port with no rate limit.
    let all = st.validator_records(0, 50);
    assert_eq!(all.len(), 2);
    let v = validators_json(&all, &effective, st.validator_count(), 0, 50, 0);
    assert_eq!(v.get("total").unwrap().as_u64(), Some(2));
    assert_eq!(v.get("returned").unwrap().as_u64(), Some(2));
    assert_eq!(v.get("next_start"), Some(&Json::Null));

    // A full page carries a cursor, and the cursor is `last index + 1` — NOT
    // `start + limit`. The registry is a map and may be sparse; a client that
    // computes the offset itself skips records the moment an index is missing.
    let first = st.validator_records(0, 1);
    let v1 = validators_json(&first, &effective, st.validator_count(), 0, 1, 0);
    assert_eq!(v1.get("returned").unwrap().as_u64(), Some(1));
    assert_eq!(v1.get("next_start").unwrap().as_u64(), Some(1));

    // Resuming from the cursor yields the rest. This page is ALSO exactly full,
    // so it carries a cursor even though it ended the registry — a full page
    // cannot know it was the last one without reading a record past it, and
    // that peek would cost a clone of a ~3.7 KB key on every page to save one
    // lookup on the last.
    let second = st.validator_records(1, 1);
    let v2 = validators_json(&second, &effective, st.validator_count(), 1, 1, 0);
    let Some(Json::Arr(recs)) = v2.get("validators") else { panic!("no validators array") };
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].get("index").unwrap().as_u64(), Some(1));
    assert_eq!(v2.get("next_start").unwrap().as_u64(), Some(2));

    // The walk terminates on the empty page, which is why a client must stop on
    // `next_start: null` and never on arithmetic over `total`.
    let third = st.validator_records(2, 1);
    assert!(third.is_empty());
    let v3 = validators_json(&third, &effective, st.validator_count(), 2, 1, 0);
    assert_eq!(v3.get("returned").unwrap().as_u64(), Some(0));
    assert_eq!(v3.get("next_start"), Some(&Json::Null));

    // Starting past the end is empty, not an error: a validator can exit
    // between two pages and a scanner must not treat that as a failure.
    let past = st.validator_records(9_999, 50);
    assert!(past.is_empty());
    let vp = validators_json(&past, &effective, st.validator_count(), 9_999, 50, 0);
    assert_eq!(vp.get("returned").unwrap().as_u64(), Some(0));
    assert_eq!(vp.get("next_start"), Some(&Json::Null));
}

/// The page record is byte-for-byte the `getvalidator` record.
///
/// One definition of what a validator looks like, so a client that already
/// parses the single-record method needs no new code — and so the two cannot
/// drift into disagreeing about the same validator.
#[test]
fn getvalidators_reuses_the_getvalidator_record_verbatim() {
    let st = state_with_balances();
    let effective: Vec<(u32, u64)> =
        st.active_validators().iter().map(|v| (v.index, v.effective_stake)).collect();

    let single = validator_json(
        &st.validator_record(1).unwrap(),
        effective.iter().find(|(i, _)| *i == 1).map(|(_, s)| *s),
        0,
    );
    let page = validators_json(&st.validator_records(1, 1), &effective, 2, 1, 1, 0);
    let Some(Json::Arr(recs)) = page.get("validators") else { panic!() };
    assert_eq!(recs[0], single, "the paged record must be the single record");
}

/// The page limit is clamped, not rejected, and the clamp is visible.
#[test]
fn getvalidators_clamps_an_absurd_page_instead_of_refusing_it() {
    let RpcRequest::Validators { start, limit } =
        route("getvalidators", Some(&parse_json("[7, 99999999]").unwrap())).unwrap()
    else {
        panic!("getvalidators must route to Validators")
    };
    assert_eq!(start, 7);
    assert_eq!(
        limit, VALIDATOR_PAGE_MAX,
        "an unbounded page is a memory amplifier on a port with no authentication"
    );

    // Defaults, so the cheap call is the one a client makes by accident.
    let RpcRequest::Validators { start, limit } = route("getvalidators", None).unwrap() else {
        panic!()
    };
    assert_eq!((start, limit), (0, VALIDATOR_PAGE_DEFAULT));

    // A start that is not a u32 index is invalid params, not a silent wrap to
    // zero — wrapping would hand back page one and call it page four billion.
    let huge = parse_json("[4294967296]").unwrap();
    assert_eq!(
        route("getvalidators", Some(&huge)).err().map(|e| e.code),
        Some(-32602)
    );
}

/// `getstakedistribution` answers at the one-third threshold, which is the one
/// that decides whether finality can be reverted.
#[test]
fn getstakedistribution_reports_nakamoto_at_one_third() {
    // Four validators at 40 / 30 / 20 / 10. Total 100.
    // > 1/3 (33.3): 40 alone clears it            → 1
    // > 1/2 (50):   40 + 30 = 70 clears it        → 2
    let roster = [(0u32, 40u64), (1, 30), (2, 20), (3, 10)];
    let v = stake_distribution_json(&roster, 100, 1_704);

    assert_eq!(v.get("epoch").unwrap().as_u64(), Some(1_704));
    assert_eq!(v.get("active").unwrap().as_u64(), Some(4));
    assert_eq!(v.get("total_active_stake_sat").unwrap().as_str(), Some("100"));

    let nc = v.get("nakamoto_coefficient").unwrap();
    assert_eq!(
        nc.get("one_third").unwrap().as_u64(),
        Some(1),
        "one_third is THE number: a finalized checkpoint reverts at one third"
    );
    assert_eq!(nc.get("one_half").unwrap().as_u64(), Some(2));

    // Strictly greater, not `>=`. Three validators at exactly one third each:
    // one of them holds exactly 1/3 and cannot revert anything alone, so the
    // coefficient is 2. A `>=` would name a set that cannot do the thing the
    // number claims it can.
    let thirds = [(0u32, 10u64), (1, 10), (2, 10)];
    let t = stake_distribution_json(&thirds, 30, 0);
    assert_eq!(
        t.get("nakamoto_coefficient").unwrap().get("one_third").unwrap().as_u64(),
        Some(2),
        "holding exactly one third is not holding more than one third"
    );
}

/// The response does not grow with the validator set, and it says what it
/// cannot know.
#[test]
fn getstakedistribution_is_fixed_size_and_disclaims_what_it_measures() {
    let roster: Vec<(u32, u64)> = (0..500u32).map(|i| (i, u64::from(i) + 1)).collect();
    let v = stake_distribution_json(&roster, 0, 7);

    let Some(Json::Arr(top)) = v.get("top") else { panic!("no top array") };
    assert_eq!(
        top.len(),
        STAKE_TOP_N,
        "the per-validator list must be capped, or the response size tracks V"
    );
    // Descending, so `top[0]` is the largest holder.
    assert_eq!(top[0].get("index").unwrap().as_u64(), Some(499));
    assert_eq!(top[0].get("effective_stake_sat").unwrap().as_str(), Some("500"));
    assert_eq!(v.get("active").unwrap().as_u64(), Some(500));

    // The disclaimer is a field, because a client rendering this as
    // "decentralisation" must render the disclaimer with it. Sixty-four indices
    // can be — and on this chain today largely are — one operator.
    assert_eq!(v.get("measures").unwrap().as_str(), Some("stake_by_validator_index"));
    let note = v.get("measures_note").unwrap().as_str().unwrap();
    assert!(note.contains("not per operator"));
    assert!(note.contains("one third"));

    // Shares are over the denominator this response publishes, so they sum to
    // 10,000 bps. Publishing one total and computing with another is how a
    // distribution that does not add up gets shipped.
    let total: u128 =
        v.get("total_active_stake_sat").unwrap().as_str().unwrap().parse().unwrap();
    assert_eq!(total, roster.iter().map(|(_, s)| u128::from(*s)).sum::<u128>());
}

/// Ties are broken deterministically, so two honest nodes on the same state
/// return the same list.
///
/// Without the tiebreak a third party diffing two nodes reads a disagreement
/// that is not there — and disagreement between nodes is exactly the thing this
/// chain's operators have spent weeks chasing for real.
#[test]
fn getstakedistribution_orders_ties_by_index() {
    let roster = [(9u32, 5u64), (2, 5), (7, 5), (4, 5)];
    let v = stake_distribution_json(&roster, 20, 0);
    let Some(Json::Arr(top)) = v.get("top") else { panic!() };
    let order: Vec<u64> = top.iter().map(|t| t.get("index").unwrap().as_u64().unwrap()).collect();
    assert_eq!(order, vec![2, 4, 7, 9]);
}

/// An empty or zero-stake active set answers, rather than dividing by zero.
///
/// Reachable for real: the inactivity leak drives effective stake toward zero,
/// and this chain has run with the leak biting.
#[test]
fn getstakedistribution_survives_an_empty_and_a_zero_stake_roster() {
    let empty = stake_distribution_json(&[], 0, 3);
    assert_eq!(empty.get("active").unwrap().as_u64(), Some(0));
    assert_eq!(empty.get("total_active_stake_sat").unwrap().as_str(), Some("0"));
    let nc = empty.get("nakamoto_coefficient").unwrap();
    assert_eq!(nc.get("one_third"), Some(&Json::Null));
    assert_eq!(nc.get("one_half"), Some(&Json::Null));
    assert_eq!(empty.get("gini_bps").unwrap().as_u64(), Some(0));
    assert_eq!(empty.get("quantiles").unwrap().get("p50_sat"), Some(&Json::Null));

    // Fully leaked: the validators are in the roster at zero, which is a
    // different fact from their absence and must not be a panic.
    let leaked = [(0u32, 0u64), (1, 0)];
    let v = stake_distribution_json(&leaked, 500, 3);
    assert_eq!(v.get("active").unwrap().as_u64(), Some(2));
    assert_eq!(
        v.get("duty_total_active_stake_sat").unwrap().as_str(),
        Some("500"),
        "the pre-leak figure getchaininfo publishes must be reported beside, and \
         apart from, the denominator used here"
    );
    let Some(Json::Arr(top)) = v.get("top") else { panic!() };
    assert_eq!(top[0].get("share_bps"), Some(&Json::Null));
}

/// Gini is 0 at perfect equality and approaches 10,000 as one holder takes all.
#[test]
fn gini_reads_zero_for_equality_and_climbs_with_concentration() {
    let equal = stake_distribution_json(&[(0, 10), (1, 10), (2, 10), (3, 10)], 40, 0);
    assert_eq!(equal.get("gini_bps").unwrap().as_u64(), Some(0));

    let skewed = stake_distribution_json(&[(0, 1), (1, 1), (2, 1), (3, 9_997)], 10_000, 0);
    let g = skewed.get("gini_bps").unwrap().as_u64().unwrap();
    assert!(g > 7_000, "one holder with 99.97% must read as extreme, got {g} bps");
    assert!(g <= 10_000, "a coefficient above 1.0 is arithmetic, not concentration");
}

/// The three new names route to their own requests, and the two paginated
/// arguments are the only ones a caller controls.
#[test]
fn the_three_new_reads_route_to_their_own_requests() {
    let spy = Spy::new();
    for (method, want) in [
        ("getsupply", RpcRequest::Supply),
        ("getstakedistribution", RpcRequest::StakeDistribution),
    ] {
        call(spy.as_ref(), &request(method, "[]"));
        assert_eq!(spy.last(), Some(want), "`{method}` must reach its own arm");
    }

    // Named params, like every other method on this surface.
    call(spy.as_ref(), &request("getvalidators", r#"{"start": 3, "limit": 2}"#));
    assert_eq!(spy.last(), Some(RpcRequest::Validators { start: 3, limit: 2 }));
}

/// What the three new reads cost, at the live validator count and at 8x it.
///
/// `cargo test -p bloch-pos-node --bin bloch-pos --release -- --ignored \
/// what_the_new_reads_cost -- --nocapture`
///
/// # Why this is a separate measurement
///
/// `what_a_read_costs_at_carryover_scale` needs the 452,726-entry carryover to
/// say anything, and building it is why that test has never been run to
/// completion on a busy box. **None of the three methods here touches the eUTXO
/// set** — that is the property that makes them safe to add — so the state they
/// need is 64 validators and nothing else, and this runs in seconds. Anything
/// that makes one of these methods depend on the carryover has changed what it
/// is, and belongs in the other test.
///
/// The pubkeys are 3,745 bytes, which is a real hybrid ML-DSA-65 ‖ Falcon-1024
/// public key, because `pubkey_hash` is SHA3-256 over that and it is the
/// dominant per-record cost of `getvalidators`. A 64-byte stub would understate
/// the page by nearly two orders of magnitude.
///
/// V=512 is measured beside V=64 to answer the only question that matters for
/// the validator-opening program: whether these methods stay cheap when the
/// registry stops being 64.
#[test]
#[ignore = "a measurement of the new read surface, not a pass/fail assertion"]
fn what_the_new_reads_cost() {
    use bloch_pos_committee::tokenomics_v4::{GENESIS_ISSUED_SAT, TOTAL_SUPPLY_SAT};
    use std::time::Instant;

    // A real hybrid PQ public key's length: ML-DSA-65 (1,952) + Falcon-1024
    // (1,793). `pubkey_hash` hashes all of it, per record, per page.
    const HYBRID_PUBKEY_BYTES: usize = 3_745;

    for v_count in [64u32, 512] {
        let validators: Vec<GenesisValidator> = (0..v_count)
            .map(|i| GenesisValidator {
                index: i,
                pubkey: vec![(i % 251) as u8; HYBRID_PUBKEY_BYTES],
                // Deliberately unequal, so the sort, the quantiles and the
                // Nakamoto walk all do real work instead of hitting a tie path.
                staked_sat: u128::from(i + 1) * 1_000 * 100_000_000,
                randao_commitment: [1u8; 32],
                withdrawal_credentials: vec![],
                commission_bps: 500,
            })
            .collect();
        let actives: Vec<u32> = (0..v_count).collect();

        let state = CommittedState::genesis(
            BlockId::of(&genesis_header()),
            [9u8; 32],
            &validators,
            &actives,
            [0u8; 32],
            [0u8; 32],
            [0u8; 32],
            EvmCommitment {
                account_root: [0u8; 32],
                receipts_root: [0u8; 32],
                gas_used: 0,
                base_fee_per_gas: 0,
            },
            &[],
        );

        println!("\n── V = {v_count} ──────────────────────────────────────────");

        // Best of N. A single sample on a shared box measures the scheduler.
        let best = |label: &str, mut f: &mut dyn FnMut()| {
            let mut best = std::time::Duration::from_secs(999);
            for _ in 0..15 {
                let t = Instant::now();
                f();
                best = best.min(t.elapsed());
            }
            println!("  {label:<34} {best:?}");
            best
        };

        // getsupply: a field read and two constants. This must not move with V
        // — if it does, someone has made it read state it does not need.
        best("getsupply", &mut || {
            let _ = supply_json(
                state.issued_sat(),
                TOTAL_SUPPLY_SAT,
                GENESIS_ISSUED_SAT,
                state.slot(),
                0,
                0,
            );
        });

        // The roster build the other two share, priced on its own so the
        // per-method numbers below can be read as "roster + the method".
        best("  (roster build alone)", &mut || {
            let _: Vec<(u32, u64)> = state
                .active_validators()
                .iter()
                .map(|v| (v.index, v.effective_stake))
                .collect();
        });

        let roster: Vec<(u32, u64)> =
            state.active_validators().iter().map(|v| (v.index, v.effective_stake)).collect();

        for limit in [VALIDATOR_PAGE_DEFAULT, VALIDATOR_PAGE_MAX] {
            best(&format!("getvalidators limit={limit}"), &mut || {
                let r: Vec<(u32, u64)> = state
                    .active_validators()
                    .iter()
                    .map(|v| (v.index, v.effective_stake))
                    .collect();
                let page = state.validator_records(0, limit);
                let _ = validators_json(&page, &r, state.validator_count(), 0, limit, 0);
            });
        }

        // The quadratic shape this signature exists to prevent, measured so the
        // claim in `validators_json`'s doc is a number and not an assertion.
        // Rebuilding the roster per record is what a naive implementation does.
        let page = state.validator_records(0, VALIDATOR_PAGE_DEFAULT);
        best("  naive per-record roster (page=50)", &mut || {
            for rec in &page {
                let eff = state
                    .active_validators()
                    .iter()
                    .find(|v| v.index == rec.index)
                    .map(|v| v.effective_stake);
                let _ = validator_json(rec, eff, 0);
            }
        });

        best("getstakedistribution", &mut || {
            let r: Vec<(u32, u64)> = state
                .active_validators()
                .iter()
                .map(|v| (v.index, v.effective_stake))
                .collect();
            let _ = stake_distribution_json(&r, 0, 0);
        });

        // The response size, which is the anti-DoS property: it must not track
        // V. Printed as bytes, because "fixed-size" is checkable and "small" is
        // not.
        let sd = stake_distribution_json(&roster, 0, 0).to_string().len();
        let sup = supply_json(0, TOTAL_SUPPLY_SAT, GENESIS_ISSUED_SAT, 0, 0, 0).to_string().len();
        let pg = validators_json(
            &state.validator_records(0, VALIDATOR_PAGE_DEFAULT),
            &roster,
            state.validator_count(),
            0,
            VALIDATOR_PAGE_DEFAULT,
            0,
        )
        .to_string()
        .len();
        println!("  response bytes: getsupply {sup}, getstakedistribution {sd}, \
                  getvalidators(50) {pg}");
    }
}

/// The `getvalidators` page cap stays inside the cost of the worst read this
/// surface already sanctions.
///
/// This is a constant assertion rather than a timing one on purpose — a
/// stopwatch in CI measures the box. The number behind it comes from
/// `what_the_new_reads_cost`: `pubkey_hash` is SHA3-256 over 3,745 bytes of
/// hybrid ML-DSA-65 ‖ Falcon-1024 key material and costs **~32 µs per record**,
/// so a page costs `limit × 32 µs` and nothing else of consequence.
///
/// At the proposed ceiling of 500 that is **17.1 ms**, measured at V=512 — one
/// uninterruptible block of the consensus thread, on a port with no
/// authentication and no rate limit. `getbalance` warm is ~1.7 ms and is the
/// most expensive read this surface currently permits. A cap of 50 keeps the
/// worst page at ~1.6 ms, so `getvalidators` adds **no new lever**: its worst
/// case is the worst case that already existed.
///
/// If you are here because you raised the cap: the fix is to cache
/// `pubkey_hash` on the validator record so a page stops being a hashing job,
/// not to widen the bound. Raising it without that re-introduces exactly the
/// amplifier this number closes.
#[test]
fn the_validator_page_cap_stays_within_the_worst_sanctioned_read() {
    /// Measured, release build: SHA3-256 over one 3,745-byte hybrid pubkey.
    const PUBKEY_HASH_MICROS: usize = 32;
    /// `getbalance` warm at the live carryover, per `balance_json`'s corrected
    /// note. The most expensive read this surface sanctions.
    const WORST_SANCTIONED_MICROS: usize = 1_700;

    let worst_page = VALIDATOR_PAGE_MAX * PUBKEY_HASH_MICROS;
    assert!(
        worst_page <= WORST_SANCTIONED_MICROS,
        "a full `getvalidators` page would cost ~{worst_page} µs, above the \
         ~{WORST_SANCTIONED_MICROS} µs of the worst read this surface already \
         permits. That is a NEW lever for an unauthenticated caller on the \
         consensus thread. Cache `pubkey_hash` on the record instead of raising \
         VALIDATOR_PAGE_MAX ({VALIDATOR_PAGE_MAX})."
    );
    assert!(
        VALIDATOR_PAGE_DEFAULT <= VALIDATOR_PAGE_MAX,
        "the default page must fit inside the cap, or the cheap call a client \
         makes by accident is the clamped one"
    );
}
