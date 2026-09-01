// SPDX-License-Identifier: AGPL-3.0-or-later

//! Weak-subjectivity ceremony tooling — the *publication* side of `ws_boot`.
//!
//! `ws_boot` is the consumer: it reads a checkpoint envelope and a signer-set
//! file at node boot and verifies them (`--ws-checkpoint` / `--ws-signer-set`,
//! BLOCH-WEAK-SUBJECTIVITY.md §4.1). Until this module existed nothing
//! *produced* those artifacts — the encoders sat in `ws_boot` marked "written
//! by the release/ceremony side", and the ceremony side was nobody. These
//! subcommands are that side:
//!
//! ```text
//! ws-keygen      one signer's hybrid keypair (run on the signer's own
//!                air-gapped machine — BLOCH-GENESIS-KEYS.md rule zero)
//! ws-signer-set  assemble the §6 arrangement file from the signers' PUBLIC
//!                keys
//! ws-checkpoint  derive the canonical 154-byte checkpoint for a FINALIZED
//!                epoch from a running node's RPC, plus its JSON view and the
//!                ws digest the signers sign
//! ws-sign        sign a checkpoint's ws digest with one signer's secret key
//!                (offline-capable: file in, file out, no network)
//! ws-envelope    assemble checkpoint + signatures into the distribution
//!                envelope `--ws-checkpoint` consumes
//! ws-verify      verify an envelope exactly as a booting node would
//! ```
//!
//! ## Division of labor, restated
//!
//! The byte formats are NOT defined here. The canonical 154 bytes are
//! `bloch_pos_committee::ws::WeakSubjectivityCheckpoint::canonical_serialize`;
//! the file framings are `ws_boot::encode_envelope_file` /
//! `encode_signer_set_file`; the digest is `ws_digest` under `DS_WSCKPT`.
//! This module only moves bytes between files, the RPC, and those functions —
//! so the artifact a ceremony produces is verified by the very code the node
//! boots with, not by a parallel implementation that could drift.
//!
//! ## What `ws-checkpoint` trusts, said plainly
//!
//! The checkpoint fields come from a node RPC the operator names. The RPC
//! answers from that node's own validated state, and the tool corroborates
//! across every `--rpc` endpoint given, refusing on any disagreement — but a
//! single endpoint is a single witness, and the tool says so out loud. The
//! signing ceremony is where the trust actually enters (§6); this tool's job
//! is to make what is being signed exact, reproducible, and checkable by every
//! signer independently before they sign.

use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::exit;
use std::time::Duration;

use bloch_pos_committee::params::SLOTS_PER_EPOCH;
use bloch_pos_committee::staking::HYBRID_PK_BYTES;
use bloch_pos_committee::ws::{
    self, CheckpointEnvelope, Signer, SignerSet, WeakSubjectivityCheckpoint, WS_FORMAT_VERSION,
    WS_GENESIS_SIGNER_SET_ID,
};

use crate::codec::{hex, hex32, unhex};
use crate::rpc::{parse_json, Json};
use crate::ws_boot::{
    self, decode_checkpoint, decode_envelope_file, decode_signer_set_file, encode_envelope_file,
    encode_signer_set_file, WsHybridVerifier,
};

/// How far below the epoch's first slot the boundary-block scan will look.
/// The checkpoint block of epoch `E` is the last canonical block strictly
/// before `E`'s first slot (`engine::checkpoint_root`'s convention — the one
/// `ws::cross_check` compares against, so the artifact MUST use it). On the
/// live chain empty slots are common but a gap of a whole day is not; a scan
/// that runs this deep means the RPC is answering for a chain in real
/// trouble, and a checkpoint should not be minted from it unattended.
const BOUNDARY_SCAN_SLOTS: u64 = 1024;

pub fn run(cmd: &str, args: &[String]) {
    let outcome = match cmd {
        "ws-keygen" => keygen(args),
        "ws-signer-set" => signer_set(args),
        "ws-checkpoint" => checkpoint(args),
        "ws-sign" => sign(args),
        "ws-envelope" => envelope(args),
        "ws-verify" => verify(args),
        _ => unreachable!("main dispatches only the commands above"),
    };
    if let Err(msg) = outcome {
        eprintln!("{cmd}: {msg}");
        exit(1);
    }
}

// ─── Shared helpers ─────────────────────────────────────────────────────────

fn req(args: &[String], name: &str) -> Result<String, String> {
    crate::arg_value(args, name).ok_or_else(|| format!("{name} is required"))
}

/// Every occurrence of a repeatable flag, in command-line order — order is
/// meaning for `--signer` (position = signer index).
fn all_values(args: &[String], name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == name {
            if let Some(v) = it.next() {
                out.push(v.clone());
            }
        }
    }
    out
}

fn read_hex_file(path: &str) -> Result<Vec<u8>, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    unhex(text.trim()).map_err(|e| format!("{path}: {e}"))
}

fn write_file(path: &str, bytes: &[u8], secret: bool) -> Result<(), String> {
    fs::write(path, bytes).map_err(|e| format!("cannot write {path}: {e}"))?;
    if secret {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .map_err(|e| format!("cannot chmod {path}: {e}"))?;
        }
    }
    Ok(())
}

/// Strip the 4-byte suite envelope `bloch_crypto` wraps around keys and
/// signatures, refusing any suite but the hybrid one. The WS wire formats
/// carry RAW halves (`ws::Signer::pubkey` is `[u8; HYBRID_PK_BYTES]`, and
/// `verify_hybrid` splits the signature at the fixed ML-DSA point), so the
/// envelope is shed exactly once, here, on the way in.
fn strip_suite(bytes: &[u8], what: &str) -> Result<Vec<u8>, String> {
    let (suite, body) = bloch_crypto::crypto::split_envelope(bytes)
        .ok_or_else(|| format!("{what}: not a suite-enveloped value"))?;
    if suite != bloch_crypto::crypto::SUITE_MLDSA65_FALCON1024 {
        return Err(format!(
            "{what}: suite {suite:#06x} is not the hybrid ML-DSA-65 ‖ Falcon-1024 suite"
        ));
    }
    Ok(body.to_vec())
}

/// The chain identity a manifest fixes: `(network_id, genesis_root)`.
/// Computed exactly as the node computes it at boot (`engine::run`):
/// `network_id` is the first four little-endian bytes of the manifest's
/// SHA3-256 digest (`ws_boot::network_id_of`), `genesis_root` is the genesis
/// block id the manifest derives.
fn manifest_identity(path: &str) -> Result<(u32, [u8; 32]), String> {
    let bytes = fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    use sha3::{Digest, Sha3_256};
    let digest: [u8; 32] = Sha3_256::digest(&bytes).into();
    let manifest = crate::genesis::Manifest::decode(&bytes)
        .map_err(|e| format!("{path}: not a genesis manifest: {e}"))?;
    Ok((ws_boot::network_id_of(&digest), *manifest.genesis_id().as_bytes()))
}

fn parse_hex32(s: &str, what: &str) -> Result<[u8; 32], String> {
    let b = unhex(s).map_err(|e| format!("{what}: {e}"))?;
    b.try_into().map_err(|b: Vec<u8>| format!("{what}: {} bytes, expected 32", b.len()))
}

// ─── JSON-RPC client (the subset the ceremony needs) ────────────────────────

/// One JSON-RPC call over HTTP/1.1. The node's server answers one request per
/// connection and closes (`rpc::serve_connection`), so the client writes one
/// POST and reads to EOF; parsing reuses `rpc::parse_json` — the same JSON
/// code the node itself runs.
fn rpc_call(addr: &str, method: &str, params: Vec<Json>) -> Result<Json, String> {
    let request = Json::obj(vec![
        ("jsonrpc", Json::s("2.0")),
        ("id", Json::u(1)),
        ("method", Json::s(method)),
        ("params", Json::Arr(params)),
    ])
    .to_string();

    let mut sock = TcpStream::connect(addr).map_err(|e| format!("{addr}: connect: {e}"))?;
    let timeout = Some(Duration::from_secs(10));
    let _ = sock.set_read_timeout(timeout);
    let _ = sock.set_write_timeout(timeout);
    let head = format!(
        "POST / HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        request.len()
    );
    sock.write_all(head.as_bytes())
        .and_then(|()| sock.write_all(request.as_bytes()))
        .map_err(|e| format!("{addr}: send: {e}"))?;

    let mut raw = Vec::new();
    // EOF is the normal end; a timeout after a complete response is tolerated
    // rather than fatal, because the bytes in hand are what matter.
    let _ = sock.read_to_end(&mut raw);
    let text = String::from_utf8_lossy(&raw);
    let (status_line, rest) = text
        .split_once("\r\n")
        .ok_or_else(|| format!("{addr}: malformed HTTP response"))?;
    if !status_line.contains(" 200 ") {
        return Err(format!("{addr}: {status_line}"));
    }
    let body = rest
        .split_once("\r\n\r\n")
        .map(|(_, b)| b)
        .ok_or_else(|| format!("{addr}: response has no body"))?;
    let json = parse_json(body.trim()).map_err(|e| format!("{addr}: bad JSON: {e}"))?;
    if let Some(err) = json.get("error") {
        if !matches!(err, Json::Null) {
            return Err(format!("{addr}: {method}: {}", err.to_string()));
        }
    }
    json.get("result")
        .cloned()
        .ok_or_else(|| format!("{addr}: {method}: no result"))
}

fn field_u64(j: &Json, key: &str, ctx: &str) -> Result<u64, String> {
    j.get(key)
        .and_then(Json::as_u64)
        .ok_or_else(|| format!("{ctx}: missing or non-integer `{key}`"))
}

fn field_hex32(j: &Json, key: &str, ctx: &str) -> Result<[u8; 32], String> {
    let s = j
        .get(key)
        .and_then(Json::as_str)
        .ok_or_else(|| format!("{ctx}: missing `{key}`"))?;
    parse_hex32(s, &format!("{ctx}.{key}"))
}

/// What one RPC endpoint says the checkpoint fields are. Everything a second
/// endpoint must agree on before the artifact is minted.
#[derive(PartialEq, Eq)]
struct ChainView {
    genesis_block: [u8; 32],
    boundary_slot: u64,
    block_root: [u8; 32],
    state_root: [u8; 32],
}

/// Derive the epoch-`epoch` checkpoint fields from one node.
fn view_of(addr: &str, epoch: u64) -> Result<ChainView, String> {
    let info = rpc_call(addr, "getchaininfo", vec![])?;
    let fin = info
        .get("finalized")
        .ok_or_else(|| format!("{addr}: getchaininfo has no `finalized`"))?;
    let fin_epoch = field_u64(fin, "epoch", "finalized")?;
    let fin_root = field_hex32(fin, "root", "finalized")?;
    // The rule that makes this tool safe to leave lying around: it will not
    // mint a checkpoint at anything the chain has not finalized. A checkpoint
    // at an unfinalized point could be reorged out from under everyone who
    // trusted it — worse than publishing nothing.
    if fin_epoch < epoch {
        return Err(format!(
            "{addr}: epoch {epoch} is NOT finalized (node's finalized epoch is {fin_epoch}); \
             refusing — a checkpoint must attest a finalized epoch, never a head"
        ));
    }

    let genesis = rpc_call(addr, "getblockbyslot", vec![Json::u(0)])?;
    let genesis_block = field_hex32(&genesis, "block_id", "genesis block")?;

    // The boundary block: last canonical block strictly before the epoch's
    // first slot — `engine::checkpoint_root`'s convention, which is the root
    // this chain's own attesters voted and its finality store holds. Missed
    // slots simply answer with an error, so scan downward.
    let first_slot = epoch
        .checked_mul(SLOTS_PER_EPOCH)
        .ok_or_else(|| format!("epoch {epoch} overflows the slot space"))?;
    let mut found: Option<(u64, Json)> = None;
    for s in (first_slot.saturating_sub(BOUNDARY_SCAN_SLOTS)..first_slot).rev() {
        if let Ok(block) = rpc_call(addr, "getblockbyslot", vec![Json::u(s)]) {
            found = Some((s, block));
            break;
        }
    }
    let (boundary_slot, block) = found.ok_or_else(|| {
        format!(
            "{addr}: no block in the {BOUNDARY_SCAN_SLOTS} slots below slot {first_slot} — \
             refusing to derive a checkpoint from a chain with a gap that deep"
        )
    })?;
    if block.get("finalized") != Some(&Json::Bool(true)) {
        return Err(format!(
            "{addr}: the epoch-{epoch} boundary block (slot {boundary_slot}) does not report \
             `finalized: true`; refusing"
        ));
    }
    let block_root = field_hex32(&block, "block_id", "boundary block")?;
    let state_root = field_hex32(&block, "state_root", "boundary block")?;
    // When the node's finalized checkpoint IS the requested epoch, its root
    // must equal the boundary block just derived — a free cross-check that
    // the scan reproduced the finality store's own convention.
    if fin_epoch == epoch && fin_root != block_root {
        return Err(format!(
            "{addr}: derived boundary block {} disagrees with the node's finalized root {} \
             at the same epoch {epoch} — convention drift, refusing",
            hex32(&block_root),
            hex32(&fin_root),
        ));
    }
    Ok(ChainView { genesis_block, boundary_slot, block_root, state_root })
}

// ─── ws-keygen ──────────────────────────────────────────────────────────────

/// `ws-keygen --out <prefix>` → `<prefix>.pk` (0644) and `<prefix>.sk`
/// (0600), hex of the suite-enveloped hybrid halves.
///
/// Checkpoint signers are not validators (`ws_boot::WsHybridVerifier`'s
/// distinction), so this does not write a validator keystore — just the
/// keypair, in the same enveloped form `bloch_crypto` mints. The key-hygiene
/// rule is the same as `keygen`'s, stated where the ceremony will read it:
/// run this ON THE SIGNER'S OWN AIR-GAPPED MACHINE. A signer key generated in
/// an observable session — a shared shell, a screen recording, a CI log — is
/// a signer that never existed.
fn keygen(args: &[String]) -> Result<(), String> {
    let prefix = req(args, "--out")?;
    let (pk, sk) = bloch_crypto::crypto::generate_keypair();
    // Fail on a malformed key before anything touches disk.
    let raw = strip_suite(&pk, "generated pubkey")?;
    if raw.len() != HYBRID_PK_BYTES {
        return Err(format!(
            "generated pubkey is {} raw bytes, expected {HYBRID_PK_BYTES}",
            raw.len()
        ));
    }
    let pk_path = format!("{prefix}.pk");
    let sk_path = format!("{prefix}.sk");
    if Path::new(&sk_path).exists() {
        return Err(format!("{sk_path} already exists; refusing to overwrite a signer key"));
    }
    write_file(&pk_path, hex(&pk).as_bytes(), false)?;
    write_file(&sk_path, hex(&sk).as_bytes(), true)?;
    println!("wrote {pk_path} (public — hand this to the signer-set assembler)");
    println!("wrote {sk_path} (SECRET, 0600 — never leaves this machine)");
    println!(
        "reminder: a weak-subjectivity signer key belongs on an air-gapped machine \
         (BLOCH-GENESIS-KEYS.md rule zero). If this session was observable, delete both \
         files and generate again where it is not."
    );
    Ok(())
}

// ─── ws-signer-set ──────────────────────────────────────────────────────────

/// `ws-signer-set --id <n> --threshold <m> --min-external <k>
///  --adopted-epoch <e> --signer <pkfile>:<internal|external> ... --out <file>`
///
/// `--signer` order IS the signer index (`signer_index` in envelopes indexes
/// into this order), so the arrangement's published table and this command
/// line must list the same keys in the same order.
fn signer_set(args: &[String]) -> Result<(), String> {
    let id: u32 = req(args, "--id")?.parse().map_err(|_| "--id must be a u32".to_string())?;
    if id == WS_GENESIS_SIGNER_SET_ID {
        return Err(format!(
            "signer-set id {WS_GENESIS_SIGNER_SET_ID} is reserved for the genesis anchor \
             (ws::WS_GENESIS_SIGNER_SET_ID); the first real arrangement is id 1 (§6.1 Phase A)"
        ));
    }
    let threshold: usize =
        req(args, "--threshold")?.parse().map_err(|_| "--threshold must be a count".to_string())?;
    let min_external: usize = req(args, "--min-external")?
        .parse()
        .map_err(|_| "--min-external must be a count".to_string())?;
    let adopted_epoch: u64 = req(args, "--adopted-epoch")?
        .parse()
        .map_err(|_| "--adopted-epoch must be an epoch number".to_string())?;
    let out = req(args, "--out")?;

    let specs = all_values(args, "--signer");
    if specs.is_empty() {
        return Err("at least one --signer <pkfile>:<internal|external> is required".into());
    }
    let mut signers = Vec::with_capacity(specs.len());
    for spec in &specs {
        let (path, subset) = spec
            .rsplit_once(':')
            .ok_or_else(|| format!("--signer `{spec}`: expected <pkfile>:<internal|external>"))?;
        let external = match subset {
            "external" => true,
            "internal" => false,
            other => {
                return Err(format!(
                    "--signer `{spec}`: subset `{other}` must be `internal` or `external` \
                     (§6.1's subset column — this flag is verification data, not a label)"
                ))
            }
        };
        let raw = strip_suite(&read_hex_file(path)?, path)?;
        let pubkey: [u8; HYBRID_PK_BYTES] = raw
            .try_into()
            .map_err(|b: Vec<u8>| format!("{path}: {} raw bytes, expected {HYBRID_PK_BYTES}", b.len()))?;
        signers.push(Signer { pubkey, external });
    }

    let set = SignerSet { id, signers, threshold, min_external, adopted_epoch };
    let bytes = encode_signer_set_file(&set);
    // The decoder is the shape gate (incoherent quorums are refused there);
    // round-tripping our own output means a file this command wrote can never
    // be one the node refuses to read.
    decode_signer_set_file(&bytes).map_err(|e| format!("assembled set is incoherent: {e}"))?;
    write_file(&out, &bytes, false)?;

    let phase = if set.matches_policy(ws::WS_PHASE_A_THRESHOLD, ws::WS_PHASE_A_SIGNERS, ws::WS_PHASE_A_MIN_EXTERNAL)
    {
        "matches the §6.1 Phase A policy (2-of-3, ≥1 external)"
    } else if set.matches_policy(ws::WS_PHASE_B_THRESHOLD, ws::WS_PHASE_B_SIGNERS, ws::WS_PHASE_B_MIN_EXTERNAL)
    {
        "matches the §6.1 Phase B policy (3-of-5, ≥2 external)"
    } else {
        "MATCHES NEITHER §6.1 PHASE — fine for a drill, wrong for publication"
    };
    println!(
        "wrote {out}: signer set id {id}, {}-of-{}, ≥{} external, adopted at epoch {adopted_epoch}",
        set.threshold,
        set.signers.len(),
        set.min_external,
    );
    println!("policy: {phase}");
    Ok(())
}

// ─── ws-checkpoint ──────────────────────────────────────────────────────────

/// `ws-checkpoint --genesis <manifest> --rpc <host:port>[,<host:port>...]
///  --epoch <E> --signer-set-id <n> [--issued-at <unix-secs>]
///  [--validator-set-root <hex32>] --out <prefix>`
///
/// Writes `<prefix>.bin` (the canonical 154 bytes — §2.3's
/// `wscheckpoint-<epoch>.bin`) and `<prefix>.json` (the human view quoting
/// the ws digest). The digest printed at the end is the exact 32 bytes each
/// signer signs.
fn checkpoint(args: &[String]) -> Result<(), String> {
    let manifest_path = req(args, "--genesis")?;
    let rpcs: Vec<String> = req(args, "--rpc")?
        .split(',')
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();
    if rpcs.is_empty() {
        return Err("--rpc needs at least one <host:port>".into());
    }
    let epoch: u64 =
        req(args, "--epoch")?.parse().map_err(|_| "--epoch must be an epoch number".to_string())?;
    if epoch == 0 {
        return Err(
            "epoch 0 is the genesis anchor — release-baked under the reserved signer-set id, \
             never published as an envelope (ws::genesis_anchor)"
                .into(),
        );
    }
    let signer_set_id: u32 = req(args, "--signer-set-id")?
        .parse()
        .map_err(|_| "--signer-set-id must be a u32".to_string())?;
    if signer_set_id == WS_GENESIS_SIGNER_SET_ID {
        return Err("signer-set id 0 is reserved for the genesis anchor".into());
    }
    let out = req(args, "--out")?;
    let issued_at: u64 = match crate::arg_value(args, "--issued-at") {
        Some(s) => s.parse().map_err(|_| "--issued-at must be unix seconds".to_string())?,
        None => std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_secs(),
    };
    // No node computes a validator-registry SMT root at this milestone — the
    // genesis anchor carries zeros for the same reason (`engine::run`, "no
    // validator-set SMT root exposed at this milestone"). The field stays in
    // the format so the day state download exists the artifact does not
    // change shape; until then zeros are the honest value, and an override
    // exists for that day.
    let validator_set_root = match crate::arg_value(args, "--validator-set-root") {
        Some(s) => parse_hex32(&s, "--validator-set-root")?,
        None => [0u8; 32],
    };

    if !ws::is_publication_epoch(epoch) {
        println!(
            "note: epoch {epoch} is not a publication epoch (multiples of {}); verification \
             does not care, but the §3 cadence does",
            ws::WS_PUBLICATION_INTERVAL_EPOCHS
        );
    }

    let (network_id, genesis_root) = manifest_identity(&manifest_path)?;

    // Every endpoint must independently derive the same fields. One endpoint
    // is one witness; the runbook (and this fleet's own g4rpc house rule)
    // wants at least two, so a single-source run says so rather than looking
    // equally authoritative.
    let mut views: Vec<(String, ChainView)> = Vec::new();
    for addr in &rpcs {
        let v = view_of(addr, epoch)?;
        println!(
            "{addr}: boundary slot {} block {} state {}",
            v.boundary_slot,
            hex32(&v.block_root),
            hex32(&v.state_root)
        );
        views.push((addr.clone(), v));
    }
    let (first_addr, first) = &views[0];
    for (addr, v) in &views[1..] {
        if v != first {
            return Err(format!(
                "{addr} and {first_addr} DISAGREE on the epoch-{epoch} checkpoint — refusing. \
                 Do not pick a side from this tool; investigate the fork first \
                 ({addr}: block {}, {first_addr}: block {})",
                hex32(&v.block_root),
                hex32(&first.block_root),
            ));
        }
    }
    if first.genesis_block != genesis_root {
        return Err(format!(
            "the chain behind {first_addr} does not start from {manifest_path}: genesis block \
             {} vs manifest {} — wrong manifest or wrong network",
            hex32(&first.genesis_block),
            hex32(&genesis_root),
        ));
    }
    if views.len() == 1 {
        println!(
            "WARNING: single RPC endpoint — this artifact rests on one node's word. \
             Re-run with --rpc <a>,<b> against independently operated nodes before the \
             ceremony signs it."
        );
    }

    let cp = WeakSubjectivityCheckpoint {
        version: WS_FORMAT_VERSION,
        network_id,
        genesis_root,
        epoch,
        block_root: first.block_root,
        state_root: first.state_root,
        validator_set_root,
        issued_at,
        signer_set_id,
    };
    let bytes = cp.canonical_serialize();
    decode_checkpoint(&bytes).map_err(|e| format!("self-check failed: {e}"))?;
    let digest = cp.ws_digest();

    let bin_path = format!("{out}.bin");
    let json_path = format!("{out}.json");
    write_file(&bin_path, &bytes, false)?;
    // §2.3: the JSON is a *view*; the binary is the artifact. The view quotes
    // the digest so an announcement and the file can be compared by eye.
    let view = Json::obj(vec![
        ("format", Json::s("bloch-ws-checkpoint")),
        ("version", Json::u(u64::from(cp.version))),
        ("network_id", Json::u(u64::from(cp.network_id))),
        ("genesis_root", Json::hex(&cp.genesis_root)),
        ("epoch", Json::u(cp.epoch)),
        ("boundary_slot", Json::u(first.boundary_slot)),
        ("block_root", Json::hex(&cp.block_root)),
        ("state_root", Json::hex(&cp.state_root)),
        ("validator_set_root", Json::hex(&cp.validator_set_root)),
        ("issued_at", Json::u(cp.issued_at)),
        ("signer_set_id", Json::u(u64::from(cp.signer_set_id))),
        ("ws_digest", Json::hex(&digest)),
    ]);
    write_file(&json_path, format!("{}\n", view.to_string()).as_bytes(), false)?;

    println!("wrote {bin_path} ({} canonical bytes) and {json_path}", bytes.len());
    println!("ws digest (what each signer signs, and what announcements quote):");
    println!("  {}", hex32(&digest));
    println!(
        "next: each signer independently re-derives this digest against their own node, \
         then runs  bloch-pos ws-sign --key <their.sk> --checkpoint {bin_path} \
         --out <name>.sig  on their signing machine."
    );
    Ok(())
}

// ─── ws-sign ────────────────────────────────────────────────────────────────

/// `ws-sign --key <skfile> --checkpoint <file.bin> --out <sigfile>
///  [--pubkey <pkfile>]`
///
/// Offline by construction: files in, file out, no network. The checkpoint's
/// 154 canonical bytes travel to the signing machine; what is signed is
/// `ws_digest` — recomputed HERE from those bytes, never accepted as a bare
/// digest, so a signer cannot be handed a digest that matches no artifact.
fn sign(args: &[String]) -> Result<(), String> {
    let key_path = req(args, "--key")?;
    let cp_path = req(args, "--checkpoint")?;
    let out = req(args, "--out")?;

    let cp_bytes = fs::read(&cp_path).map_err(|e| format!("{cp_path}: {e}"))?;
    let cp = decode_checkpoint(&cp_bytes).map_err(|e| format!("{cp_path}: {e}"))?;
    let digest = cp.ws_digest();

    let sk = read_hex_file(&key_path)?;
    let enveloped = bloch_crypto::crypto::sign(&sk, &digest)
        .map_err(|e| format!("signing failed: {e:?}"))?;
    let raw = strip_suite(&enveloped, "produced signature")?;

    // Verify before writing when the public half is at hand — a signature
    // that does not verify under the signer's own key must die here, not at
    // a quorum assembly with two other humans waiting. The check runs through
    // `ws::verify_envelope` with a throwaway 1-of-1 arrangement built around
    // this one key: `staking::verify_hybrid` is `pub(crate)` to the frozen
    // committee crate, and re-implementing the AND-composition here is
    // exactly the copy `ws.rs` forbids — so the self-check uses the whole
    // real path instead, chain-identity fields taken from the checkpoint
    // itself so only the signature can fail it.
    if let Some(pk_path) = crate::arg_value(args, "--pubkey") {
        let raw_pk = strip_suite(&read_hex_file(&pk_path)?, &pk_path)?;
        let pubkey: [u8; HYBRID_PK_BYTES] = raw_pk
            .try_into()
            .map_err(|b: Vec<u8>| format!("{pk_path}: {} raw bytes, expected {HYBRID_PK_BYTES}", b.len()))?;
        let probe_set = SignerSet {
            id: cp.signer_set_id,
            signers: vec![Signer { pubkey, external: false }],
            threshold: 1,
            min_external: 0,
            adopted_epoch: cp.epoch,
        };
        let probe = CheckpointEnvelope { checkpoint: cp, signatures: vec![(0, raw.clone())] };
        if let Err(e) = ws::verify_envelope(
            &probe,
            &probe_set,
            cp.network_id,
            &cp.genesis_root,
            &WsHybridVerifier,
        ) {
            return Err(format!(
                "produced signature does not verify under --pubkey ({e:?}); not writing it"
            ));
        }
    }

    write_file(&out, hex(&raw).as_bytes(), false)?;
    println!("signed checkpoint epoch {} — ws digest {}", cp.epoch, hex32(&digest));
    println!("wrote {out} ({} raw hybrid signature bytes)", raw.len());
    Ok(())
}

// ─── ws-envelope ────────────────────────────────────────────────────────────

/// `ws-envelope --checkpoint <file.bin> --signer-set <set.bin>
///  --sig <index>:<sigfile> ... [--genesis <manifest>] --out <env.bin>`
///
/// Assemble the distribution envelope (§2.3's `wscheckpoint-<epoch>` artifact)
/// that `--ws-checkpoint` consumes — and REFUSE to write one a booting node
/// would reject.
///
/// The gate is the last thing this does before touching disk: it calls
/// `ws::verify_envelope`, the exact function `ws_boot::boot` calls, under the
/// real hybrid verifier, on the envelope it just built — and then again on the
/// envelope as re-read from its own file bytes, because what a node loads is
/// the file and not the value that happened to be in memory. Nothing is
/// written unless both pass. An under-quorum envelope, one missing its
/// external signature, one naming the wrong arrangement, or one whose
/// checkpoint has been altered after signing cannot come out of this command.
///
/// `--signer-set` is therefore required, not optional: without the
/// arrangement there is no quorum rule to check against, and an "assemble"
/// that cannot check is just a file concatenator.
fn envelope(args: &[String]) -> Result<(), String> {
    let cp_path = req(args, "--checkpoint")?;
    let set_path = req(args, "--signer-set")?;
    let out = req(args, "--out")?;
    let cp_bytes = fs::read(&cp_path).map_err(|e| format!("{cp_path}: {e}"))?;
    let cp = decode_checkpoint(&cp_bytes).map_err(|e| format!("{cp_path}: {e}"))?;
    let set = decode_signer_set_file(&fs::read(&set_path).map_err(|e| format!("{set_path}: {e}"))?)
        .map_err(|e| format!("{set_path}: {e}"))?;

    // The chain identity to check against. Taken from the manifest when one is
    // given — the same derivation a booting node does — and otherwise from the
    // checkpoint's own claims, which is a circular check and is announced as
    // one rather than passed off as verification.
    let (network_id, genesis_root, circular) = match crate::arg_value(args, "--genesis") {
        Some(m) => {
            let (n, g) = manifest_identity(&m)?;
            (n, g, false)
        }
        None => (cp.network_id, cp.genesis_root, true),
    };

    let specs = all_values(args, "--sig");
    if specs.is_empty() {
        return Err("at least one --sig <index>:<sigfile> is required".into());
    }
    let mut signatures = Vec::with_capacity(specs.len());
    for spec in &specs {
        let (index, path) = spec
            .split_once(':')
            .ok_or_else(|| format!("--sig `{spec}`: expected <index>:<sigfile>"))?;
        let index: u8 = index
            .parse()
            .map_err(|_| format!("--sig `{spec}`: index must be the signer's 0-based position"))?;
        signatures.push((index, read_hex_file(path)?));
    }

    let env = CheckpointEnvelope { checkpoint: cp, signatures };

    // THE GATE. Not a re-implementation of the acceptance rules — the rules.
    ws::verify_envelope(&env, &set, network_id, &genesis_root, &WsHybridVerifier).map_err(
        |reject| {
            format!(
                "REFUSING to write an envelope the network would reject.\n  \
                 ws::verify_envelope (the same function a booting node runs) returned \
                 {reject:?}\n  {}\n  ws digest {}",
                explain_reject(&reject, &set),
                hex32(&env.checkpoint.ws_digest()),
            )
        },
    )?;

    let bytes = encode_envelope_file(&env);
    let back = decode_envelope_file(&bytes).map_err(|e| format!("assembled envelope is malformed: {e}"))?;
    // Verify the DECODED form too. A framing bug that survives the in-memory
    // check and not the file would otherwise ship as a valid-looking artifact.
    ws::verify_envelope(&back, &set, network_id, &genesis_root, &WsHybridVerifier).map_err(
        |reject| {
            format!(
                "self-check FAILED: the envelope verifies in memory but NOT after the file \
                 round trip ({reject:?}). Do not publish this file."
            )
        },
    )?;
    write_file(&out, &bytes, false)?;

    println!(
        "ACCEPTED by ws::verify_envelope — wrote {out}: epoch {}, {} signature(s), {} bytes",
        env.checkpoint.epoch,
        env.signatures.len(),
        bytes.len(),
    );
    println!("ws digest {}", hex32(&env.checkpoint.ws_digest()));
    println!(
        "quorum {}-of-{} met, {} of ≥{} external",
        set.threshold,
        set.signers.len(),
        env.signatures
            .iter()
            .filter(|(i, _)| set.signers.get(*i as usize).is_some_and(|s| s.external))
            .count(),
        set.min_external,
    );
    if circular {
        println!(
            "note: no --genesis given, so network_id/genesis_root were checked against the \
             checkpoint's own claims — circular, and it proves nothing about cross-chain \
             replay. Pass --genesis <manifest> to make that check real."
        );
    }
    println!("verify it as a node would:  bloch-pos ws-verify --envelope {out} --signer-set {set_path} --genesis <manifest>");
    Ok(())
}

// ─── Reject messages and the per-signature probe ────────────────────────────

/// Turn an `EnvelopeReject` into something an operator can act on. The variant
/// itself is always printed alongside, so this is a gloss on the verdict and
/// never a substitute for it.
fn explain_reject(r: &ws::EnvelopeReject, set: &SignerSet) -> String {
    use ws::EnvelopeReject as E;
    match r {
        E::WrongVersion { got } => format!(
            "the checkpoint declares format version {got}; this build speaks {WS_FORMAT_VERSION}."
        ),
        E::WrongNetwork { got, expected } => format!(
            "network id mismatch: the checkpoint carries {got:#010x}, you expected \
             {expected:#010x}. A checkpoint for one network must never verify on another. \
             Check --genesis."
        ),
        E::WrongGenesisRoot => "genesis root mismatch: this checkpoint belongs to a different \
             chain than the manifest you named. Cross-chain replay refused."
            .to_string(),
        E::WrongSignerSet { got, expected } => format!(
            "the checkpoint names arrangement {got}; the signer-set file is arrangement \
             {expected}. Re-mint the checkpoint with --signer-set-id {expected}, or verify \
             against arrangement {got}'s file. Nothing here can be fixed by signing more."
        ),
        E::ReservedSignerSet => format!(
            "signer-set id {WS_GENESIS_SIGNER_SET_ID} is reserved for the genesis anchor and \
             no envelope may claim it."
        ),
        E::ArrangementExpired { hard_stop_epoch } => format!(
            "arrangement {} is past review + grace (adopted at epoch {}, hard stop at \
             {hard_stop_epoch}). This is the §6.3 dead-man's switch: envelopes from an \
             arrangement nobody reviewed stop being accepted. Governance must adopt a new \
             arrangement — more signatures will not help.",
            set.id, set.adopted_epoch
        ),
        E::UnknownSignerIndex { index } => format!(
            "a signature claims signer index {index}, but arrangement {} has {} signers \
             (valid indices 0..{}). Check the --sig <index>:<file> pairing.",
            set.id,
            set.signers.len(),
            set.signers.len().saturating_sub(1)
        ),
        E::DuplicateSigner { index } => format!(
            "signer index {index} appears twice. One key must not count twice toward the \
             quorum — most likely the same signer's file was collected from two machines."
        ),
        E::QuorumNotReached { got, need } => format!(
            "{got} signature(s), but arrangement {} needs {need}. Collect {} more.",
            set.id,
            need.saturating_sub(*got)
        ),
        E::ExternalQuorumNotReached { got, need } => format!(
            "{got} of the listed signatures come from externally-flagged signers; \
             arrangement {} requires {need}. A quorum of only founder-adjacent keys must not \
             verify — that is the entire point of the external minimum (§2.2 rule 4). The \
             external signer has to sign.",
            set.id
        ),
        E::BadSignature { index } => format!(
            "the signature at index {index} does not verify over this checkpoint's ws digest \
             under that signer's key. Either it was made over DIFFERENT bytes (the signer was \
             shown another checkpoint), or it came from a key that is not the one at index \
             {index} of the arrangement, or the file is corrupt."
        ),
    }
}

/// Per-signature verdict, obtained by asking the REAL verifier about a
/// one-signature envelope under a quorum-relaxed clone of the arrangement.
///
/// Why not check each signature directly: the AND-composition of the two
/// hybrid halves is `staking::verify_hybrid`, deliberately `pub(crate)` to the
/// frozen committee crate precisely so a second copy cannot introduce the OR
/// bug. Probing through `verify_envelope` keeps the crypto path singular and
/// relaxes only the counting rules, which the full run judges anyway. (This is
/// the same device `ws-sign --pubkey` uses for its own self-check.)
fn probe_signatures(
    env: &CheckpointEnvelope,
    set: &SignerSet,
    network_id: u32,
    genesis_root: &[u8; 32],
) -> Vec<(u8, bool, bool)> {
    let relaxed = SignerSet { threshold: 1, min_external: 0, ..set.clone() };
    env.signatures
        .iter()
        .map(|(index, sig)| {
            let one = CheckpointEnvelope {
                checkpoint: env.checkpoint,
                signatures: vec![(*index, sig.clone())],
            };
            let external =
                set.signers.get(*index as usize).is_some_and(|s| s.external);
            let valid = ws::verify_envelope(
                &one,
                &relaxed,
                network_id,
                genesis_root,
                &WsHybridVerifier,
            )
            .is_ok();
            (*index, external, valid)
        })
        .collect()
}

// ─── ws-verify ──────────────────────────────────────────────────────────────

/// `ws-verify --envelope <file> --signer-set <file> --genesis <manifest>
///  [--rpc <host:port>] [--now-epoch <n>]`
///
/// The exact check a booting node runs (`ws::verify_envelope` under the real
/// hybrid verifier, against the chain identity the manifest fixes), minus the
/// boot: publication dry-run, release-gate check, and third-party due
/// diligence are all this one command.
///
/// It prints every field, a per-signature verdict, the quorum arithmetic, the
/// arrangement's review clock, and — when a clock is available — whether the
/// artifact is still inside the weak-subjectivity window. A stranger who did
/// not mint the artifact should be able to run exactly this and decide.
fn verify(args: &[String]) -> Result<(), String> {
    let env_path = req(args, "--envelope")?;
    let set_path = req(args, "--signer-set")?;
    let manifest_path = req(args, "--genesis")?;

    let env = decode_envelope_file(&fs::read(&env_path).map_err(|e| format!("{env_path}: {e}"))?)
        .map_err(|e| format!("{env_path}: {e}"))?;
    let set = decode_signer_set_file(&fs::read(&set_path).map_err(|e| format!("{set_path}: {e}"))?)
        .map_err(|e| format!("{set_path}: {e}"))?;
    let (network_id, genesis_root) = manifest_identity(&manifest_path)?;
    let cp = env.checkpoint;

    println!("ENVELOPE  {env_path}");
    println!("  format version    {}", cp.version);
    println!("  network id        {:#010x}", cp.network_id);
    println!("  genesis root      {}", hex32(&cp.genesis_root));
    println!("  epoch             {}", cp.epoch);
    println!("  block root        {}", hex32(&cp.block_root));
    println!("  state root        {}", hex32(&cp.state_root));
    println!("  validator set     {}{}", hex32(&cp.validator_set_root), if cp.validator_set_root == [0u8; 32] {
        "   (all-zero placeholder — see the note below)"
    } else {
        ""
    });
    println!("  issued at         {}", cp.issued_at);
    println!("  signer set id     {}", cp.signer_set_id);
    println!("  WS DIGEST         {}", hex32(&cp.ws_digest()));
    println!();

    println!("ARRANGEMENT  {set_path}");
    println!(
        "  quorum            {}-of-{}, at least {} external",
        set.threshold,
        set.signers.len(),
        set.min_external
    );
    println!("  adopted at epoch  {}", set.adopted_epoch);
    println!("  review due        epoch {} (envelopes warn after this)", set.review_deadline());
    println!("  hard stop         epoch {} (envelopes REFUSED after this — §6.3)", set.hard_stop());
    println!();

    println!("SIGNATURES  ({} listed)", env.signatures.len());
    let verdicts = probe_signatures(&env, &set, network_id, &genesis_root);
    for (index, external, valid) in &verdicts {
        println!(
            "  index {index:<3} {:<9} {}",
            if *external { "EXTERNAL" } else { "internal" },
            if *valid { "VALID" } else { "INVALID" }
        );
    }
    println!(
        "  {} valid of {} listed; {} external of ≥{} required",
        verdicts.iter().filter(|(_, _, v)| *v).count(),
        env.signatures.len(),
        verdicts.iter().filter(|(_, e, v)| *e && *v).count(),
        set.min_external,
    );
    println!();

    // Freshness. NOT part of envelope validity — the window is a consumer-side
    // rule against the consuming node's own clock (§2.1: there is deliberately
    // no expiry field) — but it decides whether this artifact is still USABLE,
    // so it is reported when a clock is available.
    let now_epoch = match crate::arg_value(args, "--now-epoch") {
        Some(s) => Some(s.parse::<u64>().map_err(|_| "--now-epoch must be an epoch number".to_string())?),
        None => match crate::arg_value(args, "--rpc") {
            Some(addr) => {
                let info = rpc_call(&addr, "getchaininfo", vec![])?;
                Some(field_u64(&info, "epoch", "getchaininfo")?)
            }
            None => None,
        },
    };
    let window_days = ws::WS_PERIOD_EPOCHS / ws::EPOCHS_PER_DAY;
    match now_epoch {
        Some(now) => {
            let age = now.saturating_sub(cp.epoch);
            let state = if age >= ws::WS_PERIOD_EPOCHS {
                "EXPIRED — a fresh node given this checkpoint would STILL refuse to sync"
            } else if age >= ws::WS_FRESH_EPOCHS {
                "STALE — inside the window but past the freshness threshold; publish a newer one"
            } else {
                "FRESH"
            };
            println!(
                "FRESHNESS  epoch {} vs now {now}: age {age} of {} epochs (~{window_days} days) — {state}",
                cp.epoch,
                ws::WS_PERIOD_EPOCHS
            );
        }
        None => println!(
            "FRESHNESS  not evaluated (pass --rpc <host:port> or --now-epoch <n>). The window \
             is {} epochs, ~{window_days} days.",
            ws::WS_PERIOD_EPOCHS
        ),
    }
    println!();

    match ws::verify_envelope(&env, &set, network_id, &genesis_root, &WsHybridVerifier) {
        Ok(ok) => {
            if ok.arrangement_past_review {
                println!(
                    "WARNING: the arrangement is past its 12-month review deadline (epoch {}, \
                     inside grace) — the §6.3 review ADR is overdue.",
                    set.review_deadline()
                );
            }
            println!("VERDICT: ACCEPTED by ws::verify_envelope.");
            println!();
            println!(
                "Before trusting it, compare this digest against a SECOND independent \
                 publication channel:\n  {}",
                hex32(&cp.ws_digest())
            );
            println!(
                "Agreement across independent channels is the evidence. The artifact's own \
                 say-so is not."
            );
            Ok(())
        }
        Err(reject) => Err(format!(
            "VERDICT: REFUSED — {reject:?}\n  {}\n  ws digest {}\n  \
             A node given this envelope would refuse to start. Do not publish it.",
            explain_reject(&reject, &set),
            hex32(&cp.ws_digest())
        )),
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> String {
        let d = std::env::temp_dir().join(format!("bloch-ws-tool-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d.to_string_lossy().into_owned()
    }

    /// The whole ceremony, files and all, against real hybrid crypto and the
    /// node's own decoders: keygen → signer-set → sign → envelope → verify.
    /// What `ws_boot`'s tests prove about the verification path, this proves
    /// about the production path — the two meet at the same byte formats.
    #[test]
    fn full_ceremony_round_trips_through_files() {
        let dir = tmp("ceremony");

        // Three signers, Phase A shape (internal, internal, external).
        for i in 0..3 {
            keygen(&[s("--out"), format!("{dir}/signer{i}")]).unwrap();
        }
        signer_set(&[
            s("--id"), s("1"),
            s("--threshold"), s("2"),
            s("--min-external"), s("1"),
            s("--adopted-epoch"), s("0"),
            s("--signer"), format!("{dir}/signer0.pk:internal"),
            s("--signer"), format!("{dir}/signer1.pk:internal"),
            s("--signer"), format!("{dir}/signer2.pk:external"),
            s("--out"), format!("{dir}/set.bin"),
        ])
        .unwrap();
        let set =
            decode_signer_set_file(&fs::read(format!("{dir}/set.bin")).unwrap()).unwrap();
        assert!(set.matches_policy(
            ws::WS_PHASE_A_THRESHOLD,
            ws::WS_PHASE_A_SIGNERS,
            ws::WS_PHASE_A_MIN_EXTERNAL
        ));

        // A checkpoint minted by hand (the RPC path needs a chain; the byte
        // path from here on is identical).
        let cp = WeakSubjectivityCheckpoint {
            version: WS_FORMAT_VERSION,
            network_id: 0x493E_7DF4,
            genesis_root: [0x61; 32],
            epoch: 1536,
            block_root: [0x22; 32],
            state_root: [0x33; 32],
            validator_set_root: [0u8; 32],
            issued_at: 1_756_600_000,
            signer_set_id: 1,
        };
        fs::write(format!("{dir}/cp.bin"), cp.canonical_serialize()).unwrap();

        // Internal signer 0 and external signer 2 sign, self-verifying.
        for i in [0usize, 2] {
            sign(&[
                s("--key"), format!("{dir}/signer{i}.sk"),
                s("--pubkey"), format!("{dir}/signer{i}.pk"),
                s("--checkpoint"), format!("{dir}/cp.bin"),
                s("--out"), format!("{dir}/sig{i}"),
            ])
            .unwrap();
        }
        envelope(&[
            s("--checkpoint"), format!("{dir}/cp.bin"),
            s("--signer-set"), format!("{dir}/set.bin"),
            s("--sig"), format!("0:{dir}/sig0"),
            s("--sig"), format!("2:{dir}/sig2"),
            s("--out"), format!("{dir}/env.bin"),
        ])
        .unwrap();

        // Verify through the node's own path.
        let env = decode_envelope_file(&fs::read(format!("{dir}/env.bin")).unwrap()).unwrap();
        ws::verify_envelope(&env, &set, 0x493E_7DF4, &[0x61; 32], &WsHybridVerifier)
            .expect("ceremony output must verify as a booting node would");

        // Quorum without the external signer must still fail through this
        // path — the file plumbing must not have widened anything.
        let env_internal = CheckpointEnvelope {
            checkpoint: env.checkpoint,
            signatures: vec![env.signatures[0].clone(), {
                sign(&[
                    s("--key"), format!("{dir}/signer1.sk"),
                    s("--checkpoint"), format!("{dir}/cp.bin"),
                    s("--out"), format!("{dir}/sig1"),
                ])
                .unwrap();
                (1, read_hex_file(&format!("{dir}/sig1")).unwrap())
            }],
        };
        assert!(matches!(
            ws::verify_envelope(&env_internal, &set, 0x493E_7DF4, &[0x61; 32], &WsHybridVerifier),
            Err(ws::EnvelopeReject::ExternalQuorumNotReached { .. })
        ));
    }

    #[test]
    fn reserved_ids_and_unfinalized_epochs_are_refused_before_any_io() {
        let dir = tmp("guards");
        let e = signer_set(&[
            s("--id"), s("0"),
            s("--threshold"), s("1"),
            s("--min-external"), s("0"),
            s("--adopted-epoch"), s("0"),
            s("--signer"), format!("{dir}/nope.pk:internal"),
            s("--out"), format!("{dir}/set.bin"),
        ])
        .unwrap_err();
        assert!(e.contains("reserved"), "{e}");

        let e = checkpoint(&[
            s("--genesis"), format!("{dir}/nope.manifest"),
            s("--rpc"), s("127.0.0.1:1"),
            s("--epoch"), s("0"),
            s("--signer-set-id"), s("1"),
            s("--out"), format!("{dir}/cp"),
        ])
        .unwrap_err();
        assert!(e.contains("genesis anchor"), "{e}");
    }

    /// The RPC-side derivation rules, against canned node responses: the
    /// finalized gate and the field extraction. (The live-path HTTP client is
    /// exercised against the real fleet; what must never regress silently is
    /// the refusal logic.)
    #[test]
    fn finalized_gate_reads_chaininfo_shape() {
        let info = parse_json(
            r#"{"finalized":{"epoch":1588,"root":"5dab3c00297a895627f264ca6c85778e6367b325a056ce011d3d4f632498417a"}}"#,
        )
        .unwrap();
        let fin = info.get("finalized").unwrap();
        assert_eq!(field_u64(fin, "epoch", "finalized").unwrap(), 1588);
        assert_eq!(
            field_hex32(fin, "root", "finalized").unwrap()[..4],
            [0x5d, 0xab, 0x3c, 0x00]
        );
    }

    // ── The refusals `ws-envelope` must not be talked out of ────────────────
    //
    // `ws-envelope` is only worth anything if it is impossible to make it
    // write something a node would reject. Each of these drives the whole
    // command — files in, file out — and asserts BOTH that nothing was
    // written and that the reason names the exact `EnvelopeReject` variant
    // `ws::verify_envelope` produced. A test that accepted "some error" would
    // pass against a command that refused for the wrong reason.

    /// A signer set, three real keys, a checkpoint, and signatures over it —
    /// the fixture every refusal below starts from. Key generation dominates
    /// the runtime, so each test builds its own directory but the shape is
    /// identical to the ceremony test's.
    struct Fixture {
        dir: String,
        set: SignerSet,
        cp: WeakSubjectivityCheckpoint,
    }

    const FIX_NET: u32 = 0x493E_7DF4;
    const FIX_GEN: [u8; 32] = [0x61; 32];

    fn fixture(name: &str, signer_set_id: u32) -> Fixture {
        let dir = tmp(name);
        for i in 0..3 {
            keygen(&[s("--out"), format!("{dir}/signer{i}")]).unwrap();
        }
        signer_set(&[
            s("--id"), s("1"),
            s("--threshold"), s("2"),
            s("--min-external"), s("1"),
            s("--adopted-epoch"), s("0"),
            s("--signer"), format!("{dir}/signer0.pk:internal"),
            s("--signer"), format!("{dir}/signer1.pk:internal"),
            s("--signer"), format!("{dir}/signer2.pk:external"),
            s("--out"), format!("{dir}/set.bin"),
        ])
        .unwrap();
        let set = decode_signer_set_file(&fs::read(format!("{dir}/set.bin")).unwrap()).unwrap();

        let cp = WeakSubjectivityCheckpoint {
            version: WS_FORMAT_VERSION,
            network_id: FIX_NET,
            genesis_root: FIX_GEN,
            epoch: 1536,
            block_root: [0x22; 32],
            state_root: [0x33; 32],
            validator_set_root: [0u8; 32],
            issued_at: 1_756_600_000,
            signer_set_id,
        };
        fs::write(format!("{dir}/cp.bin"), cp.canonical_serialize()).unwrap();
        for i in [0usize, 1, 2] {
            sign(&[
                s("--key"), format!("{dir}/signer{i}.sk"),
                s("--checkpoint"), format!("{dir}/cp.bin"),
                s("--out"), format!("{dir}/sig{i}"),
            ])
            .unwrap();
        }
        Fixture { dir, set, cp }
    }

    /// Below threshold. `ws-envelope` must not produce the file at all — the
    /// operator learns at assembly, not at somebody's failed boot.
    #[test]
    fn envelope_refuses_a_one_signature_quorum() {
        let f = fixture("neg-quorum", 1);
        let out = format!("{}/env.bin", f.dir);
        let e = envelope(&[
            s("--checkpoint"), format!("{}/cp.bin", f.dir),
            s("--signer-set"), format!("{}/set.bin", f.dir),
            s("--sig"), format!("2:{}/sig2", f.dir),
            s("--out"), out.clone(),
        ])
        .unwrap_err();
        assert!(e.contains("QuorumNotReached"), "{e}");
        assert!(e.contains("REFUSING to write"), "{e}");
        assert!(!Path::new(&out).exists(), "a refused envelope must not reach disk");
    }

    /// Two internal keys reach the threshold but not the external minimum —
    /// §2.2 rule 4, the rule that stops a founder-only quorum.
    #[test]
    fn envelope_refuses_a_quorum_with_no_external_signer() {
        let f = fixture("neg-external", 1);
        let out = format!("{}/env.bin", f.dir);
        let e = envelope(&[
            s("--checkpoint"), format!("{}/cp.bin", f.dir),
            s("--signer-set"), format!("{}/set.bin", f.dir),
            s("--sig"), format!("0:{}/sig0", f.dir),
            s("--sig"), format!("1:{}/sig1", f.dir),
            s("--out"), out.clone(),
        ])
        .unwrap_err();
        assert!(e.contains("ExternalQuorumNotReached"), "{e}");
        assert!(!Path::new(&out).exists());
    }

    /// The checkpoint names an arrangement that is not the one signing. The
    /// signatures are genuine; the envelope is still not usable, and the
    /// message must say which two ids disagree.
    #[test]
    fn envelope_refuses_a_wrong_signer_set_id() {
        let f = fixture("neg-setid", 7); // checkpoint says 7, the set is id 1
        let out = format!("{}/env.bin", f.dir);
        let e = envelope(&[
            s("--checkpoint"), format!("{}/cp.bin", f.dir),
            s("--signer-set"), format!("{}/set.bin", f.dir),
            s("--sig"), format!("0:{}/sig0", f.dir),
            s("--sig"), format!("2:{}/sig2", f.dir),
            s("--out"), out.clone(),
        ])
        .unwrap_err();
        assert!(e.contains("WrongSignerSet"), "{e}");
        assert!(e.contains('7') && e.contains('1'), "must name both ids: {e}");
        assert!(!Path::new(&out).exists());
    }

    /// The attack the whole artifact exists to stop: real signatures, but the
    /// checkpoint they are paired with has been altered after signing. One
    /// flipped bit in `block_root` — a different chain history — must not
    /// produce a publishable envelope.
    #[test]
    fn envelope_refuses_a_tampered_root() {
        let f = fixture("neg-tamper", 1);
        let mut tampered = f.cp;
        tampered.block_root[0] ^= 0x01;
        let tampered_path = format!("{}/cp-tampered.bin", f.dir);
        fs::write(&tampered_path, tampered.canonical_serialize()).unwrap();
        assert_ne!(tampered.ws_digest(), f.cp.ws_digest());

        let out = format!("{}/env.bin", f.dir);
        let e = envelope(&[
            s("--checkpoint"), tampered_path,
            s("--signer-set"), format!("{}/set.bin", f.dir),
            s("--sig"), format!("0:{}/sig0", f.dir),
            s("--sig"), format!("2:{}/sig2", f.dir),
            s("--out"), out.clone(),
        ])
        .unwrap_err();
        assert!(e.contains("BadSignature"), "{e}");
        assert!(!Path::new(&out).exists(), "a tampered checkpoint must not reach disk");
    }

    /// A signature paired with the wrong index. Genuine bytes, wrong slot.
    #[test]
    fn envelope_refuses_a_misindexed_signature() {
        let f = fixture("neg-index", 1);
        let out = format!("{}/env.bin", f.dir);
        // signer 1's signature offered as signer 2 (the external slot).
        let e = envelope(&[
            s("--checkpoint"), format!("{}/cp.bin", f.dir),
            s("--signer-set"), format!("{}/set.bin", f.dir),
            s("--sig"), format!("0:{}/sig0", f.dir),
            s("--sig"), format!("2:{}/sig1", f.dir),
            s("--out"), out.clone(),
        ])
        .unwrap_err();
        assert!(e.contains("BadSignature"), "{e}");
        assert!(!Path::new(&out).exists());
    }

    /// Cross-chain replay: the same envelope, checked against another chain's
    /// identity, must be refused. This is the check that is CIRCULAR when
    /// `--genesis` is omitted, so it is exercised explicitly.
    #[test]
    fn a_valid_envelope_is_still_refused_on_another_chain() {
        let f = fixture("neg-network", 1);
        let out = format!("{}/env.bin", f.dir);
        envelope(&[
            s("--checkpoint"), format!("{}/cp.bin", f.dir),
            s("--signer-set"), format!("{}/set.bin", f.dir),
            s("--sig"), format!("0:{}/sig0", f.dir),
            s("--sig"), format!("2:{}/sig2", f.dir),
            s("--out"), out.clone(),
        ])
        .unwrap();
        let env = decode_envelope_file(&fs::read(&out).unwrap()).unwrap();

        // Right chain: accepted.
        ws::verify_envelope(&env, &f.set, FIX_NET, &FIX_GEN, &WsHybridVerifier).unwrap();
        // Wrong network id, and wrong genesis root: refused both ways.
        assert!(matches!(
            ws::verify_envelope(&env, &f.set, FIX_NET ^ 0xFF, &FIX_GEN, &WsHybridVerifier),
            Err(ws::EnvelopeReject::WrongNetwork { .. })
        ));
        assert!(matches!(
            ws::verify_envelope(&env, &f.set, FIX_NET, &[0x62; 32], &WsHybridVerifier),
            Err(ws::EnvelopeReject::WrongGenesisRoot)
        ));
    }

    /// Every reject variant gets an actionable gloss, and the gloss never
    /// replaces the variant. A refusal an operator cannot act on is a refusal
    /// that gets worked around.
    #[test]
    fn every_reject_variant_explains_itself() {
        let set = SignerSet {
            id: 1,
            signers: vec![
                Signer { pubkey: [0u8; HYBRID_PK_BYTES], external: false },
                Signer { pubkey: [1u8; HYBRID_PK_BYTES], external: true },
            ],
            threshold: 2,
            min_external: 1,
            adopted_epoch: 0,
        };
        use ws::EnvelopeReject as E;
        for r in [
            E::WrongVersion { got: 9 },
            E::WrongNetwork { got: 1, expected: 2 },
            E::WrongGenesisRoot,
            E::WrongSignerSet { got: 3, expected: 1 },
            E::ReservedSignerSet,
            E::ArrangementExpired { hard_stop_epoch: 100 },
            E::UnknownSignerIndex { index: 9 },
            E::DuplicateSigner { index: 1 },
            E::QuorumNotReached { got: 1, need: 2 },
            E::ExternalQuorumNotReached { got: 0, need: 1 },
            E::BadSignature { index: 0 },
        ] {
            let m = explain_reject(&r, &set);
            assert!(m.len() > 40, "{r:?} deserves a real explanation, got {m:?}");
            assert!(!m.contains("{"), "unformatted placeholder in {m:?}");
        }
    }

    /// `validator_set_root` is all zeros in every checkpoint this tool mints,
    /// and that is deliberate — pinned here so nobody "fixes" it into a
    /// fabricated value.
    ///
    /// The validator registry IS pinned by the checkpoint, transitively and
    /// cryptographically: `state_root` is the root of the single state SMT
    /// that carries every `ValidatorRecord` under `TAG_VALIDATOR`
    /// (`state_root::build_state_tree_inner`). `validator_set_root` is a
    /// SEPARATE, convenience commitment the spec (§4.3 step 2) reserves so a
    /// checkpoint-syncing node can verify a downloaded registry without
    /// rebuilding the whole state tree. No such root is computed anywhere in
    /// this repository, checkpoint-sync state download does not exist yet
    /// (`ws_boot`'s "honestly not wired" note), and `ws::verify_envelope`
    /// never reads the field — it is bound into `ws_digest`, and nothing more.
    /// The node itself passes the same zeros to `ws::genesis_anchor`.
    ///
    /// The hazard this test guards is the FUTURE one: when §4.3.2 lands, its
    /// implementation must REFUSE an all-zero `validator_set_root` rather than
    /// treat it as "matches". If that day comes, this test is the note.
    #[test]
    fn zero_validator_set_root_is_deliberate_and_does_not_weaken_the_envelope() {
        let f = fixture("vsr", 1);
        assert_eq!(f.cp.validator_set_root, [0u8; 32]);
        let out = format!("{}/env.bin", f.dir);
        envelope(&[
            s("--checkpoint"), format!("{}/cp.bin", f.dir),
            s("--signer-set"), format!("{}/set.bin", f.dir),
            s("--sig"), format!("0:{}/sig0", f.dir),
            s("--sig"), format!("2:{}/sig2", f.dir),
            s("--out"), out.clone(),
        ])
        .unwrap();
        let env = decode_envelope_file(&fs::read(&out).unwrap()).unwrap();
        ws::verify_envelope(&env, &f.set, FIX_NET, &FIX_GEN, &WsHybridVerifier)
            .expect("zeros are accepted — the verifier never reads this field");

        // But the field IS covered by the signature: changing it changes the
        // digest, so it cannot be edited in a published artifact.
        let mut other = f.cp;
        other.validator_set_root = [0x44; 32];
        assert_ne!(other.ws_digest(), f.cp.ws_digest());
        let other_path = format!("{}/cp-vsr.bin", f.dir);
        fs::write(&other_path, other.canonical_serialize()).unwrap();
        let e = envelope(&[
            s("--checkpoint"), other_path,
            s("--signer-set"), format!("{}/set.bin", f.dir),
            s("--sig"), format!("0:{}/sig0", f.dir),
            s("--sig"), format!("2:{}/sig2", f.dir),
            s("--out"), format!("{}/env2.bin", f.dir),
        ])
        .unwrap_err();
        assert!(e.contains("BadSignature"), "{e}");
    }

    /// No command writes key material anywhere but the `.sk` file it was told
    /// to write, and the signature it publishes carries none of it.
    #[test]
    fn published_artifacts_carry_no_key_material() {
        let f = fixture("nokeys", 1);
        let sk = fs::read(format!("{}/signer0.sk", f.dir)).unwrap();
        let sk_raw = unhex(String::from_utf8_lossy(&sk).trim()).unwrap();

        let out = format!("{}/env.bin", f.dir);
        envelope(&[
            s("--checkpoint"), format!("{}/cp.bin", f.dir),
            s("--signer-set"), format!("{}/set.bin", f.dir),
            s("--sig"), format!("0:{}/sig0", f.dir),
            s("--sig"), format!("2:{}/sig2", f.dir),
            s("--out"), out.clone(),
        ])
        .unwrap();

        let contains = |hay: &[u8], needle: &[u8]| -> bool {
            !needle.is_empty()
                && hay.len() >= needle.len()
                && hay.windows(needle.len()).any(|w| w == needle)
        };
        for artifact in ["sig0", "set.bin", "env.bin", "cp.bin", "signer0.pk"] {
            let bytes = fs::read(format!("{}/{artifact}", f.dir)).unwrap();
            assert!(!contains(&bytes, &sk_raw), "{artifact} contains the whole secret key");
            for window in sk_raw.chunks(64) {
                assert!(
                    !contains(&bytes, window),
                    "{artifact} contains 64 bytes of the secret key"
                );
            }
        }

        // And the secret file itself is 0600.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(format!("{}/signer0.sk", f.dir))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "a signer secret must not be group/world readable");
        }
    }

    fn s(v: &str) -> String {
        v.to_string()
    }
}
