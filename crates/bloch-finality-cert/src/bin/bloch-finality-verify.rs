// SPDX-License-Identifier: AGPL-3.0-or-later

//! `bloch-finality-verify` — check Bloch finality certificates offline.
//!
//! ```text
//! bloch-finality-verify --anchor <block-id-hex> [--anchor ..] [--max-hop N]
//!                       [--network-domain <hex>] CERT [CERT ..]
//! ```
//!
//! `CERT` is a file holding a proof as raw bytes, as hex, or as the JSON body
//! of `getlcproof` (format `BLCLMP01`, field `"proof"`) or
//! `getfinalitycertificate` (format `BLOCHFC1`, field `"certificate"`). Proofs
//! are checked in order and each verified checkpoint is trusted for the next
//! one (chain-of-certificates). Exit status 0 only if every proof verifies;
//! one JSON line per proof on stdout.
//!
//! Votes are judged by the consensus rule of their epoch: the v1 or bound v2
//! form, and KES leaves once KES binds. A bare `BLOCHFC1` certificate is refused
//! from a set source in the frozen-set gate epoch (e7180) on, because it does not
//! prove the weights, and past the KES gate, because it does not prove the keys:
//! use `getlcproof`. `--network-domain` defaults to Genesis-4 mainnet's
//! and is what KES signatures commit to (`getvalidatoradmission`).

use bloch_finality_cert::lc_proof::{self, Config, HybridConsensusVerifier, MainnetProof, Weights};
use bloch_finality_cert::{from_hex, to_hex, Certificate};
use std::collections::BTreeSet;
use std::process::ExitCode;

fn json_field(text: &str, name: &str) -> Option<Result<String, String>> {
    let tag = format!("\"{name}\"");
    let at = text.find(&tag)?;
    let rest = &text[at + tag.len()..];
    let Some(open) = rest.find('"') else {
        return Some(Err(format!("{name} field has no string")));
    };
    let rest = &rest[open + 1..];
    let Some(close) = rest.find('"') else {
        return Some(Err(format!("unterminated {name} string")));
    };
    Some(Ok(rest[..close].to_string()))
}

fn load(path: &str) -> Result<Vec<u8>, String> {
    let raw = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    if raw.starts_with(bloch_finality_cert::MAGIC) || raw.starts_with(lc_proof::PROOF_MAGIC) {
        return Ok(raw);
    }
    let text = String::from_utf8(raw).map_err(|_| format!("{path}: neither binary nor text"))?;
    let hex = match json_field(&text, "proof").or_else(|| json_field(&text, "certificate")) {
        Some(field) => field?,
        None => text.split_whitespace().collect::<String>(),
    };
    from_hex(&hex).ok_or_else(|| format!("{path}: bad hex"))
}

fn decode(bytes: &[u8]) -> Result<MainnetProof, String> {
    if bytes.starts_with(lc_proof::PROOF_MAGIC) {
        return MainnetProof::decode(bytes).ok_or_else(|| "decode: malformed BLCLMP01".to_string());
    }
    let cert = Certificate::decode(bytes).map_err(|e| format!("decode: {e}"))?;
    Ok(MainnetProof { cert, finality_set: None, kes: None })
}

fn main() -> ExitCode {
    let mut trusted: BTreeSet<[u8; 32]> = BTreeSet::new();
    let mut cfg = Config::mainnet();
    let mut files = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--anchor" => {
                let Some(h) = args.next().and_then(|h| from_hex(&h)).and_then(|b| <[u8; 32]>::try_from(b).ok())
                else {
                    eprintln!("--anchor needs a 32-byte hex block id");
                    return ExitCode::from(2);
                };
                trusted.insert(h);
            }
            "--max-hop" => {
                let Some(n) = args.next().and_then(|n| n.parse().ok()) else {
                    eprintln!("--max-hop needs an epoch count");
                    return ExitCode::from(2);
                };
                cfg.max_hop_epochs = n;
            }
            "--network-domain" => {
                let Some(d) = args.next().and_then(|h| from_hex(&h)).and_then(|b| <[u8; 32]>::try_from(b).ok())
                else {
                    eprintln!("--network-domain needs 32 bytes of hex");
                    return ExitCode::from(2);
                };
                cfg.network_domain = d;
            }
            "-h" | "--help" => {
                println!(
                    "usage: bloch-finality-verify --anchor <block-id-hex> [--anchor ..] [--max-hop N] \
                     [--network-domain <hex>] CERT [CERT ..]"
                );
                return ExitCode::SUCCESS;
            }
            _ => files.push(a),
        }
    }
    if trusted.is_empty() || files.is_empty() {
        eprintln!("need at least one --anchor and one certificate file (see --help)");
        return ExitCode::from(2);
    }
    for f in &files {
        let proof = match load(f).and_then(|b| decode(&b)) {
            Ok(p) => p,
            Err(e) => {
                println!("{{\"file\":\"{f}\",\"ok\":false,\"error\":\"{}\"}}", e.replace('"', "'"));
                return ExitCode::FAILURE;
            }
        };
        match lc_proof::verify(&proof, &trusted, &cfg, &HybridConsensusVerifier) {
            Ok(v) => {
                trusted.insert(v.root);
                println!(
                    "{{\"file\":\"{f}\",\"ok\":true,\"epoch\":{},\"root\":\"{}\",\"checkpoint_slot\":{},\
                     \"state_root\":\"{}\",\"set_source\":\"{}\",\"votes\":[{},{}],\
                     \"stake\":[[\"{}\",\"{}\"],[\"{}\",\"{}\"]],\"weights\":\"{}\",\"kes_votes\":{},\"ancestry_tip\":{}}}",
                    v.epoch,
                    to_hex(&v.root),
                    v.checkpoint_header.slot,
                    to_hex(&v.checkpoint_header.state_root),
                    to_hex(&v.set_source_root),
                    v.votes[0],
                    v.votes[1],
                    v.stake[0].0,
                    v.stake[0].1,
                    v.stake[1].0,
                    v.stake[1].1,
                    match v.weights {
                        Weights::Bond => "bond",
                        Weights::Frozen { with_pending: false } => "frozen",
                        Weights::Frozen { with_pending: true } => "frozen+pending",
                    },
                    v.kes_votes,
                    v.ancestry_tip
                        .map(|h| format!(
                            "{{\"slot\":{},\"id\":\"{}\"}}",
                            h.slot,
                            to_hex(bloch_pos_committee::header::BlockId::of(&h).as_bytes())
                        ))
                        .unwrap_or_else(|| "null".into()),
                );
            }
            Err(e) => {
                println!("{{\"file\":\"{f}\",\"ok\":false,\"error\":\"{}\"}}", format!("{e:?}").replace('"', "'"));
                return ExitCode::FAILURE;
            }
        }
    }
    ExitCode::SUCCESS
}
