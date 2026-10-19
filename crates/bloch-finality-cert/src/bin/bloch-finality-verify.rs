// SPDX-License-Identifier: AGPL-3.0-or-later

//! `bloch-finality-verify` — check Bloch finality certificates offline.
//!
//! ```text
//! bloch-finality-verify --anchor <block-id-hex> [--anchor ..] [--max-hop N] CERT [CERT ..]
//! ```
//!
//! `CERT` is a file holding the certificate as raw bytes, as hex, or as the
//! JSON body `getfinalitycertificate` returns (its `"certificate"` field is
//! used). Certificates are checked in order and each verified checkpoint is
//! trusted for the next one (chain-of-certificates). Exit status 0 only if
//! every certificate verifies; one JSON line per certificate on stdout.

use bloch_finality_cert::{from_hex, to_hex, verify, Certificate, HybridSigCheck, TrustAnchors};
use std::process::ExitCode;

fn load(path: &str) -> Result<Vec<u8>, String> {
    let raw = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    if raw.starts_with(bloch_finality_cert::MAGIC) {
        return Ok(raw);
    }
    let text = String::from_utf8(raw).map_err(|_| format!("{path}: neither binary nor text"))?;
    let hex = if let Some(at) = text.find("\"certificate\"") {
        let rest = &text[at + "\"certificate\"".len()..];
        let open = rest.find('"').ok_or("certificate field has no string")?;
        let rest = &rest[open + 1..];
        let close = rest.find('"').ok_or("unterminated certificate string")?;
        rest[..close].to_string()
    } else {
        text.split_whitespace().collect::<String>()
    };
    from_hex(&hex).ok_or_else(|| format!("{path}: bad hex"))
}

fn main() -> ExitCode {
    let mut anchors = TrustAnchors::new([]);
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
                anchors.roots.insert(h);
            }
            "--max-hop" => {
                let Some(n) = args.next().and_then(|n| n.parse().ok()) else {
                    eprintln!("--max-hop needs an epoch count");
                    return ExitCode::from(2);
                };
                anchors.max_hop_epochs = n;
            }
            "-h" | "--help" => {
                println!(
                    "usage: bloch-finality-verify --anchor <block-id-hex> [--anchor ..] [--max-hop N] CERT [CERT ..]"
                );
                return ExitCode::SUCCESS;
            }
            _ => files.push(a),
        }
    }
    if anchors.roots.is_empty() || files.is_empty() {
        eprintln!("need at least one --anchor and one certificate file (see --help)");
        return ExitCode::from(2);
    }
    for f in &files {
        let cert = match load(f).map_err(|e| e.to_string()).and_then(|b| {
            Certificate::decode(&b).map_err(|e| format!("decode: {e}"))
        }) {
            Ok(c) => c,
            Err(e) => {
                println!("{{\"file\":\"{f}\",\"ok\":false,\"error\":\"{}\"}}", e.to_string().replace('"', "'"));
                return ExitCode::FAILURE;
            }
        };
        match verify(&cert, &anchors, &HybridSigCheck) {
            Ok(v) => {
                anchors.roots.insert(v.root);
                println!(
                    "{{\"file\":\"{f}\",\"ok\":true,\"epoch\":{},\"root\":\"{}\",\"checkpoint_slot\":{},\
                     \"state_root\":\"{}\",\"set_source\":\"{}\",\"votes\":[{},{}],\
                     \"stake\":[[\"{}\",\"{}\"],[\"{}\",\"{}\"]],\"ancestry_tip\":{}}}",
                    v.epoch,
                    to_hex(&v.root),
                    v.checkpoint_slot,
                    to_hex(&v.checkpoint_state_root),
                    to_hex(&v.set_source_root),
                    v.votes[0],
                    v.votes[1],
                    v.stake[0].0,
                    v.stake[0].1,
                    v.stake[1].0,
                    v.stake[1].1,
                    v.ancestry_tip
                        .map(|(s, id)| format!("{{\"slot\":{s},\"id\":\"{}\"}}", to_hex(&id)))
                        .unwrap_or_else(|| "null".into()),
                );
            }
            Err(e) => {
                println!("{{\"file\":\"{f}\",\"ok\":false,\"error\":\"{}\"}}", e.to_string().replace('"', "'"));
                return ExitCode::FAILURE;
            }
        }
    }
    ExitCode::SUCCESS
}
