// SPDX-License-Identifier: AGPL-3.0-or-later

//! `bloch-indexer` — the historical index an explorer reads instead of a
//! validator.
//!
//! ## The safety argument
//!
//! A Genesis-4 node answers about **current state only**. `getbalance` sums the
//! committed eUTXO set as it stands; `getblockbyslot` returns one header
//! summary and, notably, `tx_count` rather than the transactions; and
//! `gettransaction` refuses outright — `RpcError::no_transaction_index()` — so
//! there is nothing to index against. Every historical question therefore
//! becomes a burst of RPC calls, against a port with **no authentication and no
//! rate limiting**, served by the thread that runs consensus. `rpc.rs` says so
//! itself: *"the node's consensus thread must survive its RPC port being
//! hammered."* A test has already starved the nodes it was measuring.
//!
//! So: read the chain once, from an archival observer, and answer everything
//! from here.
//!
//! ## Reused, not reimplemented
//!
//! Three things are the node's own code, included by path rather than copied,
//! so there is exactly one decoder and it is the one consensus uses:
//!
//! - [`codec`] — the frame and envelope codec.
//! - [`genesis`] — the manifest and the carryover ingest, including all four
//!   commitment checks. The opening ledger the index starts from is therefore
//!   the same one the chain opened with, checked the same way, rather than a
//!   second reading of a 54 MB TSV.
//! - [`log`]'s frame table, ported from `perf/network-sync` `e904a6db`.
//!
//! Both included modules depend only on `bloch_pos_committee`, `sha3` and
//! `std`, so this crate adds **no new entry to `Cargo.lock`**.

// The node's codec, verbatim. `genesis` below refers to it as `crate::codec`,
// which is why the name here matters.
#[path = "../../../crates/bloch-pos-node/src/codec.rs"]
pub mod codec;

// The node's genesis manifest reader and carryover ingest, verbatim.
#[path = "../../../crates/bloch-pos-node/src/genesis.rs"]
pub mod genesis;

pub mod api;
pub mod rpcprobe;
pub mod index;
pub mod json;
pub mod log;
pub mod model;

#[cfg(test)]
mod tests;

use std::path::Path;

use model::{OutPoint, ScriptHash, Utxo};

/// Load the genesis manifest and its carryover snapshot, and produce the
/// opening ledger the index starts from.
///
/// This goes through `Manifest::ingest_carryover`, which runs all four
/// commitment checks — file digest, set root, entry count, total — and refuses
/// the file otherwise. An indexer that skipped them would happily open with the
/// wrong ledger and report balances that are internally consistent and wrong,
/// which is the failure mode nobody notices.
pub fn opening_ledger(
    manifest_path: &Path,
    carryover_path: &Path,
) -> std::io::Result<(genesis::Manifest, [u8; 32], Vec<(OutPoint, Utxo)>)> {
    let bytes = std::fs::read(manifest_path)?;
    let mut manifest = genesis::Manifest::decode(&bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    if manifest.carryover.is_some() {
        manifest.ingest_carryover(carryover_path)?;
    }
    let genesis_id = *manifest.genesis_id().as_bytes();
    let outputs = manifest
        .opening_balances()
        .into_iter()
        .map(|e| {
            (
                OutPoint { txid: e.txid, vout: e.vout },
                Utxo {
                    value_sat: e.value,
                    script_hash: e.script_hash as ScriptHash,
                    created_height: 0,
                },
            )
        })
        .collect();
    Ok((manifest, genesis_id, outputs))
}

/// Lowercase hex, the one encoding this crate emits for a 32-byte identifier.
pub fn hex32(b: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

/// Parse 64 lowercase or uppercase hex characters into 32 bytes.
///
/// Deliberately refuses anything else — in particular a `bloch1…` address
/// string, with the reason. Two `script_hash` derivations once existed in this
/// repository and disagreed, and the same key showed 74,999,997,782 sat under
/// one and 0 under the other; the index will not guess which one a caller meant.
pub fn parse_script_hash(s: &str) -> Result<[u8; 32], String> {
    let s = s.trim();
    if s.starts_with("bloch1") {
        return Err(
            "that is an address, not a script_hash. Genesis-4 locks outputs with 32 bytes and \
             there is no address->script_hash conversion, deliberately: an address carries 20 \
             bytes and a native key's script_hash is all 32 of SHA3-256(pubkey). Zero-extending \
             the 20 gives a DIFFERENT key that `transition::owns` also accepts, so the mistake \
             is silent. Ask the holder for the script_hash."
                .to_string(),
        );
    }
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() != 64 {
        return Err(format!("script_hash is 64 hex characters, got {}", s.len()));
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|_| "script_hash is not hex".to_string())?;
    }
    Ok(out)
}
