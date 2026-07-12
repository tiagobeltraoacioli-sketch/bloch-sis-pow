// SPDX-License-Identifier: MIT OR Apache-2.0
//! Reference **anchored-notary** — the end-to-end pattern any L2 / finality
//! gadget / RWA builder can fork.
//!
//! A notary maintains some off-chain state (here: a running log of documents).
//! Periodically it (1) computes a compact commitment over its current state,
//! (2) anchors that commitment to Bloch, (3) waits for PoW confirmations, and
//! (4) later proves — to anyone — that the commitment was anchored at a given
//! height/txid. The notary's data lives in the notary's OWN store; Bloch only
//! orders + timestamps the digest.
//!
//! Runs fully offline against the in-memory mock. To point it at a live node,
//! build with `--features http` and swap `MockTransport` for
//! `bloch_anchoring::http::HttpTransport`, and swap `MockSigner` for a real
//! `bloch-crypto` `WalletCore`-backed signer.
//!
//! Run: `cargo run --example anchored_notary`

use bloch_anchoring::rpc::{BlochRpc, MockTransport};
use bloch_anchoring::{AnchorClient, Anchoring, Commitment, MockSigner, WaitPolicy};

/// A toy notary whose "state" is just the documents it has notarized.
struct Notary {
    documents: Vec<String>,
}

impl Notary {
    fn new() -> Self {
        Notary {
            documents: Vec::new(),
        }
    }

    fn notarize(&mut self, doc: &str) {
        self.documents.push(doc.to_string());
    }

    /// The compact commitment over current state — this is the ONLY thing that
    /// touches Bloch. The full documents stay here (this is your DA).
    fn state_commitment(&self) -> Commitment {
        let blob = self.documents.join("\n");
        Commitment::hash_payload(blob.as_bytes())
    }
}

fn main() -> bloch_anchoring::Result<()> {
    println!("== Bloch anchored-notary reference (SCAFFOLD, unaudited) ==\n");

    // 1. The anchoring client: a mock Bloch node + a mock signer (offline).
    //    In production: HttpTransport + a WalletCore-backed signer.
    let transport = MockTransport::new(1_000);
    let client = AnchorClient::new(BlochRpc::new(transport), MockSigner::default());

    // 2. The notary accumulates off-chain state (its own data availability).
    let mut notary = Notary::new();
    notary.notarize("deed-0001: transfer of parcel A");
    notary.notarize("deed-0002: lien release on parcel B");
    notary.notarize("attestation-0003: audit sign-off Q3");

    let commitment = notary.state_commitment();
    println!("notary state commitment : {commitment}");
    println!("(the documents themselves never leave the notary — Bloch only anchors the digest)\n");

    // 3. Submit the commitment to Bloch (pays BLCH fees on a real node).
    let anchor = client.submit_commitment(&commitment)?;
    println!("submitted anchor tx     : {}", anchor.txid);
    println!("  finality              : {:?} ({} confs)", anchor.finality(), anchor.confirmations);

    // 4. Wait for confirmations. Ask for 6; drive the mock to mine them.
    //    (poll_interval_ms = 0 so the example doesn't actually sleep.)
    client.rpc().transport().mine(5);
    let policy = WaitPolicy {
        max_polls: 10,
        poll_interval_ms: 0,
    };
    let confirmed = client.wait_for_confirmations(&anchor.txid, 6, policy)?;
    println!(
        "\nconfirmed               : height {:?}, {} confs -> {:?}",
        confirmed.height,
        confirmed.confirmations,
        confirmed.finality()
    );

    // 5. Prove inclusion by txid — anyone can recover the committed digest
    //    straight off the chain and check it against the notary's state.
    let reference = client.prove_by_txid(&anchor.txid)?;
    println!("\n-- inclusion reference (by txid) --");
    println!("  recovered commitment  : {}", reference.commitment);
    println!("  anchored at height    : {:?}", reference.anchor.height);
    println!("  carrier outputs       : {} P2PKH burn scripts", reference.carrier_scripts.len());

    // Independent verification: recompute the commitment from the notary's data
    // and confirm the on-chain anchor matches.
    let recomputed = notary.state_commitment();
    let matches = reference.commitment == recomputed;
    println!("\n  verify vs notary DA   : {}", if matches { "MATCH ✓" } else { "MISMATCH ✗" });
    assert!(matches, "anchored commitment must equal recomputed state commitment");

    // 6. Prove by height (given candidate txids at that height — from
    //    getblockbyheight/gettxsbyblock or your own index).
    if let Some(h) = reference.anchor.height {
        let hits = client.prove_by_height(h, &[anchor.txid])?;
        println!("\n-- inclusion references at height {h} --");
        println!("  found {} anchoring tx(s) at that height", hits.len());
    }

    println!("\nDone. Bloch gave this digest ordering + timestamp + anchor — and nothing more.");
    println!("Your execution, validity, DA, and finality remain yours. Bring your own architecture.");
    Ok(())
}
