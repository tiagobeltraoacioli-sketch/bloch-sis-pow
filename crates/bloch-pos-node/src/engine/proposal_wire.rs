// SPDX-License-Identifier: AGPL-3.0-or-later
//! Producer-only packing. This is not an incoming block validity limit.
use super::*;

// Leave room for the gossipsub message's topic, author, sequence and transport
// signature framing. The block's own hybrid signature is budgeted separately
// from the actual signing implementation, before touching its watermark.
const ENVELOPE_BUDGET: usize = crate::p2p::MAX_PROPOSAL_ENVELOPE_BYTES;

pub(super) fn fit(header: &BlockHeaderV4, atts: &mut Vec<Attestation>, txs: &[PosTransaction]) -> bool {
    let base = BlockEnvelope {
        header: header.clone(),
        proposer_sig: vec![0; bloch_crypto::crypto::max_signature_len()],
        body: Body {
            transactions: txs.iter().map(PosTransaction::canonical_bytes).collect(),
            attestations: Vec::new(),
        },
    };
    // Ask the current codec, including every length prefix. A codec change
    // cannot silently invalidate an independently copied size formula.
    let mut used = crate::codec::encode_envelope(&base).len();
    if used > ENVELOPE_BUDGET { return false; }
    let mut keep = 0usize;
    let mut encoded = Vec::new();
    for att in atts.iter() {
        encoded.clear();
        crate::codec::encode_attestation(&mut encoded, att);
        let Some(next) = used.checked_add(encoded.len()) else { break };
        if next > ENVELOPE_BUDGET { break; }
        used = next;
        keep = keep.saturating_add(1);
    }
    // The caller already ordered by (slot, validator, signing_root). Retain
    // that prefix exactly; no input pool entry or rejection cache is changed.
    atts.truncate(keep);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (BlockHeaderV4, Attestation, Vec<u8>) {
        let (pk, sk) = bloch_crypto::crypto::generate_keypair_from_seed(&[87; 32]).unwrap();
        let header = Manifest {
            genesis_time_ms: 0, slot_ms: 30_000, validators: Vec::new(),
            cohort: Vec::new(), carryover: None, allocations: Vec::new(),
            carryover_entries: Vec::new(), pre_state_root: std::sync::OnceLock::new(), format: crate::genesis::ManifestFormat::V1Unbound,
        }.genesis_header();
        let data = AttestationData {
            slot: 32, head: [1; 32], source_epoch: 0, source_root: [2; 32],
            target_epoch: 1, target_root: [3; 32],
        };
        let signature = bloch_crypto::crypto::sign(&sk, &data.signing_root()).unwrap();
        assert!(bloch_crypto::crypto::verify(&pk, &data.signing_root(), &signature));
        (header, Attestation { data, validator: 0, signature }, sk)
    }

    #[test]
    fn proposal_wire_real_signatures_fit_codec_and_preserve_order() {
        let (header, att, sk) = fixture();
        let original: Vec<_> = (0..MAX_ATTESTATIONS_PER_BLOCK).map(|i| {
            let mut next = att.clone();
            next.validator = i as u32;
            next
        }).collect();
        // The copied attestation signatures test wire size, not committee
        // validity for the synthetic validator indices.
        let mut atts = original.clone();
        let txs = vec![PosTransaction::Exit { validator: 42 }];
        assert!(fit(&header, &mut atts, &txs));
        assert!(!atts.is_empty());
        assert!(atts.len() < original.len(), "the fixture must cross the old frame cliff");
        assert_eq!(atts, original[..atts.len()]);
        let mut header = header;
        header.attestation_root = derive::attestation_root(&atts);
        let signature = bloch_crypto::crypto::sign(&sk, &header.proposal_signing_root()).unwrap();
        let env = BlockEnvelope { header, proposer_sig: signature,
            body: Body { attestations: atts.clone(), transactions: txs.iter().map(PosTransaction::canonical_bytes).collect() } };
        let bytes = crate::codec::encode_envelope(&env);
        assert!(bytes.len() <= ENVELOPE_BUDGET);
        let decoded = crate::codec::decode_envelope(&bytes).unwrap();
        assert_eq!(decoded.body.attestations, atts);
        let mut again = original;
        assert!(fit(&env.header, &mut again, &txs));
        assert_eq!(again, atts);
    }

    #[test]
    fn proposal_wire_exact_codec_boundary_and_one_byte_overflow() {
        let (header, mut att, _) = fixture();
        let empty = BlockEnvelope { header: header.clone(),
            proposer_sig: vec![0; bloch_crypto::crypto::max_signature_len()],
            body: Body { attestations: Vec::new(), transactions: Vec::new() } };
        att.signature.clear();
        let mut encoded_att = Vec::new();
        crate::codec::encode_attestation(&mut encoded_att, &att);
        let signature_room = ENVELOPE_BUDGET - crate::codec::encode_envelope(&empty).len() - encoded_att.len();
        // Synthetic signature length isolates the codec boundary; verification
        // is deliberately outside this producer byte-packing unit test.
        att.signature = vec![0; signature_room];
        let mut exact = vec![att.clone()];
        assert!(fit(&header, &mut exact, &[]));
        assert_eq!(exact.len(), 1);
        let mut env = empty;
        env.body.attestations = exact;
        assert_eq!(crate::codec::encode_envelope(&env).len(), ENVELOPE_BUDGET);
        att.signature.push(0);
        let mut oversized = vec![att];
        assert!(fit(&header, &mut oversized, &[]));
        assert!(oversized.is_empty());
    }
}
