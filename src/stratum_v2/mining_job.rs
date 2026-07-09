// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Stratum V2 Mining Protocol — NewMiningJob + MiningSetNewPrevHash encoders.
//
// Sprint 10-gamma: encode-only implementations for pushing work to a
// mining client that already opened a Standard channel.
//
// Wire format references (SRI spec v2, Mining Protocol):
//   - NewMiningJob       = msg_type 0x15, section 5.4.6
//   - MiningSetNewPrevHash = msg_type 0x20, section 5.4.5
//
// SV2 framing (section 3.1):
//   - 2 bytes extension_type
//   - 1 byte  msg_type
//   - 3 bytes msg_length (little-endian, payload only; header excluded)
//   - N bytes payload
//
// Encoders here return a complete frame (header + payload). The caller
// is responsible for passing the result through NoiseCodec::encrypt
// before writing to the wire.
//
// Note on channel semantics: Sprint 10-gamma does NOT yet compute a
// real merkle_root or min_ntime — these encoders are called with
// caller-supplied values, and the `session.rs` wiring in a later
// sprint will fill them from a live Template + per-channel extranonce.

const MSG_TYPE_NEW_MINING_JOB: u8            = 0x15;
const MSG_TYPE_MINING_SET_NEW_PREV_HASH: u8  = 0x20;

/// Errors that can occur while encoding a Mining Protocol frame.
#[derive(Debug, thiserror::Error)]
pub enum MiningEncodeError {
    #[error("payload too large for SV2 u24 length field: {0} bytes")]
    PayloadTooLarge(usize),
}

/// Build a 6-byte SV2 frame header.
///
/// extension_type = 0x0000 (standard channels, no extensions)
fn build_header(msg_type: u8, payload_len: usize) -> Result<[u8; 6], MiningEncodeError> {
    if payload_len > 0x00FF_FFFF {
        return Err(MiningEncodeError::PayloadTooLarge(payload_len));
    }
    let mut hdr = [0u8; 6];
    // extension_type stays as [0, 0]
    hdr[2] = msg_type;
    // msg_length: little-endian u24
    hdr[3] = (payload_len & 0xFF) as u8;
    hdr[4] = ((payload_len >> 8)  & 0xFF) as u8;
    hdr[5] = ((payload_len >> 16) & 0xFF) as u8;
    Ok(hdr)
}

/// Encode a `NewMiningJob` message (msg_type 0x15).
///
/// Fields per SRI spec 5.4.6:
///   - channel_id (U32, LE)
///   - job_id (U32, LE)
///   - min_ntime (OPTION[U32]): 1 byte presence flag + optional U32 LE
///   - version (U32, LE)
///   - merkle_root (B0_32): 1 byte length prefix + up to 32 bytes
///     (in practice always length=32 for standard mining)
///
/// `min_ntime = None` means "miner may use current ntime"; most
/// implementations pass `None` and rely on a subsequent
/// MiningSetNewPrevHash to set the tip of the work.
pub fn encode_new_mining_job(
    channel_id:  u32,
    job_id:      u32,
    min_ntime:   Option<u32>,
    version:     u32,
    merkle_root: &[u8; 32],
) -> Result<Vec<u8>, MiningEncodeError> {
    // Payload size:
    //   4 (channel_id) + 4 (job_id) + 1 (flag) + [4 if Some] + 4 (version)
    //   + 1 (merkle len prefix) + 32 (merkle data)
    let payload_len = 4 + 4 + 1 + if min_ntime.is_some() { 4 } else { 0 } + 4 + 1 + 32;

    let hdr = build_header(MSG_TYPE_NEW_MINING_JOB, payload_len)?;
    let mut out = Vec::with_capacity(6 + payload_len);
    out.extend_from_slice(&hdr);

    out.extend_from_slice(&channel_id.to_le_bytes());
    out.extend_from_slice(&job_id.to_le_bytes());

    match min_ntime {
        None => out.push(0),
        Some(t) => {
            out.push(1);
            out.extend_from_slice(&t.to_le_bytes());
        }
    }

    out.extend_from_slice(&version.to_le_bytes());

    // B0_32: 1-byte length prefix, then bytes. Standard channel = 32.
    out.push(32);
    out.extend_from_slice(merkle_root);

    debug_assert_eq!(out.len(), 6 + payload_len);
    Ok(out)
}

/// Encode a `MiningSetNewPrevHash` message (msg_type 0x20).
///
/// Fields per SRI spec 5.4.5:
///   - channel_id (U32, LE)
///   - job_id (U32, LE)     — job this new prev_hash applies to
///   - prev_hash (U256)     — 32 bytes, big-endian per Bitcoin convention
///                            but wire-level we just pass the caller's bytes
///   - min_ntime (U32, LE)
///   - nbits (U32, LE)      — difficulty encoding (not the target itself)
///
/// In Bloch-SIS Protocol's BlockDAG world, `prev_hash` is a single hash derived
/// from the DAG's selected tip (the chain-version, not the multi-parent
/// set). The session wiring in a future sprint picks which field of
/// `TipChanged` feeds this — likely `tip.hash` via `parents_commitment`.
pub fn encode_mining_set_new_prev_hash(
    channel_id: u32,
    job_id:     u32,
    prev_hash:  &[u8; 32],
    min_ntime:  u32,
    nbits:      u32,
) -> Result<Vec<u8>, MiningEncodeError> {
    // Payload: 4 + 4 + 32 + 4 + 4 = 48
    let payload_len = 4 + 4 + 32 + 4 + 4;

    let hdr = build_header(MSG_TYPE_MINING_SET_NEW_PREV_HASH, payload_len)?;
    let mut out = Vec::with_capacity(6 + payload_len);
    out.extend_from_slice(&hdr);

    out.extend_from_slice(&channel_id.to_le_bytes());
    out.extend_from_slice(&job_id.to_le_bytes());
    out.extend_from_slice(prev_hash);
    out.extend_from_slice(&min_ntime.to_le_bytes());
    out.extend_from_slice(&nbits.to_le_bytes());

    debug_assert_eq!(out.len(), 6 + payload_len);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_encodes_msg_type_and_length() {
        let hdr = build_header(0x15, 50).unwrap();
        assert_eq!(hdr[0], 0);           // extension_type byte 0
        assert_eq!(hdr[1], 0);           // extension_type byte 1
        assert_eq!(hdr[2], 0x15);        // msg_type
        assert_eq!(hdr[3], 50);          // length byte 0
        assert_eq!(hdr[4], 0);
        assert_eq!(hdr[5], 0);
    }

    #[test]
    fn header_rejects_oversized_payload() {
        // u24 max + 1
        let err = build_header(0x15, 0x0100_0000).unwrap_err();
        assert!(matches!(err, MiningEncodeError::PayloadTooLarge(_)));
    }

    #[test]
    fn new_mining_job_with_no_min_ntime_has_expected_size() {
        let frame = encode_new_mining_job(
            7, 42, None, 0x20000000, &[0xAA; 32]
        ).unwrap();
        // header(6) + channel_id(4) + job_id(4) + flag(1)
        // + version(4) + merkle_len(1) + merkle(32) = 52
        assert_eq!(frame.len(), 52);
        // Verify header msg_type:
        assert_eq!(frame[2], MSG_TYPE_NEW_MINING_JOB);
        // Verify channel_id (LE) at offset 6:
        assert_eq!(&frame[6..10], &7u32.to_le_bytes());
        // Verify job_id (LE) at offset 10:
        assert_eq!(&frame[10..14], &42u32.to_le_bytes());
        // Verify min_ntime flag at offset 14:
        assert_eq!(frame[14], 0);
        // Verify version at offset 15-19:
        assert_eq!(&frame[15..19], &0x20000000u32.to_le_bytes());
        // merkle_root length prefix at offset 19:
        assert_eq!(frame[19], 32);
        // merkle_root bytes at offset 20-52:
        assert_eq!(&frame[20..52], &[0xAA; 32]);
    }

    #[test]
    fn new_mining_job_with_min_ntime_includes_four_extra_bytes() {
        let frame = encode_new_mining_job(
            1, 1, Some(0x6512_3456), 0x20000000, &[0; 32]
        ).unwrap();
        // 52 + 4 = 56 when min_ntime is Some
        assert_eq!(frame.len(), 56);
        assert_eq!(frame[14], 1); // flag
        assert_eq!(&frame[15..19], &0x6512_3456u32.to_le_bytes());
    }

    #[test]
    fn set_new_prev_hash_has_fixed_size() {
        let frame = encode_mining_set_new_prev_hash(
            10, 99, &[0xBB; 32], 0x6512_3456, 0x1d00_ffff
        ).unwrap();
        // header(6) + channel_id(4) + job_id(4) + prev_hash(32)
        // + min_ntime(4) + nbits(4) = 54
        assert_eq!(frame.len(), 54);
        assert_eq!(frame[2], MSG_TYPE_MINING_SET_NEW_PREV_HASH);
        // channel_id
        assert_eq!(&frame[6..10], &10u32.to_le_bytes());
        // job_id
        assert_eq!(&frame[10..14], &99u32.to_le_bytes());
        // prev_hash (unmodified by encoder)
        assert_eq!(&frame[14..46], &[0xBB; 32]);
        // min_ntime
        assert_eq!(&frame[46..50], &0x6512_3456u32.to_le_bytes());
        // nbits
        assert_eq!(&frame[50..54], &0x1d00_ffffu32.to_le_bytes());
    }

    #[test]
    fn header_length_field_is_little_endian_u24() {
        let hdr = build_header(0x20, 48).unwrap();
        assert_eq!(&hdr[3..6], &[48, 0, 0]);

        // Multi-byte length
        let hdr2 = build_header(0x15, 0x1234).unwrap();
        assert_eq!(&hdr2[3..6], &[0x34, 0x12, 0x00]);
    }
}
