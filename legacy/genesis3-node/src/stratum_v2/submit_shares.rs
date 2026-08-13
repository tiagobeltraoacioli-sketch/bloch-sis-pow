// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Stratum V2 Mining Protocol — SubmitSharesStandard decoder.
//
// Sprint 10-gamma: decode-only implementation.
//
// A mining client that opened a Standard channel sends SubmitSharesStandard
// (msg_type 0x1a) when it finds a nonce that meets the share target. The
// server must:
//
//   1. Look up the channel + job
//   2. Reconstruct the 80-byte block header using the job's merkle_root
//      and the submitted (version, ntime, nonce)
//   3. Compute double-SHA256 and compare against the share target
//   4. If the share also meets the block target, submit the full block
//      to the acceptance pipeline
//   5. Reply with SubmitSharesSuccess (0x1c) or SubmitSharesError (0x1d)
//
// Steps 2-5 arrive in Sprint 10-delta/epsilon. This module handles step 1's
// input parsing only.
//
// Wire format reference (SRI spec v2, section 5.4.8):
//
//   Frame header (6 bytes, shared across SV2):
//     - extension_type: u16 LE  (0x0000 for standard channels)
//     - msg_type:       u8      (0x1a for SubmitSharesStandard)
//     - msg_length:     u24 LE  (payload length)
//
//   Payload (24 bytes, all LE):
//     - channel_id:      u32
//     - sequence_number: u32
//     - job_id:          u32
//     - nonce:           u32
//     - ntime:           u32
//     - version:         u32

const MSG_TYPE_SUBMIT_SHARES_STANDARD: u8 = 0x1a;
const EXPECTED_PAYLOAD_LEN: usize         = 24;
const FRAME_HEADER_LEN: usize             = 6;

/// Fully-decoded SubmitSharesStandard message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedSubmitSharesStandard {
    pub channel_id:      u32,
    pub sequence_number: u32,
    pub job_id:          u32,
    pub nonce:           u32,
    pub ntime:           u32,
    pub version:         u32,
}

/// Errors that can occur while decoding a SubmitSharesStandard frame.
#[derive(Debug, thiserror::Error)]
pub enum ShareDecodeError {
    #[error("frame too short: got {0} bytes, need at least {FRAME_HEADER_LEN}")]
    FrameTooShort(usize),

    #[error("wrong msg_type: got 0x{got:02x}, expected 0x{expected:02x}")]
    WrongMsgType { got: u8, expected: u8 },

    #[error("payload length mismatch: header says {header_says}, frame has {frame_has} payload bytes")]
    PayloadLengthMismatch { header_says: usize, frame_has: usize },

    #[error("payload wrong size: got {0} bytes, expected {EXPECTED_PAYLOAD_LEN}")]
    WrongPayloadSize(usize),
}

/// Parse the 6-byte SV2 frame header and return (msg_type, payload_len_from_header).
fn parse_header(frame: &[u8]) -> Result<(u8, u32), ShareDecodeError> {
    if frame.len() < FRAME_HEADER_LEN {
        return Err(ShareDecodeError::FrameTooShort(frame.len()));
    }
    // extension_type (bytes 0..2) ignored at this layer.
    let msg_type = frame[2];
    let payload_len: u32 = (frame[3] as u32)
        | ((frame[4] as u32) << 8)
        | ((frame[5] as u32) << 16);
    Ok((msg_type, payload_len))
}

/// Decode a SubmitSharesStandard frame (header + payload).
///
/// Returns the parsed struct on success, or an error if:
///   - the frame is shorter than a header
///   - the msg_type is not 0x1a
///   - the header's payload_len does not match the actual payload bytes
///   - the payload is not exactly 24 bytes
pub fn decode_submit_shares_standard(
    frame: &[u8],
) -> Result<DecodedSubmitSharesStandard, ShareDecodeError> {
    let (msg_type, header_payload_len) = parse_header(frame)?;

    if msg_type != MSG_TYPE_SUBMIT_SHARES_STANDARD {
        return Err(ShareDecodeError::WrongMsgType {
            got:      msg_type,
            expected: MSG_TYPE_SUBMIT_SHARES_STANDARD,
        });
    }

    let payload = &frame[FRAME_HEADER_LEN..];
    if (header_payload_len as usize) != payload.len() {
        return Err(ShareDecodeError::PayloadLengthMismatch {
            header_says: header_payload_len as usize,
            frame_has:   payload.len(),
        });
    }

    if payload.len() != EXPECTED_PAYLOAD_LEN {
        return Err(ShareDecodeError::WrongPayloadSize(payload.len()));
    }

    // All fields are LE u32. Total = 24 bytes in 6 fields.
    let channel_id      = u32::from_le_bytes(payload[0..4].try_into().unwrap());
    let sequence_number = u32::from_le_bytes(payload[4..8].try_into().unwrap());
    let job_id          = u32::from_le_bytes(payload[8..12].try_into().unwrap());
    let nonce           = u32::from_le_bytes(payload[12..16].try_into().unwrap());
    let ntime           = u32::from_le_bytes(payload[16..20].try_into().unwrap());
    let version         = u32::from_le_bytes(payload[20..24].try_into().unwrap());

    Ok(DecodedSubmitSharesStandard {
        channel_id,
        sequence_number,
        job_id,
        nonce,
        ntime,
        version,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a well-formed SubmitSharesStandard frame for tests.
    fn build_valid_frame(
        channel_id: u32,
        seq:        u32,
        job_id:     u32,
        nonce:      u32,
        ntime:      u32,
        version:    u32,
    ) -> Vec<u8> {
        let mut frame = Vec::with_capacity(FRAME_HEADER_LEN + EXPECTED_PAYLOAD_LEN);
        // Header: ext=0, msg_type=0x1a, len=24
        frame.extend_from_slice(&[0, 0, MSG_TYPE_SUBMIT_SHARES_STANDARD, 24, 0, 0]);
        // Payload:
        frame.extend_from_slice(&channel_id.to_le_bytes());
        frame.extend_from_slice(&seq.to_le_bytes());
        frame.extend_from_slice(&job_id.to_le_bytes());
        frame.extend_from_slice(&nonce.to_le_bytes());
        frame.extend_from_slice(&ntime.to_le_bytes());
        frame.extend_from_slice(&version.to_le_bytes());
        frame
    }

    #[test]
    fn happy_path_round_trip() {
        let frame = build_valid_frame(
            7, 1001, 42, 0xDEAD_BEEF, 0x6512_3456, 0x2000_0000,
        );
        let decoded = decode_submit_shares_standard(&frame).unwrap();

        assert_eq!(decoded.channel_id,      7);
        assert_eq!(decoded.sequence_number, 1001);
        assert_eq!(decoded.job_id,          42);
        assert_eq!(decoded.nonce,           0xDEAD_BEEF);
        assert_eq!(decoded.ntime,           0x6512_3456);
        assert_eq!(decoded.version,         0x2000_0000);
    }

    #[test]
    fn rejects_truncated_frame() {
        let short = [0, 0, 0x1a];
        let err = decode_submit_shares_standard(&short).unwrap_err();
        assert!(matches!(err, ShareDecodeError::FrameTooShort(3)));
    }

    #[test]
    fn rejects_wrong_msg_type() {
        // msg_type 0x15 (NewMiningJob) with otherwise plausible frame
        let mut frame = build_valid_frame(0, 0, 0, 0, 0, 0);
        frame[2] = 0x15;
        let err = decode_submit_shares_standard(&frame).unwrap_err();
        assert!(matches!(
            err,
            ShareDecodeError::WrongMsgType { got: 0x15, expected: 0x1a }
        ));
    }

    #[test]
    fn rejects_header_length_mismatch() {
        // Claim 100 bytes of payload in header but only provide 24
        let mut frame = build_valid_frame(0, 0, 0, 0, 0, 0);
        frame[3] = 100;  // header says 100 bytes
        let err = decode_submit_shares_standard(&frame).unwrap_err();
        assert!(matches!(
            err,
            ShareDecodeError::PayloadLengthMismatch { header_says: 100, frame_has: 24 }
        ));
    }

    #[test]
    fn rejects_payload_wrong_size() {
        // Header + payload that's internally consistent but too small.
        // Need header_says == frame_has to reach WrongPayloadSize check.
        let mut frame = Vec::new();
        // Header: msg_type 0x1a, length 10
        frame.extend_from_slice(&[0, 0, MSG_TYPE_SUBMIT_SHARES_STANDARD, 10, 0, 0]);
        frame.extend_from_slice(&[0u8; 10]);
        let err = decode_submit_shares_standard(&frame).unwrap_err();
        assert!(matches!(err, ShareDecodeError::WrongPayloadSize(10)));
    }

    #[test]
    fn all_zero_fields_decode_cleanly() {
        // Edge case: zeroed frame must still parse (not ambiguous with errors).
        let frame = build_valid_frame(0, 0, 0, 0, 0, 0);
        let decoded = decode_submit_shares_standard(&frame).unwrap();
        assert_eq!(
            decoded,
            DecodedSubmitSharesStandard {
                channel_id:      0,
                sequence_number: 0,
                job_id:          0,
                nonce:           0,
                ntime:           0,
                version:         0,
            }
        );
    }

    #[test]
    fn max_u32_fields_decode_cleanly() {
        let frame = build_valid_frame(
            u32::MAX, u32::MAX, u32::MAX, u32::MAX, u32::MAX, u32::MAX,
        );
        let decoded = decode_submit_shares_standard(&frame).unwrap();
        assert_eq!(decoded.channel_id,      u32::MAX);
        assert_eq!(decoded.sequence_number, u32::MAX);
        assert_eq!(decoded.job_id,          u32::MAX);
        assert_eq!(decoded.nonce,           u32::MAX);
        assert_eq!(decoded.ntime,           u32::MAX);
        assert_eq!(decoded.version,         u32::MAX);
    }
}
