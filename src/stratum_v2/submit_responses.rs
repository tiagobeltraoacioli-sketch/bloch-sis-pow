// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Stratum V2 Mining Protocol — SubmitSharesSuccess + SubmitSharesError
// encoders.
//
// Sprint 10-epsilon Phase 3: encode-only implementations. When a V2 miner
// sends SubmitSharesStandard (0x1a), the server must eventually respond
// with either SubmitSharesSuccess (0x1c) on an accepted share or
// SubmitSharesError (0x1d) on rejection. This module produces the
// plaintext wire frames; the session layer is responsible for running
// them through NoiseCodec::encrypt before writing to the stream.
//
// Wire format references (SRI spec v2, section 5.4):
//   - SubmitSharesSuccess = msg_type 0x1c, section 5.4.9
//   - SubmitSharesError   = msg_type 0x1d, section 5.4.10
//
// SV2 framing (section 3.1):
//   - 2 bytes extension_type (0x0000 for standard mining channels)
//   - 1 byte  msg_type
//   - 3 bytes msg_length (little-endian u24, payload length only)
//   - N bytes payload
//
// These encoders return a complete frame (header + payload). The caller
// is responsible for NoiseCodec::encrypt on the plaintext output.

const MSG_TYPE_SUBMIT_SHARES_SUCCESS: u8 = 0x1c;
const MSG_TYPE_SUBMIT_SHARES_ERROR:   u8 = 0x1d;

/// Errors that can occur while encoding a submit-response frame.
#[derive(Debug, thiserror::Error)]
pub enum SubmitResponseEncodeError {
    #[error("error_code too long: {0} bytes (max 255 for STR0_255)")]
    ErrorCodeTooLong(usize),

    #[error("payload too large for SV2 u24 length field: {0} bytes")]
    PayloadTooLarge(usize),
}

/// Canonical SubmitShares error codes per SRI spec v2 section 5.4.10.
///
/// When a share fails validation, the server replies with
/// SubmitSharesError + one of these short string identifiers. V2 miners
/// use the string to classify the rejection (stale job vs bad PoW vs
/// malformed frame).
pub enum SubmitErrorCode {
    /// Share references a channel the server does not recognize.
    InvalidChannelId,
    /// Share references a job_id that is stale or never existed.
    InvalidJobId,
    /// Share was valid against a previous job but the channel has since
    /// moved on. Miners should drop in-flight shares for that job.
    StaleShare,
    /// Reconstructed header double-SHA256 does not meet the share target.
    DifficultyTooLow,
    /// Catch-all for malformed frames, sequence violations, etc.
    Other,
    /// Escape hatch for operator-defined codes; kept &'static str so we
    /// do not allocate on the response hot path.
    Custom(&'static str),
}

impl SubmitErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidChannelId  => "invalid-channel-id",
            Self::InvalidJobId      => "invalid-job-id",
            Self::StaleShare        => "stale-share",
            Self::DifficultyTooLow  => "difficulty-too-low",
            Self::Other             => "other",
            Self::Custom(s)         => s,
        }
    }
}

/// Build a 6-byte SV2 frame header.
///
/// extension_type is always 0x0000 at this layer — channel_msg routing
/// is implicit in msg_type for the standard mining protocol.
fn build_header(msg_type: u8, payload_len: usize) -> Result<[u8; 6], SubmitResponseEncodeError> {
    if payload_len > 0x00FF_FFFF {
        return Err(SubmitResponseEncodeError::PayloadTooLarge(payload_len));
    }
    let mut hdr = [0u8; 6];
    // extension_type bytes [0..2] stay as zero.
    hdr[2] = msg_type;
    hdr[3] = (payload_len & 0xFF) as u8;
    hdr[4] = ((payload_len >> 8)  & 0xFF) as u8;
    hdr[5] = ((payload_len >> 16) & 0xFF) as u8;
    Ok(hdr)
}

/// Encode `SubmitSharesSuccess` (msg_type 0x1c).
///
/// Payload layout per SRI spec 5.4.9 (all little-endian):
///   - channel_id:                 u32  (4 bytes)
///   - last_sequence_number:       u32  (4 bytes)  — the highest seq_num
///                                                   acknowledged by
///                                                   this response
///   - new_submits_accepted_count: u32  (4 bytes)  — running counter of
///                                                   accepted submits on
///                                                   this channel
///   - new_shares_sum:             u64  (8 bytes)  — cumulative weight
///                                                   (difficulty units)
///
/// Total frame size: 6-byte header + 20-byte payload = 26 bytes.
pub fn encode_submit_shares_success(
    channel_id:                 u32,
    last_sequence_number:       u32,
    new_submits_accepted_count: u32,
    new_shares_sum:             u64,
) -> Result<Vec<u8>, SubmitResponseEncodeError> {
    const PAYLOAD_LEN: usize = 4 + 4 + 4 + 8;

    let header = build_header(MSG_TYPE_SUBMIT_SHARES_SUCCESS, PAYLOAD_LEN)?;

    let mut out = Vec::with_capacity(6 + PAYLOAD_LEN);
    out.extend_from_slice(&header);
    out.extend_from_slice(&channel_id.to_le_bytes());
    out.extend_from_slice(&last_sequence_number.to_le_bytes());
    out.extend_from_slice(&new_submits_accepted_count.to_le_bytes());
    out.extend_from_slice(&new_shares_sum.to_le_bytes());
    Ok(out)
}

/// Encode `SubmitSharesError` (msg_type 0x1d).
///
/// Payload layout per SRI spec 5.4.10:
///   - channel_id:      u32       (4 bytes LE)
///   - sequence_number: u32       (4 bytes LE)  — the rejected share's
///                                                 seq_num, echoed from
///                                                 the miner's submit
///   - error_code:      STR0_255  (1-byte length prefix + ASCII bytes)
///
/// Total frame size: 6-byte header + 9 + error_code.len() bytes.
pub fn encode_submit_shares_error(
    channel_id:      u32,
    sequence_number: u32,
    error_code:      &str,
) -> Result<Vec<u8>, SubmitResponseEncodeError> {
    let code_bytes = error_code.as_bytes();
    if code_bytes.len() > 255 {
        return Err(SubmitResponseEncodeError::ErrorCodeTooLong(code_bytes.len()));
    }

    let payload_len = 4 + 4 + 1 + code_bytes.len();
    let header = build_header(MSG_TYPE_SUBMIT_SHARES_ERROR, payload_len)?;

    let mut out = Vec::with_capacity(6 + payload_len);
    out.extend_from_slice(&header);
    out.extend_from_slice(&channel_id.to_le_bytes());
    out.extend_from_slice(&sequence_number.to_le_bytes());
    out.push(code_bytes.len() as u8);
    out.extend_from_slice(code_bytes);
    Ok(out)
}

// ─────────────────────────────────────────────────────────────────────
//                               TESTS
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_frame_has_correct_header() {
        let frame = encode_submit_shares_success(1, 42, 1, 1_000_000).unwrap();
        // extension_type = 0x0000
        assert_eq!(&frame[0..2], &[0x00, 0x00]);
        // msg_type = 0x1c
        assert_eq!(frame[2], 0x1c);
        // u24 LE payload length = 20
        assert_eq!(frame[3], 0x14);
        assert_eq!(frame[4], 0x00);
        assert_eq!(frame[5], 0x00);
        assert_eq!(frame.len(), 6 + 20);
    }

    #[test]
    fn success_frame_serializes_all_fields_little_endian() {
        // Use non-symmetric values so byte-order bugs surface.
        let frame = encode_submit_shares_success(
            0x1234_5678,              // channel_id
            0xAABB_CCDD,              // last_sequence_number
            0x0102_0304,              // new_submits_accepted_count
            0x1122_3344_5566_7788,    // new_shares_sum
        ).unwrap();
        let p = &frame[6..];
        assert_eq!(&p[0..4],  &[0x78, 0x56, 0x34, 0x12]);
        assert_eq!(&p[4..8],  &[0xDD, 0xCC, 0xBB, 0xAA]);
        assert_eq!(&p[8..12], &[0x04, 0x03, 0x02, 0x01]);
        assert_eq!(&p[12..20],&[0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]);
    }

    #[test]
    fn error_frame_has_correct_header_and_length() {
        let frame = encode_submit_shares_error(
            1, 42, SubmitErrorCode::StaleShare.as_str(),
        ).unwrap();
        // msg_type = 0x1d
        assert_eq!(frame[2], 0x1d);
        // payload = 4 (channel_id) + 4 (seq_num) + 1 (len prefix) + 11 (stale-share) = 20
        let expected_payload_len: u32 = 4 + 4 + 1 + "stale-share".len() as u32;
        let encoded_len =
            (frame[3] as u32)
            | ((frame[4] as u32) << 8)
            | ((frame[5] as u32) << 16);
        assert_eq!(encoded_len, expected_payload_len);
        assert_eq!(frame.len(), 6 + expected_payload_len as usize);
    }

    #[test]
    fn error_frame_serializes_error_code_as_str0_255() {
        let code = "invalid-job-id";
        let frame = encode_submit_shares_error(7, 99, code).unwrap();
        let p = &frame[6..];
        // channel_id LE
        assert_eq!(&p[0..4], &[7, 0, 0, 0]);
        // sequence_number LE
        assert_eq!(&p[4..8], &[99, 0, 0, 0]);
        // STR0_255: 1 byte length + body
        assert_eq!(p[8] as usize, code.len());
        assert_eq!(&p[9..9 + code.len()], code.as_bytes());
    }

    #[test]
    fn error_code_too_long_is_rejected() {
        // Build a 256-byte string; must fail bounds check.
        let too_long: String = "x".repeat(256);
        let err = encode_submit_shares_error(1, 0, &too_long).unwrap_err();
        assert!(matches!(
            err,
            SubmitResponseEncodeError::ErrorCodeTooLong(256)
        ));
    }

    #[test]
    fn error_code_at_boundary_accepted() {
        // Exactly 255 bytes is OK.
        let max_len: String = "y".repeat(255);
        let frame = encode_submit_shares_error(1, 0, &max_len).unwrap();
        // Payload length should be 4 + 4 + 1 + 255 = 264
        let encoded_len =
            (frame[3] as u32)
            | ((frame[4] as u32) << 8)
            | ((frame[5] as u32) << 16);
        assert_eq!(encoded_len, 264);
    }

    #[test]
    fn all_canonical_error_codes_are_ascii_nonempty() {
        // Smoke test: canonical codes must encode without failure and
        // never produce empty strings (empty error_code is ambiguous
        // on the wire).
        for code in [
            SubmitErrorCode::InvalidChannelId,
            SubmitErrorCode::InvalidJobId,
            SubmitErrorCode::StaleShare,
            SubmitErrorCode::DifficultyTooLow,
            SubmitErrorCode::Other,
        ] {
            let s = code.as_str();
            assert!(!s.is_empty());
            assert!(s.is_ascii());
            assert!(encode_submit_shares_error(1, 0, s).is_ok());
        }
    }
}
