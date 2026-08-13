// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Sprint 10-beta: Decode OpenStandardMiningChannel from a decrypted SV2 frame.
//
// Manual byte parser (no SRI dependency) to avoid API surprises between
// mining_sv2 v1.0 and v8.0. The wire format is stable (SV2 spec section 5.4.1)
// so a hand parser is fine and faster than round-tripping through borrowed
// types.
//
// Wire format for OpenStandardMiningChannel payload:
//   request_id         : u32  LE        (4 bytes)
//   user_identity      : Str0255        (1 byte len + UTF-8)
//   nominal_hash_rate  : f32  LE        (4 bytes)
//   max_target         : U256           (32 bytes BE)
//
// Frame header (6 bytes, preceeds payload):
//   extension_type     : u16  LE        (2 bytes, must be 0 for mining)
//   msg_type           : u8              (1 byte, 0x10 for this message)
//   msg_length         : u24  LE        (3 bytes)

#[derive(Debug, Clone)]
pub struct DecodedOpenStandardChannel {
    pub request_id:         u32,
    pub user_identity:      String,
    pub nominal_hash_rate:  f32,
    pub max_target:         [u8; 32],
}

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("frame too short: {0} bytes (need at least 6 for SV2 header)")]
    TooShort(usize),

    #[error("unexpected msg_type: 0x{got:02x} (expected 0x{want:02x})")]
    WrongMessageType { got: u8, want: u8 },

    #[error("payload length mismatch: header says {header}, got {actual}")]
    PayloadLengthMismatch { header: u32, actual: usize },

    #[error("payload truncated at field `{0}`: need {1} more bytes")]
    PayloadTruncated(&'static str, usize),

    #[error("user_identity contains invalid UTF-8")]
    InvalidUtf8,
}

const MSG_TYPE_OPEN_STANDARD_CHANNEL: u8 = 0x10;

fn parse_header(frame: &[u8]) -> Result<(u8, u32), DecodeError> {
    if frame.len() < 6 {
        return Err(DecodeError::TooShort(frame.len()));
    }
    let msg_type = frame[2];
    let msg_length = u32::from(frame[3])
        | (u32::from(frame[4]) << 8)
        | (u32::from(frame[5]) << 16);
    Ok((msg_type, msg_length))
}

pub fn decode_open_standard_channel(
    frame: &[u8],
) -> Result<DecodedOpenStandardChannel, DecodeError> {
    let (msg_type, msg_length) = parse_header(frame)?;

    if msg_type != MSG_TYPE_OPEN_STANDARD_CHANNEL {
        return Err(DecodeError::WrongMessageType {
            got:  msg_type,
            want: MSG_TYPE_OPEN_STANDARD_CHANNEL,
        });
    }

    let payload = &frame[6..];
    if payload.len() != msg_length as usize {
        return Err(DecodeError::PayloadLengthMismatch {
            header: msg_length,
            actual: payload.len(),
        });
    }

    let mut cursor = 0usize;

    // request_id : u32 LE
    if payload.len() < cursor + 4 {
        return Err(DecodeError::PayloadTruncated("request_id", 4));
    }
    let request_id = u32::from_le_bytes([
        payload[cursor], payload[cursor + 1],
        payload[cursor + 2], payload[cursor + 3],
    ]);
    cursor += 4;

    // user_identity : Str0255 (1-byte length prefix + UTF-8)
    if payload.len() < cursor + 1 {
        return Err(DecodeError::PayloadTruncated("user_identity_len", 1));
    }
    let user_len = payload[cursor] as usize;
    cursor += 1;
    if payload.len() < cursor + user_len {
        return Err(DecodeError::PayloadTruncated("user_identity_bytes", user_len));
    }
    let user_identity = std::str::from_utf8(&payload[cursor..cursor + user_len])
        .map_err(|_| DecodeError::InvalidUtf8)?
        .to_string();
    cursor += user_len;

    // nominal_hash_rate : f32 LE
    if payload.len() < cursor + 4 {
        return Err(DecodeError::PayloadTruncated("nominal_hash_rate", 4));
    }
    let nominal_hash_rate = f32::from_le_bytes([
        payload[cursor], payload[cursor + 1],
        payload[cursor + 2], payload[cursor + 3],
    ]);
    cursor += 4;

    // max_target : U256 (32 bytes big-endian per SV2 spec)
    if payload.len() < cursor + 32 {
        return Err(DecodeError::PayloadTruncated("max_target", 32));
    }
    let mut max_target = [0u8; 32];
    max_target.copy_from_slice(&payload[cursor..cursor + 32]);
    // cursor += 32;  // not needed, end of payload

    Ok(DecodedOpenStandardChannel {
        request_id,
        user_identity,
        nominal_hash_rate,
        max_target,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_frame_rejected() {
        let err = decode_open_standard_channel(&[0; 3]).unwrap_err();
        assert!(matches!(err, DecodeError::TooShort(3)));
    }

    #[test]
    fn wrong_message_type_rejected() {
        // header only: extension_type=0, msg_type=0x00, length=0
        let frame = [0, 0, 0x00, 0, 0, 0];
        let err = decode_open_standard_channel(&frame).unwrap_err();
        assert!(matches!(err, DecodeError::WrongMessageType { got: 0x00, .. }));
    }

    #[test]
    fn round_trip_minimal_valid() {
        // Build a valid frame manually:
        //   request_id = 42 (u32 LE)
        //   user = "alice" (5 bytes, len prefix 0x05)
        //   nominal_hash_rate = 1000.0 (f32 LE)
        //   max_target = all 0xFF (U256)
        let user = b"alice";
        let mut payload = Vec::new();
        payload.extend_from_slice(&42u32.to_le_bytes());
        payload.push(user.len() as u8);
        payload.extend_from_slice(user);
        payload.extend_from_slice(&1000.0f32.to_le_bytes());
        payload.extend_from_slice(&[0xFFu8; 32]);

        let mut frame = Vec::new();
        // header: ext_type=0, msg_type=0x10, length=payload.len()
        frame.extend_from_slice(&[0, 0, 0x10]);
        let len = payload.len() as u32;
        frame.push((len & 0xFF) as u8);
        frame.push(((len >> 8) & 0xFF) as u8);
        frame.push(((len >> 16) & 0xFF) as u8);
        frame.extend_from_slice(&payload);

        let decoded = decode_open_standard_channel(&frame).unwrap();
        assert_eq!(decoded.request_id, 42);
        assert_eq!(decoded.user_identity, "alice");
        assert_eq!(decoded.nominal_hash_rate, 1000.0);
        assert_eq!(decoded.max_target, [0xFF; 32]);
    }

    #[test]
    fn truncated_payload_rejected() {
        // header says payload = 10 bytes, but we only provide 5.
        // Should get PayloadLengthMismatch.
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0, 0, 0x10, 10, 0, 0]);
        frame.extend_from_slice(&[0u8; 5]);
        let err = decode_open_standard_channel(&frame).unwrap_err();
        assert!(matches!(err, DecodeError::PayloadLengthMismatch { .. }));
    }
}
