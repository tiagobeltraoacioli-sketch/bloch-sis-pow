// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Sprint 10-beta: Encode OpenStandardMiningChannel.Success (0x11)
// and OpenMiningChannel.Error (0x12) as SV2 plaintext frames.
//
// Output is plaintext (pre-Noise-encryption). Session layer is responsible
// for passing the buffer through NoiseCodec before wire write.
//
// Wire format for OpenStandardMiningChannelSuccess payload:
//   request_id         : u32  LE        (4 bytes)
//   channel_id         : u32  LE        (4 bytes)
//   target             : U256 BE        (32 bytes)
//   extranonce_prefix  : B032           (1 byte len + data, <= 32)
//   group_channel_id   : u32  LE        (4 bytes)
//
// Wire format for OpenMiningChannelError payload:
//   request_id  : u32  LE         (4 bytes)
//   error_code  : Str0255         (1 byte len + UTF-8)

const MSG_TYPE_OPEN_STANDARD_CHANNEL_SUCCESS: u8 = 0x11;
const MSG_TYPE_OPEN_MINING_CHANNEL_ERROR:     u8 = 0x12;

/// Error codes per SV2 spec section 5 (Mining Protocol).
pub enum ChannelErrorCode {
    UnknownUser,
    MaxTargetOutOfRange,
    TooManyChannels,
    Custom(&'static str),
}

impl ChannelErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UnknownUser           => "unknown-user",
            Self::MaxTargetOutOfRange   => "max-target-out-of-range",
            Self::TooManyChannels       => "too-many-channels",
            Self::Custom(s)             => s,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EncodeError {
    #[error("error_code too long: {0} bytes (max 255)")]
    ErrorCodeTooLong(usize),

    #[error("extranonce_prefix too long: {0} bytes (max 32 for B032)")]
    ExtranoncePrefixTooLong(usize),

    #[error("message payload too large: {0} bytes (SV2 u24 limit)")]
    PayloadTooLarge(usize),
}

/// Build a 6-byte SV2 frame header.
///
/// Layout (little-endian):
///   [0..2] extension_type = 0 (mining)
///   [2]    msg_type
///   [3..6] msg_length (u24)
fn build_header(msg_type: u8, payload_len: usize) -> Result<[u8; 6], EncodeError> {
    if payload_len > 0x00_FFFFFF {
        return Err(EncodeError::PayloadTooLarge(payload_len));
    }
    let len = payload_len as u32;
    Ok([
        0x00, 0x00,                     // extension_type = 0
        msg_type,
        (len & 0xFF) as u8,
        ((len >> 8) & 0xFF) as u8,
        ((len >> 16) & 0xFF) as u8,
    ])
}

/// Encode OpenStandardMiningChannel.Success as a plaintext SV2 frame.
pub fn encode_open_standard_channel_success(
    request_id:         u32,
    channel_id:         u32,
    target:             &[u8; 32],
    extranonce_prefix:  &[u8],
    group_channel_id:   u32,
) -> Result<Vec<u8>, EncodeError> {
    if extranonce_prefix.len() > 32 {
        return Err(EncodeError::ExtranoncePrefixTooLong(extranonce_prefix.len()));
    }

    let mut payload = Vec::with_capacity(4 + 4 + 32 + 1 + extranonce_prefix.len() + 4);
    payload.extend_from_slice(&request_id.to_le_bytes());
    payload.extend_from_slice(&channel_id.to_le_bytes());
    payload.extend_from_slice(target);
    payload.push(extranonce_prefix.len() as u8);
    payload.extend_from_slice(extranonce_prefix);
    payload.extend_from_slice(&group_channel_id.to_le_bytes());

    let header = build_header(MSG_TYPE_OPEN_STANDARD_CHANNEL_SUCCESS, payload.len())?;

    let mut frame = Vec::with_capacity(6 + payload.len());
    frame.extend_from_slice(&header);
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// Encode OpenMiningChannel.Error as a plaintext SV2 frame.
pub fn encode_open_mining_channel_error(
    request_id: u32,
    error_code: ChannelErrorCode,
) -> Result<Vec<u8>, EncodeError> {
    let code_str = error_code.as_str();
    let code_bytes = code_str.as_bytes();

    if code_bytes.len() > 255 {
        return Err(EncodeError::ErrorCodeTooLong(code_bytes.len()));
    }

    let mut payload = Vec::with_capacity(4 + 1 + code_bytes.len());
    payload.extend_from_slice(&request_id.to_le_bytes());
    payload.push(code_bytes.len() as u8);
    payload.extend_from_slice(code_bytes);

    let header = build_header(MSG_TYPE_OPEN_MINING_CHANNEL_ERROR, payload.len())?;

    let mut frame = Vec::with_capacity(6 + payload.len());
    frame.extend_from_slice(&header);
    frame.extend_from_slice(&payload);
    Ok(frame)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_frame_header_correct() {
        let target = [0xAAu8; 32];
        let prefix = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let frame = encode_open_standard_channel_success(
            0x12345678, 1, &target, &prefix, 0
        ).unwrap();

        assert_eq!(&frame[0..2], &[0, 0]);
        assert_eq!(frame[2], MSG_TYPE_OPEN_STANDARD_CHANNEL_SUCCESS);

        let expected_payload_len = 4 + 4 + 32 + 1 + 8 + 4;
        let header_len = u32::from(frame[3])
            | (u32::from(frame[4]) << 8)
            | (u32::from(frame[5]) << 16);
        assert_eq!(header_len as usize, expected_payload_len);
        assert_eq!(frame.len(), 6 + expected_payload_len);
    }

    #[test]
    fn success_frame_payload_layout() {
        let target = [0xAAu8; 32];
        let prefix = vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let frame = encode_open_standard_channel_success(
            0x12345678, 0x00000001, &target, &prefix, 0x00000002
        ).unwrap();

        // request_id at [6..10] LE
        assert_eq!(&frame[6..10], &[0x78, 0x56, 0x34, 0x12]);
        // channel_id at [10..14] LE
        assert_eq!(&frame[10..14], &[0x01, 0x00, 0x00, 0x00]);
        // target at [14..46]
        assert_eq!(&frame[14..46], &[0xAA; 32]);
        // extranonce len prefix at [46]
        assert_eq!(frame[46], 8);
        // extranonce bytes at [47..55]
        assert_eq!(&frame[47..55], &prefix[..]);
        // group_channel_id at [55..59] LE
        assert_eq!(&frame[55..59], &[0x02, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn error_frame_has_correct_msg_type_and_code() {
        let frame = encode_open_mining_channel_error(
            0xAABBCCDD,
            ChannelErrorCode::UnknownUser,
        ).unwrap();
        assert_eq!(frame[2], MSG_TYPE_OPEN_MINING_CHANNEL_ERROR);
        assert_eq!(&frame[6..10], &[0xDD, 0xCC, 0xBB, 0xAA]);
        assert_eq!(frame[10] as usize, "unknown-user".len());
        assert_eq!(&frame[11..11 + "unknown-user".len()], b"unknown-user");
    }

    #[test]
    fn custom_error_code_works() {
        let frame = encode_open_mining_channel_error(
            1,
            ChannelErrorCode::Custom("registry-full"),
        ).unwrap();
        assert_eq!(frame[10] as usize, "registry-full".len());
        assert_eq!(&frame[11..11 + "registry-full".len()], b"registry-full");
    }

    #[test]
    fn extranonce_too_long_rejected() {
        let prefix = vec![0u8; 33];
        let err = encode_open_standard_channel_success(
            1, 1, &[0; 32], &prefix, 0
        ).unwrap_err();
        assert!(matches!(err, EncodeError::ExtranoncePrefixTooLong(33)));
    }
}
