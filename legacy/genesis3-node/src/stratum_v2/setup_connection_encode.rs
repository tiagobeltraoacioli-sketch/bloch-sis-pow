// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Sprint 9-gamma: encode SetupConnectionResponseDescriptor into SV2 wire frames.

use super::binary_sv2;
use super::common_messages_sv2::{
    self, SetupConnectionError, SetupConnectionSuccess,
};
use super::setup_connection_decode::SV2_FRAME_HEADER_LEN;
use super::setup_connection_sri::SetupConnectionResponseDescriptor;

use binary_sv2::Str0255;

#[derive(Debug)]
pub enum EncodeError {
    BinaryError(String),
    Str0255Conversion(String),
    PayloadTooLarge(usize),
}

impl std::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BinaryError(s) => write!(f, "binary_sv2 encode: {s}"),
            Self::Str0255Conversion(s) => write!(f, "Str0255 conversion: {s}"),
            Self::PayloadTooLarge(n) => {
                write!(f, "payload {n} bytes exceeds SV2 U24 max (16_777_215)")
            }
        }
    }
}

impl std::error::Error for EncodeError {}

const SV2_U24_MAX: usize = 16_777_215;

pub fn encode_setup_response(
    descriptor: &SetupConnectionResponseDescriptor,
) -> Result<Vec<u8>, EncodeError> {
    let (msg_type, payload) = match descriptor {
        SetupConnectionResponseDescriptor::Success {
            used_version,
            used_flags,
        } => {
            let msg = SetupConnectionSuccess {
                used_version: *used_version,
                flags: *used_flags,
            };
            let bytes = binary_sv2::to_bytes(msg)
                .map_err(|e| EncodeError::BinaryError(format!("{e:?}")))?;
            (
                common_messages_sv2::MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS,
                bytes,
            )
        }
        SetupConnectionResponseDescriptor::Error { error_code } => {
            let code_string: String = (*error_code).to_owned();
            let code_str0255: Str0255<'static> = code_string
                .try_into()
                .map_err(|e| EncodeError::Str0255Conversion(format!("{e:?}")))?;

            let msg = SetupConnectionError {
                flags: 0,
                error_code: code_str0255,
            };
            let bytes = binary_sv2::to_bytes(msg)
                .map_err(|e| EncodeError::BinaryError(format!("{e:?}")))?;
            (
                common_messages_sv2::MESSAGE_TYPE_SETUP_CONNECTION_ERROR,
                bytes,
            )
        }
    };

    if payload.len() > SV2_U24_MAX {
        return Err(EncodeError::PayloadTooLarge(payload.len()));
    }

    let mut frame = Vec::with_capacity(SV2_FRAME_HEADER_LEN + payload.len());
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.push(msg_type);
    let len = payload.len() as u32;
    frame.push((len & 0xff) as u8);
    frame.push(((len >> 8) & 0xff) as u8);
    frame.push(((len >> 16) & 0xff) as u8);
    frame.extend_from_slice(&payload);

    Ok(frame)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_success_produces_valid_frame() {
        let descriptor = SetupConnectionResponseDescriptor::Success {
            used_version: 2,
            used_flags: 0x0000_0001,
        };
        let frame = encode_setup_response(&descriptor).expect("encode ok");

        assert_eq!(frame[0], 0x00);
        assert_eq!(frame[1], 0x00);
        assert_eq!(
            frame[2],
            common_messages_sv2::MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS
        );

        let msg_length =
            (frame[3] as usize) | ((frame[4] as usize) << 8) | ((frame[5] as usize) << 16);
        assert_eq!(msg_length, frame.len() - SV2_FRAME_HEADER_LEN);
        assert_eq!(msg_length, 6);

        assert_eq!(frame[SV2_FRAME_HEADER_LEN], 0x02);
        assert_eq!(frame[SV2_FRAME_HEADER_LEN + 1], 0x00);
        assert_eq!(frame[SV2_FRAME_HEADER_LEN + 2], 0x01);
        assert_eq!(frame[SV2_FRAME_HEADER_LEN + 3], 0x00);
        assert_eq!(frame[SV2_FRAME_HEADER_LEN + 4], 0x00);
        assert_eq!(frame[SV2_FRAME_HEADER_LEN + 5], 0x00);
    }

    #[test]
    fn encode_error_produces_valid_frame() {
        let descriptor = SetupConnectionResponseDescriptor::Error {
            error_code: "unsupported-protocol",
        };
        let frame = encode_setup_response(&descriptor).expect("encode ok");

        assert_eq!(
            frame[2],
            common_messages_sv2::MESSAGE_TYPE_SETUP_CONNECTION_ERROR
        );

        let msg_length =
            (frame[3] as usize) | ((frame[4] as usize) << 8) | ((frame[5] as usize) << 16);
        assert_eq!(msg_length, frame.len() - SV2_FRAME_HEADER_LEN);

        assert_eq!(frame[SV2_FRAME_HEADER_LEN], 0x00);
        assert_eq!(frame[SV2_FRAME_HEADER_LEN + 1], 0x00);
        assert_eq!(frame[SV2_FRAME_HEADER_LEN + 2], 0x00);
        assert_eq!(frame[SV2_FRAME_HEADER_LEN + 3], 0x00);

        assert_eq!(frame[SV2_FRAME_HEADER_LEN + 4], 20);
        assert_eq!(
            &frame[SV2_FRAME_HEADER_LEN + 5..SV2_FRAME_HEADER_LEN + 5 + 20],
            b"unsupported-protocol"
        );
    }

    #[test]
    fn encode_error_handles_all_known_codes() {
        for code in &[
            "unsupported-protocol",
            "protocol-version-mismatch",
            "unsupported-feature-flags",
        ] {
            let descriptor = SetupConnectionResponseDescriptor::Error { error_code: code };
            encode_setup_response(&descriptor)
                .unwrap_or_else(|e| panic!("encode failed for code {code:?}: {e}"));
        }
    }
}
