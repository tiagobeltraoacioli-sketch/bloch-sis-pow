// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Sprint 9-alpha: decode `SetupConnection` from decrypted plaintext.
//
// The decrypted plaintext produced by `NoiseCodec::decrypt` is a raw
// SV2 frame: 6-byte header (extension | msg_type | msg_length)
// followed by the payload. This module splits that framing, dispatches
// on `msg_type`, and deserialises the payload into an owned struct
// that the session loop can forward to the policy layer.
//
// Why own the fields instead of returning `SetupConnection<'decoder>`?
// The SRI struct borrows from the decode buffer via `Str0255<'decoder>`,
// which means the buffer has to outlive every downstream consumer.
// Copying the handful of small strings into `String` and dropping the
// borrowed struct keeps the session loop ownership simple. Sprint
// 9-gamma will build the response `SetupConnectionSuccess` from these
// owned values plus policy output, so nothing is lost by materialising
// here.

use super::binary_sv2;
use super::common_messages_sv2::{self, SetupConnection};

/// SV2 fixed frame header size: 3-byte extension + 1-byte msg_type +
/// 3-byte msg_length = 7 bytes total when encoded as SV2 U24 fields.
///
/// Reference: https://github.com/stratum-mining/sv2-spec/blob/main/03-Protocol-Overview.md#3-framing
/// Layout:
///   bytes 0..2  : extension_type (U16)
///   byte  2     : msg_type       (U8)
///   bytes 3..6  : msg_length     (U24)
pub const SV2_FRAME_HEADER_LEN: usize = 6;

/// Owned, lifetime-free mirror of `SetupConnection<'decoder>`.
///
/// Populated by [`decode_setup_connection`]; consumed by the session
/// loop to drive the `SetupConnectionPolicy` in Sprint 9-beta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedSetupConnection {
    /// Raw protocol discriminant. `0 = Mining`, `1 = JobDeclaration`,
    /// `2 = TemplateDistribution`. Matched against
    /// `SetupConnectionProtocol::from_u8` in the policy layer.
    pub protocol: u8,
    pub min_version: u16,
    pub max_version: u16,
    pub flags: u32,
    pub endpoint_host: String,
    pub endpoint_port: u16,
    pub vendor: String,
    pub hardware_version: String,
    pub firmware: String,
    pub device_id: String,
}

/// Errors that can occur while decoding a SetupConnection frame.
#[derive(Debug)]
pub enum DecodeError {
    /// Buffer was shorter than the SV2 frame header.
    Truncated { got: usize, need: usize },
    /// Header claimed a payload longer than what we actually have.
    PayloadShort { claimed: usize, available: usize },
    /// Frame header was valid but `msg_type` was not
    /// `MESSAGE_TYPE_SETUP_CONNECTION (0x00)`.
    UnexpectedMessageType(u8),
    /// `binary_sv2::from_bytes` rejected the payload.
    BinaryError(String),
    /// Str0255 field was not valid UTF-8 when materialised.
    /// SV2 allows arbitrary bytes in these fields; we reject for now
    /// and revisit if a real device trips it.
    NotUtf8 { field: &'static str },
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated { got, need } => {
                write!(f, "plaintext truncated: got {got} bytes, need {need}")
            }
            Self::PayloadShort { claimed, available } => write!(
                f,
                "header claims {claimed}-byte payload but only {available} bytes available"
            ),
            Self::UnexpectedMessageType(t) => {
                write!(f, "expected msg_type 0x00 (SetupConnection), got 0x{t:02x}")
            }
            Self::BinaryError(s) => write!(f, "binary_sv2 decode: {s}"),
            Self::NotUtf8 { field } => write!(f, "field '{field}' not valid UTF-8"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Parse an SV2 frame header out of `buf` and return
/// `(msg_type, payload_len)` plus the offset at which the payload
/// starts. Does not allocate.
fn parse_header(buf: &[u8]) -> Result<(u8, usize), DecodeError> {
    if buf.len() < SV2_FRAME_HEADER_LEN {
        return Err(DecodeError::Truncated {
            got: buf.len(),
            need: SV2_FRAME_HEADER_LEN,
        });
    }
    // Bytes 0..2 : extension_type (we don't care at this layer)
    let msg_type = buf[2];
    // Bytes 3..6 : msg_length (U24, little-endian per SV2 spec)
    let msg_length = (buf[3] as usize)
        | ((buf[4] as usize) << 8)
        | ((buf[5] as usize) << 16);
    Ok((msg_type, msg_length))
}

/// Decode a `SetupConnection` message from a decrypted SV2 plaintext
/// buffer.
///
/// `plaintext` is consumed by this function (re-interpreted in-place
/// by the SV2 decoder). The caller keeps ownership of the underlying
/// `Vec<u8>` and can reuse it.
pub fn decode_setup_connection(
    plaintext: &mut [u8],
) -> Result<DecodedSetupConnection, DecodeError> {
    let (msg_type, payload_len) = parse_header(plaintext)?;

    if msg_type != common_messages_sv2::MESSAGE_TYPE_SETUP_CONNECTION {
        return Err(DecodeError::UnexpectedMessageType(msg_type));
    }

    let header_end = SV2_FRAME_HEADER_LEN;
    let payload_end = header_end
        .checked_add(payload_len)
        .ok_or(DecodeError::PayloadShort {
            claimed: payload_len,
            available: 0,
        })?;

    if payload_end > plaintext.len() {
        return Err(DecodeError::PayloadShort {
            claimed: payload_len,
            available: plaintext.len().saturating_sub(header_end),
        });
    }

    let payload = &mut plaintext[header_end..payload_end];

    // `from_bytes` borrows from `payload` for `'decoder`. We immediately
    // copy the handful of fields we care about into owned values and
    // drop the borrow before returning.
    let msg: SetupConnection = binary_sv2::from_bytes(payload)
        .map_err(|e| DecodeError::BinaryError(format!("{e:?}")))?;

    // Each Str0255 exposes `.as_utf8_or_hex()` (hex fallback). We want
    // strict UTF-8 at this layer; hex escape would silently accept
    // garbage from a buggy client.
    let endpoint_host = str0255_to_owned(msg.endpoint_host.inner_as_ref(), "endpoint_host")?;
    let vendor = str0255_to_owned(msg.vendor.inner_as_ref(), "vendor")?;
    let hardware_version = str0255_to_owned(msg.hardware_version.inner_as_ref(), "hardware_version")?;
    let firmware = str0255_to_owned(msg.firmware.inner_as_ref(), "firmware")?;
    let device_id = str0255_to_owned(msg.device_id.inner_as_ref(), "device_id")?;

    Ok(DecodedSetupConnection {
        protocol: msg.protocol as u8,
        min_version: msg.min_version,
        max_version: msg.max_version,
        flags: msg.flags,
        endpoint_host,
        endpoint_port: msg.endpoint_port,
        vendor,
        hardware_version,
        firmware,
        device_id,
    })
}

fn str0255_to_owned(bytes: &[u8], field: &'static str) -> Result<String, DecodeError> {
    std::str::from_utf8(bytes)
        .map(|s| s.to_owned())
        .map_err(|_| DecodeError::NotUtf8 { field })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Happy-path: hand-crafted SetupConnection payload.
    ///
    /// Extension=0, msg_type=0 (SetupConnection), len set to payload size.
    /// Payload fields (all strings empty to keep the byte layout trivial
    /// and avoid re-implementing the SV2 encoder by hand):
    ///   protocol=0 (Mining), min=2, max=2, flags=0,
    ///   endpoint_host="", endpoint_port=3334,
    ///   vendor="sv2-test", hardware_version="", firmware="0.1",
    ///   device_id="".
    ///
    /// We encode it via `binary_sv2::to_bytes` to avoid hard-coding
    /// byte offsets that are a moving target across SRI minor releases.
    #[test]
    fn decode_happy_path_roundtrip() {
        use super::binary_sv2;
        use super::common_messages_sv2::{Protocol, SetupConnection};

        // Build the message (requires helpers to construct Str0255).
        // If this test fails to compile because Str0255 construction
        // API changed, fall back to hex-hardcoded bytes.
        let msg = SetupConnection {
            protocol: Protocol::MiningProtocol,
            min_version: 2,
            max_version: 2,
            flags: 0,
            endpoint_host: "".to_string().try_into().expect("endpoint_host"),
            endpoint_port: 3334,
            vendor: "sv2-test".to_string().try_into().expect("vendor"),
            hardware_version: "".to_string().try_into().expect("hardware_version"),
            firmware: "0.1".to_string().try_into().expect("firmware"),
            device_id: "".to_string().try_into().expect("device_id"),
        };

        let payload = binary_sv2::to_bytes(msg).expect("encode payload");

        // Build SV2 frame: header (6 bytes) + payload.
        let mut frame = Vec::with_capacity(SV2_FRAME_HEADER_LEN + payload.len());
        frame.extend_from_slice(&[0x00, 0x00]);                          // extension_type
        frame.push(common_messages_sv2::MESSAGE_TYPE_SETUP_CONNECTION);  // msg_type
        let len = payload.len() as u32;
        frame.push((len & 0xff) as u8);                                  // msg_length U24 LE
        frame.push(((len >> 8) & 0xff) as u8);
        frame.push(((len >> 16) & 0xff) as u8);
        frame.extend_from_slice(&payload);

        let decoded = decode_setup_connection(&mut frame).expect("decode ok");
        assert_eq!(decoded.protocol, 0);
        assert_eq!(decoded.min_version, 2);
        assert_eq!(decoded.max_version, 2);
        assert_eq!(decoded.flags, 0);
        assert_eq!(decoded.endpoint_port, 3334);
        assert_eq!(decoded.vendor, "sv2-test");
        assert_eq!(decoded.firmware, "0.1");
    }

    #[test]
    fn decode_rejects_truncated_header() {
        let mut buf = vec![0u8; 3];
        let err = decode_setup_connection(&mut buf).unwrap_err();
        assert!(matches!(err, DecodeError::Truncated { got: 3, need: 6 }));
    }

    #[test]
    fn decode_rejects_wrong_msg_type() {
        // Valid 6-byte header, msg_type = 0x01 (SetupConnectionSuccess)
        let mut buf = vec![0x00, 0x00, 0x01, 0x00, 0x00, 0x00];
        let err = decode_setup_connection(&mut buf).unwrap_err();
        assert!(matches!(err, DecodeError::UnexpectedMessageType(0x01)));
    }

    #[test]
    fn decode_rejects_payload_short() {
        // Header claims 100-byte payload, we only supply 10 bytes of payload.
        let mut buf = vec![0u8; SV2_FRAME_HEADER_LEN + 10];
        buf[2] = common_messages_sv2::MESSAGE_TYPE_SETUP_CONNECTION;
        buf[3] = 100;
        let err = decode_setup_connection(&mut buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::PayloadShort { claimed: 100, available: 10 }
        ));
    }
}
