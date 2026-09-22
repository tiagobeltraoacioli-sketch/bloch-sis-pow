//! Bounded reader for the existing bincode::serialize fixed-int proof wire.
use bincode::Options;
use serde::{de::DeserializeOwned, Serialize};

/// Bincode checks encoded size before allocating the returned output buffer.
/// This cannot bound memory already used to construct the native proof value.
pub(crate) fn encode_bounded<T: Serialize>(value: &T, limit: u64) -> Result<Vec<u8>, String> {
    bincode::DefaultOptions::new().with_fixint_encoding().with_limit(limit)
        .serialize(value).map_err(|_| "proof exceeds output budget or cannot be encoded".into())
}

pub(crate) fn decode_bounded<T: DeserializeOwned>(bytes: &[u8], limit: u64) -> Result<T, String> {
    if bytes.len() as u64 > limit { return Err("proof exceeds byte limit".into()); }
    bincode::DefaultOptions::new().with_fixint_encoding().with_limit(limit)
        .reject_trailing_bytes().deserialize(bytes).map_err(|_| "invalid proof encoding".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn emitted_fixed_int_wire_roundtrips_and_refuses_aliases_or_trailing_data() {
        let value = vec![7u64, 300u64];
        let emitted = bincode::serialize(&value).unwrap();
        assert_eq!(encode_bounded(&value, emitted.len() as u64).unwrap(), emitted);
        assert!(encode_bounded(&value, emitted.len() as u64 - 1).is_err());
        assert_eq!(decode_bounded::<Vec<u64>>(&emitted, 1024).unwrap(), value);
        assert!(bincode::DefaultOptions::new().with_limit(1024).deserialize::<Vec<u64>>(&emitted).is_err());
        let varint = bincode::DefaultOptions::new().serialize(&value).unwrap();
        assert!(decode_bounded::<Vec<u64>>(&varint, 1024).is_err());
        let mut trailing = emitted.clone(); trailing.push(0);
        assert!(decode_bounded::<Vec<u64>>(&trailing, 1024).is_err());
        assert!(decode_bounded::<Vec<u64>>(&emitted, 1).is_err());
    }
}
