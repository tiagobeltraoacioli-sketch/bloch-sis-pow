#![no_main]
//! Genesis-4's envelope and attestation decoders at the remote-wire boundary.

use bloch_pos_node::codec::{self, Reader};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = codec::decode_envelope(data);

    let mut reader = Reader::new(data);
    let _ = codec::decode_attestation(&mut reader).and_then(|_| reader.finish());
});
