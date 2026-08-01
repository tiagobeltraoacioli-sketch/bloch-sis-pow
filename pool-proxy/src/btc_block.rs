//! Bitcoin block serialization primitives for the merged-mining BTC-relay path
//! (a `BtcAndBloch` win — the parent hash met Bitcoin's own target, so it is a
//! real BTC block worth relaying to `bitcoind` via `submitblock`).
//!
//! Every primitive here is validated against a KNOWN Bitcoin test vector — the
//! genesis block (header hash + full non-witness block hex + coinbase txid +
//! single-leaf merkle root), the BIP CompactSize vectors, and the BIP141
//! witness-commitment construction — so the serialization is provably
//! byte-correct without a live node.
//!
//! SCOPE: the non-witness block serialization ([`build_block_hex`]) and the
//! witness-commitment output ([`witness_commitment_spk`]) are complete and
//! vector-tested. Relaying a block on a SEGWIT chain additionally needs the full
//! segwit block wrapper (marker/flag + coinbase witness), whose final sign-off
//! requires a live `bitcoind` — see [`crate::merged_engine`]. The Bloch-security
//! path (`submitauxblock`) does NOT depend on any of this.

use crate::validator::sha256d;

/// Bitcoin CompactSize (varint) encoding.
pub fn compact_size(n: u64) -> Vec<u8> {
    if n < 0xfd {
        vec![n as u8]
    } else if n <= 0xffff {
        let mut v = vec![0xfd];
        v.extend_from_slice(&(n as u16).to_le_bytes());
        v
    } else if n <= 0xffff_ffff {
        let mut v = vec![0xfe];
        v.extend_from_slice(&(n as u32).to_le_bytes());
        v
    } else {
        let mut v = vec![0xff];
        v.extend_from_slice(&n.to_le_bytes());
        v
    }
}

/// Double-SHA256 of an 80-byte block header (internal little-endian order; the
/// displayed block hash is this reversed).
pub fn block_header_hash(header: &[u8; 80]) -> [u8; 32] {
    sha256d(header)
}

/// Bitcoin transaction/witness merkle root over `leaves` (bottom-up, duplicating
/// the last node on an odd level). A single leaf returns itself.
pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(*level.last().unwrap());
        }
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&pair[0]);
            buf[32..].copy_from_slice(&pair[1]);
            next.push(sha256d(&buf));
        }
        level = next;
    }
    level[0]
}

/// The BIP141 witness-commitment scriptPubKey a segwit coinbase must carry:
/// `OP_RETURN 0x24 aa21a9ed ‖ SHA256d(witness_root ‖ witness_reserved)`.
///
/// `witness_root` is the merkle root over `[coinbase_wtxid(=0x00…00)] ++
/// other_wtxids` (BIP141 defines the coinbase's wtxid as all-zeros).
/// `witness_reserved` is the 32-byte value in the coinbase input's witness — the
/// standard choice (and what pools use) is all-zeros.
pub fn witness_commitment_spk(other_wtxids: &[[u8; 32]]) -> Vec<u8> {
    let mut leaves = Vec::with_capacity(other_wtxids.len() + 1);
    leaves.push([0u8; 32]); // coinbase wtxid
    leaves.extend_from_slice(other_wtxids);
    let witness_root = merkle_root(&leaves);
    let mut pre = [0u8; 64];
    pre[..32].copy_from_slice(&witness_root);
    // pre[32..] left zero = the reserved value
    let commitment = sha256d(&pre);
    let mut spk = Vec::with_capacity(38);
    spk.extend_from_slice(&[0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]); // OP_RETURN PUSH36 header
    spk.extend_from_slice(&commitment);
    spk
}

/// Serialize a Bitcoin block (non-witness): `header(80) ‖ CompactSize(tx_count)
/// ‖ coinbase ‖ other_txs…`, hex-encoded. `coinbase`/`other_txs` are
/// already-serialized transactions (the non-witness serialization that forms the
/// txid merkle tree — the form `submitblock` accepts for a pre-segwit block, and
/// the base a segwit block wraps with marker/flag + witness).
pub fn build_block_hex(header: &[u8; 80], coinbase: &[u8], other_txs: &[Vec<u8>]) -> String {
    let total: usize = 80 + 9 + coinbase.len() + other_txs.iter().map(Vec::len).sum::<usize>();
    let mut b = Vec::with_capacity(total);
    b.extend_from_slice(header);
    b.extend_from_slice(&compact_size(1 + other_txs.len() as u64));
    b.extend_from_slice(coinbase);
    for t in other_txs {
        b.extend_from_slice(t);
    }
    hex::encode(b)
}

/// Recover the parent header (80 bytes) and full coinbase from an AuxPoW blob
/// (the wire `serialize_auxpow` / `AuxPow::from_bytes` reads): `u32(=80) ‖
/// header(80) ‖ u32(len) ‖ coinbase ‖ …`. Used to assemble the BTC block for a
/// win from the same blob handed to the node.
pub fn header_and_coinbase_from_auxpow(blob: &[u8]) -> Option<([u8; 32], [u8; 80], Vec<u8>)> {
    if blob.len() < 4 + 80 + 4 {
        return None;
    }
    if u32::from_le_bytes(blob[0..4].try_into().ok()?) != 80 {
        return None;
    }
    let mut header = [0u8; 80];
    header.copy_from_slice(&blob[4..84]);
    let cb_len = u32::from_le_bytes(blob[84..88].try_into().ok()?) as usize;
    let end = 88usize.checked_add(cb_len)?;
    if end > blob.len() {
        return None;
    }
    let coinbase = blob[88..end].to_vec();
    Some((block_header_hash(&header), header, coinbase))
}

/// Convert a non-witness (legacy) coinbase serialization into its BIP144 segwit
/// form: insert the `00 01` marker+flag after the 4-byte version, and append the
/// coinbase input's witness (`CompactSize(1) ‖ CompactSize(32) ‖ reserved(32)`)
/// immediately before the 4-byte locktime. The txid (legacy serialization) is
/// unchanged — only the wire/relay form gains the witness. `coinbase` must be a
/// legacy tx of at least version(4)+…+locktime(4) bytes.
pub fn coinbase_with_witness(coinbase: &[u8], witness_reserved: &[u8; 32]) -> Option<Vec<u8>> {
    if coinbase.len() < 8 {
        return None;
    }
    let (version, rest) = coinbase.split_at(4);
    let body = &rest[..rest.len() - 4]; // inputs+outputs (between version and locktime)
    let locktime = &coinbase[coinbase.len() - 4..];
    let mut out = Vec::with_capacity(coinbase.len() + 2 + 34);
    out.extend_from_slice(version);
    out.extend_from_slice(&[0x00, 0x01]); // segwit marker + flag
    out.extend_from_slice(body);
    // coinbase input witness: one stack item, 32 bytes, the reserved value.
    out.extend_from_slice(&compact_size(1));
    out.extend_from_slice(&compact_size(32));
    out.extend_from_slice(witness_reserved);
    out.extend_from_slice(locktime);
    Some(out)
}

/// Serialize a Bitcoin block in BIP144 SEGWIT form for `submitblock`:
/// `header(80) ‖ CompactSize(tx_count) ‖ segwit-coinbase ‖ other_txs…`. The
/// header's merkle root still commits to the LEGACY txids (what the miner
/// hashed, and what the AuxPoW folds) — only the block BODY carries the coinbase
/// witness so bitcoind can verify the witness commitment. `other_txs` are their
/// own already-serialized (witness-carrying, as from `getblocktemplate`) forms.
pub fn build_segwit_block_hex(
    header: &[u8; 80],
    coinbase_legacy: &[u8],
    witness_reserved: &[u8; 32],
    other_txs: &[Vec<u8>],
) -> Option<String> {
    let cb = coinbase_with_witness(coinbase_legacy, witness_reserved)?;
    let mut b = Vec::with_capacity(80 + 9 + cb.len() + other_txs.iter().map(Vec::len).sum::<usize>());
    b.extend_from_slice(header);
    b.extend_from_slice(&compact_size(1 + other_txs.len() as u64));
    b.extend_from_slice(&cb);
    for t in other_txs {
        b.extend_from_slice(t);
    }
    Some(hex::encode(b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator::hex_to_bytes;

    // ── The Bitcoin GENESIS block — the canonical serialization vector ──────────
    const GENESIS_HEADER: &str = concat!(
        "01000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a",
        "29ab5f49", "ffff001d", "1dac2b7c",
    );
    const GENESIS_COINBASE: &str = concat!(
        "01000000010000000000000000000000000000000000000000000000000000000000000000",
        "ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368",
        "616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f75742066",
        "6f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a671",
        "30b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384",
        "df7ba0b8d578a4c702b6bf11d5fac00000000",
    );
    // Displayed genesis block hash + full raw block, from Bitcoin Core.
    const GENESIS_HASH_DISPLAY: &str =
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
    const GENESIS_MERKLE_INTERNAL: &str =
        "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a";

    #[test]
    fn genesis_header_hashes_to_the_genesis_block_hash() {
        let hb = hex_to_bytes(GENESIS_HEADER).unwrap();
        assert_eq!(hb.len(), 80);
        let mut header = [0u8; 80];
        header.copy_from_slice(&hb);
        let mut h = block_header_hash(&header);
        h.reverse(); // internal → display order
        assert_eq!(hex::encode(h), GENESIS_HASH_DISPLAY);
    }

    #[test]
    fn genesis_coinbase_txid_is_the_header_merkle_root() {
        let cb = hex_to_bytes(GENESIS_COINBASE).unwrap();
        let txid = sha256d(&cb);
        // single-tx block: merkle root == coinbase txid == header merkle field.
        assert_eq!(hex::encode(txid), GENESIS_MERKLE_INTERNAL);
        assert_eq!(merkle_root(&[txid]), txid);
    }

    #[test]
    fn build_block_hex_reproduces_the_genesis_block() {
        let hb = hex_to_bytes(GENESIS_HEADER).unwrap();
        let mut header = [0u8; 80];
        header.copy_from_slice(&hb);
        let cb = hex_to_bytes(GENESIS_COINBASE).unwrap();
        let block = build_block_hex(&header, &cb, &[]);
        // header ‖ 01 (tx count) ‖ coinbase — exactly Bitcoin Core's raw genesis.
        let expected = format!("{}01{}", GENESIS_HEADER.to_lowercase(), GENESIS_COINBASE);
        assert_eq!(block, expected);
    }

    #[test]
    fn compact_size_matches_bip_vectors() {
        assert_eq!(compact_size(0), vec![0x00]);
        assert_eq!(compact_size(0xfc), vec![0xfc]);
        assert_eq!(compact_size(0xfd), vec![0xfd, 0xfd, 0x00]);
        assert_eq!(compact_size(0xff), vec![0xfd, 0xff, 0x00]);
        assert_eq!(compact_size(0x0100), vec![0xfd, 0x00, 0x01]);
        assert_eq!(compact_size(0xffff), vec![0xfd, 0xff, 0xff]);
        assert_eq!(compact_size(0x0001_0000), vec![0xfe, 0x00, 0x00, 0x01, 0x00]);
        assert_eq!(compact_size(0xffff_ffff), vec![0xfe, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(
            compact_size(0x0001_0000_0000),
            vec![0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn merkle_root_duplicates_last_on_odd_levels() {
        // 3 leaves: the standard "duplicate the last" behaviour.
        let a = [0x11u8; 32];
        let b = [0x22u8; 32];
        let c = [0x33u8; 32];
        // hand-fold: L0=[a,b,c,c] → [ab, cc] → [abcc]
        let ab = {
            let mut x = [0u8; 64];
            x[..32].copy_from_slice(&a);
            x[32..].copy_from_slice(&b);
            sha256d(&x)
        };
        let cc = {
            let mut x = [0u8; 64];
            x[..32].copy_from_slice(&c);
            x[32..].copy_from_slice(&c);
            sha256d(&x)
        };
        let root = {
            let mut x = [0u8; 64];
            x[..32].copy_from_slice(&ab);
            x[32..].copy_from_slice(&cc);
            sha256d(&x)
        };
        assert_eq!(merkle_root(&[a, b, c]), root);
    }

    #[test]
    fn witness_commitment_empty_block_is_bip141_shaped_and_deterministic() {
        let spk = witness_commitment_spk(&[]);
        assert_eq!(spk.len(), 38);
        assert_eq!(&spk[0..6], &[0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]); // OP_RETURN PUSH36 aa21a9ed
        // Empty block: witness_root = coinbase wtxid = 0x00..00, reserved = 0x00..00,
        // so the commitment is SHA256d(64 zero bytes) — the fixed BIP141 value a
        // real empty segwit block's coinbase carries.
        let expect = sha256d(&[0u8; 64]);
        assert_eq!(&spk[6..38], &expect[..]);
    }

    #[test]
    fn extract_header_and_coinbase_round_trips_a_blob() {
        // Build a minimal auxpow-style blob: u32(80) ‖ header ‖ u32(len) ‖ cb ‖ tail
        let header = [0x7u8; 80];
        let cb = b"coinbase-bytes".to_vec();
        let mut blob = Vec::new();
        blob.extend_from_slice(&80u32.to_le_bytes());
        blob.extend_from_slice(&header);
        blob.extend_from_slice(&(cb.len() as u32).to_le_bytes());
        blob.extend_from_slice(&cb);
        blob.extend_from_slice(&[0u8; 12]); // branch/index tail — ignored
        let (hash, h, c) = header_and_coinbase_from_auxpow(&blob).expect("parses");
        assert_eq!(h, header);
        assert_eq!(c, cb);
        assert_eq!(hash, block_header_hash(&header));
        // Truncated → None, never a panic.
        assert!(header_and_coinbase_from_auxpow(&blob[..50]).is_none());
    }

    #[test]
    fn coinbase_with_witness_inserts_marker_flag_and_witness() {
        // Use the genesis coinbase (a valid legacy tx) as the input.
        let legacy = hex_to_bytes(GENESIS_COINBASE).unwrap();
        let reserved = [0u8; 32];
        let sw = coinbase_with_witness(&legacy, &reserved).expect("converts");

        // version(4) preserved, then the 00 01 marker+flag.
        assert_eq!(&sw[0..4], &legacy[0..4]);
        assert_eq!(&sw[4..6], &[0x00, 0x01]);
        // Tail: … witness(01 20 ‖ 32 zero) ‖ locktime(4). Locktime unchanged.
        assert_eq!(&sw[sw.len() - 4..], &legacy[legacy.len() - 4..]);
        let witness = &sw[sw.len() - 4 - 34..sw.len() - 4];
        assert_eq!(witness[0], 0x01); // one stack item
        assert_eq!(witness[1], 0x20); // 32 bytes
        assert_eq!(&witness[2..34], &reserved[..]);
        // Exactly +2 (marker/flag) +34 (witness) bytes over the legacy form.
        assert_eq!(sw.len(), legacy.len() + 2 + 34);

        // Stripping marker/flag + witness reconstructs the legacy tx exactly.
        let mut back = Vec::new();
        back.extend_from_slice(&sw[0..4]); // version
        back.extend_from_slice(&sw[6..sw.len() - 4 - 34]); // body (skip 00 01; drop witness)
        back.extend_from_slice(&sw[sw.len() - 4..]); // locktime
        assert_eq!(back, legacy);
    }

    #[test]
    fn segwit_block_carries_witness_but_header_is_unchanged() {
        let header_bytes = hex_to_bytes(GENESIS_HEADER).unwrap();
        let mut header = [0u8; 80];
        header.copy_from_slice(&header_bytes);
        let legacy_cb = hex_to_bytes(GENESIS_COINBASE).unwrap();
        let block = build_segwit_block_hex(&header, &legacy_cb, &[0u8; 32], &[]).expect("builds");
        let raw = hex_to_bytes(&block).unwrap();
        // Header is byte-identical to the legacy block's header.
        assert_eq!(&raw[0..80], &header_bytes[..]);
        // tx count varint (01) then the segwit coinbase marker+flag at [81..83].
        assert_eq!(raw[80], 0x01);
        assert_eq!(&raw[81..85], &legacy_cb[0..4]); // coinbase version
        assert_eq!(&raw[85..87], &[0x00, 0x01]); // marker+flag
        // The non-witness block (what the txid-merkle commits to) is the shorter form.
        let legacy_block = build_block_hex(&header, &legacy_cb, &[]);
        assert!(raw.len() > hex_to_bytes(&legacy_block).unwrap().len());
    }
}
