//! Payout-address parsing for the OPEN merged pool: a worker declares where its
//! own rewards go in the Stratum username, so the pool never custodies anything.
//!
//! Username grammar (dot-separated, order-free, extra parts ignored as a worker
//! label):
//!
//! ```text
//!   bloch1<…>                        → Bloch coinbase to this address
//!   bloch1<…>.bc1<…>                 → …and the parent-BTC coinbase to this one
//!   bloch1<…>.bc1<…>.rig07           → …with a free-form worker label
//!   bloch1<…>.hex:0014<40 hex>       → raw BTC scriptPubKey escape hatch
//! ```
//!
//! A missing/unparseable BTC part falls back to the operator's configured script
//! (the miner still mines Bloch to its OWN address — the Bloch part is required).
//! Bech32/bech32m checksums are VERIFIED: a typo must not silently redirect a
//! block reward into an unspendable script.

/// Parsed payout intent from a Stratum username.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkerPayout {
    /// Bloch address the node's `createauxblock` coinbase pays.
    pub bloch_addr: String,
    /// Parent-BTC coinbase scriptPubKey, if the worker declared one.
    pub btc_script: Option<Vec<u8>>,
    /// Free-form label (anything that is neither address), for logs.
    pub label: Option<String>,
}

/// Parse a Stratum username. `None` when no `bloch1…` part is present — the
/// caller must then refuse `mining.authorize` with an explanatory error rather
/// than serve jobs whose reward has no owner.
pub fn parse_worker_username(user: &str) -> Option<WorkerPayout> {
    let mut bloch_addr = None;
    let mut btc_script = None;
    let mut label = None;

    for part in user.split('.').map(str::trim).filter(|p| !p.is_empty()) {
        let low = part.to_ascii_lowercase();
        if low.starts_with("bloch1") && bloch_addr.is_none() {
            bloch_addr = Some(part.to_string());
        } else if let Some(hex) = low.strip_prefix("hex:") {
            if btc_script.is_none() {
                btc_script = parse_hex_spk(hex);
            }
        } else if (low.starts_with("bc1") || low.starts_with("bcrt1") || low.starts_with("tb1"))
            && btc_script.is_none()
        {
            btc_script = btc_address_to_spk(&low);
        } else if label.is_none() {
            label = Some(part.to_string());
        }
    }
    bloch_addr.map(|bloch_addr| WorkerPayout { bloch_addr, btc_script, label })
}

/// A raw scriptPubKey in hex — accepted only in the standard output shapes so a
/// mistyped script cannot burn a coinbase.
fn parse_hex_spk(hex_str: &str) -> Option<Vec<u8>> {
    let b = hex::decode(hex_str).ok()?;
    match b.as_slice() {
        // P2WPKH / P2WSH / P2TR
        [0x00, 0x14, ..] if b.len() == 22 => Some(b),
        [0x00, 0x20, ..] if b.len() == 34 => Some(b),
        [0x51, 0x20, ..] if b.len() == 34 => Some(b),
        // P2PKH: OP_DUP OP_HASH160 <20> … OP_EQUALVERIFY OP_CHECKSIG
        [0x76, 0xa9, 0x14, .., 0x88, 0xac] if b.len() == 25 => Some(b),
        // P2SH: OP_HASH160 <20> … OP_EQUAL
        [0xa9, 0x14, .., 0x87] if b.len() == 23 => Some(b),
        _ => None,
    }
}

const BECH32_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

fn bech32_polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3];
    let mut chk: u32 = 1;
    for v in values {
        let b = chk >> 25;
        chk = ((chk & 0x1ff_ffff) << 5) ^ (*v as u32);
        for (i, g) in GEN.iter().enumerate() {
            if (b >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let mut v: Vec<u8> = hrp.bytes().map(|c| c >> 5).collect();
    v.push(0);
    v.extend(hrp.bytes().map(|c| c & 31));
    v
}

/// Regroup 5-bit words into 8-bit bytes, rejecting a non-canonical tail
/// (leftover bits must be zero and fewer than 5) — BIP173 `convertbits`.
fn convert_bits_5_to_8(data: &[u8]) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::new();
    for v in data {
        if *v > 31 {
            return None;
        }
        acc = (acc << 5) | (*v as u32);
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    if bits >= 5 || ((acc << (8 - bits)) & 0xff) != 0 {
        return None;
    }
    Some(out)
}

/// Decode a segwit address (BIP173 bech32 for v0, BIP350 bech32m for v1+) into
/// its scriptPubKey. The HRP is NOT checked against a network: the coinbase
/// commits to a script, and the same key material is spendable on whichever
/// chain the parent turns out to be.
pub fn btc_address_to_spk(addr: &str) -> Option<Vec<u8>> {
    let s = addr.to_ascii_lowercase();
    if s.len() < 8 || s.len() > 90 || !s.is_ascii() {
        return None;
    }
    let sep = s.rfind('1')?;
    let (hrp, data_part) = (&s[..sep], &s[sep + 1..]);
    if hrp.is_empty() || data_part.len() < 6 {
        return None;
    }
    let mut data = Vec::with_capacity(data_part.len());
    for c in data_part.bytes() {
        data.push(BECH32_CHARSET.iter().position(|x| *x == c)? as u8);
    }
    // Checksum: bech32 (v0) uses constant 1, bech32m (v1+) uses 0x2bc830a3.
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(&data);
    let chk = bech32_polymod(&values);
    let witver = data[0];
    let expect = if witver == 0 { 1 } else { 0x2bc8_30a3 };
    if chk != expect {
        return None;
    }
    let program = convert_bits_5_to_8(&data[1..data.len() - 6])?;
    match (witver, program.len()) {
        (0, 20) | (0, 32) => {}
        (1, 32) => {}
        (1..=16, 2..=40) => {}
        _ => return None,
    }
    let mut spk = Vec::with_capacity(2 + program.len());
    spk.push(if witver == 0 { 0x00 } else { 0x50 + witver }); // OP_0 / OP_1..OP_16
    spk.push(program.len() as u8);
    spk.extend_from_slice(&program);
    Some(spk)
}

#[cfg(test)]
mod tests {
    use super::*;

    // BIP173/BIP350 vectors + the operator's own address.
    #[test]
    fn decodes_known_segwit_vectors() {
        // BIP173: P2WPKH
        assert_eq!(
            hex::encode(btc_address_to_spk("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap()),
            "0014751e76e8199196d454941c45d1b3a323f1433bd6"
        );
        // BIP173: P2WSH
        assert_eq!(
            hex::encode(
                btc_address_to_spk(
                    "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"
                )
                .unwrap()
            ),
            "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"
        );
        // BIP350: P2TR (bech32m)
        assert_eq!(
            hex::encode(
                btc_address_to_spk(
                    "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"
                )
                .unwrap()
            ),
            "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
        // The pool operator's payout address.
        assert_eq!(
            hex::encode(btc_address_to_spk("bc1qjpnqq4f6hjh2n39tzwy8ttrj4h78yx22retkyk").unwrap()),
            "0014906600553abcaea9c4ab138875ac72adfc72194a"
        );
    }

    #[test]
    fn rejects_bad_checksum_and_wrong_witness_shapes() {
        // One character flipped in the data part → checksum must fail.
        assert!(btc_address_to_spk("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5").is_none());
        // bech32 (v0) checksum used with a v1 program → BIP350 rejects it.
        assert!(btc_address_to_spk("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd").is_none());
        // Empty / junk.
        assert!(btc_address_to_spk("bc1").is_none());
        assert!(btc_address_to_spk("not-an-address").is_none());
    }

    #[test]
    fn username_carries_both_payouts_in_any_order() {
        let u = "bloch1qe986db5149cff7499b282a048272a09aff0af4ff84242073.bc1qjpnqq4f6hjh2n39tzwy8ttrj4h78yx22retkyk.rig07";
        let p = parse_worker_username(u).expect("parses");
        assert!(p.bloch_addr.starts_with("bloch1"));
        assert_eq!(hex::encode(p.btc_script.unwrap()), "0014906600553abcaea9c4ab138875ac72adfc72194a");
        assert_eq!(p.label.as_deref(), Some("rig07"));

        // Reversed order, no label.
        let p2 = parse_worker_username(
            "bc1qjpnqq4f6hjh2n39tzwy8ttrj4h78yx22retkyk.bloch1qe986db5149cff7499b282a048272a09aff0af4ff84242073",
        )
        .expect("parses");
        assert_eq!(p2.bloch_addr, "bloch1qe986db5149cff7499b282a048272a09aff0af4ff84242073");
        assert!(p2.btc_script.is_some());
    }

    #[test]
    fn bloch_only_username_keeps_operator_btc_fallback() {
        let p = parse_worker_username("bloch1qabc").expect("parses");
        assert_eq!(p.bloch_addr, "bloch1qabc");
        assert!(p.btc_script.is_none(), "no BTC part → caller falls back to the operator script");
    }

    #[test]
    fn username_without_a_bloch_address_is_refused() {
        assert!(parse_worker_username("").is_none());
        assert!(parse_worker_username("worker1").is_none());
        // A BTC address alone is not enough: the Bloch coinbase would be ownerless.
        assert!(parse_worker_username("bc1qjpnqq4f6hjh2n39tzwy8ttrj4h78yx22retkyk").is_none());
    }

    #[test]
    fn hex_spk_escape_hatch_accepts_only_standard_shapes() {
        let p = parse_worker_username("bloch1qabc.hex:0014906600553abcaea9c4ab138875ac72adfc72194a").unwrap();
        assert_eq!(p.btc_script.unwrap().len(), 22);
        // Non-standard / truncated → ignored (falls back), never used as a script.
        assert!(parse_worker_username("bloch1qabc.hex:00").unwrap().btc_script.is_none());
        assert!(parse_worker_username("bloch1qabc.hex:zzzz").unwrap().btc_script.is_none());
    }
}
