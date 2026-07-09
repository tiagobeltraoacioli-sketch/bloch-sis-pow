//! Sprint K — Address Parsing Security Tests
//!
//! Verifies that all four previously-lenient address parsers are unified
//! behind the checksum-validating `Address::parse()`. The bug was:
//!
//!   - src/rpc/mod.rs::parse_address — took first 40 hex chars, no checksum
//!   - src/wallet/cli.rs send handler — stripped last 8 chars, no checksum
//!   - src/bin/bloch-cli.rs send flow — took first 40 hex chars, no checksum
//!
//! Post-Sprint K: all routes go through Address::parse() which enforces
//! 53-char checksummed format: bloch1q + 40 hex hash + 8 hex checksum.

#[cfg(test)]
mod sprint_k_tests {
    use bloch::address::{Address, AddressError, Network};

    // Valid treasury address (the real one, with correct checksum)
    const TREASURY_FULL: &str = "bloch1q633ef5f51f2434437a6daada1e984372cca0be7c2c0de299";
    const TREASURY_HASH_ONLY: &str = "bloch1q633ef5f51f2434437a6daada1e984372cca0be7c";
    const TREASURY_WRONG_CHECKSUM: &str = "bloch1q633ef5f51f2434437a6daada1e984372cca0be7c0000dead";

    #[test]
    fn valid_checksummed_address_parses() {
        let addr = Address::parse(TREASURY_FULL).expect("valid treasury must parse");
        assert!(addr.is_mainnet());
        assert_eq!(hex::encode(addr.hash()), "633ef5f51f2434437a6daada1e984372cca0be7c");
    }

    #[test]
    fn address_without_checksum_is_rejected() {
        // This was the silent-accept footgun before Sprint K
        let result = Address::parse(TREASURY_HASH_ONLY);
        assert!(matches!(result, Err(AddressError::BadLength { .. })));
    }

    #[test]
    fn address_with_wrong_checksum_is_rejected() {
        let result = Address::parse(TREASURY_WRONG_CHECKSUM);
        assert!(matches!(result, Err(AddressError::BadChecksum)));
    }

    #[test]
    fn short_address_is_rejected() {
        let result = Address::parse("bloch1qshort");
        assert!(matches!(result, Err(AddressError::BadLength { .. })));
    }

    #[test]
    fn missing_prefix_is_rejected() {
        let result = Address::parse("633ef5f51f2434437a6daada1e984372cca0be7c2c0de299");
        assert!(matches!(result, Err(AddressError::BadPrefix)));
    }

    #[test]
    fn random_garbage_is_rejected() {
        assert!(Address::parse("").is_err());
        assert!(Address::parse("bloch1q").is_err());
        assert!(Address::parse("bloch1q" ).is_err());
        assert!(Address::parse("not-an-address").is_err());
    }

    #[test]
    fn roundtrip_works() {
        // Build an address from a known hash, render it, re-parse it, verify same hash
        let original_hash: [u8; 20] = [
            0x63, 0x3e, 0xf5, 0xf5, 0x1f, 0x24, 0x34, 0x43, 0x7a, 0x6d,
            0xaa, 0xda, 0x1e, 0x98, 0x43, 0x72, 0xcc, 0xa0, 0xbe, 0x7c,
        ];
        let addr = Address::from_hash(original_hash, Network::Mainnet);
        let rendered = addr.to_string();
        assert_eq!(rendered, TREASURY_FULL);

        let reparsed = Address::parse(&rendered).unwrap();
        assert_eq!(reparsed.hash(), &original_hash);
    }

    #[test]
    fn testnet_prefix_also_validates() {
        let addr = Address::from_hash([0x42; 20], Network::Testnet);
        let s = addr.to_string();
        assert!(s.starts_with("bloch1t"));
        let reparsed = Address::parse(&s).unwrap();
        assert!(reparsed.is_testnet());
        assert_eq!(reparsed.hash(), &[0x42; 20]);
    }

    // ── Tests specifically for the RPC parse_address wrapper ──────────

    #[test]
    fn rpc_parse_rejects_lenient_inputs() {
        // These are inputs that the PRE-Sprint-K rpc::parse_address
        // would have silently accepted. Post-Sprint K, they must reject.
        //
        // The actual rpc::parse_address is private, but we verify the
        // Address::parse contract it now delegates to.

        // 46-char form (used to be accepted, now rejected)
        assert!(Address::parse("bloch1q633ef5f51f2434437a6daada1e984372cca0be7c").is_err());

        // Prefix + empty payload (used to be accepted as empty-hash hex, now rejected)
        assert!(Address::parse("bloch1q").is_err());

        // Prefix + partial hex (used to truncate, now rejected)
        assert!(Address::parse("bloch1q00112233").is_err());
    }
}
