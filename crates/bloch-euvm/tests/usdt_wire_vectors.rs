//! Independent Python hashlib fixed-word ABI fixture: bridge/test-vectors/usdt-v1.json.
//! Constants are intentionally pinned here so tests need no sibling checkout.
use bloch_euvm::ustav::gateway::{Deposit, Release, Route};

fn hex(value: [u8; 32]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn python_abi_vectors_match_native_ids_for_both_source_domains() {
    let cases = [
        (
            0x11,
            "bedfb1847536bad45596e081fd252de7706dd95a67a451dd590943753a79e365",
            "9856510a180e52c66e907abc5a4c2294273d4b0854ad93e0910e7d6a628cf89d",
            "b0601056ff581bfd91e0b233f806f477958c68c3fe8fabc9bed9e212917b533a",
        ),
        (
            0xaa,
            "9b9eab23042ff74bfa60b50e710f7c3851b282568a192118428af5fb0b1c488a",
            "27f7a7b64559c4bf0196c3907924e97346292b0ea037a59e409d9b481878d0fd",
            "939cc0db9088b7d8aa7018e423298d0baeaf6f54122c80b5cf864c3145d8f48b",
        ),
    ];
    let mut identities = Vec::new();
    for (source, route_id, deposit_id, release_id) in cases {
        let route = Route {
            source_domain: [source; 32],
            native_domain: [0x22; 32],
            native_asset: [0x33; 32],
            token: [0x44; 20],
            vault: [0x55; 20],
            decimals: 6,
            cap: 10_000_000_000,
            vault_code_hash: [0xab; 32],
        };
        assert_eq!(hex(route.id()), route_id);
        let deposit = Deposit {
            route: route.id(),
            nonce: 0x0102030405060708,
            sender: [0x66; 20],
            amount: 123_456_789,
            pq_recipient_hash: [0x88; 32],
        };
        assert_eq!(hex(deposit.id()), deposit_id);
        let release = Release {
            route: route.id(),
            nonce: deposit.nonce,
            recipient: [0x77; 20],
            amount: deposit.amount,
            native_burn: [0x99; 32],
        };
        assert_eq!(hex(release.id()), release_id);
        identities.push((route.id(), deposit.id(), release.id()));
    }
    assert_ne!(identities[0].0, identities[1].0);
    assert_ne!(identities[0].1, identities[1].1);
    assert_ne!(identities[0].2, identities[1].2);
}
