// SPDX-License-Identifier: AGPL-3.0-or-later

//! L1M-05: `Certificate::decode` must not pre-allocate for list counts the
//! input cannot hold. A ~1 KB input that declares 65 536 registry records (or
//! votes) used to force multi-megabyte `Vec::with_capacity` calls before a
//! single entry was read. This test binary installs a counting allocator and
//! checks the largest single allocation made while decoding such inputs.

use bloch_finality_cert::{Certificate, Refusal, MAGIC, VERSION};
use bloch_pos_committee::header::BlockHeaderV4;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

struct Counting;
static LARGEST: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        LARGEST.fetch_max(layout.size(), Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        LARGEST.fetch_max(new_size, Ordering::Relaxed);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

fn prefix() -> Vec<u8> {
    let real = std::fs::read(format!("{}/tests/fixtures/mainnet-cert-e7018.bin", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let headers = 2 * BlockHeaderV4::ENCODED_LEN;
    assert_eq!(&real[..8], MAGIC);
    assert_eq!(u16::from_le_bytes([real[8], real[9]]), VERSION);
    real[..10 + headers].to_vec()
}

fn largest_alloc_while_decoding(input: &[u8]) -> (usize, Result<Certificate, Refusal>) {
    LARGEST.store(0, Ordering::Relaxed);
    let out = Certificate::decode(input);
    (LARGEST.load(Ordering::Relaxed), out)
}

#[test]
fn an_overclaimed_count_does_not_preallocate() {
    // 65 536 records claimed, 1 KB of padding actually present.
    let mut records = prefix();
    records.extend_from_slice(&(1u32 << 16).to_le_bytes());
    records.extend_from_slice(&[0u8; 1024]);

    // Zero records/absences, then a link that claims 65 536 votes.
    let mut votes = prefix();
    votes.extend_from_slice(&0u32.to_le_bytes());
    votes.extend_from_slice(&0u32.to_le_bytes());
    votes.extend_from_slice(&[0u8; 8 + 32 + 8 + 32]);
    votes.extend_from_slice(&(1u32 << 16).to_le_bytes());
    votes.extend_from_slice(&[0u8; 1024]);

    for (what, input) in [("records", records), ("votes", votes)] {
        let (largest, out) = largest_alloc_while_decoding(&input);
        assert_eq!(out.unwrap_err(), Refusal::Malformed("truncated"), "{what}");
        assert!(largest < 64 * 1024, "{what}: decoding a {}-byte input allocated {largest} bytes at once", input.len());
    }

    // Valid certificates still decode identically (one test function, so no
    // concurrent test thread pollutes the global allocation counter above).
    for e in [7018u64, 7019] {
        let bytes = std::fs::read(format!("{}/tests/fixtures/mainnet-cert-e{e}.bin", env!("CARGO_MANIFEST_DIR"))).unwrap();
        let cert = Certificate::decode(&bytes).unwrap();
        assert_eq!(cert.encode(), bytes, "e{e} round-trips");
    }
}
