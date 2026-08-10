#![no_std]
#![no_main]
extern crate alloc;
use core::panic::PanicInfo;
use core::alloc::{GlobalAlloc, Layout};
use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Verifier};
use tide_fn_dsa_vrfy::{FalconProfile, VerifyingKey1024, VerifyingKey};

// Number of HYBRID signatures (ML-DSA-65 + Falcon-1024) verified in one run.
const N: usize = 1;

static MSG: &[u8; 36] = include_bytes!("../../kat/msg.bin");

struct Bump;
static mut ARENA: [u8; 1 << 22] = [0; 1 << 22];
static mut OFF: usize = 0;
unsafe impl GlobalAlloc for Bump {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let base = &raw mut ARENA as *mut u8;
        let pad = base.add(OFF).align_offset(l.align());
        OFF += pad + l.size();
        base.add(OFF - l.size())
    }
    unsafe fn dealloc(&self, _p: *mut u8, _l: Layout) {}
}
#[global_allocator]
static A: Bump = Bump;

core::arch::global_asm!(
    ".section .text._start", ".globl _start", "_start:",
    "  la sp, _stack_top", "  call main",
);

#[no_mangle]
pub extern "C" fn main() -> ! {
    let mut ok = true;
    {
        static PK: &[u8; 1952] = include_bytes!("../../kat/h0_mldsa_pk.bin");
        static SG: &[u8; 3309] = include_bytes!("../../kat/h0_mldsa_sig.bin");
        static FPK: &[u8; 1793] = include_bytes!("../../kat/h0_falcon_pk.bin");
        static FSG: &[u8; 1275] = include_bytes!("../../kat/h0_falcon_sig.bin");
        if N > 0 {
            let a = match ml_dsa_65::PublicKey::try_from_bytes(*PK) {
                Ok(k) => k.verify(MSG, SG, &[]), Err(_) => false };
            let b = match VerifyingKey1024::decode(FPK) {
                Some(vk) => vk.verify_falcon(FalconProfile::PqClean, FSG, MSG), None => false };
            if !(a && b) { ok = false; }
        }
    }
    {
        static PK: &[u8; 1952] = include_bytes!("../../kat/h1_mldsa_pk.bin");
        static SG: &[u8; 3309] = include_bytes!("../../kat/h1_mldsa_sig.bin");
        static FPK: &[u8; 1793] = include_bytes!("../../kat/h1_falcon_pk.bin");
        static FSG: &[u8; 1277] = include_bytes!("../../kat/h1_falcon_sig.bin");
        if N > 1 {
            let a = match ml_dsa_65::PublicKey::try_from_bytes(*PK) {
                Ok(k) => k.verify(MSG, SG, &[]), Err(_) => false };
            let b = match VerifyingKey1024::decode(FPK) {
                Some(vk) => vk.verify_falcon(FalconProfile::PqClean, FSG, MSG), None => false };
            if !(a && b) { ok = false; }
        }
    }
    {
        static PK: &[u8; 1952] = include_bytes!("../../kat/h2_mldsa_pk.bin");
        static SG: &[u8; 3309] = include_bytes!("../../kat/h2_mldsa_sig.bin");
        static FPK: &[u8; 1793] = include_bytes!("../../kat/h2_falcon_pk.bin");
        static FSG: &[u8; 1265] = include_bytes!("../../kat/h2_falcon_sig.bin");
        if N > 2 {
            let a = match ml_dsa_65::PublicKey::try_from_bytes(*PK) {
                Ok(k) => k.verify(MSG, SG, &[]), Err(_) => false };
            let b = match VerifyingKey1024::decode(FPK) {
                Some(vk) => vk.verify_falcon(FalconProfile::PqClean, FSG, MSG), None => false };
            if !(a && b) { ok = false; }
        }
    }
    {
        static PK: &[u8; 1952] = include_bytes!("../../kat/h3_mldsa_pk.bin");
        static SG: &[u8; 3309] = include_bytes!("../../kat/h3_mldsa_sig.bin");
        static FPK: &[u8; 1793] = include_bytes!("../../kat/h3_falcon_pk.bin");
        static FSG: &[u8; 1268] = include_bytes!("../../kat/h3_falcon_sig.bin");
        if N > 3 {
            let a = match ml_dsa_65::PublicKey::try_from_bytes(*PK) {
                Ok(k) => k.verify(MSG, SG, &[]), Err(_) => false };
            let b = match VerifyingKey1024::decode(FPK) {
                Some(vk) => vk.verify_falcon(FalconProfile::PqClean, FSG, MSG), None => false };
            if !(a && b) { ok = false; }
        }
    }
    halt(if ok { 1 } else { 0 })
}
fn halt(c: u32) -> ! { unsafe { core::arch::asm!("mv a0, {0}", "ecall", in(reg) c, options(noreturn)); } }
#[panic_handler] fn p(_: &PanicInfo) -> ! { halt(0xdead) }
