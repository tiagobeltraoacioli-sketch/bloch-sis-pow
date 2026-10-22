// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Bare-metal RV32IM harness: verify ONE SLH-DSA-SHAKE-128s signature (FIPS
// 205 pure, with the suite-0x0003 context string) and halt. Executed by the
// instruction-counting interpreter in ../../prover-cost/emu/rv32.py, the
// same harness that produced HYBRID_VERIFY_INSTRUCTIONS, so the two counts
// are on one scale (no Keccak precompile: a pessimistic ceiling).

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use fips205::slh_dsa_shake_128s as slh;
use fips205::traits::{SerDes, Verifier};

static PK:  &[u8; 32]   = include_bytes!("../../kat/slh128s_pk.bin");
static SIG: &[u8; 7856] = include_bytes!("../../kat/slh128s_sig.bin");
static MSG: &[u8; 32]   = include_bytes!("../../kat/msg.bin");
const CTX: &[u8] = b"BLOCH/SUITE/0x0003/SLH-DSA-SHAKE-128s+Falcon-1024/v1";

core::arch::global_asm!(
    ".section .text._start",
    ".globl _start",
    "_start:",
    "  la sp, _stack_top",
    "  call main",
);

#[no_mangle]
pub extern "C" fn main() -> ! {
    let ok = match slh::PublicKey::try_from_bytes(PK) {
        Ok(k) => k.verify(MSG, SIG, CTX),
        Err(_) => false,
    };
    halt(if ok { 1 } else { 0 })
}

fn halt(code: u32) -> ! {
    unsafe {
        core::arch::asm!("mv a0, {0}", "ecall", in(reg) code, options(noreturn));
    }
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    halt(0xdead)
}
