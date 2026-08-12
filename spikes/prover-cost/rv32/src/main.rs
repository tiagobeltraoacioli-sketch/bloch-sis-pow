// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Bare-metal RV32IM harness: verify ONE ML-DSA-65 signature and halt.
// Executed by the instruction-counting interpreter in ../emu/rv32.py.
//
// Instruction count here is the pessimistic upper bound on SP1 cycles: SP1
// charges roughly one cycle per RISC-V instruction, and its Keccak precompile
// would REPLACE the many thousands of instructions the SHAKE-256 calls cost
// here. So: measured here = no-precompile ceiling.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Verifier};

static PK:  &[u8; 1952] = include_bytes!("../../kat/mldsa65_pk.bin");
static SIG: &[u8; 3309] = include_bytes!("../../kat/mldsa65_sig.bin");
static MSG: &[u8; 36]   = include_bytes!("../../kat/msg.bin");

core::arch::global_asm!(
    ".section .text._start",
    ".globl _start",
    "_start:",
    "  la sp, _stack_top",
    "  call main",
);

#[no_mangle]
pub extern "C" fn main() -> ! {
    let ok = match ml_dsa_65::PublicKey::try_from_bytes(*PK) {
        Ok(k) => k.verify(MSG, SIG, &[]),
        Err(_) => false,
    };
    // a0 = 1 on success; the interpreter reports it. ecall = halt.
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
