#![no_std]
#![no_main]
use core::panic::PanicInfo;
use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};

const OUT: usize = 13600; // bytes squeezed; SHAKE-256 rate = 136 B = 1 permutation

core::arch::global_asm!(
    ".section .text._start", ".globl _start", "_start:",
    "  la sp, _stack_top", "  call main",
);

#[no_mangle]
pub extern "C" fn main() -> ! {
    let mut h = Shake256::default();
    h.update(b"bloch");
    let mut xof = h.finalize_xof();
    let mut buf = [0u8; 136];
    let mut acc: u32 = 0;
    let mut left = OUT;
    while left > 0 {
        xof.read(&mut buf);
        acc = acc.wrapping_add(buf[0] as u32);
        left -= 136;
    }
    halt(acc)
}
fn halt(c: u32) -> ! { unsafe { core::arch::asm!("mv a0, {0}", "ecall", in(reg) c, options(noreturn)); } }
#[panic_handler] fn p(_: &PanicInfo) -> ! { halt(0xdead) }
