#![no_std]
#![no_main]
extern crate alloc;
use core::panic::PanicInfo;
use core::alloc::{GlobalAlloc, Layout};

// Bump allocator over a static arena — same shape SP1's guest allocator uses.
// Never frees; the program runs once and halts.
struct Bump;
static mut ARENA: [u8; 1 << 22] = [0; 1 << 22];
static mut OFF: usize = 0;
unsafe impl GlobalAlloc for Bump {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let base = &raw mut ARENA as *mut u8;
        let cur = base.add(OFF);
        let pad = cur.align_offset(l.align());
        OFF += pad + l.size();
        base.add(OFF - l.size())
    }
    unsafe fn dealloc(&self, _p: *mut u8, _l: Layout) {}
}
#[global_allocator]
static A: Bump = Bump;
use tide_fn_dsa_vrfy::{FalconProfile, VerifyingKey1024, VerifyingKey};

static PK:  &[u8; 1793]     = include_bytes!("../../kat/falcon1024_pk.bin");
static SIG: &[u8; 1274]  = include_bytes!("../../kat/falcon1024_sig.bin");
static MSG: &[u8; 36]       = include_bytes!("../../kat/msg.bin");

core::arch::global_asm!(
    ".section .text._start", ".globl _start", "_start:",
    "  la sp, _stack_top", "  call main",
);

#[no_mangle]
pub extern "C" fn main() -> ! {
    let ok = match VerifyingKey1024::decode(PK) {
        Some(vk) => vk.verify_falcon(FalconProfile::PqClean, SIG, MSG),
        None => false,
    };
    halt(if ok { 1 } else { 0 })
}
fn halt(c: u32) -> ! { unsafe { core::arch::asm!("mv a0, {0}", "ecall", in(reg) c, options(noreturn)); } }
#[panic_handler] fn p(_: &PanicInfo) -> ! { halt(0xdead) }
