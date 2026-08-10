#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Minimal RV32IM interpreter that COUNTS INSTRUCTIONS.
#
# Purpose: SP1 charges ~1 cycle per retired RISC-V instruction, so the count
# here is a hardware-independent proxy for zkVM cycles. It is deliberately an
# UPPER BOUND: this runs SHAKE-256 as plain RV32IM instructions, whereas SP1
# would replace each Keccak permutation with a precompile costing far less.
#
# Not a general emulator: enough of RV32IM to run a static, no-syscall ELF
# that ends in `ecall`. Traps on anything it does not implement, so an
# unsupported instruction is a visible failure, never a silent wrong count.

import struct, sys
from collections import Counter

def load_elf(path):
    d = open(path, 'rb').read()
    assert d[:4] == b'\x7fELF' and d[4] == 1, "esperado ELF32"
    entry, phoff = struct.unpack_from('<II', d, 24)
    phentsize, phnum = struct.unpack_from('<HH', d, 42)
    mem = bytearray(1 << 26)          # 64 MiB, base 0x80000000
    BASE = 0x80000000
    for i in range(phnum):
        o = phoff + i * phentsize
        p_type, p_offset, p_vaddr, _, p_filesz, p_memsz = struct.unpack_from('<IIIIII', d, o)
        if p_type != 1:               # PT_LOAD
            continue
        dst = p_vaddr - BASE
        mem[dst:dst + p_filesz] = d[p_offset:p_offset + p_filesz]
        if p_memsz > p_filesz:        # .bss
            mem[dst + p_filesz:dst + p_memsz] = b'\0' * (p_memsz - p_filesz)
    return mem, entry, BASE

M32 = 0xFFFFFFFF
def s32(x):
    x &= M32
    return x - (1 << 32) if x & 0x80000000 else x

def run(path, limit=4_000_000_000, watch=None, rng=None):
    mem, pc, BASE = load_elf(path)
    x = [0] * 32
    count = 0
    hist = Counter()
    watch = watch or set()
    watch_hits = 0
    rlo, rhi = rng if rng else (0, 0)
    in_range = 0

    def ld(a, n, signed=False):
        o = a - BASE
        v = int.from_bytes(mem[o:o + n], 'little')
        if signed and v & (1 << (n * 8 - 1)):
            v -= 1 << (n * 8)
        return v & M32 if not signed else v

    def st(a, n, v):
        o = a - BASE
        mem[o:o + n] = (v & ((1 << (n * 8)) - 1)).to_bytes(n, 'little')

    while count < limit:
        ins = int.from_bytes(mem[pc - BASE:pc - BASE + 4], 'little')
        count += 1
        if pc in watch:
            watch_hits += 1
        if rlo <= pc < rhi:
            in_range += 1
        op = ins & 0x7F
        rd = (ins >> 7) & 0x1F
        f3 = (ins >> 12) & 7
        rs1 = (ins >> 15) & 0x1F
        rs2 = (ins >> 20) & 0x1F
        f7 = (ins >> 25) & 0x7F
        npc = pc + 4
        hist[op] += 1

        if op == 0x37:                                     # LUI
            x[rd] = ins & 0xFFFFF000
        elif op == 0x17:                                   # AUIPC
            x[rd] = (pc + (ins & 0xFFFFF000)) & M32
        elif op == 0x6F:                                   # JAL
            imm = (((ins >> 31) & 1) << 20) | (((ins >> 12) & 0xFF) << 12) | \
                  (((ins >> 20) & 1) << 11) | (((ins >> 21) & 0x3FF) << 1)
            if imm & (1 << 20): imm -= 1 << 21
            x[rd] = npc; npc = (pc + imm) & M32
        elif op == 0x67:                                   # JALR
            imm = ins >> 20
            if imm & 0x800: imm -= 1 << 12
            t = npc; npc = (x[rs1] + imm) & ~1 & M32; x[rd] = t
        elif op == 0x63:                                   # BRANCH
            imm = (((ins >> 31) & 1) << 12) | (((ins >> 7) & 1) << 11) | \
                  (((ins >> 25) & 0x3F) << 5) | (((ins >> 8) & 0xF) << 1)
            if imm & (1 << 12): imm -= 1 << 13
            a, b = x[rs1], x[rs2]
            take = [s32(a) == s32(b), s32(a) != s32(b), None, None,
                    s32(a) < s32(b), s32(a) >= s32(b), a < b, a >= b][f3]
            if take is None: raise SystemExit(f"branch f3={f3} @0x{pc:08x}")
            if take: npc = (pc + imm) & M32
        elif op == 0x03:                                   # LOAD
            imm = ins >> 20
            if imm & 0x800: imm -= 1 << 12
            a = (x[rs1] + imm) & M32
            x[rd] = {0: lambda: ld(a, 1, True) & M32, 1: lambda: ld(a, 2, True) & M32,
                     2: lambda: ld(a, 4), 4: lambda: ld(a, 1), 5: lambda: ld(a, 2)}[f3]()
        elif op == 0x23:                                   # STORE
            imm = (((ins >> 25) & 0x7F) << 5) | ((ins >> 7) & 0x1F)
            if imm & 0x800: imm -= 1 << 12
            a = (x[rs1] + imm) & M32
            st(a, [1, 2, 4][f3], x[rs2])
        elif op == 0x13:                                   # OP-IMM
            imm = ins >> 20
            if imm & 0x800: imm -= 1 << 12
            a = x[rs1]
            if f3 == 0:   x[rd] = (a + imm) & M32
            elif f3 == 2: x[rd] = 1 if s32(a) < imm else 0
            elif f3 == 3: x[rd] = 1 if a < (imm & M32) else 0
            elif f3 == 4: x[rd] = (a ^ imm) & M32
            elif f3 == 6: x[rd] = (a | imm) & M32
            elif f3 == 7: x[rd] = (a & imm) & M32
            elif f3 == 1: x[rd] = (a << (rs2 & 31)) & M32
            elif f3 == 5: x[rd] = (a >> (rs2 & 31)) if f7 == 0 else (s32(a) >> (rs2 & 31)) & M32
        elif op == 0x33:                                   # OP / M-extension
            a, b = x[rs1], x[rs2]
            if f7 == 1:                                    # MUL/DIV
                if f3 == 0:   x[rd] = (s32(a) * s32(b)) & M32
                elif f3 == 1: x[rd] = ((s32(a) * s32(b)) >> 32) & M32
                elif f3 == 2: x[rd] = ((s32(a) * b) >> 32) & M32
                elif f3 == 3: x[rd] = ((a * b) >> 32) & M32
                elif f3 == 4: x[rd] = M32 if b == 0 else (abs(s32(a)) // abs(s32(b)) * (1 if (s32(a) < 0) == (s32(b) < 0) else -1)) & M32
                elif f3 == 5: x[rd] = M32 if b == 0 else (a // b) & M32
                elif f3 == 6: x[rd] = a if b == 0 else (abs(s32(a)) % abs(s32(b)) * (1 if s32(a) >= 0 else -1)) & M32
                elif f3 == 7: x[rd] = a if b == 0 else (a % b) & M32
            else:
                sh = b & 31
                if f3 == 0:   x[rd] = (a - b) & M32 if f7 == 0x20 else (a + b) & M32
                elif f3 == 1: x[rd] = (a << sh) & M32
                elif f3 == 2: x[rd] = 1 if s32(a) < s32(b) else 0
                elif f3 == 3: x[rd] = 1 if a < b else 0
                elif f3 == 4: x[rd] = a ^ b
                elif f3 == 5: x[rd] = (a >> sh) if f7 == 0 else (s32(a) >> sh) & M32
                elif f3 == 6: x[rd] = a | b
                elif f3 == 7: x[rd] = a & b
        elif op == 0x0F:                                   # FENCE — nop here
            pass
        elif op == 0x73:                                   # ECALL — halt
            return count, x[10], hist, watch_hits, in_range
        else:
            raise SystemExit(f"opcode 0x{op:02x} nao implementado @0x{pc:08x} (ins=0x{ins:08x})")

        x[0] = 0
        pc = npc
    raise SystemExit("limite de instrucoes atingido")

if __name__ == '__main__':
    args = sys.argv[2:]
    rng = None
    if args and ':' in args[-1]:
        lo, sz = args[-1].split(':'); rng = (int(lo, 16), int(lo, 16) + int(sz))
        args = args[:-1]
    w = {int(a, 16) for a in args}
    n, a0, hist, wh, inr = run(sys.argv[1], watch=w, rng=rng)
    print(f"instrucoes executadas : {n:,}")
    print(f"a0 (1 = assinatura valida) : {a0}")
    tot = sum(hist.values())
    names = {0x33: "OP(reg)", 0x13: "OP-IMM", 0x03: "LOAD", 0x23: "STORE",
             0x63: "BRANCH", 0x6F: "JAL", 0x67: "JALR", 0x37: "LUI", 0x17: "AUIPC"}
    print("mix:", ", ".join(f"{names.get(k, hex(k))} {v*100/tot:.1f}%"
                            for k, v in hist.most_common(6)))
    if w:
        print(f"entradas no simbolo observado : {wh:,}")
    if rng:
        print(f"instrucoes DENTRO do simbolo  : {inr:,}  ({inr*100/n:.1f}% do total)")
