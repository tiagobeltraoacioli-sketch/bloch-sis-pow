<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# bloch-sbpf — sBPF-style execution core (foundation)

Front 1 of `docs/specs/BLOCH-SBPF-CORE.md`: a load-time **verifier** and a
deterministic, compute-metered **interpreter** for a declared subset of the
sBPF/eBPF instruction set, plus the BSC-0 program container.

## What this is NOT (read first — §0 of the spec)

- **Not "Solana compatible."** No ELF loader, no relocations, no `sol_*`
  syscalls, no loaders, no Sealevel scheduler, no JIT. An arbitrary
  `cargo build-sbf` `.so` does NOT load here. The compatibility gate is §9 of
  the spec and it has not been approached, let alone passed. Until it is, the
  public name of this work is exactly the title above.
- **Not consensus.** This crate is standalone — the posture `bloch-euvm`
  holds. It is not a dependency of `bloch-pos-node` or `bloch-pos-committee`
  (`cargo tree -i bloch-sbpf` lists no dependents), and making it one collides
  with ADR-040 and the SR-2 single-re-freeze rule: a founder decision, not a
  dependency edge.
- **Not a JIT.** The interpreter is the candidate semantics; a future JIT
  would have to be proven bit-equivalent to it.

## What it does do

```rust
let program = bloch_sbpf::load(&bsc0_bytes)?;                  // verify once
let out = bloch_sbpf::execute(&program, input, budget,         // run metered
                              &bloch_sbpf::SyscallRegistry::v0());
```

`execute()` only accepts a `VerifiedProgram`, and `load()` is its only
constructor — running unverified bytecode is unrepresentable by construction.
Every failure is a deterministic `Fault` inside the `Outcome`; nothing panics.

- Verifier (§4): opcode whitelist (rejection by non-listing, never a
  deny-list), `lddw` pairing, register bounds incl. the read-only frame
  pointer, jump-target bounds, call resolution. Deliberately NO termination
  analysis — that is the meter's job, and only the meter's.
- Memory (§5): fixed VA map (TEXT+RO / STACK / HEAP / INPUT) at 4 GiB strides,
  every access `checked_add` + range + permission checked before a byte moves,
  unaligned access as checked byte copies.
- Meter (§6): charge-then-execute from a caller budget; 1 CU per instruction
  plus per-byte syscall terms; `COST_TABLE_VERSION` is serialized into every
  canonical `Outcome`.
- Syscalls (§7): exactly `abort`, `log`, `sha3_256`.

## Determinism (spec item c) — the doors and how they are shut

| Vector | Closure |
|---|---|
| Host floating point | ISA has no FP opcode + whitelist + no math syscall (§3-FP) |
| Map iteration order | `BTreeMap` only; no `HashMap` in the crate |
| Host memory addresses | programs see fixed VA constants; no host pointer is observable |
| Uninitialized memory | STACK/HEAP zeroed per execution |
| Alignment traps | unaligned access is a checked byte copy |
| Integer overflow | `wrapping_*` IS the semantics; workspace `overflow-checks` catches the unintended |

## Bounded cost (spec item d)

Caller budget in CU, debited before each instruction; static ceilings on every
allocation: text ≤ 65 536 slots, rodata ≤ 512 KiB, stack 256 KiB, heap 32 KiB,
log ≤ 32 KiB per execution. Nothing grows without a limit.

## Tests

`cargo test -p bloch-sbpf`. Negative/control pairs throughout (§10): every
rejecting test ships the minimally-different program that passes, and control
halves assert the exact `Outcome`, not the absence of an error. Golden vectors
(D2) pin SHA3-256 over the canonical `Outcome` bytes.

Fuzz harnesses live in the repo's `fuzz/` workspace (nightly):
`cargo +nightly fuzz run sbpf_load` (reject-or-verify, never panic) and
`cargo +nightly fuzz run sbpf_exec` (panic-freedom + double-run determinism).

## Not done

See the spec's §11: M4 (ELF→BSC-0 converter and a real compiled program) is a
separate approval and the §9 gate. Everything about accounts, scheduling,
state writeback and CPI is Front 2 or later.
