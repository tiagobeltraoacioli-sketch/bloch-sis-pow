# coherence-prover (Coherence C2b-prover) — SP1 guest + hosts, pinned to v6.5.0

The zero-knowledge half of the shielded pool: prove the C1 spend statement
(`coherence-core::check_spend`) with **SP1** (hash-STARK / FRI, Plonky3) and
verify the **raw FRI core proof** — never SP1's Groth16/PLONK wrappers (curve
SNARKs would break post-quantum coherence, `COHERENCE-C1.md §3`).

> **Not built by the node's `cargo build`.** The repo-root workspace excludes
> this directory; `script/` + `service/` form their own workspace here (shared,
> committed `Cargo.lock`), and `program/` is its own workspace built by the
> SP1 toolchain. Everything is pinned to **SP1 v6.5.0** — toolchain
> (`sp1up --version v6.5.0`), `sp1-zkvm = "=6.5.0"`, `sp1-sdk = "=6.5.0"`.
> The full prerequisite list (protoc, locks, ELF path) lives in `REPRO.md`
> §"SP1 guest".

## Layout

- `program/` — the **canonical SP1 guest**: reads `SpendPublic` +
  `SpendWitness`, runs `check_spend` (a violated statement makes proving fail),
  and commits the public inputs. **This is the ELF whose vkey the node's
  verifier pins** — its committed `Cargo.lock` + the pinned toolchain are
  consensus-adjacent (same lock + toolchain ⇒ same ELF ⇒ same vkey).
- `script/` — the **host smoke test**: proves a small real witness against the
  guest ELF and FRI-verifies it (one-shot, local).
- `service/` — the **delegated HTTP prover** (`/prove`, `/verify`, `/health`)
  with bearer-token auth, for wallets that cannot prove locally. See the
  privacy warning below and [`deploy/sp1-prover/`](../../deploy/sp1-prover/).
- `measure/` — the **frozen measurement harness** behind
  `docs/audit/COHERENCE-PROOF-SIZE-2026-08-29.md` (proof sizes/cycles in Core
  AND Compressed). It mirrors the guest and stays self-contained on purpose so
  the recorded numbers remain reproducible; it is not the dev entry point.

## PRIVACY — the delegated prover sees everything

**`service/` is NOT private with respect to its operator.** A `/prove` request
carries the full spend witness: every input note (value, `pk_d`, `rho`, `psi`),
every output note, the Merkle paths, and the **nullifier key `nk`**. The
operator of the box can read every amount, link the spends in the request, and
— because `nk` derives all of that wallet's nullifiers — link that wallet's
**past and future** shielded spends. Delegated proving trades privacy-from-the-
prover for the ability to spend from weak hardware. Run the service yourself,
or point your wallet only at an operator you are willing to show your entire
shielded history to. The proof the chain sees leaks nothing; the *request to
build it* leaks everything, to one party, once.

(The only fully-private path is local proving: measured at 83 s Core / 215 s
Compressed for a 2-in/2-out spend on 8 desktop cores, ~16 GB — see the audit
doc. Phones cannot do that today, which is why `service/` exists at all.)

## Build + run

```bash
# once per machine — PINNED toolchain (a bare `sp1up` will NOT match the pins)
curl -L https://sp1up.succinct.xyz | bash && sp1up --version v6.5.0
brew install protobuf     # sp1-prover-types generates code from .proto

# 1) guest ELF (committed Cargo.lock; keep --locked)
cd crates/coherence-prover/program && cargo prove build --locked
# → target/elf-compilation/riscv64im-succinct-zkvm-elf/release/coherence-spend-program

# 2) hosts (must come after 1 — they include_bytes! the ELF)
cd .. && cargo build --release --locked        # script + service
cargo run --release -p coherence-prover-script # prove + FRI-verify a real witness
```

## Post-quantum coherence rule

Use the **core STARK/FRI** proof and verification path, and construct the
prover **explicitly** (SDK 6 blocking API):

```rust
let client = ProverClient::builder().cpu().build();      // NEVER from_env()/new()
let pk = client.setup(Elf::Static(ELF))?;
let proof = client.prove(&pk, stdin).mode(SP1ProofMode::Core).run()?; // FRI, PQ
client.verify(&proof, pk.verifying_key(), None)?;         // FRI verification
```

Do **NOT** call `.groth16()` / `.plonk()` — those wrap the STARK in an
elliptic-curve SNARK (Shor-breakable) and are forbidden here. And do **NOT**
use env-sensitive constructors: on a box with `SP1_PROVER=mock` they hand back
a mock prover whose "proofs" verify, which is how a `/verify` endpoint ends up
saying `valid: true` for garbage. Both `script/` and `service/` also refuse to
emit or accept anything but `SP1Proof::Core`.

## Why script/ and service/ were fixed rather than retired

When these crates didn't compile (SDK 4 pins, dead ELF path, env-sensitive
constructor), the working `measure/` harness was the obvious replacement
candidate. They were fixed instead, for three reasons:

1. **`program/` cannot be retired**: it is the canonical guest whose vkey the
   verifier pins. `measure/guest` is a deliberate *mirror* of it, frozen with
   the 2026-08-29 measurement; promoting the mirror would invert the
   single-source-of-truth relationship.
2. **`measure/host` answers a different question** — proof sizes across modes,
   including Compressed, which the node's verifier rejects. Using it as the
   day-to-day host invites proving in a mode consensus refuses. `script/` is
   the Core-only, verify-included smoke test of the canonical guest.
3. **`service/` has no substitute**: local proving needs desktop-class hardware
   (see above), so a delegated prover is the only spend path for mobile — the
   `deploy/sp1-prover/` GPU recipe targets exactly this crate. Retiring it
   removes a product capability, not a redundancy. The real cost of keeping it
   is the operator-sees-the-witness trust, which is now stated loudly here, in
   the crate manifest, in the service's own module docs, and in the deploy
   README — instead of a parenthetical "(non-private)" in the C1 spec.

## Status

Compiles and proves end-to-end against the pinned toolchain (the measurement
run used this exact guest logic). Proof size vs. the block cap remains an OPEN
consensus question — Core is 5.3x and Compressed 2.4x `MAX_BLOCK_TX_BYTES_V2`;
see `docs/audit/COHERENCE-PROOF-SIZE-2026-08-29.md`. The node-side verifier is
fail-closed and not yet wired to a pinned vkey.
