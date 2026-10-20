<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Crypto audit status: p9e findings, 2026-10-20

**Audit:** p9e crypto audit, commit `e9b52781` on
`codex/bloch-p9e-cryptoaudit-20261019` (2026-10-19). It covers Falcon-1024,
ML-DSA-65 and the SLH-DSA candidates, with FIPS 204/205 KATs, hybrid boundary
tests, and five verify-side fuzzers. Each fuzzer ran about 30 minutes on
x86_64 Cascade Lake and found no crashes.

**Base:** mainnet release `b4a21fb6`.

**This branch:** `codex/hf-cryptoaudit-20261020`. The audit suite is ported
onto `b4a21fb6` and the signer-side hardening for finding 2 is added here.
Everything on this branch is node-side or test-only. No consensus rule,
signature encoding or verifier changes. With every activation gate off, a
node built from this branch accepts and produces exactly the same bytes as
`b4a21fb6`.

## Findings and status

| # | Severity | Finding | Fix branch | Status |
|---|---|---|---|---|
| 1 | MED | ML-DSA-65 verify depends on the CPU. `pqcrypto-mldsa` default features dispatch to AVX2, NEON or `clean`, so a backend disagreement would split the chain by hardware. | `codex/hf2-sigdet-20261020` (`9105c59b`, the P9f pin of consensus ML-DSA-65 to PQClean `clean` on every platform) | Fixed on that branch, which another agent owns. Not duplicated here. The differential ACVP tests ported here (`acvp_fips204_full.rs`, fuzz `mldsa_backend_diff`) remain the regression guard. |
| 2 | MED | Validators sign with Falcon-1024 on hot hosts every slot. The `clean` signer is constant-time only by design: no timing test had been run on the built binary. Power/EM and fault attacks still apply. Devnet `keygen` generates keys on the host. | **`codex/hf-cryptoaudit-20261020` (this branch)** | Hardened, node-only. See [Finding 2](#finding-2-falcon-signing-on-hot-hosts). The remaining physical-access residual risk is documented below. |
| 3 | LOW | One signature has several accepted byte forms: header optional, Falcon zero padding, and recombined halves. | `codex/hf2-sigdet-20261020` (`ae5d0351`, `2e7cb51b`) | Fixed on that branch. The node relay policy is active now. The consensus `SIG_CANONICAL_ACTIVATION_EPOCH` gate ships inert (`u64::MAX`). Not duplicated here. |
| 4 | LOW | The suite id is not in the signed context. With the Falcon half stripped, a 0x0001 signature verifies under a 0x0002 key that reuses the same ML-DSA key. | `codex/hf2-sigdet-20261020` (`ae5d0351`, `2e7cb51b`) | Fixed on that branch with the v2 suite-bound context (`SignaturePolicy::Bound`), behind the inert gate. It must be armed before any "drop Falcon" re-wrap migration. Not duplicated here. |
| 5a | INFO | The production ML-DSA signer is FIPS 204 final: all 25 keyGen and 30 sigGen ACVP vectors match the independent `fips204` crate. | n/a | Conformance confirmed. The tests are ported here (`audit/pq-conformance`, `acvp_fips204_full.rs`). |
| 5b | INFO | Both SLH-DSA-SHAKE-128s candidates pass FIPS 205 ACVP, and neither is audited: `fips205` 0.4.1 has no internal API, and `slh-dsa` is 0.2.0-rc.5. | `codex/hf3-slhdsa-20261020` (suite 0x0003 work) | Open, owner decision. Nothing ships on mainnet before HF3, and the ACVP tests ported here keep checking whichever crate is chosen. |

### Merge note for the integrator

`codex/hf2-sigdet-20261020` and this branch both modify `Keystore::sign` in
`crates/bloch-pos-node/src/keys.rs`. Resolve the conflict like this:

- Keep hf2-sigdet's `sign_under(policy, root)`.
- Route its body through this branch's `sign_released(root, sign_fn,
  verify_fn)`, passing the signer and verifier of the same policy:

```rust
self.sign_released(
    signing_root,
    |sk, m| bloch_crypto::crypto::sign_with_policy(crypto_policy(policy), sk, m),
    |pk, m, s| bloch_crypto::crypto::verify_with_policy(crypto_policy(policy), pk, m, s),
)
```

That way every policy's signatures are verified before release. Both branches
carry the identical p9e commit (`e9b52781` cherry-picked), so the ported test
files merge cleanly.

## Finding 2: Falcon signing on hot hosts

### Already in place before this branch

`docs/specs/BLOCH-FALCON-ONLINE-SIGNING.md` (finding F1) covers the earlier
work:

- Falcon signing is pinned to PQClean's integer-only `clean` variant
  (`default-features = false`).
- The `falcon_native_fp_variants_are_not_linked` tripwire test and
  `scripts/falcon-clean-guard.sh` keep it pinned.
- A seeded KAT pins the produced bytes.
- Signing is randomized, which defeats "Sleeping Falcon".

The p9e audit confirmed that the KAT pinned on aarch64 reproduces on x86_64.

### Added on this branch (node-side, non-consensus)

| Measure | Where | What it does |
|---|---|---|
| Verify-before-release | `bloch_crypto::crypto::hardening::sign_verified{,_with}`; `Keystore::sign` → `sign_released` | Every validator signature is verified under the keystore's own public key before it leaves the process. This is the standard countermeasure against fault attacks on lattice signers: a faulted signature that gets published can leak key material. A failing signature is withheld and signing is retried with fresh randomness, up to `SIGN_VERIFY_ATTEMPTS = 3` times. After that the process aborts rather than keep exercising the key. The returned bytes are exactly what `crypto::sign` produced. |
| Power-on self-test | `hardening::falcon_signing_self_test`, `Keystore::signer_self_test`, called from `engine::run` before the first duty | Runs a seeded Falcon-1024 KAT on a dedicated thread (the seeded RNG is thread-local and scoped), checking the same pins as the unit test. It also checks that unseeded signing is still randomized, and runs a pairwise consistency sign+verify of the loaded keypair. The pairwise message is 40 bytes, so it can never be a 32-byte signing root. If any check fails, the node refuses to start. |
| Platform check | `hardening::signing_platform_check` | Validator start is refused unless the binary targets x86_64 or aarch64. Those are the architectures on which the signer's one hardware assumption has been reviewed: constant-time 32x32→64 integer multiplication. Override: `BLOCH_ALLOW_UNVETTED_SIGNING_PLATFORM=1`. |
| No core dumps, no same-user ptrace | `keys::harden_signing_process`, called from `engine::run` when a keystore is loaded | Sets `RLIMIT_CORE=0` so a crash cannot write the hybrid secret to `/var/crash` or systemd-coredump. On Linux it also sets `PR_SET_DUMPABLE=0`, which stops other processes of the same user from ptrace-attaching or reading `/proc/<pid>/mem`. Side effect: `/proc/<pid>/{fd,environ,maps,smaps,mem}` become root-only. `stat`, `statm` and `status`, which `ps` and `top` use, are unaffected. Opt-out for debugging: `BLOCH_ALLOW_CORE_DUMPS=1`. |
| Constant-latency floor (opt-in) | `BLOCH_SIGN_LATENCY_FLOOR_MS` (capped at 2000) | `Keystore::sign` does not return before the floor has elapsed. The network-observable publication time then carries the floor rather than the signer's running time. Off by default, because in-process multi-validator harnesses would serialize the sleeps. **Recommended `100` for mainnet validator units.** This is the node-side form of the fixed-deadline publication rule in BLOCH-FALCON-ONLINE-SIGNING.md §5. |
| Timing test | `crates/bloch-crypto/tests/falcon_sign_timing.rs` (ignored; run in `--release`) | A dudect-style Welch t-test that compares two secret keys over the same message. It also runs a public-message class as a positive control, which is expected to differ because of `hash_to_point_vartime`. Measured result: see below. `BLOCH_FALCON_TIMING_ASSERT=1` makes it a gate. |

### Timing measurement

First run on 2026-10-20, on the owner's Mac. The host is Apple silicon, but
the Rust toolchain there is `x86_64-apple-darwin`, so the binary ran under
Rosetta 2. Several other workspace builds were running concurrently. The
release build took 4,000 samples per class:

| Class | Mean per signature | t (all samples) | max \|t\| (cropped) |
|---|---|---|---|
| secret key A vs key B | 78.2 ms vs 77.6 ms | 1.08 | 1.19 |
| fixed vs random message (positive control) | 88.2 ms vs 88.4 ms | -0.43 | 0.75 |

**Reading.** At this noise level the test detects no secret-key-dependent
timing: |t| = 1.19, below dudect's 4.5 threshold. The positive control did not
fire either. Its expected message-dependent difference is microseconds, far
below the jitter of an emulated and heavily loaded host. So this run
**does not prove** constant time. It shows only that there is no leak large
enough to see through this much noise.

The conclusive measurement still needs to be run:

- a native x86_64 build on an idle, dedicated host that matches the validator
  CPUs (Cascade Lake), plus an aarch64 native build;
- at least 10^5 samples per class, with `BLOCH_FALCON_TIMING_ASSERT=1`.

No fleet host was used for this run, per the integration rules.

### Residual risk and operator guidance

These are not fixable in code and are recorded for the hosting decision:

- **Power, EM and fault injection** need physical or hypervisor access. On a
  shared VPS the hypervisor operator has that access, so validator hosts
  should be dedicated or bare-metal where stake justifies it.
  - Verify-before-release catches faults that produce invalid signatures.
  - It does not catch faults that still produce a valid but leaky signature.
    For that case the hybrid AND combiner is the backstop: forging still
    needs the ML-DSA half.
- **SMT and co-tenancy**: the `clean` signer has no secret-dependent memory
  access by design, but do not run validators on hosts where untrusted
  tenants share physical cores.
- **Keygen off-box.** SHIFT SNARE is a single-trace power attack on Falcon
  keygen.
  - `bloch-pos keygen` remains labelled devnet/throwaway.
  - Mainnet keys should be generated on an offline machine and only loaded on
    the validator.
  - This branch does not change `keygen`, so existing onboarding flows keep
    working.
- **Process isolation of the signer** (a separate signer process or HSM-style
  boundary) is the larger step. The P3a signer anchor, rollback guard and
  per-key flock are on `codex/hf-node-only-20261020`; a separate signing
  process is future work.
- **FIPS 206 / FN-DSA**: unchanged from BLOCH-FALCON-ONLINE-SIGNING.md §4.
  FN-DSA would be a new suite, never an in-place swap.

## Ported audit suite: test inventory

| Item | Location | Result on this branch (macOS aarch64) |
|---|---|---|
| ACVP FIPS 204 ML-DSA-65 keyGen/sigGen/sigVer on every compiled backend | `crates/bloch-crypto/tests/acvp_fips204_full.rs` | 4 passed |
| Hybrid boundary tests | `crates/bloch-crypto/tests/p9e_hybrid_boundaries.rs` | 5 passed |
| FIPS 204 cross-impl + FIPS 205 ACVP (own workspace) | `audit/pq-conformance` | 9 passed (2 ML-DSA cross-impl + 7 SLH-DSA ACVP; release) |
| Verify-side fuzzers (own cargo-fuzz workspace) | `crates/bloch-crypto/fuzz` | Not re-run here (nightly + cargo-fuzz). 30 min per target on 2026-10-19, 0 crashes |
| Signer hardening unit tests | `bloch_crypto::crypto::hardening::tests`, `bloch-pos-node keys::signer_hardening_tests` | 8 (bloch-crypto) + 6 (bloch-pos-node) passed; full `cargo test -p bloch-crypto`: 261 passed / 0 failed / 5 ignored; full `cargo test -p bloch-pos-node`: 712 passed / 0 failed / 28 ignored |
