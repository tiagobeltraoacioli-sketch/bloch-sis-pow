# Annex A12 — Dynamic analysis: build, test suites, lints, dependency policy

*Environment: Linux x86_64, 4 vCPU, 15 GB RAM; rustc/cargo 1.94.1 (the release pin); network via proxy; no fleet access. All commands run against the clean tree at `562e220`.*

## A12.1 Build

| Command | Result | Wall time |
|---|---|---|
| `cargo check --workspace --all-targets` | **exit 0, 0 errors**; warnings in Annex A0 §A0.2 | 4 m 44 s |

## A12.2 Test suites (live and shared crates, `cargo test -p <crate> --no-fail-fast`, debug profile with the workspace's per-package opt-level overrides)

| Crate | Result | Passed | Failed | Ignored | Wall time | Note |
|---|---|---|---|---|---|---|
| bloch-pos-committee | ok | 421 + 109 + 5 + 1 + 5 + 29 + 4 + 15 + 6 + 2 + 9 + 2 = **608** | 0 | 6 | 1 m 36 s | lib 421 (69 s); integration suites e2e/committee/properties/schedule/etc. |
| bloch-crypto | ok | **168** | 0 | 4 | 32 s | |
| coherence-core | ok | **13** | 0 | 0 | 5 s | |
| bloch-sis-pow | ok | **78** | 0 | 3 | **18 m 45 s** | `solver::tests::mine_with_max_target_succeeds_quickly` and two integration tests run > 60 s each unoptimized (the crate has no `opt-level` override); harmless but the name is misleading in a debug build and it dominates the CI wall clock for this crate |
| bloch-pq-vault | ok | **22** | 0 | 0 | 9 s | |
| pqcrypto-internals | ok | **18** | 0 | 2 | 5 s | includes `tests/vendor_pin.rs` (PQClean hash pin) and the seeded-RNG child-process abort tests |
| genesis4-ceremony | ok | **28** | 0 | 0 | 13 s | |
| bloch-pos-node | ok | 378 + 1 + 4 + 3 + 4 + 1 + 4 + 5 + 1 = **401** | 0 | 20 | 2 m 18 s | lib 378 (42 s); `cold_start` 52 s; `replay_hotpath_perf` and the two-engine lifecycle rehearsal are `#[ignore]`d measurements |
| bloch-ustav | ok | **5** | 0 | 0 | 4 s | |
| bloch-btc-wallet | ok | **7** | 0 | 0 | 1 s | |

The README's "366 tests green, measured 2026-08-13" for the consensus crate is now 608 passing tests; the crate has grown by two thirds in a month, which is itself a signal about how much consensus code has changed since launch without an external review.

## A12.3 Clippy (live crates, `--all-targets -W clippy::all`)

`cargo clippy -p bloch-pos-committee -p bloch-pos-node -p bloch-crypto --all-targets -- -W clippy::all`: **exit 0, 0 errors, 229 warnings**, all style-class. Distribution: `transition.rs` 36, `engine.rs` 18, `bloch-crypto/src/core/mod.rs` 22, `wallet/encryption.rs` 7, `ws.rs` 6, `p2p.rs` 6, `rpc.rs` 5, `genesis.rs` 5, `finality.rs` 9. Most frequent: `clone` on a `Copy` type or replaceable by `slice::from_ref` (45), complex types (13), manual `is_multiple_of` (12), doc-list indentation (17), constant-valued assertions (10 — all inside `#[cfg(test)]` modules or the binary's `selfcheck` command, where a compile-time-constant `assert!` is the intended self-check; none is a dead runtime guard), `large size difference between variants` on `interfaces.rs:256`, `transition.rs:306` (`PosTransaction`), `net.rs:113`, `rpc.rs:841` (a `Box` of the large variant would shrink every `Vec<PosTransaction>`; performance only). Nothing in the set changes behaviour; the repository's own `scripts/hardened-clippy.sh` runs a stricter, consensus-scoped configuration in GitLab CI (Annex A10 INF-03/INF-04 on whether that job currently runs).

## A12.4 Dependency policy (`cargo deny`, `cargo audit`)

`cargo install cargo-deny --locked` / `cargo install cargo-audit --locked` (latest at audit time; the CI pins 0.20.2 / 0.22.2), advisory database fetched 2026-09-16.

| Command | Result |
|---|---|
| `cargo deny check bans` | **ok** — `multiple-versions = "deny"` passes; 4 `wildcard` warnings on first-party path dependencies (`bloch-pq-vault`, `bloch-ustav`) |
| `cargo deny check licenses sources` | **ok** |
| `cargo deny check advisories` | **FAILED** — `error[vulnerability]` **RUSTSEC-2026-0285** (`rustls 0.23.38`, published 2026-09-14, CVSS 5.3): TLS 1.3 handshake messages accepted across encryption-level boundaries; fix `>= 0.23.45`. Reachable from the live binary: `rustls` ← `futures-rustls` ← `libp2p-websocket 0.45.1` ← `libp2p 0.56.0` ← `bloch-pos-node` (and `hyper-rustls`). Plus **10 `advisory-not-detected` warnings**: `deny.toml` ignores for `RUSTSEC-2025-0012`, `2024-0384`, `2021-0139`, `2024-0388`, `2025-0119`, `2025-0134`, `2026-0002`, `2026-0253`, `2026-0163`, `2026-0173` match nothing in the resolved graph (the SP1/arkworks stack they were written for is no longer reachable from the root workspace) |
| `cargo audit -n` | **1 vulnerability found** — the same RUSTSEC-2026-0285. (The yanked-crate check could not complete: the sandbox's registry proxy answered 503 to the index API; yank status is therefore unverified.) |
| `cargo update -p rustls --dry-run` | see §A12.6 LD-01 |

Consequence: both GitHub jobs named `cargo-audit (blocking)` and `cargo-deny (blocking)` (`.github/workflows/security.yml:76-105`) fail on the current tree, and so does GitLab's `supply-chain` job. The blocking supply-chain gate has been red since the advisory was published on 2026-09-14, three days after the last commit on this branch.

## A12.5 Static scans performed by the lead (outside the reviewers' scopes)

- `Cargo.lock` vs the resolved graph: the lock file carries **876 entries but `cargo metadata --locked` resolves only 587 packages** for the root workspace — 289 entries (the SP1/arkworks/alloy stack: `ark-ff` ×4, `sha3 0.11`, `axum 0.8`, `syn 1.0.109`, `bincode 1`, …) are unreachable leftovers from when `crates/coherence-prover` was a workspace member. In the *resolved* graph 38 names are duplicated, and `cargo deny check bans` **passes** (§A12.4). This corrects Annex A10's INF-05, which inferred from the raw lock file that the gate was red: the gate is green; what is wrong is the lock hygiene (stale entries that a future `cargo update` will silently drop, changing the lock without any intent) and `deny.toml`'s claim that its skip list is an exact, exhaustive pin. INF-05 is downgraded to Low in §6.
- Consensus crate non-determinism scan: no `f32`/`f64`, `SystemTime`, `Instant`, `rand`, `std::env` or `HashMap` on the non-test consensus path except the fork-choice store (`forkchoice.rs`, `HashMap` for latest messages/stake/equivocators — reviewed in A2 FC-06: the head selection is order-independent by construction and ties break on the root value, not on iteration order) and a singleton memo in `state_root.rs`.
- Node environment variables (complete list): `BLOCH_KEYSTORE_PASSPHRASE`, `BLOCH_KEYSTORE_PASSPHRASE_FILE`, `BLOCH_KEYSTORE_ALLOW_PLAINTEXT`, `BLOCH_NO_DOPPELGANGER`, `BLOCH_ALLOW_FINALITY_REWIND`. None reaches a consensus rule; the last two are node-local safety levers (A5 EN-22).
- `consensus_invariant!` sites: 9 in `transition.rs`, 1 in `params.rs`; A1/A2 checked each and found none reachable from peer input.

## A12.6 Findings from the dynamic run (lead)

### LD-01 — Blocking supply-chain gates are red on `main`: `rustls 0.23.38` carries RUSTSEC-2026-0285, reachable from `bloch-pos-node` through `libp2p-websocket`
- **Severity:** Medium (operational: every PR fails the two blocking supply-chain jobs until the lock moves; the vulnerability's own impact on this node is Low — the live fleet does not run the libp2p transport, the WebSocket transport is not configured, and the advisory's practical effect is acceptance of plaintext handshake messages that should have been encrypted, with the transcript still authenticated). **Status:** NEW (advisory published 2026-09-14, after the last commit).
- **Evidence:** Annex A12 §A12.4; dependency path `rustls v0.23.38 ← futures-rustls v0.26.0 ← libp2p-websocket v0.45.1 ← libp2p v0.56.0 ← bloch-pos-node v0.1.0-mainnet`; `.github/workflows/security.yml:76-105`.
- **Recommendation:** `cargo update -p rustls` (semver-compatible, §A12.4 dry run), re-run both gates, and consider dropping the `websocket` feature of `libp2p` if the node never dials `/ws` multiaddrs. Then remove the ten stale `ignore` entries from `deny.toml`/`.cargo/audit.toml` (or move them to the coherence-prover lockfile scan they were written for), so the advisory allowlist only names advisories that exist in the graph it governs.

### LD-02 — `Cargo.lock` carries 289 unreachable entries and `deny.toml` ten ignores that match nothing (hygiene; corrects INF-05)
- **Severity:** Low. **Status:** NEW.
- **Evidence:** §A12.5; `cargo deny check advisories` `advisory-not-detected` ×10; `SECURITY_TOOLING.md` records the skip list as measured on 2026-09-06 against a lock that has since moved.
- **Recommendation:** run `cargo update --workspace` (no version changes, prunes stale entries) in its own commit; add a CI check that fails on `advisory-not-detected` (`cargo deny check --hide-inclusion-graph` treats it as a warning today) and on unmatched `skip` entries.

### LD-03 — `bloch-sis-pow` test suite takes 18 m 45 s unoptimized because three tests mine real solutions in debug mode
- **Severity:** Info. **Status:** NEW.
- **Evidence:** §A12.2; `solver::tests::mine_with_max_target_succeeds_quickly`, `tests::integration::{corrupted_solution_fails_verify, manually_constructed_pass_through_verify}` each > 60 s.
- **Recommendation:** add `[profile.dev.package.bloch-sis-pow] opt-level = 3` at the workspace root (the same pattern already used for `argon2`, `sha3`, `keccak`), or gate the mining tests behind `--release`/`#[ignore]` with a documented reason.
