# GIP-0003: Stratum V2 Adoption

| Field | Value |
|---|---|
| GIP | 0003 |
| Title | Stratum V2 Mining + Template Distribution Adoption |
| Author | BLOCH Founder <founder@blochlayer.com> |
| Status | Draft |
| Type | Standards (Interface) |
| Created | 2026-04-22 |
| Last Updated | 2026-04-23 (v0.3 — Sprint 8 detailed design) |
| Target Release | v0.7.0 |
| Supersedes | — |
| Requires | v0.6.0 |

---

## Abstract

This GIP specifies the adoption of the Stratum V2 (SV2) protocol for Bloch-SIS Protocol's mining interface, running in parallel with the existing Stratum V1 (SV1) implementation. Only the Mining Protocol and Template Distribution Protocol subsets of SV2 are in scope; Job Declaration is deferred to GIP-0004.

The implementation uses the official SRI (Stratum Reference Implementation) low-level crates through the `stratum-core` umbrella crate. Bloch-SIS Protocol's SV2 Pool role will listen on port 3334 using the Noise_NX_Secp256k1+EllSwift_ChaChaPoly_SHA256 handshake, and will not break or modify the existing SV1 listener on port 3333.

No consensus rule, block format, storage schema, or serialized message format changes. This is a pure interface upgrade.

---

## Motivation

SV1 has known shortcomings when used over untrusted networks:

1. **No native encryption.** Share submissions and job assignments travel in cleartext, which permits hashrate hijacking and share theft.
2. **String-based JSON framing.** Each message carries ~3x the bytes of an equivalent binary frame, inflating latency on low-bandwidth links.
3. **No authenticated identity.** Miners cannot cryptographically verify pool identity; pools cannot verify miner identity.

SV2 addresses all three. It also gives Bloch-SIS Protocol access to the broader SV2 tooling ecosystem (Braiins translator, SRI pool templates, Bitcoin Core's Template Provider protocol) with minimal adaptation.

Running SV2 in parallel with SV1 allows incremental rollout: existing SV1 miners keep working while SV2 miners can opt in.

---

## Specification

### 1. Scope

**In scope for this GIP:**
- Mining Protocol (SV2 spec chapter 5)
- Template Distribution Protocol (SV2 spec chapter 7)
- NOISE_NX authenticated handshake (SV2 spec chapter 4)

**Out of scope (deferred):**
- Job Declaration Protocol → GIP-0004
- Translator Proxy (SV1↔SV2 bridge) → external tool, not bundled with node
- SV2 miner-side implementation → not a node concern

### 2. Wire Format

Bloch-SIS Protocol SV2 uses the exact binary frame format specified in the SV2 spec. No Bloch-SIS Protocol-specific extensions are introduced in this GIP. Frame structure:

```
Extension type (2 bytes, little-endian)
Message type   (1 byte)
Message length (3 bytes, little-endian)
Payload        (variable, up to 16 MB)
```

All frames after the NOISE handshake are encrypted via ChaCha20-Poly1305 AEAD with zero-length associated data. Handshake frames are not encrypted.

### 3. NOISE Handshake

Protocol name: `Noise_NX_Secp256k1+EllSwift_ChaChaPoly_SHA256`

- DH curve: secp256k1 (same as Bitcoin)
- AEAD: ChaCha20-Poly1305
- Hash: SHA-256
- Public key encoding: EllSwift (64 bytes, per BIP 324)

Act 1 (initiator → responder, unencrypted):
```
e.public_key (64 bytes EllSwift)
```

Act 2 (responder → initiator, responder static key encrypted):
```
e.public_key                        (64 bytes EllSwift)
Encrypt(s.public_key)               (64 bytes EllSwift + 16 MAC = 80 bytes)
Encrypt(SIGNATURE_NOISE_MESSAGE)    (74 bytes payload + 16 MAC = 90 bytes)
```

After Act 2, both parties derive two CipherState objects (initiator→responder and responder→initiator) and transition to transport mode.

### 4. Pool Identity Certificate

The responder (pool) provides a SIGNATURE_NOISE_MESSAGE in Act 2, which constitutes a certificate binding the static key to an identity controlled by the pool operator's **authority key**.

Certificate contents (74 bytes):
```
version            u16  (= 0x0000)
valid_from         u32  (unix timestamp, inclusive)
not_valid_after    u32  (unix timestamp, exclusive)
signature          [u8; 64]  (Schnorr signature over {version || valid_from || not_valid_after || static_pubkey_x})
```

The authority keypair is separate from the per-session static keypair. The authority key is long-lived (years); the static keypair may be rotated (months). The authority public key is published in the pool's documentation and miners pin it.

For Bloch-SIS Protocol mainnet:
- **Authority keypair:** stored at `/etc/bloch/sv2-authority-key.json` (operator-managed, 0600)
- **Static keypair:** stored at `/etc/bloch/sv2-static-key.json` (node-managed, 0600)
- **Certificate validity:** default 30 days; regenerated on startup if expiring within 7 days

### 5. SetupConnection

After NOISE handshake completes, the first SV2 message the initiator sends is `SetupConnection`. Bloch-SIS Protocol accepts only:

| Field | Accepted value(s) | Rationale |
|---|---|---|
| `protocol` | `0x00` (Mining) in 8a-8d; `0x02` (Template Distribution) in future sprint | JD deferred to GIP-0004 |
| `min_version` | `2` | SV2 is version 2 |
| `max_version` | `2` | Only v2 supported |
| `flags` | Any; Bloch-SIS Protocol echoes back intersection with pool-supported flags | Per SV2 spec §5.3.1 |
| `endpoint_host` | Any; validated as valid hostname | — |
| `endpoint_port` | Any u16 | — |

Response:
- On success: `SetupConnection.Success { used_version: 2, flags: <intersection> }`
- On failure: `SetupConnection.Error { flags: <rejection_reason>, error_code: <string> }`

Bloch-SIS Protocol will return the following `error_code` values (UTF-8 strings, max 255 bytes per SV2 spec):

- `"unsupported-protocol"` — `protocol` is not 0x00 (Mining) or 0x02 (TDP)
- `"unsupported-feature-flags"` — mandatory flag not supported
- `"protocol-version-mismatch"` — max_version < 2 or min_version > 2
- `"internal-error"` — unexpected server-side failure (log and close)

### 6. Mining Protocol (Sprint 9, not this sprint)

Specification of `OpenStandardMiningChannel`, `NewMiningJob`, `SubmitSharesStandard`, etc. will be detailed when Sprint 9 starts. This GIP v0.3 is the design through Sprint 8 only; mining semantics will be added in v0.4.

### 7. Template Distribution Protocol (Sprint 10, not this sprint)

Same as above — detailed design will be added to this GIP when Sprint 10 begins.

### 8. Port Allocation

| Port | Protocol | Encryption | Default enabled |
|---|---|---|---|
| 3333 | SV1 (Bloch-SIS Protocol existing) | None (cleartext) | Yes |
| 3334 | SV2 Mining | NOISE_NX mandatory | No (opt-in via `--stratum-v2` flag) |
| 3335 | SV2 Template Distribution | NOISE_NX mandatory | No (opt-in via `--stratum-v2-tdp` flag, Sprint 10) |

### 9. Configuration

New CLI flags added to `bloch` binary (gated behind compile-time `stratum-v2` feature):

```
--stratum-v2                                 Enable SV2 listener on port 3334
--stratum-v2-addr <SOCKETADDR>               Bind address (default: 0.0.0.0:3334)
--stratum-v2-max-sessions <NUM>              Concurrent session cap (default: 500)
--stratum-v2-cert-path <PATH>                Static keypair JSON (default: /etc/bloch/sv2-static-key.json)
--stratum-v2-authority-path <PATH>           Authority keypair JSON (default: /etc/bloch/sv2-authority-key.json)
--stratum-v2-cert-validity-days <NUM>        Certificate validity window (default: 30)
```

### 10. Compile-time Feature

To guarantee the v0.6.0-compatible binary remains reproducible, SV2 code is gated:

```toml
[features]
default = []
stratum-v2 = ["dep:stratum-core", "dep:key-utils"]
```

Standard build (`cargo build --release`) produces a binary identical in behavior to v0.6.0 (modulo bug fixes). SV2-enabled build (`cargo build --release --features stratum-v2`) includes the listener.

Release artifacts will ship both variants during v0.7.0-alpha; v0.7.0 stable will enable the feature by default once integration tests pass.

---

## Implementation — Sprint Breakdown

Total effort: **120 person-hours** across 5 sprints (Sprint 7 through 11).

### Sprint 7: Wire skeleton — COMPLETE (16h)

Status: ✅ Committed as `c20d889`. See `src/stratum_v2/` on `main`.

Deliverables:
- `Sv2Config`, `Sv2StaticKeypair`, `listener::run()` accept-loop
- 8 unit tests passing
- `stratum-core = "0.2"` wired

Key discovery: direct consumption of SRI library crates (`framing_sv2`, `mining_sv2`, etc.) from crates.io fails with `"could not find binary_sv2 in super"` because the derive macros expect workspace context. The `stratum-core` umbrella crate exists specifically to solve this and is the supported path.

### Sprint 8: NOISE handshake + SetupConnection + main.rs wiring (22h)

Commit 8a: cert.rs + Schnorr signatures (4h)

- New file `src/stratum_v2/cert.rs` (~120 lines)
- `SignatureNoiseMessage::new(authority_priv, static_pub, valid_from, not_valid_after) -> [u8; 74]`
- `SignatureNoiseMessage::verify(authority_pub, static_pub, bytes) -> Result<(), CertError>`
- Cargo.toml: add `key-utils = "1.2"`, enable feature `secp256k1/schnorr`
- 4 unit tests: happy path, expired cert, signature mismatch, wrong authority key
- Behind `#[cfg(feature = "stratum-v2")]` gate

Commit 8b: handshake.rs (6h)

- New file `src/stratum_v2/handshake.rs` (~180 lines)
- Async `perform_handshake(stream, static_keypair, cert) -> Result<TransportPair, Sv2Error>`
- Uses `stratum_core::codec_sv2::State::HandShake(HandshakeRole::Responder(...))`
- 5-second handshake timeout (configurable)
- Reads Act 1 (64 bytes), writes Act 2 (170 bytes), transitions to transport
- 4 unit tests: happy path with a mock initiator, malformed Act 1, timeout, abrupt close

Commit 8c: setup_connection.rs + session.rs (6h)

- New file `src/stratum_v2/setup_connection.rs` (~100 lines): parse `SetupConnection` frame, build `Success`/`Error` responses
- New file `src/stratum_v2/session.rs` (~150 lines): per-session state machine (`Handshake → SetupDone → Live → Closed`), main read/write loop
- Updates to `src/stratum_v2/listener.rs`: replace `drop(socket)` stub with `session::spawn()`
- 5 unit tests: setup success, unsupported protocol, version mismatch, flag intersection, bad message format

Commit 8d: main.rs wiring + integration test (6h)

- Updates to `src/main.rs`: CLI flag parsing, conditional `tokio::spawn(stratum_v2::run(...))` behind `cfg(feature = "stratum-v2")`
- New file `src/stratum_v2/tests/integration_test.rs` (~150 lines): two Bloch-SIS Protocol nodes exchange full handshake + SetupConnection over localhost
- Release notes drafted at `docs/releases/v0.7.0-alpha.1.md`
- Tag `v0.7.0-alpha.1` pushed

### Sprint 9: Mining Protocol (40h)

Out of scope for GIP-0003 v0.3. Design will be added in v0.4 when Sprint 9 begins.

Summary: `OpenStandardMiningChannel` → `NewMiningJob` → `SubmitSharesStandard` → `SubmitSharesSuccess`/`.Error`. Requires bridging `stratum::TipChanged` into SV2 `NewMiningJob` format, including proper `merkle_path` construction and `extranonce_prefix` management.

### Sprint 10: Template Distribution Protocol (28h)

Also deferred. Summary: pool serves templates to external template-providers or translator proxies. Requires exposing the `TemplateContext` through SV2 wire in `NewTemplate` + `SetNewPrevHash`.

### Sprint 11: Interop tests + v0.7.0 release (14h)

- Interop with SRI translator (connects a SV1 miner through a SV2 pool to Bloch-SIS Protocol)
- Interop with Braiins Farm Proxy (if time permits)
- Stress test: 500 concurrent SV2 sessions on production-spec node
- Prometheus metrics for SV2 connections, handshake time, session lifetime
- Documentation: operator guide for enabling SV2 on existing nodes
- Release v0.7.0 stable with SV2 feature enabled by default

---

## Rationale

### Why `stratum-core` and not vendoring

The v0.2 draft of this GIP considered git-submodule vendoring of the SRI workspace. Investigation during Sprint 7 revealed that SRI publishes the `stratum-core` umbrella crate specifically to solve the "can I use these library crates independently from crates.io" problem. It re-exports all low-level crates (`binary_sv2`, `framing_sv2`, `codec_sv2`, `noise_sv2`, `mining_sv2`, etc.) via `pub use`, which places them all in the same scope and resolves the `binary_sv2 in super` compile error from derive macros.

Using `stratum-core` means:
- One Cargo.toml line instead of 8
- Guaranteed version compatibility across SV2 crates (coordinated by SV2-bot)
- Clean diff, no submodule dance, no git history pollution
- Same code path used by all SV2 pool implementations

### Why parallel SV1 and SV2

The alternative would be a "compatibility shim" that translates between SV1 and SV2 at the wire level — but SV2 features like authenticated handshake, binary framing, and job declaration cannot be meaningfully translated down to SV1. Running both in parallel lets each protocol express its native capabilities without lowest-common-denominator compromise.

### Why feature-flag the V2 code in v0.7.0-alpha

A flag-gated alpha release lets operators test SV2 on low-stakes hardware while production miners continue to run the audited v0.6.0 code path. It also produces a clean "did SV2 break anything" test: build without `--features stratum-v2` and diff the binary against v0.6.0. If the diff is zero (modulo bug fixes), SV2 integration is proven to be additive. Flag is removed in v0.7.0 stable.

### Why NOISE_NX not NOISE_XX

NX has the responder (pool) reveal its static key only encrypted in Act 2, with a server-signed SIGNATURE_NOISE_MESSAGE acting as a certificate. XX would require client static keys too, which most miners don't want to manage. NX is the SV2 spec choice and matches the SRI implementation directly.

### Why mandatory encryption on port 3334

Port 3333 (SV1) remains cleartext for backward compatibility. Port 3334 (SV2) requires NOISE handshake, no exceptions. This ensures the "upgrade path" is also an "encryption path" and eliminates the class of hashrate-hijacking attacks that SV1 is vulnerable to.

### Why authority key separate from static key

The authority key is the operator's identity root. It signs certificates that bind the static keypair to the pool's identity. The static keypair does the per-session ECDH math during NOISE. If the static key is compromised (disk theft, memory dump), the operator rotates it and signs a new certificate with the still-safe authority key — miners who have pinned the authority pubkey continue to trust the pool without reconnection.

---

## Backwards Compatibility

No breaking changes. SV1 port 3333 and all V1 behavior preserved exactly.

Node operators who do not opt in to SV2 (the default) are unaffected. The binary they build and run after v0.7.0 upgrade is behaviorally identical to v0.6.0 on SV1 traffic.

Miners running SV1 firmware connect to port 3333 exactly as before.

---

## Security Considerations

**Authority key compromise** is catastrophic — a malicious holder can issue valid certificates for any static key, impersonating the pool indefinitely until miners un-pin. Mitigation: offline storage, HSM for high-value pools, documented key-rotation procedure.

**Static key compromise** is recoverable — operator rotates keypair, signs new certificate, restarts node. Miners re-establish handshake automatically.

**Certificate expiry** — if the node's clock is wrong, certificates may be rejected or accepted inappropriately. Mitigation: require NTP on node hosts; Sprint 11 will add a Prometheus alert for certificate validity window <48h.

**Replay attacks** — NOISE_NX with ephemeral keys in Act 1 provides replay protection for the handshake itself. The symmetric CipherState nonce counter provides replay protection for all transport messages post-handshake.

**Downgrade attacks** — There is no SV1↔SV2 negotiation on the wire; they're completely separate ports. A MITM cannot downgrade an SV2 connection to SV1, because SV2 miners configure port 3334 explicitly and pin the authority key.

**Denial of service** — A malicious actor can open many TCP connections to port 3334 and force the pool to initiate the expensive (ECDH × 2) handshake path. Mitigation: `max_sessions` cap (default 500) rejects additional connections before handshake work is performed. Sprint 11 will add an optional per-IP rate limit before handshake.

---

## Test Vectors

To be populated during Sprints 8–11 as fixed test vectors are created.

Placeholder structure:
- `tests/vectors/sv2/handshake_act1.bin` (64 bytes)
- `tests/vectors/sv2/handshake_act2.bin` (170 bytes)
- `tests/vectors/sv2/setup_connection_success.bin` (TBD)
- `tests/vectors/sv2/setup_connection_error_version.bin` (TBD)

These vectors will be shipped alongside v0.7.0 so independent implementers can verify their SV2 stack against Bloch-SIS Protocol's.

---

## References

1. Stratum V2 Specification — https://github.com/stratum-mining/sv2-spec
2. Stratum Reference Implementation (SRI) — https://github.com/stratum-mining/stratum
3. `stratum-core` umbrella crate — https://docs.rs/stratum-core
4. NOISE Protocol Framework — https://noiseprotocol.org/noise.html
5. BIP 324 (EllSwift encoding) — https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki
6. GroundState v0.6.0 mainnet launch (Sprint AA hard fork) — commit `2ee6589`
7. GroundState v0.7.0-alpha.1 target (Sprint 8 wire skeleton) — commit `c20d889`

---

## Changelog

- **v0.3 (2026-04-23)** — Added Sprint 8 detailed design with 4-commit breakdown, feature-flag spec, authority-key/static-key distinction, full cert structure, CLI flag list, full security considerations section
- **v0.2 (2026-04-22)** — Locked SRI low-level-crates integration approach after ask_user_input session
- **v0.1 (2026-04-22)** — Initial draft
