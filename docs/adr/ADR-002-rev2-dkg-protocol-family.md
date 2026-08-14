# ADR-002-rev2 — DKG Protocol Family

**Status:** **SUPERSEDED** — Genesis-4 uses **no BLS and no DKG**: each validator signs individually with hybrid ML-DSA-65 ‖ Falcon-1024. No DKG ceremony runs on the live chain and none is planned. The chain this ADR governs — Genesis-3, proof of work — stopped permanently at height **39,918** on 2026-08-13. The live chain is **Genesis-4, proof of stake** (30 s slots, 32-slot epochs, finality by epoch, hybrid ML-DSA-65 ‖ Falcon-1024, no mining). The decision, context and consequences below are **not** rewritten: this is a decision log and what was decided, when, is the record. Read it as history, not as guidance.

*Original status line, retained:* **Status:** Accepted
**Date:** 2026-04-30
**Supersedes:** ADR-002-rev1 (2026-04-28)
**Sprint:** 2.1.C-rev1 (Phase β onwards)
**Author:** BLOCH Founder

---

## 1. Context

BLOCH's FFG layer (activating at block 210,000 per ADR-011) requires threshold
signatures over BLS12-381 for finality certificates. The signing key is
generated via Distributed Key Generation (DKG), specifically Gennaro's
secure DKG protocol over discrete-log groups.

ADR-002-rev1 selected `gennaro-dkg = "0.8"` from crates.io as the reference
implementation, sponsored by LIT Protocol and audited by Kudelski Security
(2023, no significant findings).

During Sprint 2.1.C-rev1 Phase β Day 1 (2026-04-29 to 2026-04-30), this
selection was found to be unbuildable: `gennaro-dkg 0.8` and `0.9.0-rc2`
both transitively depend (via `uint-zigzag = "0.2.1"`) on `core2 ^0.4`.
Both `core2 0.4.0` and `core2 0.3.3` are yanked from crates.io, leaving no
satisfiable resolution. Cargo `[patch.crates-io]` cannot fix this without
an alternative source (registry patches require git or path sources, not
version pinning).

This rev2 documents the resolution: maintain the audited algorithm via
**internal git forks of two specific crates**, preserving the zkcrypto
elliptic-curve stack (`bls12_381 = "0.8"`, `ff = "0.13"`, `group = "0.13"`)
in its current audited state.

## 2. Decision

BLOCH will fork two crates under `Entanglementlayer` GitLab namespace:

1. **`uint-zigzag` fork** at
   `https://gitlab.com/Entanglementlayer/uint-zigzag-fork`
   - Source: `mikelodder7/uint` upstream (Apache-2.0, passively maintained)
   - Modification: replace `core2 ^0.4` dependency with vendored equivalent
     or remove (only `core2::io::{Read, Write}` traits are used; `std::io`
     is sufficient when `std` feature is on, which is our case)

2. **`gennaro-dkg` fork** at
   `https://gitlab.com/Entanglementlayer/gennaro-dkg-fork`
   - Source: `mikelodder7/gennaro-dkg` upstream (Apache-2.0, audited
     Kudelski 2023)
   - Modification: redirect `uint-zigzag` dependency to BLOCH fork above
   - **No algorithmic changes.** Audit findings preserved.

BLOCH's `Cargo.toml` will reference the fork via `git` source, mirroring
the existing pattern for `pqcrypto-internals` (already forked under same
namespace for ML-DSA-65 patches).

The reference implementation continues to be:

```
gennaro-dkg = { git = "https://gitlab.com/Entanglementlayer/gennaro-dkg-fork", tag = "v0.9.0-bloch-1" }
```

The choice of stack remains as in rev1:
- **Curve:** BLS12-381 (`bls12_381 = "0.8"`, zkcrypto, audited)
- **Field traits:** `ff = "0.13"`
- **Group traits:** `group = "0.13"`
- **DKG:** Gennaro 1999 secure protocol (Fig. 2 of original paper)
- **Threshold:** 14-of-21 (committee size from ADR-001)

## 3. Rationale

### 3.1 Why not switch to Arkworks (`secret_sharing_and_dkg`)

The Arkworks ecosystem (`ark-ec`, `ark-ff`, `ark-bls12-381`) carries an
explicit upstream disclaimer:

> "WARNING: This is an academic proof-of-concept prototype, and in
> particular has not received careful code review. This implementation
> is NOT ready for production use."

While Arkworks is used in production by ZCash, Aleo, Mina, and Anoma,
those projects fund their own audits or maintain internal forks. Adopting
Arkworks at BLOCH would (a) require new cryptographic auditing during the
pre-mainnet phase, increasing audit cost and timeline, and (b) replace
zkcrypto's audited `bls12_381 = "0.8"` with an unaudited implementation
of the same curve.

The zkcrypto stack (`bls12_381`, `ff`, `group`) has received external
review through its use in production by Filecoin, Zcash Sapling, and
Penumbra, with formal audits of the underlying field/group operations.

### 3.2 Why fork is acceptable

BLOCH already maintains `pqcrypto-internals` as an internal fork for
ML-DSA-65 patches (see ADR-001). The auditor questions answered for that
fork are well-rehearsed:

1. **Why fork?** Specific upstream limitation cannot be resolved
   otherwise.
2. **What changed?** Minimal, documented diff vs. upstream.
3. **Who maintains?** BLOCH Core, with documented update procedure.
4. **What is audit scope?** The fork itself is audited as part of
   BLOCH pre-mainnet review.

Adding `gennaro-dkg-fork` and `uint-zigzag-fork` extends the same model.

### 3.3 Why fork-of-fork (uint-zigzag separately)

A naive fork would be: fork only `gennaro-dkg`, keep `uint-zigzag`
upstream. This is rejected because `uint-zigzag 0.2.1` upstream still
depends on yanked `core2 0.4.0`. Without forking `uint-zigzag` itself,
no version of `gennaro-dkg` (forked or not) will resolve.

Fork scope of `uint-zigzag`:
- The crate is **a codec**, not cryptographic primitive
- No algorithmic correctness questions
- Modification: removing or vendoring 1 dependency (`core2`)
- Audit scope: trivial (review codec correctness against zigzag standard)

### 3.4 Why preserve Kudelski 2023 audit applicability

The audit covered the `gennaro-dkg` algorithm and its implementation.
Algorithmic surface is unchanged in our fork. Dependency surface change
is limited to `uint-zigzag` (codec) and elimination of yanked `core2`.

The auditor question "does the Kudelski 2023 audit still apply?" is
answered: yes, with the caveat that BLOCH's pre-mainnet auditor
re-validates the dependency change.

## 4. Implementation Plan

### 4.1 Fork procedure

See companion document: `runbook-fork-procedure.md`.

Summary:
1. Clone `mikelodder7/uint` → push to `Entanglementlayer/uint-zigzag-fork`
2. Apply patch removing `core2` dependency (use `std::io` directly)
3. Tag as `v0.2.1-bloch-1`
4. Clone `mikelodder7/gennaro-dkg` → push to `Entanglementlayer/gennaro-dkg-fork`
5. Patch `Cargo.toml` to point `uint-zigzag` at BLOCH fork
6. Tag as `v0.9.0-bloch-1`
7. Update BLOCH `Cargo.toml` to reference both forks via git

### 4.2 Maintenance commitments

- **Quarterly:** Review upstream for security patches; cherry-pick if
  applicable
- **On audit findings:** Document fix in fork; escalate to upstream if
  applicable to broader community
- **Versioning:** Use `vX.Y.Z-bloch-N` tag suffix to track BLOCH-specific
  patch level

### 4.3 Fork visibility

Both forks **public** (Apache-2.0 license requires source availability
for distributed binaries). This is also the case for `pqcrypto-internals`.

## 5. Phase β Cronogram (preserved)

The 13-day Phase β plan from ADR-002-rev1 §5 is preserved with one
adjustment:

- **Day 0 (NEW):** Fork procedure (~4 hours one-time)
- Day 1: Add deps to BLOCH Cargo.toml (now references forks, not crates.io)
- Day 2-13: Wrapping (EntlG1, EntlG2, EntlScalar), tests, EIP-2537
  vectors, integration

Total Phase β: 14 days (13 dev + 1 fork setup).

## 6. Cargo.toml Changes

```toml
# === Sprint 2.1.C-rev1 Phase β — DKG dependencies ===
gennaro-dkg = { git = "https://gitlab.com/Entanglementlayer/gennaro-dkg-fork", tag = "v0.9.0-bloch-1" }
bls12_381   = "0.8"
ff          = "0.13"
group       = "0.13"
rand_chacha = "0.3"

# Note: subtle (line ~61) and zeroize (line ~65) are already declared
# above and reused as-is.
```

`[patch.crates-io]` section gets one new entry to ensure the forked
`uint-zigzag` is used wherever pulled (in case other deps reach for
upstream):

```toml
[patch.crates-io]
pqcrypto-internals = { git = "https://gitlab.com/Entanglementlayer/pqcrypto-fork", branch = "main" }
uint-zigzag = { git = "https://gitlab.com/Entanglementlayer/uint-zigzag-fork", tag = "v0.2.1-bloch-1" }
```

## 7. Risks and Mitigations

| Risk | Likelihood | Mitigation |
|------|-----------|------------|
| Upstream `gennaro-dkg` releases security fix we miss | Medium | Quarterly upstream review; `mikelodder7/gennaro-dkg` watch on GitLab |
| Auditor flags fork as "unmaintained" upstream | High | Document mitigation in pre-audit prep: "passively maintained but algorithm correct; we own maintenance burden" |
| Future deps of `gennaro-dkg` get yanked | Medium | Same fork strategy applies; we now have process |
| Migration from fork back to upstream in future | Low | Tag fork commits cleanly; rebase possible if upstream resumes |

## 8. Alternatives Rejected

| Alternative | Reason rejected |
|-------------|-----------------|
| Arkworks `secret_sharing_and_dkg` | Upstream "academic POC" disclaimer; replaces audited zkcrypto with unaudited Arkworks |
| Implement Gennaro DKG from scratch | 4-6 weeks dev + new audit ~$100k+; not justifiable when audited reference exists |
| `[patch.crates-io] core2 = "=0.3.3"` | Both core2 0.3.3 and 0.4.0 yanked; not satisfiable |
| `[patch.crates-io] core2 = "=0.3.3"` as direct dep | Same yanked issue; cannot pin to yanked version |
| Stay on `gennaro-dkg = "0.8"` upstream | Unbuildable; demonstrated 2026-04-30 |
| `bls_on_arkworks + custom Gennaro` | 2 weeks extra dev + still uses Arkworks |
| `blst + custom Gennaro` | 3 weeks extra dev; viable but premature optimization |

## 9. Acceptance Criteria

This ADR is fulfilled when:

- [ ] `Entanglementlayer/uint-zigzag-fork` exists, public, tagged `v0.2.1-bloch-1`
- [ ] `Entanglementlayer/gennaro-dkg-fork` exists, public, tagged `v0.9.0-bloch-1`
- [ ] BLOCH `Cargo.toml` references both forks; `cargo build --lib` succeeds
- [ ] `cargo test --lib` returns 469+ tests passing (no regression)
- [ ] Existing 469 tests unchanged in behavior
- [ ] This ADR committed to `docs/adr/` and pushed
- [ ] Pre-mainnet audit checklist updated to include fork review

## 10. References

- ADR-001: ML-DSA-65 + BLS12-381 finality scheme
- ADR-002-rev1: DKG Protocol Family (superseded)
- ADR-005: Committee era + Phragmén selection
- ADR-007: Bonding contract + slashing
- Gennaro et al. 1999, "Secure Distributed Key Generation for
  Discrete-Log Based Cryptosystems"
- Kudelski Security audit report (2023, sponsored by LIT Protocol)
- Plano de Ação Pré-Mainnet v1.0 (2026-04-15), deadline 2026-05-15
