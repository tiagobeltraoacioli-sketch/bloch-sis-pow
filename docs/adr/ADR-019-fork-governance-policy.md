# ADR-019 — Fork Governance Policy

**Status:** Accepted
**Date:** 2026-04-30
**Sprint:** 2.1.C-rev1
**Author:** BLOCH Founder

---

## 1. Context

BLOCH maintains internal forks of upstream crates as a documented engineering
pattern. As of 2026-04-30, BLOCH has three such forks:

1. `pqcrypto-internals` — patches for ML-DSA-65 implementation (per ADR-001)
2. `gennaro-dkg` — preservation of audited DKG algorithm (per ADR-002-rev2)
3. `uint-zigzag` — codec dependency required by gennaro-dkg fork (per ADR-002-rev2)

Without consolidated policy, fork management becomes ad-hoc, increasing
audit friction and operational risk.

This ADR defines policy for fork governance: when forking is acceptable,
how forks are maintained, and how they interact with the pre-mainnet
audit process.

## 2. Decision

BLOCH forks upstream crates only when at least **one** of these conditions
holds:

1. **Cryptographic patch needed** that upstream has not accepted (e.g.,
   pqcrypto-internals ML-DSA-65 conformance fixes)
2. **Upstream dependency is yanked** and resolution is impossible without
   modifying the dependency tree (e.g., uint-zigzag → core2 yanked)
3. **Upstream is abandoned** (>12 months no commits, no maintainer
   response to security disclosure)
4. **Audit-preservation requirement** where the audited algorithm exists
   only in upstream that has dependency rot (e.g., gennaro-dkg)

Forks are **NOT** acceptable for:

- Adding features not strictly required for BLOCH operation
- Style preferences or refactoring
- Avoiding upstream issues that have a non-fork resolution
- Replacing upstream because we "could write it better"

## 3. Fork Lifecycle

### 3.1 Creation

Each fork creation requires:

1. **Justification document:** ADR (or section of ADR) explaining the
   condition triggering the fork (per §2)
2. **Diff documentation:** explicit list of changes vs. upstream
3. **Tag:** `vX.Y.Z-bloch-N` where X.Y.Z mirrors upstream version, N is
   BLOCH patch level (starts at 1)
4. **Public visibility:** repository public on GitLab namespace
   `Entanglementlayer/`
5. **README addition:** the fork's README adds an "BLOCH Modifications"
   section with diff summary

### 3.2 Maintenance

Each quarter (4 times/year):

1. **Upstream review:** check if upstream has security patches BLOCH
   should backport
2. **Patch backport decision:** documented in fork's CHANGELOG
3. **CI run:** confirm fork still builds and tests pass
4. **Audit log:** append review summary to `docs/forks/MAINTENANCE.md`

### 3.3 Sunset

Fork is sunset (returned to upstream) when:

- Upstream resumes maintenance and accepts BLOCH patches
- BLOCH no longer requires the patched behavior
- A drop-in replacement crate emerges with no fork required

Sunsetting requires:

1. ADR documenting reason
2. Migration commit changing `Cargo.toml` references
3. Fork repo archived (read-only) but not deleted (audit trail)

## 4. Fork Inventory (as of 2026-04-30)

### 4.1 pqcrypto-internals

- **URL:** https://gitlab.com/Entanglementlayer/pqcrypto-fork
- **Trigger condition:** §2.1 (cryptographic patch needed)
- **Reason:** ML-DSA-65 conformance with FIPS 204 final (upstream still
  IPD-aligned)
- **Created:** Sprint 1.6 (~2026-Q1)
- **Audit:** Pending pre-mainnet review
- **Diff:** see fork README + ADR-001 §6

### 4.2 gennaro-dkg

- **URL:** https://gitlab.com/Entanglementlayer/gennaro-dkg-fork
- **Trigger condition:** §2.4 (audit-preservation, dependency rot)
- **Reason:** preserve Kudelski 2023 audit while resolving yanked
  transitive dep
- **Created:** Sprint 2.1.C-rev1 Phase β (2026-04-30)
- **Audit:** Algorithm covered by Kudelski 2023; fork delta covered
  by BLOCH pre-mainnet audit
- **Diff:** ONLY redirects `uint-zigzag` dep to BLOCH fork; no algorithmic
  changes

### 4.3 uint-zigzag

- **URL:** https://gitlab.com/Entanglementlayer/uint-zigzag-fork
- **Trigger condition:** §2.2 (yanked dependency)
- **Reason:** upstream depends on yanked `core2 ^0.4`
- **Created:** Sprint 2.1.C-rev1 Phase β (2026-04-30)
- **Audit:** Codec correctness review (trivial scope)
- **Diff:** removes `core2` dependency; uses `std::io` directly (we
  always have `std` enabled)

## 5. Pre-Mainnet Audit Implications

### 5.1 Auditor Disclosure

The pre-mainnet audit RFP (currently being prepared per Plano de Ação
Pré-Mainnet v1.0) must explicitly disclose:

1. List of forks (per §4)
2. Trigger condition for each
3. Diff summary for each
4. Maintenance procedure (this ADR)
5. BLOCH Core's commitment to long-term maintenance

### 5.2 Audit Cost Allocation

Each fork is in-scope for the audit:

- Algorithmic forks (e.g., `pqcrypto-internals`): **full review** by
  cryptographic auditor
- Codec/utility forks (e.g., `uint-zigzag`): **delta-only review** vs.
  upstream
- Dependency-only forks (e.g., `gennaro-dkg`): **algorithm preserved
  from prior audit**, only delta reviewed

Estimated audit cost adder for current 3-fork inventory: **+$15-25k**
above baseline BLOCH pre-mainnet audit.

### 5.3 Auditor Response Preparation

Anticipated auditor questions and BLOCH responses, by fork type:

| Question | Response |
|----------|----------|
| "Why fork instead of upstream PR?" | Per §2, condition X documented in ADR-Y |
| "How long will you maintain?" | §3.2; quarterly review documented |
| "What if upstream releases security fix?" | §3.2 backport procedure |
| "Why not switch to alternative crate?" | Documented in originating ADR's "Alternatives Rejected" section |

## 6. Tooling Requirements

The following tools/processes must exist for fork governance compliance:

1. **`docs/forks/MAINTENANCE.md`** — running log of quarterly reviews
2. **`docs/forks/INVENTORY.md`** — auto-generated from this ADR §4 (kept
   in sync)
3. **CI job `fork-build-test`** — validates each fork builds and tests
   pass independently of BLOCH main repo

These will be created in Sprint 2.1.D (post-Phase β).

## 7. Acceptance Criteria

This ADR is fulfilled when:

- [ ] All current forks (per §4) have `vX.Y.Z-bloch-N` tags
- [ ] All current forks have README "BLOCH Modifications" section
- [ ] `docs/forks/MAINTENANCE.md` created with first review entry
- [ ] Quarterly review calendar set up
- [ ] Pre-mainnet audit RFP includes fork disclosure (per §5.1)

## 8. Future Considerations

If the fork count exceeds 5, BLOCH should reconsider:

- Whether to consolidate into a single `bloch-vendored-deps` workspace
- Whether to bring crates fully in-house with new namespace
- Whether to fund upstream maintenance directly

These options are out of scope for this ADR but flagged for future
revision.

## 9. References

- ADR-001: ML-DSA-65 + BLS12-381 finality scheme (originating
  pqcrypto-internals fork)
- ADR-002-rev2: DKG Protocol Family (originating gennaro-dkg + uint-zigzag forks)
- Plano de Ação Pré-Mainnet v1.0 (2026-04-15)
