# Security Policy

> **Updated 2026-08-13, the day the chain changed underneath this file.** The
> reporting flow, disclosure timeline and development practices below are
> current and were never era-specific. The **Status** section has been
> rewritten: it described Genesis-3 proof-of-work as the live network, and
> that stopped being true at 21:31:19 UTC on 2026-08-13.

## Status

The live network is **Genesis-4**, and it is **proof of stake**. It started at
**2026-08-13 21:31:19 UTC** on 64 genesis validators across five servers,
produces a block every 30 s, and finalises every epoch. Block version
`0xB10C_0005`. Fork choice is LMD-GHOST, finality is Casper-style FFG over an
epoch committee, and signatures on every consensus path are hybrid
**ML-DSA-65 ‖ Falcon-1024** — no BLS anywhere. The code that runs it is
`crates/bloch-pos-committee` (consensus) and `crates/bloch-pos-node` (the
`bloch-pos` binary).

**Genesis-3, the proof-of-work chain, is closed.** It ran from 2026-07-29 and
stopped at height **39,918**; SHA-256d, ASIC-mined, with Bitcoin merged mining
(AuxPoW) from height 8,500. Nothing produces blocks on it. Its node is kept
buildable at `legacy/genesis3-node/` because Genesis-4's opening ledger is the
balance set carried across from that height, and an auditor has to be able to
re-derive it. Report a Genesis-3 finding if it changes what that carried
ledger should have been; a finding that only affects mining or block
production on a chain nobody is producing on has no live impact.

The live network is **unaudited**, and stake is heavily concentrated: the
founder holds 93.94% of the carried-over balance
(`LARGEST_CARRYOVER_ADDRESS_BLOCH` / `CARRYOVER_TOTAL_BLOCH`,
`tokenomics_v4.rs`) and it is stakeable, so a naive Nakamoto coefficient is 1.
The genesis validator cohort was allocated by the founder; its current host
distribution is tracked in [`deploy/FLEET-INVENTORY.md`](./deploy/FLEET-INVENTORY.md)
rather than restated here as a round number this file cannot keep current.
Running a live mainnet is a designation, not a security claim, and no
security property is claimed.

**The epoch-2700 flag day (2026-09-12 21:31 UTC) is the next scheduled
consensus change** — it arms the gate that closes the 2026-08-24
finality-divergence finding. See
[`deploy/FLAG-DAY-EPOCH-2700.md`](./deploy/FLAG-DAY-EPOCH-2700.md) for the
prerequisites, verification steps, and abort criteria; a report against a
finding that flag day closes should note whether it was filed before or
after the gate armed.
**No external security audit has been contracted to date**; if any other page
or document suggests otherwise, this statement is the accurate one. The
posture we are building toward — and its open gates — is in
[`docs/THREAT-MODEL.md`](./docs/THREAT-MODEL.md) and [`ROADMAP.md`](./ROADMAP.md);
both of those are Genesis-3-era documents and say so at the top.

## Reporting a vulnerability

**Do not open a public issue, discussion, or merge request for a sensitive
security or privacy finding.**

- Use the repository's **private security advisory** flow, or
- contact a maintainer directly via an encrypted channel with `[bloch-security]`
  in the subject.

Include: affected component, version/commit, reproduction (a PoC is ideal),
impact (what can an attacker do, under what assumptions), a suggested fix if you
have one, and whether you want public credit.

We aim to acknowledge within a few days and to coordinate a fix + disclosure
timeline with you (typically: acknowledge ≤ 2 days, fix and coordinated
disclosure as fast as the severity warrants). Good-faith research is welcome; we
will not pursue reporters acting in good faith.

## In scope

- **Genesis-4 consensus** (`crates/bloch-pos-committee`): the state transition,
  LMD-GHOST fork choice, FFG justification and finality, the epoch committee
  and proposer schedule, the RANDAO beacon, staking (deposit, exit, withdrawal)
  and slashing, the state root, and the tokenomics-V4 emission and supply cap.
- The Genesis-4 node (`crates/bloch-pos-node`): block and attestation
  handling, the P2P and RPC surfaces, keystore handling, and cold start.
- Hybrid Falcon ‖ ML-DSA signatures and serialization/deserialization on any
  consensus path.
- **Genesis-3** (`legacy/genesis3-node/`, `crates/bloch-crypto`,
  `crates/bloch-euvm`) only where a finding changes the carried-over ledger
  Genesis-4 opened from — the balance set at height 39,918. GhostDAG ordering,
  SHA-256d and AuxPoW verification, difficulty retargeting and reorg on a
  chain that has stopped producing are historical, not live.
- The Coherence privacy layer (shielded pool, spend proofs). Network-layer
  metadata privacy (Dandelion++) is **roadmap, not shipped** — the code
  present in the tree is dead/unwired (see the Round-3 remediation audit's
  legacy-network findings), so a report against "Dandelion++" as a live
  protection is out of scope until it is actually wired into a transport
  path; a report that the *absence* of Dandelion++ makes a specific
  deanonymization attack cheaper is in scope under the privacy-findings
  bullet below.
- Node, wallet, keystore, RPC, and the attestation layer (L1–L3).
- **Privacy findings are explicitly in scope** — deanonymization, metadata leaks,
  address linkability, and any way the protocol could surveil or link users (it
  is designed not to; see the privacy-first positioning in the roadmap).

## Out of scope

- The **known** stake-concentration exposure — the founder holding roughly 94%
  of a stakeable supply, and having allocated the genesis validator cohort, is
  a documented, disclosed gap, not a bug (a concrete exploit beyond it — e.g.
  a way to justify or finalise without an honest two-thirds, or to attest
  without being in the committee — is in scope).
- The retired Genesis-3 chain's low-hashrate exposure. It was real while the
  chain was live and it is now moot: nothing mines it, and the canonical
  artifact is the signed snapshot at height 39,918, not a chain anyone is
  defending.
- Gaps already documented as unaudited / claim-gated in the threat model (the
  documented gap is not a new finding — but a concrete exploit of it is).
- Denial of service requiring implausible resources; issues only in third-party
  infrastructure.

## Development security practices

- **Supply chain:** `Cargo.lock` committed; the PQ-crypto fork is vendored
  (`crates/pqcrypto-internals`) so the workspace is self-contained. `cargo deny
  check` (`deny.toml`) enforces permissive licenses (no copyleft), no external
  git deps, and RUSTSEC advisories — run in CI.
- **Secret scanning:** `gitleaks` runs as a **blocking** CI job (fixed
  2026-09-04, finding I-H4 — it and `osv-scanner` used to `allow_failure`/
  `continue-on-error` and silently skip when the binary was missing on a
  runner, going green having scanned nothing; both now install a pinned
  binary via `scripts/ci-install-scanner.sh` and fail the pipeline on a
  hit, held to that posture by `scripts/check-scanners-blocking.py`).
  Rotate any credential that ever touches a shell or history regardless —
  a blocking scanner catches what gets committed going forward, not
  history that predates it.
- **Reproducible builds:** the node image is byte-reproducible (L1); releases
  should be signed. The OS images (Postern OS) are reproducible by construction.
- **Least privilege:** the node runs hardened (L2 container hardening / the NixOS
  `services.bloch` systemd sandbox); keystores are encrypted (Argon2 + AEAD).
- **Attestable integrity:** the immutable OS profile binds a dm-verity roothash
  into `getattestation`, verifiable against the reproducible image (L1→L3).
- **Fuzzing:** coverage-guided fuzz targets (`fuzz/`, cargo-fuzz) for the
  untrusted-input parsers (`Block::from_bitcoin_bytes`,
  `Transaction::from_stratum_bytes`); new parsers of untrusted bytes get a target.

## No claims before their gate

We do not claim any security or privacy property before its audit gate clears
(S1/S2 for security, P2/C4 for privacy). No "100% private" claim, ever, before an
external audit.

## Guidance for integrators: when to treat a block as settled

An integrator (exchange, bridge, custody provider, another chain's light
client) asking "when is a Genesis-4 transaction safe to credit" should use
**finality plus a margin, confirmed by more than one independently-operated
node**, not raw confirmation depth:

- Wait for the transaction's block to be **finalized** (Casper-style FFG;
  `finalized_epoch` in `getchaininfo`/the RPC surface), not merely included —
  an included-but-unfinalized block can still be reorganized under this
  fork-choice rule.
- Then wait roughly **30 further, uninterrupted epochs** before treating a
  large or irreversible credit as final. This margin exists because the
  finality ratchet itself is new and its edge cases are still being found in
  audit (the Round-3 remediation audit's M-1 finding describes a scenario
  where the engine's own downward finality ratchet can refuse a legitimate
  rewind and silently partition a node from the honest branch) — 30 epochs
  of continued, uninterrupted agreement between independently-operated nodes
  is meant to be well past the window in which that class of defect would
  surface as a visible disagreement, not a guarantee derived from a formal
  bound.
- **Query at least two nodes you do not operate as a single point of
  observation** — i.e., nodes that do not share an operator, a keystore, or
  (ideally) a network path — and require them to agree on the same
  finalized root at the same finalized epoch before treating the answer as
  authoritative. A single node's `getchaininfo` answer proves only that one
  node's view, and the whole reason two-node cross-checks appear repeatedly
  in this repository's own runbooks (`deploy/bootnodes/verify-bootnodes.sh`'s
  fork check, `deploy/FLAG-DAY-EPOCH-2700.md`'s verification section) is that
  a single node's self-report is not independent evidence of anything.
- Re-read the current Round-3 (or later) remediation audit before relying on
  any specific consensus gate — several fixes exist in code but are not yet
  armed on the live chain (§4.2 of that audit); a defect a report names may
  be "fixed" in a sense that does not yet apply to blocks being produced
  today.
