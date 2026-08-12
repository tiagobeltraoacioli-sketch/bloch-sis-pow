# Bloch-SIS Protocol (BLOCH) — Security Self-Assessment

> **Genesis-3-era document — sealed 2026-08-12.** Bloch's proof-of-work
> chain halts by consensus rule at the terminal height (50,000) and
> Genesis-4 relaunches as proof of stake; the ownerless thesis was
> retracted (`docs/adr/ADR-036-retract-ownerless-adopt-foundation.md`).
>
> §4 (cryptographic primitives), §7 (memory safety) and §8 (wallet security)
> stand. The executive comparison table, §3 (decentralization) and §5
> (consensus protocol) are hashrate-framed and describe a chain that is
> ending. This document also predates Genesis-2 and Genesis-3.

**Document version:** 1.0
**Last updated:** 2026-04-19
**Scope:** Bloch-SIS Protocol (rebrand from GroundState `v0.5.9-rc1`, design preserved) compared against Bitcoin Core `29.x` (2026)
**Status:** Self-assessment by the maintainers. **Not an external audit.**

---

## Why this document exists

We are frequently asked "how secure is Bloch-SIS Protocol?" — sometimes by users
weighing whether to hold BLOCH, sometimes by developers considering whether
to build on it. The honest answer requires benchmarking against something
mature. Bitcoin is the natural yardstick: 16 years of adversarial life,
the largest economic incentive ever assembled to find bugs in its code,
and the reference implementation every other chain is compared to.

This document is deliberately structured to make Bloch-SIS Protocol look bad
where it is worse than Bitcoin, because lying by omission is how crypto
projects get their users hurt. It is also structured to show where
Bloch-SIS Protocol is genuinely better, because the project exists for a reason —
post-quantum security is a real concern.

**If you take one thing away from this document:** Bloch-SIS Protocol is a young
project (less than 1 year of mainnet; one developer; zero external audits)
doing something new (post-quantum BlockDAG). Bitcoin is a mature project
(16 years; hundreds of contributors; one recently-completed external audit
that found nothing serious) doing something deeply understood (linear PoW
chain). If all you care about is "is my money safe today," Bitcoin is the
better answer. If you care about "will my money be safe in 20 years when
someone builds a large quantum computer," the answer is much less clear —
and that gap is the reason this project exists.

---

## Executive summary

| Property | Bitcoin | BLOCH | Winner |
|---|---|---|---|
| **Age in production** | 16 years (Jan 2009) | < 1 year | Bitcoin (massively) |
| **External audits** | 1 major audit (Quarkslab 2025, 100 man-days, found 2 low + 13 informational) | 0 | Bitcoin |
| **Independent implementations** | Bitcoin Core, btcd, bcoin, libbitcoin, Bitcoin Knots | 1 (Rust) | Bitcoin |
| **Full-time contributors** | Dozens, paid by Brink / Chaincode / Spiral | 1 | Bitcoin |
| **Lines of consensus-critical code** | ~50,000 LOC (C++) | ~4,800 LOC (Rust) | — (smaller = smaller attack surface but also less battle-tested) |
| **Network hashrate (Apr 2026)** | ~1 ZH/s (10^21 H/s) | ~1–40 MH/s (10^6–10^7 H/s) | Bitcoin by 14–15 orders of magnitude |
| **Cost of 51% attack** | Billions of USD | Dollars (laptop CPU) | Bitcoin |
| **Independent node count** | ~20,000 reachable | ~5 (1 seed + ~4 workers, all operated by the founder) | Bitcoin |
| **Memory-safe language** | No (C++) | Yes (Rust, zero `unsafe`) | BLOCH |
| **Signature scheme** | ECDSA (secp256k1) | ML-DSA-65 (FIPS 204) | BLOCH (for quantum) |
| **Transport encryption** | BIP324 (x25519, classical) | Kyber768 hybrid (PQ) | BLOCH |
| **Address hashing** | RIPEMD160(SHA-256) | SHA3-256 truncated | BLOCH (marginally) |
| **Consensus protocol** | Nakamoto PoW (linear) | GhostDAG-Q / PHANTOM, k=10 | — (different tradeoffs) |
| **Transaction finality** | Probabilistic (6 confirmations ≈ 60 min) | Probabilistic + checkpoint | Bitcoin (better-understood) |
| **Wallet recovery from seed** | BIP39 works correctly | Currently broken (Sprint S pending) | Bitcoin |
| **Formal specification** | Scattered in BIPs, de facto "the code" | One README section | Bitcoin |
| **Bug bounty program** | Discretionary rewards | Tracked under Sprint 13 Labs operationalization roadmap (post-mainnet) | — |

A single table does not do this justice. The sections below go through
each category in depth.

---

## 1. Maturity

### 1.1 Bitcoin

- **Launched:** January 3, 2009
- **Mainnet uptime:** ~16 years with essentially no major outages (one
  emergency hard fork in March 2013 at block 225430 due to a database
  compatibility bug between v0.7 and v0.8 — resolved within 6 hours).
- **Catastrophic bug count (consensus-invalidating in the wild):** 2 —
  the March 2013 accidental fork, and the August 2010 "value overflow
  incident" (CVE-2010-5139) where a bug allowed a transaction creating
  184 billion BTC. Both were fixed, both within 24 hours. Neither
  recurred.
- **Commits to Bitcoin Core:** ~46,000 over 16 years
- **Roughly when a bug would reach users:** weeks to months of review by
  multiple Core contributors before merge; release candidate stage; then
  voluntary operator upgrades over months.

### 1.2 Bloch-SIS Protocol

- **Launched:** mainnet live ~2026-04, less than a month of continuous
  uptime at the time of writing
- **Genesis block:** recent; chain was reset once during development
  after catching a treasury configuration bug (see `SPRINTS.md` Sprint M
  history)
- **Catastrophic bug count in production:** none *yet*, which reflects the
  size of the attack surface (almost no one is looking) as much as the
  quality of the code.
- **Commits:** ~100s, all by a single author
- **Release cycle:** every few days during active development

**Honest framing:** Bloch-SIS Protocol has not been alive long enough for its
unknown unknowns to have surfaced. Any chain that has not been attacked
for years should be treated as "probably secure against known attacks,
but the attack it will die of has probably not been thought of yet."

---

## 2. Independent review

### 2.1 Bitcoin

- **First external third-party audit:** Quarkslab, commissioned by
  Brink via OSTIF, completed in September [2025], the audit totaled 100 man-days of work conducted by three Quarkslab engineers, with technical support from Brink and Bitcoin research and development firm Chaincode Labs. Scope was the P2P layer, mempool, chain
  management, consensus validation, and transaction handling.
- **Findings:** no critical, high, or medium-severity issues. The auditors identified two low-severity issues and provided 13 informational recommendations.
- **Ongoing scrutiny:** continuous public review on GitHub, IRC, bitcoin-dev
  mailing list; Fuzzamoto fuzzing infrastructure; peer scoring research
  published at academic venues.
- **CVE history:** dozens of public CVEs over 16 years, mostly DoS vectors,
  a handful of consensus-impacting bugs, all responsibly disclosed and
  patched. A sample from the CVE database includes Bitcoin Core before 22.0 has a CAddrMan nIdCount integer overflow, Bitcoin Core before 24.0.1 allows remote attackers to cause a denial of service (daemon crash) via a flood of low-difficulty header chains, and similar DoS findings.

### 2.2 Bloch-SIS Protocol

- **External audits:** zero. This document is an internal self-assessment.
- **Pre-audit readiness:** we maintain a `tests/security_audit.rs` file
  enumerating 8 documented vulnerability classes (VULN-01 through VULN-08);
  6 of these are now marked FIXED in code, 1 is partial, 1 is open
  (unauthenticated RPC). This is internal test coverage, not external
  validation.
- **Public attack history:** none. Also: no known white-hat researchers
  currently looking at the code. The absence of reported bugs does not
  imply absence of bugs.
- **Known unresolved issues** (from `SPRINTS.md` backlog):
  - HD wallet generates random keypairs ignoring the mnemonic (Sprint T)
  - ML-DSA-65 seed derivation is a stub (Sprint S)
  - Mempool validation diverges from block validation at 4 entry points
    (Sprint N-full)
  - 470.4 GRND supply-accounting gap on Era 1 GroundState chain (likely empty-script miner outputs,
    Sprint O)
  - RPC has no authentication layer when `--rpc-public` (Sprint M)

**Honest framing:** a single external audit comparable to Quarkslab's
Bitcoin Core engagement would cost on the order of $100,000–$250,000 USD
at today's rates and take 2–4 months. We have not commissioned one. If
you operate a node expecting the codebase to have received equivalent
scrutiny, you will be disappointed.

---

## 3. Decentralization

### 3.1 Bitcoin

- **Reachable nodes** (public, accepting inbound connections): ~20,000
  globally, running multiple implementations
- **Mining hashrate:** Bitcoin network hashrate: 993 EH/s, distributed across many pools and tens of thousands of ASIC miners
- **Hashrate concentration:** the top 3 pools typically hold 50–60% of
  hashrate, which is a real concern the Bitcoin community discusses often
- **Geographic distribution:** nodes on every continent, pools in US,
  China, Russia, Europe, South America
- **Cost of a 51% attack:** acquiring enough ASIC capacity would cost
  multiple billions of USD and be publicly visible

### 3.2 Bloch-SIS Protocol

- **Reachable nodes:** 1 seed (Njalla VPS) + ~5 Akash workers, all
  currently controlled by the founder. Zero independent third-party nodes.
- **Hashrate:** the seed mines ~1 MH/s on a single VPS core. Workers
  contribute another ~5–40 MH/s.
- **Implementations:** one (Rust). No alternative client.
- **Geographic distribution:** seed in one datacenter; workers on one
  Akash provider.
- **Cost of a 51% attack today:** renting enough CPU on a commodity cloud
  to match ~40 MH/s is negligible. A laptop CPU mining SHA-256 in software
  does ~1 MH/s; a modest GPU mining rig would dwarf the entire network.
  Buying a single second-hand SHA-256 ASIC would make the attacker the
  dominant miner for the cost of a used car.

**Honest framing:** Bloch-SIS Protocol is not decentralized. It is a single-operator
network running a protocol that could become decentralized if adopted, in
the same sense Bitcoin was not decentralized in 2009 when Satoshi and Hal
Finney mined most of the early blocks. The project's design is
decentralization-compatible, but the deployment reality today is a
one-person testnet with real money in it. Users should treat it
accordingly.

This gap is **the single largest security difference** between Bloch-SIS Protocol
and Bitcoin. It dwarfs every technical advantage listed below.

---

## 4. Cryptographic primitives

This is where Bloch-SIS Protocol has genuine structural advantages — at the cost
of being less battle-tested.

### 4.1 Digital signatures

**Bitcoin:** ECDSA over secp256k1. Classical security ~128 bits.
**Completely broken** by a sufficiently large quantum computer running
Shor's algorithm in polynomial time. Bitcoin, like most major blockchains, relies on elliptic curve digital signatures, which are secure against classical attacks but theoretically vulnerable to Shor's algorithm on a future large-scale quantum computer. If elliptic curve cryptography were broken, private keys could be derived directly from exposed public keys — not through brute-force guessing, which would remain infeasible, but through a mathematical shortcut enabled by quantum algorithms.

Bitcoin has mitigations: unused P2PKH addresses do not reveal their
public key on chain, so only *spent* addresses are at immediate risk. But
this is a weak mitigation — the first time any address spends, its pubkey
goes public, and an attacker with Shor can then sign arbitrary transactions
from it.

**Bloch-SIS Protocol:** ML-DSA-65 (FIPS 204, formerly CRYSTALS-Dilithium). The
security reduction is to the Module-LWE problem, which has no known
polynomial-time attack (classical or quantum). NIST finalized the standard
in August 2024.

Costs: ML-DSA-65 signatures are 3,309 bytes vs. 64–72 bytes for ECDSA.
Public keys are 1,952 bytes vs. 33–65 bytes. This blows up block size per
transaction by roughly 30×. Bloch-SIS Protocol chose a higher MAX_BLOCK_SIZE
(1 MB, same as Bitcoin) combined with a dust threshold to discourage spam,
but the throughput per-KB of chain data is lower.

**Verdict:** Bloch-SIS Protocol wins on quantum resistance. The tradeoff is
signature size and relative implementation youth — ML-DSA has been around
for ~8 years, ECDSA for ~35. Implementation bugs in new crypto are a real
risk.

### 4.2 Transport layer

**Bitcoin:** BIP324 (v2 P2P transport protocol, deployed in Bitcoin Core
26.0) uses Elligator Swift + x25519 for key agreement and ChaCha20-Poly1305
for AEAD. All classical primitives. An attacker recording Bitcoin P2P
traffic today can decrypt it retroactively once they have a quantum
computer (harvest-now/decrypt-later). Before BIP324, Bitcoin traffic
was cleartext.

**Bloch-SIS Protocol (v0.5.9):** Kyber768 (ML-KEM, FIPS 203) for session key
establishment, Ed25519 for peer identity, ChaCha20-Poly1305 for AEAD.
Hybrid PQ — confidentiality is PQ-resistant, authentication is classical.

**Verdict:** Bloch-SIS Protocol wins decisively on confidentiality. The
harvest-now/decrypt-later scenario is a real concern for any traffic that
reveals economic information (who talks to whom, transaction patterns,
node topology). Bitcoin's BIP324 is a significant improvement over clear
but is not PQ-secure.

### 4.3 Address hashing

**Bitcoin:** RIPEMD160(SHA-256(pubkey)) for P2PKH; SHA-256 for witness
scripts in P2WPKH/P2TR. 160-bit address space.

**Bloch-SIS Protocol:** SHA3-256(pubkey) truncated to 20 bytes. 160-bit address
space.

Under a classical attacker, both have 2^80 collision resistance (birthday
bound) and 2^160 preimage resistance. Under a quantum attacker, Grover
reduces preimage to 2^80 queries — still astronomical but less
comfortable.

**Verdict:** roughly equivalent. SHA3 is a slightly more modern design
(Keccak, post-competition) and has no length-extension weakness, but this
matters zero for address hashing. Essentially a tie.

### 4.4 Proof-of-work

Both chains use SHA-256. Identical primitive, identical quantum resistance
profile (Grover halves the effective security, which for PoW means double
the hashrate — still not a practical attack).

---

## 5. Consensus protocol

### 5.1 Bitcoin — Nakamoto PoW

- Longest-chain rule
- 10 minute target block time
- Finality: probabilistic; 6 confirmations ≈ 1 hour ≈ ~60% of typical
  reorg risk eliminated. Academic literature has studied reorg depth
  distributions extensively.
- Selfish mining attack (Eyal & Sirer 2014): proven possible in theory,
  observed at small scale; economically disincentivized at scale.
- Block-withholding and empty-block attacks also well-studied.

### 5.2 Bloch-SIS Protocol — GhostDAG-Q (PHANTOM k=10)

- Based on Sompolinsky-Wyborski-Zohar (2021) "PHANTOM GHOSTDAG: A Scalable
  Generalization of Nakamoto Consensus"
- 150 second target block time — 4× faster than Bitcoin (V2 per ADR-006 and ADR-028; the V1 design specified 10s / 60× faster, superseded before mainnet)
- Ordering rule: selected parent = argmax(blue_work); blue set computed
  with k=10 anticone constraint
- Reference implementation cross-checked against `kaspanet/rusty-kaspa`
- Selfish mining resistance: GhostDAG is provably more resistant than
  Nakamoto because blocks mined in parallel by honest miners still
  contribute to `blue_work`
- Finality: probabilistic, with a checkpoint mechanism at a depth stored
  in the `finalized_height` meta key that rejects reorgs below it

**Verdict:** GhostDAG is a **newer** protocol than Nakamoto and has had
less academic scrutiny at adversarial scale. The core safety proof is
published and peer-reviewed, but the engineering realities (timing
attacks, memory-bounded parent selection, DAG topology manipulation) are
less studied than Bitcoin's counterparts.

**Specific unknowns in our implementation:**
- Anticone computation cost under adversarial DAG topologies has not
  been stress-tested
- Blue-set recomputation on reorg has not been fuzzed
- Parent-count bounds are implicit (via MAX_BLOCK_SIZE) rather than
  explicit

A real external audit would prioritize these.

---

## 6. Specification and governance

### 6.1 Bitcoin

- **Specification:** de facto "Bitcoin Core code is the spec." Formal
  properties are documented in BIPs (Bitcoin Improvement Proposals).
- **Consensus changes:** soft fork via BIP9 / BIP8 activation mechanisms
  with miner signaling and user activated fallback (UASF). Hard forks
  are extremely controversial and rare.
- **Governance:** rough consensus among maintainers + mining/holder
  pressure. No on-chain governance. Slow, conservative, and stable.

### 6.2 Bloch-SIS Protocol

- **Specification:** README + SPRINTS.md + THREAT_MODEL.md + source code.
  No formal grammar or state-machine specification.
- **Consensus changes:** ad hoc at the moment — the entire network is
  operated by one person, so "coordination" means recompiling. Hard forks
  are planned (Sprint J) but the activation mechanism is not yet
  implemented.
- **Governance:** benevolent dictator (the founder) until community
  emerges.

**Verdict:** Bitcoin's governance is a feature; Bloch-SIS Protocol's is a
phase. For a project of Bloch-SIS Protocol's maturity, having a single decision-
maker is efficient. It also concentrates risk.

---

## 7. Memory safety and implementation language

### 7.1 Bitcoin

- C++. Several memory-safety-related CVEs historically (e.g., integer
  overflows, use-after-free in libevent deps, etc.).
- Bitcoin Core 29 has ~200,000 lines of C++ and more than 1,200 tests.
- Memory-safety practice is high-discipline code review, fuzzing, and
  sanitizers (ASan, UBSan), not the language.

### 7.2 Bloch-SIS Protocol

- Rust 2021 edition, ~4,800 LOC in safety-critical modules
- Zero `unsafe` blocks in our own code (verified by `grep -r "unsafe" src/`
  returning zero hits)
- Transitive `unsafe` via `pqcrypto-mldsa` and `pqcrypto-kyber` (which FFI
  to PQClean C reference implementations)
- ~94 tests organized per sprint

**Verdict:** Rust rules out a large class of bugs (buffer overflow, use-
after-free, data race) by construction. C++ needs discipline and tooling
to achieve the same. This is a real Bloch-SIS Protocol advantage.

Caveat: the FFI boundary to PQClean is C, and the soundness of the Rust
wrappers around it has not been independently verified. A future audit
should look here.

---

## 8. Wallet security

### 8.1 Bitcoin

- BIP39 mnemonic → BIP32 HD derivation, extensively deployed, works
  correctly everywhere.
- Hardware wallet ecosystem (Trezor, Ledger, ColdCard, Foundation) well
  established.
- Multisig (2-of-3, 3-of-5, etc.) built into standard wallet software
  and interoperates across implementations.
- Decades of UX learning about phrase backup, steel plates, Shamir
  sharing, etc.

### 8.2 Bloch-SIS Protocol

- BIP39 mnemonic generation works.
- **BIP32-style HD derivation does not work.** `src/hd_wallet/mod.rs`
  calls the random keypair generator instead of deriving from the
  mnemonic. The `master_key` derived from the seed is never used.
  (Sprint T.)
- **Seed-based recovery does not work.** Restoring from a 24-word phrase
  produces a fresh random wallet, not the original. Users must back up
  the encrypted wallet file itself. (Sprint S.)
- No hardware wallet support. No multisig.

**Verdict:** Bloch-SIS Protocol wallet is significantly less mature than Bitcoin.
If you use Bloch-SIS Protocol today:

1. Back up the wallet file (`~/.bloch/wallet.json` or wherever), not just
   the mnemonic.
2. Don't trust the phrase alone.
3. Keystore files are properly encrypted (AES-256-GCM + Argon2id with
   64 MiB memory cost), so a stolen file without password is not
   immediately fatal — but a weak password is.

This is the area where a careful Bloch-SIS Protocol user can lose funds today
with no adversary involved, just by trusting the mnemonic.

---

## 9. Operational posture

### 9.1 Known operational hazards on Bitcoin

- Weak passwords on wallet encryption
- Phishing / fake wallet software
- Cloud wallet custody failures (exchanges)
- Transaction malleability (fixed by segwit)
- Fee estimation failures leaving txs stuck

### 9.2 Known operational hazards on Bloch-SIS Protocol

All of the above, plus:

- **RPC public by default in production deployments.** The seed node runs
  with `--rpc-public` for explorer access and has no rate limiting or
  authentication. A misuse of this flag on a node holding keys would be
  very bad. Operators must firewall.
- **Workers running without `--miner-address`** produce unspendable
  coinbase outputs (the suspected root of the Era 1 470 GRND supply gap; BLOCH genesis is regenerated cleanly so no equivalent gap).
  Enforcement is a pending fix (Sprint O).
- **Treasury and founder keys are in a single keystore file each**, not
  multisig. Compromise of either is catastrophic. Sprint M adds a startup
  integrity check.
- **No CI-enforced version discipline.** Cargo.toml, git tags, and
  deployed Docker image versions have drifted in the past. Sprint R
  tightens this.
- **One Docker image, built on a developer machine.** Not reproducible
  across CI. A supply-chain attack on the build host is not currently
  detectable.

---

## 10. What a user should conclude

### 10.1 If you are evaluating Bloch-SIS Protocol as a store of value

Do not put meaningful money into Bloch-SIS Protocol today. The network is too
young, too centralized, and too unaudited. Funds held here are more at
risk from mundane failures (operator mistake, software bug that escapes
our own tests, compromised build pipeline) than from any quantum threat
Bloch-SIS Protocol is designed to resist.

### 10.2 If you are evaluating Bloch-SIS Protocol as a technical project

The technical choices are defensible and the implementation quality is
better than most Layer 1 projects at similar age (Rust, zero unsafe,
organized test suite, honest internal documentation of known gaps).
The post-quantum thesis is serious and the Kyber-hybrid transport is
one of the first production deployments of NIST-standardized PQ
cryptography in a blockchain P2P layer.

The delta from "interesting technical project" to "production-grade
cryptosystem" is measured in multiple person-years of hardening, external
audits, and adversarial scrutiny. None of that has happened yet.

### 10.3 If you are considering running a node

Yes — we need more nodes. Running a node improves decentralization. Do
not expose RPC publicly without a reverse proxy. Do not mine without
`--miner-address`. Do not store large amounts in the wallet.

### 10.4 If you are a security researcher

Please. See `SECURITY.md` for disclosure process. The Era 1 BOUNTIES.md is deferred to Sprint 13 Labs operationalization roadmap;
reward tiers. The areas most likely to yield findings are:

- GhostDAG implementation edge cases under adversarial DAG topology
- Mempool / block validation divergence (Sprint N-full)
- RPC surface with `--rpc-public` (unauthenticated)
- PQClean FFI boundary in `pqcrypto-*` wrappers
- Kyber handshake transcript binding

---

## 11. What we will do about it

Ranked roadmap items that reduce the gap with Bitcoin:

1. **Sprint S** — fix ML-DSA-65 seed derivation so BIP39 actually works
   (4–6h)
2. **Sprint T** — rename hd_wallet to multi_key_wallet and stop promising
   seed recovery that doesn't work (3–4h). Later, option A: implement real
   HD derivation (12–16h)
3. **Sprint O** (Era 1 reference) — diagnosed and tracked the 470 GRND supply-accounting gap on the Era 1 GroundState chain. Under BLOCH the genesis is regenerated, so no equivalent gap exists at launch; the underlying `--miner-address` enforcement requirement carries forward
   (4–6h)
4. **Sprint N-full** — unify transaction validation across mempool, P2P,
   RPC, and block-acceptance paths (6–8h)
5. **Sprint M** — treasury keystore startup integrity check (2–3h)
6. **Sprint R** — version discipline, CI checks, reproducible builds
   (6–10h)
7. **Sprint D** — Prometheus metrics and structured logging so we can
   notice problems in production (8–12h)
8. **Engage an external audit firm** — realistic target: after Sprint E
   (consensus refactor) ships, budget permitting. Ballpark estimate
   from comparable engagements: $80k–$200k for a 2-month P2P + consensus
   review.
9. **Grow independent node operators** — at least three independent
   parties running workers, with deployment documentation sufficient
   that a new operator can join the network in under an hour.

See `SPRINTS.md` for full ordering.

---

## 12. Comparison table — condensed

For readers who skipped to the end.

**Where Bloch-SIS Protocol is clearly better than Bitcoin:**
- Post-quantum signatures
- Post-quantum transport confidentiality
- Memory-safe implementation language
- Smaller consensus-critical codebase (smaller attack surface)

**Where Bloch-SIS Protocol is clearly worse than Bitcoin:**
- Age and battle-testing (16 years vs <1 year)
- External audits (1 major vs 0)
- Implementation diversity (5+ clients vs 1)
- Hashrate and 51%-attack cost (~10^14 to 10^15 times cheaper to attack)
- Decentralization (~20,000 reachable nodes vs ~5, all operated by us)
- Wallet recovery (BIP39 works vs currently broken)
- Formal specification (BIPs + code vs code only)
- Hardware wallet and multisig ecosystem (extensive vs nonexistent)
- Community governance (rough consensus vs single maintainer)

**Where it is roughly a wash:**
- Hash function choice (SHA-256 vs SHA-256/SHA3)
- Operational hazards common to any PoW chain
- Mempool DoS defenses (both have them, both have edge cases)

---

## 13. Change log

- **1.0 (2026-04-19):** Initial version. Compares against Bitcoin Core 29
  post-Quarkslab audit.

---

*This is a living document. As sprints ship and audits happen, the
Bloch-SIS Protocol side of the comparison will improve. If it does not, this
document should be updated to reflect stagnation honestly.*

**2026-04-25 — Bloch-SIS Protocol rebrand (Phase 3.e.8).** This document
was originally the GroundState v0.5.9-rc1 security self-assessment.
As part of the April 2026 rebrand, identifiers, subsection headers,
comparison-table cells, and wallet config path were updated to
Bloch-SIS Protocol (BLOCH). The methodology (Bitcoin vs BLOCH section-
by-section comparison), all numeric facts (Kyber768 PQ key sizes,
ML-DSA-65 signature sizes, GhostDAG-Q k=10 parameters, MAX_BLOCK_SIZE
ratios), and the honest framing of comparative immaturity (single-
operator, no third-party audit, ~30-day-old codebase) are preserved
unchanged. Era 1 historical artifacts (470.4 GRND supply-accounting
gap from Sprint O on Era 1 chain, BOUNTIES.md program) are preserved
as factual record with explicit "Era 1" qualification, and forward
references are redirected to the Sprint 13 Labs operationalization
roadmap. The dangling links to BOUNTIES.md (deleted in Phase 3.d.2)
were replaced. The "If you take one thing away" framing — that BLOCH
is a young, incompletely-reviewed, single-operator project that
should not yet hold meaningful value — applies at least as strongly
under BLOCH as under GroundState; the rebrand does not change
maturity status.
