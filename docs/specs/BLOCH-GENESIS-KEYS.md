<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# Bloch — Genesis-4 key and address requirements

```
Document:   BLOCH-GENESIS-KEYS
Status:     DRAFT — requirements and custody plan; NO production key exists yet
Created:    2026-08-11
Relates to: BLOCH-TOKENOMICS-V4.md (§1, §3.3, §3.3.1, §7),
            BLOCH-POS-SHA3-LATTICE-MIGRATION.md (§6.2 hybrid suite, §6.3 RANDAO),
            tools/genesis4-ceremony/ (the consumer of everything listed here)
```

This document states **what key material must exist before the Genesis-4
ceremony can run, in what order it should come into existence, and under what
custody** — and nothing else. It deliberately contains no key, no address, no
seed, and no fixture that could be mistaken for one.

**Rule zero: no production key may be generated inside an AI-agent session,
a shared terminal, a CI job, or any machine whose transcript, shell history,
or memory is observable by more than the custodian.** A key that has ever
existed in an observable context is compromised by definition — there is no
way to prove a transcript was not retained. Every keypair below is generated
by a human running the pinned keygen tool on an air-gapped machine. Agents
and tooling (including the ceremony tool itself) only ever touch **public**
halves: address hashes, raw public keys, RANDAO commitments.

---

## 1. Inventory — what the ceremony consumes

The ceremony (`tools/genesis4-ceremony`) takes public data only. Working
backwards from its inputs, this is everything that must exist:

| # | Artifact | Count | Format the ceremony sees | Backed by |
|---|---|---:|---|---|
| 1 | Bucket addresses: founder grant, VC, team, marketing, liquidity | 5 | 20-byte address hash (40 hex), one per bucket, mutually distinct, absent from the carryover set | 5 hybrid keypairs, cold |
| 2 | Genesis-cohort validator keys | 64 (floor; the launch plan is exactly 64) | raw 3,745-byte hybrid public key per validator (no suite envelope) | 64 hybrid keypairs, warm/hot |
| 3 | RANDAO commitments | 64 (one per validator) | 32-byte chain head `c_0` | 64 secret 32-byte seeds, hot beside each validator |
| 4 | Withdrawal addresses for the cohort | 1–64 (see §3.4) | 32-byte address (`staking::Address`) per validator | 1–64 hybrid keypairs, cold |
| 5 | Carryover holder addresses | 448,337 UTXOs / 15 addresses | already fixed by the signed artifact | the holders' **existing Genesis-3 keys** — nothing new is generated |

So the ceremony requires, at minimum, **70 new hybrid keypairs** (5 bucket +
64 validator + 1 shared withdrawal) and **64 RANDAO seeds**; at maximum 133
keypairs if every validator gets its own withdrawal key. Row 5 requires
nothing: carryover balances cross by address hash, and the keys that spend
them are the same keys that spent them on Genesis-3. Their custody is out of
scope here, with one exception noted in §5.1.

### What each address is for

- **Founder grant (2,100,000,000 BLCH)** — nothing spendable before year 10,
  fully vested year 50. The key signs nothing for a decade.
- **VC (2,100,000,000)** — cliffed 12 months, fully vested year 3.
- **Team (2,100,000,000)** — cliffed 18 months, fully vested year 4.5.
- **Marketing (840,000,000)** — 25% spendable at slot 0, rest over 24 months.
  The one bucket key that must sign *early and routinely*.
- **Liquidity (1,050,000,000 minus bonded cohort stake)** — fully liquid at
  slot 0; deploys to order books and funds the cohort (§3.3.1).
- **Validator keys** — hot consensus keys: propose blocks, attest, sign
  exits. Compromise loses at most the slashable bonded stake, never the
  principal (that returns only to the withdrawal address, fixed at genesis).
- **Withdrawal address(es)** — where cohort principal returns on exit. Cold;
  never needed online until an exit completes.

---

## 2. The cryptography these keys are made of

Every signing key is one pair of the **hybrid suite ML-DSA-65 ‖ Falcon-1024**
— `generate_keypair` in `crates/bloch-crypto/src/crypto/mod.rs`. Public key
1,952 + 1,793 = 3,745 bytes raw (3,749 with the 4-byte suite envelope the
wallet tooling emits — the ceremony's cohort file wants it *stripped*);
secret key ≈ 6.3 KB. Both halves must sign; the AND rule means custody of a
key is custody of **both** lattice secrets, always together.

Each genesis validator additionally holds a **RANDAO secret seed**: 32 bytes,
from the OS RNG, expanded into an 8,192-step SHAKE-256 hash chain
(`crates/bloch-pos-committee/src/beacon.rs`). The published commitment `c_0`
is the head of the chain; each proposed slot reveals one preimage step. Two
custody consequences:

- the chain is **deterministically rebuildable from the seed**
  (`RandaoChain::generate`), so the backup artifact is the 32-byte seed, not
  the 256 KB chain;
- the seed must be **available to the validator process** (the chain is
  walked on a proposal schedule), so it is hot by construction. Losing it
  before the chain produces blocks is severe: a re-commit transaction needs a
  running chain, and a genesis validator that lost its seed cannot propose
  until one lands. If *all 64* seeds were lost at slot 0, the chain could
  never start. Seeds get the same backup discipline as keys.

Two facts worth stating because they cut opposite ways:

- **Cryptanalysis is not the threat.** The suite is already post-quantum;
  there is no harvest-now-break-later story against these signatures. The
  threat model is entirely *theft and loss of key material*.
- **`generate_keypair_from_seed` is version-pinned.** Seed-deterministic
  generation reproduces keys only under the exact `pqcrypto-mldsa` internals
  compiled at generation time (the compatibility warning in
  `crypto/mod.rs`). For custody horizons of 10–50 years, a seed alone is
  **not** a backup — see §4.3.

---

## 3. The hard problem, stated plainly

**No HSM on the market signs ML-DSA-65 ‖ Falcon-1024.** Hardware wallets
(Ledger, Trezor) are secp256k1/ed25519 devices and cannot ever custody these
keys. Early enterprise-HSM support for ML-DSA is appearing on vendor
roadmaps, but the hybrid needs *both* halves, and no HSM implements
Falcon-1024's Gaussian sampling. There is no partial option: a device that
signs one half signs nothing.

So every key in §1 is a **software key**, and the buckets they guard are
measured in billions of BLCH with lock horizons of 1 to 10 years before
first spend (founder: 10-year cliff, vesting until year 50). The custody
problem is therefore: *decade-scale cold storage of file-based secrets, with
no hardware root of trust, and no rotation* — the addresses are baked into
the genesis `state_root`, and an output's schedule follows its address
forever. A leaked bucket key cannot be rotated away; the only response would
be a visible, chain-splitting re-genesis. Custody has to be designed so that
leak-detection is irrelevant because leakage is structurally prevented.

What this buys instead of hardware:

### 3.1 Air-gap as the perimeter

All cold keys (5 bucket + withdrawal) are generated and stored on a machine
that has never had and will never have a network interface enabled —
provisioned from verified install media, keygen tool built reproducibly and
carried in on write-once media, outputs carried out the same way. **Only
public halves leave the air gap.** The machine (or its disk) is destroyed or
vaulted after the ceremony; signing at unlock time (§6) happens the same way.

### 3.2 Sharding instead of a vault key

Each cold secret (the ≈6.3 KB secret-key blob) is split k-of-n
(Shamir, e.g. 3-of-5) on the air-gapped machine. Shares go to geographically
separate, organisationally separate custodians in tamper-evident storage
(metal or archival media — a 10-year horizon outlives consumer flash). No
single custodian, site, or disaster reaches quorum. Reassembly happens only
on an air-gapped machine, only to sign, and the reassembled key is destroyed
after each signing session.

### 3.3 Bounding the hot keys

Validator keys and RANDAO seeds cannot be cold — they sign every proposed
block. The design already bounds what they are worth: stake principal
returns only to the cold withdrawal address, so a fully compromised
validator box loses at most its slashable stake and its RANDAO chain (a
one-bit-per-slot bias, bounded by `beacon.rs`). Hot-key custody is ordinary
server discipline: per-box keys, no key ever on more than its own box plus
one sealed offline backup, and an exit-and-replace runbook instead of any
attempt at "recovering" a suspect validator key.

### 3.4 Withdrawal fan-out

One shared withdrawal address for all 64 validators concentrates exit
proceeds into one key but keeps the cold-custody surface minimal; per-
validator withdrawal keys multiply the sharding work by 64 for little
benefit while the cohort has one beneficial owner (§3.3.1 — the founder
operates the whole set, and the spec is explicit that spreading records
across addresses must not be dressed up as decentralisation). **Decision:
one withdrawal address, custodied exactly like a bucket key, is the
default;** revisit only if cohort operation is ever split across operators.

---

## 4. Exposure window — when to generate

Genesis is roughly six months out. **A key that exists is a key that can
leak, and no key below is needed — by anyone, for anything — until the dates
given.** The chain does not need the private halves at genesis at all; it
needs hashes and public keys. Generating early buys nothing and spends
exposure time. Every month a bucket key exists before genesis is a month of
risk with zero return.

| When | What comes into existence | Why then and not earlier |
|---|---|---|
| Now → T−6 weeks | Nothing secret. Custody roles assigned, air-gap hardware procured, keygen runbook written, **throwaway** devnet keys used freely for rehearsal | Process can be rehearsed with worthless keys; only the process needs the lead time |
| T−6 → T−4 weeks | Full ceremony dry-run end-to-end with throwaway keys, including shard-and-reassemble drill and a signing drill on the air gap | The first reassembly of a real key must not be the first reassembly ever performed |
| T−2 weeks | 64 validator keypairs + 64 RANDAO seeds, generated on (or sealed-transferred to) the production validator boxes; cohort TSV assembled from their public halves | Hot keys need integration time with the validator clients; their value is bounded (§3.3), so two weeks of existence is an acceptable price for a tested launch |
| T−1 week → T−72 h | The 5 bucket keypairs and the withdrawal keypair, on the air gap; sharded immediately; **only the 6 address hashes leave the room** | These guard the billions. They are needed only as hashes at the ceremony and sign nothing for months (marketing) to a decade (founder). Latest responsible moment |
| T (ceremony) | Nothing. The ceremony consumes public data only and several operators reproduce the same `block_id` independently | By construction — `genesis4-ceremony` has no input field for a secret |

### 4.1 Recommendation, in one line

**Generate cold keys in the final week before the ceremony; hot keys two
weeks out; nothing before that but rehearsal with throwaways.**

### 4.2 What must never happen

- No production key or seed generated before its window, "to be safe".
- No production key on a networked or multi-user machine, ever — including
  the machines used to run the ceremony tool (they see public data only).
- No key generated by, or pasted into, an agent session — rule zero.
- No "test transaction" from a bucket address before genesis: there is no
  chain for it, and constructing one would mean reassembling a sharded key
  for nothing.

### 4.3 The 10-to-50-year backup problem

The founder bucket signs nothing until year 10 and is not fully vested until
year 50. For that horizon:

- **Back up the raw secret-key bytes, not a derivation seed.** Seed
  determinism is pinned to a `pqcrypto-mldsa` version (§2) that will not
  exist as a buildable artifact in 2036 without deliberate effort.
- Additionally archive, alongside the shards: the keygen binary, its full
  source tree, the toolchain version, and a VM image that runs it — so that
  *verification* (not regeneration) remains possible decades out.
- Schedule periodic custody audits (share presence and tamper-evidence
  checked, nothing reassembled) — yearly is enough.
- Write the succession plan down: who inherits shares, under what proof.
  A 40-year vest will outlive employments and possibly custodians.

---

## 5. Order of operations, end to end

1. **Custody design signed off** (this document, revised as needed) —
   custodians named, k-of-n chosen, sites chosen.
2. **Rehearsals** with throwaway keys until the runbook has no open steps.
3. **T−2 w:** validator keygen on production boxes → 64 raw pubkeys + 64
   `c_0` commitments exported; per-box sealed seed backups made.
4. **T−1 w:** air-gap session — 5 bucket + 1 withdrawal keypairs generated,
   sharded, shards dispersed; 6 address hashes exported on write-once media.
5. **Cohort TSV assembled** (public data: indices, pubkeys, commitments,
   stakes, withdrawal address) and published for review alongside the
   carryover artifact and its digest.
6. **Ceremony:** independent operators run `genesis4-ceremony` on the same
   published inputs and compare `state_root` / `cohort_root` / `block_id`.
   Agreement between independent parties is the evidence.
7. **Launch:** validator boxes start with their hot keys; every cold shard
   is already where it will sit for years.

### 5.1 The carryover exception worth naming

The largest value at stake on day one is not any bucket: it is the carried-
over founder balance (3,546,175,400 BLCH), liquid at slot 0, guarded by
**Genesis-3 keys that already exist today** — generated long ago, under
older procedures, on the old suite's tooling. Their exposure window is
already open and cannot be shortened by anything in this document. The only
available mitigation is to bring their storage up to §3.1–§3.2 discipline
*before* genesis makes them instantly spendable on the new chain, and that
work should be scheduled with the same seriousness as the ceremony itself.

---

## 6. After genesis

- **Marketing** signs within weeks of launch: its custody must support
  routine air-gapped signing sessions without eroding discipline.
- **Liquidity** signs at launch (order books, AMM seeding): same.
- **VC / team / founder** shards stay dispersed until their cliffs (months
  12 / 18 / 120). Each first-signing is a scheduled custody event with the
  same protocol as generation.
- **Validator exits** pay to the cold withdrawal address; the withdrawal key
  comes out of custody only after an exit completes, which is never a
  surprise event.

---

## 7. Summary table

| Key class | Count | Temperature | Guards | First signature | Custody |
|---|---:|---|---|---|---|
| Founder grant | 1 | cold, sharded | 2.1 B BLCH | year 10 | §3.1–§3.2, §4.3 |
| VC | 1 | cold, sharded | 2.1 B BLCH | month 12 | §3.1–§3.2 |
| Team | 1 | cold, sharded | 2.1 B BLCH | month 18 | §3.1–§3.2 |
| Marketing | 1 | cold, routine-signing | 840 M BLCH | launch | §3.1–§3.2, §6 |
| Liquidity | 1 | cold, routine-signing | 1.05 B − stake | launch | §3.1–§3.2, §6 |
| Withdrawal | 1 | cold, sharded | cohort principal | first exit | §3.4 |
| Validator | 64 | hot | slashable stake only | slot 0 | §3.3 |
| RANDAO seeds | 64 | hot | proposal liveness | slot 0 reveal | §2, §3.3 |
| G3 carryover | existing | varies | 3.77 B BLCH liquid | slot 0 | §5.1 — outside this doc, inside this risk |
