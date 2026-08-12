<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Public-release audit — BlochPOS → public Bloch repository

> **Redacted for publication.** Host addresses by role, SSH key filenames, Cloudflare
> account/zone/tunnel identifiers, per-box free disk and RAM, and firewall rule listings
> were replaced with placeholders. None of them were secrets — together they were an
> operational map of a three-box fleet, which is a different thing and not worth publishing.
> The technique is intact; the inventory is not. Operators substitute their own.


Measured 2026-08-12 against `integration/pos-modules` @ `d2df82e`, in an agent
worktree. **Nothing was published, nothing was pushed, no history was
rewritten.** This document is the preparation and the finding set; the
publication itself is the founder's call and is the last step.

Scope of the sweep: **all 392 commits reachable from `--all`**, not just HEAD —
every blob in `git rev-list --all`, matched by content, not by filename alone.

---

## 0. Headline: no secret was found — and the premise was wrong

**No private key, no seed phrase, no API token, and no password exists anywhere
in this repository's history.** Every one of these patterns returned zero hits
across all 392 revisions:

| Pattern class | Regex used | Hits |
|---|---|---|
| PEM/OpenSSH private keys | `BEGIN [A-Z ]*PRIVATE KEY`, `BEGIN OPENSSH` | **0** |
| GitLab / GitHub tokens | `glpat-…`, `ghp_…`, `github_pat_…` | **0** |
| AWS / Slack / OpenAI | `AKIA[0-9A-Z]{16}`, `xox[baprs]-…`, `sk-…` | **0** |
| Bearer / JWT | `Authorization: Bearer …`, `eyJhbGciOi` | **0** |
| Fly.io / Cloudflare API tokens | `fo1_…`, `FlyV1 `, `CF_API_TOKEN=…` | **0** |
| BIP-39 mnemonic material | `abandon abandon abandon`, seed-word runs | **0** |
| Pool payout address (`bloch1q1c8997…d67b`) | literal | **0** |
| `~/.git-credentials` token values | literal match of each of the 4 tokens in that file | **0** |

The GitLab token in `~/.git-credentials` was checked by extracting each token
value and grepping every revision for the literal string. **It never entered
the repository.** No SSH private key material is present either — only
*filenames* of keys (see F-2).

The 29 files matching `mnemonic` are all wallet **implementation and
documentation** (`crates/bloch-crypto/src/wallet/seed.rs`, `docs/THREAT_MODEL.md`,
etc.) — the word, the BIP-39 code paths, and the English wordlist handling.
No actual phrase. The 3 files matching `password` are
`crates/bloch-crypto/src/wallet/encryption.rs` (the KDF implementation) and
`scripts/regtest-merged-rehearsal.sh`, which passes `-rpcpassword="$BTC_RPC_PASS"`
— a shell variable, on **regtest**, never a literal.

### And the working hypothesis "this repo was private its whole life" is false

`github/g3-integration` = `fb24825` **is an ancestor of local HEAD**. The
repository at <https://github.com/tiagobeltraoacioli-sketch/bloch-sis-pow> is
**PUBLIC** (verified: GitHub API 200, `"visibility":"PUBLIC"`), and it already
carries 249 of the 392 commits, including `src/main.rs`, `carryover.tsv.gz`,
`docs/CARRYOVER.md` and the founder address.

**Only 143 commits and 235 changed files are actually new to the public.** The
audit that matters is the audit of that delta, and it is done below.

---

## 1. Findings

### F-1 — `deploy/RPC-SURVIVAL-RUNBOOK.md` — fleet reconnaissance document → **founder decision, recommend redact**

*Commits:* new since public (in the `deploy/g3-terminal-height` line of work).
*Status:* **absent from the public repo today.**

This is the single most sensitive new file. It is not a credential leak — it is
an *operational map*. In one document:

- All three box IPs with role, and which service listens where.
- The exact SSH private-key **filenames** per box: `~/.ssh/PRODUCER_KEY`,
  `~/.ssh/RELAY_KEY`, `~/.ssh/ARCHIVAL_KEY`,
  `~/.ssh/TUNNEL_KEY`. (Filenames only — no key bytes.)
- SSH login lines: `ssh -i ~/.ssh/ARCHIVAL_KEY OPERATOR@ARCHIVAL_IP`, i.e.
  the fleet username is `ubuntu`.
- The Cloudflare **account ID** `CLOUDFLARE_ACCOUNT_ID` (line 283),
  the **zone ID** `CLOUDFLARE_ZONE_ID` (line 62), and the
  **tunnel UUID** `TUNNEL_UUID` (lines 95, 338).
- Per-box free disk, free RAM and `ufw` posture ("default deny inbound; allows
  22, 11434, 16110 only") — i.e. exactly which ports are open on each host.

None of these is a secret on its own. Together they are the target list an
attacker would otherwise have to build. The Cloudflare account/zone/tunnel IDs
are identifiers, not credentials, but they are the two halves of an API call
that only needs a token to complete.

**Verdict: needs founder decision.** Recommendation: publish the *technique*
(the 1003-error analysis, the socat/tunnel pattern, the sslip.io interim) and
strip the inventory — IPs stay only where they are already public service
endpoints, SSH key filenames and the Cloudflare IDs go. Since the file is not
yet public, this is an ordinary edit — **no history rewrite is required.**

### F-2 — `fleet-recovery/README.md` — box→binary provenance map → **founder decision**

*Status:* absent from the public repo.

Maps each box IP to the binary path running on it, the home directory layout
(`~/bloch-regossip`, `~/BlochSISPoW-project/target/release/bloch`), and states
plainly that a live mainnet producer runs an unidentifiable binary with dirty
working tree. Honest engineering history, and the project's culture is to
publish exactly this kind of thing. But it also advertises that the producer's
running code is unverified.

**Verdict: founder decision** — publishing it is defensible and in character;
just make it a conscious choice, not a side effect. No secret in it.

### F-3 — Bitcoin address `bc1qDOC0RESERVED0EXAMPLE0ADDRESS0NOT0SPENDABLE` → **founder decision**

*Files:* `fleet-recovery/addr.rs.new`, `fleet-recovery/auxpow-uncommitted.patch`,
`fleet-recovery/tracked.patch`. **Not in the public repo.**

Used as the test vector for the merged-mining stratum worker-username parser,
paired with the founder Bloch address. A Bitcoin address is public by
construction and cannot spend anything. The issue is **linkability**: publishing
it next to the founder address ties a real BTC address to the project's payout
path forever. Its `scriptPubKey` hex `0014906600553abcaea9c4ab138875ac72adfc72194a`
appears alongside it.

**Verdict: founder decision.** Cheap fix: swap the test vector for a
documentation-reserved address before publishing. No history rewrite needed.

### F-4 — Infrastructure IPs → **can go public (already are)**

`136.244.82.226`, `RELAY_IP`, `PRODUCER_IP` appear in
`docs/CARRYOVER.md`, `docs/SNAPSHOT-BOOTSTRAP.md`,
`apps/posternpool-site/index.html` and `apps/explorer/wrangler.toml`. **All four
files are already on the public GitHub repo**, and in each case the IP is a
*published service endpoint*: `--peer /ip4/…/tcp/16116` bootstrap peers, and
`stratum+tcp://…:3336` pool URLs that miners are told to use because rigs do not
do DNS.

`apps/explorer/wrangler.toml` argues the point itself, in a comment already
public: *"The archival node's IP is a public fact about a read-only public RPC;
there is nothing here to keep secret."*

**Verdict: can go public.** Removing them would break documented onboarding.

### F-5 — Founder address `bloch1qe986db…42073` → **can go public (already is)**

Hardcoded as `FOUNDER_ADDRESS_HEX` at `src/main.rs:217`, and in `fly.toml`,
`crates/bloch-crypto/src/core/tokenomics_v2.rs`, `deploy/genesis2/akash-node.yaml`.
Already public; it is a consensus constant (the genesis coinbase and the vesting
output pay it), and it is visible on-chain to anyone with a block explorer. The
adjacent comment names the keystore *path* `~/bloch-founder.json` and says the
password is held by the founder only — the file itself is not in the repo and
never was.

**Verdict: can go public.** Note it makes supply concentration trivially
auditable, which is the stated intent.

### F-6 — `carryover.tsv.gz` (15.8 MB, tracked) → **can go public (already is)**

The Genesis-1 → Genesis-3 opening-balance snapshot, ~413k UTXOs. It is balance
data, and it does reveal the concentration. It is **already on the public repo**,
and it is consensus input: without it a fresh node cannot reproduce the genesis
state, which is the whole point of `REPRO.md`. Its `.sha256` sits beside it.

**Verdict: can go public.** Withdrawing it now would both be futile (already
published) and break verifiability.

### F-7 — 23.6 MB compiled binary in history → **keep the branch unpublished**

`deploy/artifacts/bloch-terminal-height` (23,590,368 bytes) exists in commit
`38258aa` on branch `deploy/g3-terminal-50000`. It is **not at HEAD**, **not in
the public repo**, and `deploy/artifacts/` is in `.gitignore` — it was committed
before the ignore rule, on a branch that is not an ancestor of HEAD.
`deploy/artifacts/bloch-snapshot-utxo` (9.7 MB) is the same story.

**Verdict: do not publish that branch.** If `deploy/g3-terminal-50000` must be
published, the binaries have to come out of *its* history first — that is a
rewrite (see §2). If only `integration/pos-modules` is published, nothing is
needed: these blobs are unreachable from it.

### F-8 — `.env.example` files → **can go public**

`tools/faucet/.env.example` and `tools/indexer/.env.example` are clean
templates. Every value is a placeholder or a localhost default; the faucet one
explicitly documents the signer seam with "*do NOT hardcode keys*" and defaults
to `FAUCET_DRY_RUN=true`. No real `.env` is tracked (`.env` is gitignored).

### F-9 — CI configuration → **can go public**

`.gitlab-ci.yml` (16 KB) and `.github/workflows/security.yml` contain **zero**
matches for `TOKEN`, `SECRET`, `PASSWORD` or `KEY`. Nothing to redact.

### F-10 — Commit author identities → **can go public**

366 commits from `groundstate100@users.noreply.github.com` (GitHub privacy
address), plus `pmo@posternlabs.com`, `founder@posternlabs.com`,
`protocol@bloch-sis`, `build@postern.local`, `bloch-sis-main@proton.me`.
Role addresses and one Proton address. Nothing personal beyond what the public
repo already carries.

---

## 2. History rewrite — is it needed?

**No — not for `integration/pos-modules`.**

Every item that needs to change (F-1, F-2, F-3) lives in files that are **not
yet in the public repository**. They can be edited or deleted with an ordinary
commit before publication, and the public repo will never have seen the earlier
version. That is the entire advantage of catching this now.

A rewrite becomes necessary in exactly one case: **if branch
`deploy/g3-terminal-50000` is published** (F-7), because the 23.6 MB binary is
inside a commit, not in the working tree. Stating it plainly, as required:
**removing a blob from history is a history rewrite. Every commit hash from the
touched commit onward changes; anyone who has cloned must re-clone; already-
published commit hashes that the fleet, releases or documents refer to would no
longer exist.** Since `github/g3-integration` is already public and shared, a
rewrite that touches it would break the public repo for existing clones.

The command, **for the founder to run, not run here**:

```bash
# NOT EXECUTED. Requires git-filter-repo (brew install git-filter-repo).
# Run on a FRESH CLONE, never on the working repo.
git clone --no-local /Users/tiagoacioli/dev/BlochPOS /tmp/bloch-rewrite
cd /tmp/bloch-rewrite
git filter-repo --invert-paths \
  --path deploy/artifacts/bloch-terminal-height \
  --path deploy/artifacts/bloch-snapshot-utxo
# then verify, then force-push ONLY the affected branch:
#   git push --force origin deploy/g3-terminal-50000
```

Recommendation: **do not rewrite.** Publish `integration/pos-modules` only, and
leave `deploy/g3-terminal-50000` private. The rewrite buys nothing that the
branch selection does not already buy.

---

## 3. License and SPDX headers

`LICENSE` is the full GNU AGPL v3 text. `docs/adr/ADR-039-agpl-license-pos-crates.md`
records the decision, and the house rule is `SPDX-License-Identifier: AGPL-3.0-or-later`
on new files.

Measured over the 497 tracked code files at HEAD (`.rs .toml .sh .nix .py .js .ts`;
`.md` was not in scope of this check):

| Type | Missing SPDX | Tracked | Coverage |
|---|---:|---:|---:|
| `.rs` | **246** | 333 | 26% |
| `.toml` | **69** | 72 | 4% |
| `.sh` | **12** | 19 | 37% |
| `.nix` | **11** | 11 | 0% |
| `.py` | **4** | 17 | 76% |
| `.js` | **4** | 5 | 20% |
| `.ts` | **2** | 40 | 95% |
| **Total** | **348** | **497** | **30%** |

The CertiK dossier's "59 of 115" was a narrower sample; over the whole tree the
real number is **348 of 497 files without an SPDX header**. The newest crates are
the compliant ones (`crates/bloch-pos-committee/src/*.rs` all carry it); the
older core is not.

Missing `.rs` by directory (top offenders):

| Directory | Missing `.rs` |
|---|---:|
| `tests/` | 62 |
| `crates/bloch-euvm` | 22 |
| `pool-proxy/src` | 21 |
| `crates/bloch-crypto` | 18 |
| `pool/src` | 13 |
| `src/stratum_v2` | 11 |
| `fuzz/fuzz_targets` | 11 |
| `src/bin` | 9 |
| `euvm-tooling` | 12 |
| `src/sync`, `src/stratum` | 5 each |
| `crates/bloch-sis-pow`, `crates/bloch-pq-vault` | 5 each |

The complete 348-file list is in **Appendix A**.

This is not a blocker for publication — the `LICENSE` file governs the whole
work regardless of per-file headers — but a public AGPL release is the moment it
gets noticed, and a mechanical header insertion pass is a one-commit fix.

---

## 4. What must NOT be published

Confirmed against the tracked tree, not assumed:

| Item | State today | Action |
|---|---|---|
| `.claude/worktrees/` | **already gitignored** | none |
| `.claude/workflows/roadmap-execution.js` | **TRACKED** | remove before publishing — internal agent orchestration, not protocol |
| `target/`, `**/target/` | already gitignored | none |
| `deploy/artifacts/` | already gitignored (blobs survive on one non-HEAD branch, F-7) | do not publish that branch |
| `data/`, `node_data/`, `logs/`, `*.db`, `*.sqlite` | already gitignored | none |
| `carryover.tsv` (uncompressed) | already gitignored | none; the `.gz` is intentional (F-6) |
| `docs/specs/*.pdf` | already gitignored | none |
| `journal.txt` | already gitignored | none |
| 56 `worktree-agent-*` local branches | local only | **never push `--all`** — see §5 |

`docs/papers/Acioli_2026_The_Cryptographic_Constitution.pdf` (194 KB) is the only
tracked PDF. It is small, it is the project's own paper, and it belongs in the
release.

Total tracked payload at HEAD: **27.2 MB across 2,254 files**, of which
`carryover.tsv.gz` alone is 15.9 MB. The `.git` directory is 255 MB — mostly the
history of the compiled artifacts of F-7 and the pack of 392 commits across 63
branches.

### Proposed `.gitignore` additions

The existing `.gitignore` is already good. Three additions:

```gitignore
# Agent tooling — the whole directory, not just worktrees
.claude/

# Compiled artifacts must never be committed again (already present, kept explicit)
deploy/artifacts/

# Local datadir snapshots and chain state dumps
*.tsv
!carryover.tsv.gz.sha256
snapshot-*/
*-datadir/
```

Note `.claude/` supersedes the current `.claude/worktrees/` line and requires
`git rm --cached .claude/workflows/roadmap-execution.js`.

---

## 5. The public repository

**It is <https://github.com/tiagobeltraoacioli-sketch/bloch-sis-pow>.**

| Property | Value |
|---|---|
| Visibility | **PUBLIC** (GitHub API 200) |
| Default branch | `g3-integration` |
| Last push | 2026-08-10 |
| Description | *(empty)* |
| Public branches | `main`, `g3-integration`, `feat/g2-hardfork-euvm`, `feat/reachability-fast-gate`, `feat/reachability-ws-b`, `fix/backfill-finality-floor`, `fix/dag-redblock-finality` |
| Linked from | `~/dev/posternlabs-deploy` — repo, `/releases`, `/releases/latest`, and `blob/main/docs/SNAPSHOT-BOOTSTRAP.md` |

It is configured here as remote `github`. A second public home exists on GitLab:
`https://gitlab.com/blochsispow-group/BlochSISPoW-project` (remote
`upstream-gitlab`, API 200 → public, also linked from the site). The private
PoS repo is `https://gitlab.com/blochsispow-group/bloch-pos` (remote `origin`,
API **404** unauthenticated → private, as expected).

State relative to local:

- `github/g3-integration` = `origin/g3-integration` = `fb24825` — **identical**,
  and an ancestor of local HEAD.
- **143 commits** in local `integration/pos-modules` not yet public.
- `github/main` has **12 commits** not in local HEAD — a divergent line. Publishing
  onto `main` is a merge, not a fast-forward. Publishing onto `g3-integration`
  *is* a fast-forward.

### Publication shape (for the founder — not executed)

Push **one explicit refspec**, never `--all`. There are 63 local branches, 56 of
them `worktree-agent-*` agent scratch branches, plus `deploy/g3-terminal-50000`
which carries the 23.6 MB binaries.

```bash
# NOT EXECUTED — founder's call, after review.
git push github integration/pos-modules:integration/pos-modules
# and only then, if desired, open a PR onto g3-integration.
```

---

## 6. Pre-publication checklist

1. [ ] Decide F-1: redact or drop `deploy/RPC-SURVIVAL-RUNBOOK.md`.
2. [ ] Decide F-2: publish `fleet-recovery/README.md` or drop it.
3. [ ] Decide F-3: replace the BTC test-vector address in `fleet-recovery/*`.
4. [ ] `git rm --cached .claude/workflows/roadmap-execution.js`; apply the
       `.gitignore` additions from §4.
5. [ ] (Optional, recommended) mechanical SPDX header pass over the 348 files in
       Appendix A.
6. [ ] Push **one** refspec. Never `--all`, never `deploy/g3-terminal-50000`.

---

## Appendix A — files without an SPDX header (348)

<!-- SPDX-APPENDIX-BEGIN -->
```
.cargo/audit.toml
.claude/workflows/roadmap-execution.js
Cargo.toml
anchoring/Cargo.toml
apps/explorer/functions/rpc.js
apps/explorer/src/lib/rpc.ts
apps/explorer/vite.config.ts
apps/explorer/wrangler.toml
apps/posternpool-site/functions/rpc.js
audit.toml
blochv-node-10.fly.toml
blochv-node-2.fly.toml
blochv-node-3.fly.toml
blochv-node-4.fly.toml
blochv-node-5.fly.toml
blochv-node-6.fly.toml
blochv-node-7.fly.toml
blochv-node-8.fly.toml
blochv-node-9.fly.toml
crates/bloch-btc-wallet/Cargo.toml
crates/bloch-btc-wallet/src/lib.rs
crates/bloch-crypto/Cargo.toml
crates/bloch-crypto/src/address.rs
crates/bloch-crypto/src/bin/postern-wallet.rs
crates/bloch-crypto/src/core/mod.rs
crates/bloch-crypto/src/core/tokenomics_v2.rs
crates/bloch-crypto/src/crypto/mod.rs
crates/bloch-crypto/src/hd_wallet/mod.rs
crates/bloch-crypto/src/lib.rs
crates/bloch-crypto/src/types/heights.rs
crates/bloch-crypto/src/types/mod.rs
crates/bloch-crypto/src/util.rs
crates/bloch-crypto/src/wallet/cli.rs
crates/bloch-crypto/src/wallet/client.rs
crates/bloch-crypto/src/wallet/disclosure.rs
crates/bloch-crypto/src/wallet/encryption.rs
crates/bloch-crypto/src/wallet/errors.rs
crates/bloch-crypto/src/wallet/mod.rs
crates/bloch-crypto/src/wallet/seed.rs
crates/bloch-crypto/tests/tx_under_dual_and.rs
crates/bloch-euvm/Cargo.toml
crates/bloch-euvm/src/batcher.rs
crates/bloch-euvm/src/harness.rs
crates/bloch-euvm/src/kirpich.rs
crates/bloch-euvm/src/kirpich/completeness.rs
crates/bloch-euvm/src/kirpich/conflicts.rs
crates/bloch-euvm/src/kirpich/emitted.rs
crates/bloch-euvm/src/kirpich/params.rs
crates/bloch-euvm/src/lib.rs
crates/bloch-euvm/src/minting.rs
crates/bloch-euvm/src/modules.rs
crates/bloch-euvm/src/state.rs
crates/bloch-euvm/tests/audit_activation.rs
crates/bloch-euvm/tests/audit_batcher.rs
crates/bloch-euvm/tests/audit_conservation.rs
crates/bloch-euvm/tests/audit_determinism.rs
crates/bloch-euvm/tests/audit_determinism_commitment.rs
crates/bloch-euvm/tests/audit_gas.rs
crates/bloch-euvm/tests/audit_modules.rs
crates/bloch-euvm/tests/audit_modules_supply.rs
crates/bloch-euvm/tests/audit_panics.rs
crates/bloch-euvm/tests/audit_stateproof.rs
crates/bloch-euvm/tests/kirpich_gate.rs
crates/bloch-ffg/Cargo.toml
crates/bloch-ffg/src/lib.rs
crates/bloch-pos-committee/Cargo.toml
crates/bloch-pq-vault/Cargo.toml
crates/bloch-pq-vault/src/anchor.rs
crates/bloch-pq-vault/src/lib.rs
crates/bloch-pq-vault/src/preimage.rs
crates/bloch-pq-vault/src/script_eval.rs
crates/bloch-pq-vault/src/vault.rs
crates/bloch-sis-pow/Cargo.toml
crates/bloch-sis-pow/rust-toolchain.toml
crates/bloch-sis-pow/tests/design_guardrail.rs
crates/bloch-sis-pow/tests/difficulty_props.rs
crates/bloch-sis-pow/tests/difficulty_scaling.rs
crates/bloch-sis-pow/tests/fuzz_robustness.rs
crates/bloch-sis-pow/tests/pow_binding.rs
crates/coherence-core/Cargo.toml
crates/coherence-core/src/lib.rs
crates/coherence-core/tests/fuzz_robustness.rs
crates/coherence-prover/program/Cargo.toml
crates/coherence-prover/program/src/main.rs
crates/coherence-prover/script/Cargo.toml
crates/coherence-prover/script/src/main.rs
crates/coherence-prover/service/Cargo.toml
crates/coherence-prover/service/src/main.rs
crates/pqcrypto-internals/Cargo.toml
crates/pqcrypto-internals/build.rs
crates/pqcrypto-internals/src/lib.rs
deny.toml
deploy/attestation/sign-image.sh
deploy/deploy.sh
deploy/genesis2/blochv-g2-1.fly.toml
deploy/genesis2/blochv-g2-10.fly.toml
deploy/genesis2/blochv-g2-11.fly.toml
deploy/genesis2/blochv-g2-12.fly.toml
deploy/genesis2/blochv-g2-2.fly.toml
deploy/genesis2/blochv-g2-3.fly.toml
deploy/genesis2/blochv-g2-4.fly.toml
deploy/genesis2/blochv-g2-5.fly.toml
deploy/genesis2/blochv-g2-6.fly.toml
deploy/genesis2/blochv-g2-7.fly.toml
deploy/genesis2/blochv-g2-8.fly.toml
deploy/genesis2/blochv-g2-9.fly.toml
deploy/genesis2/blochv-node-10.fly.toml
deploy/genesis2/blochv-node-2.fly.toml
deploy/genesis2/blochv-node-3.fly.toml
deploy/genesis2/blochv-node-4.fly.toml
deploy/genesis2/blochv-node-5.fly.toml
deploy/genesis2/blochv-node-6.fly.toml
deploy/genesis2/blochv-node-7.fly.toml
deploy/genesis2/blochv-node-8.fly.toml
deploy/genesis2/blochv-node-9.fly.toml
deploy/pow-estimator/estimate.py
deploy/pow-estimator/screen.py
deploy/pow-estimator/smallk.py
deploy/pow-estimator/sweep.py
deploy/repro/build.sh
deploy/sp1-prover/fly.toml
euvm-tooling/Cargo.toml
euvm-tooling/src/asm.rs
euvm-tooling/src/encode.rs
euvm-tooling/src/examples.rs
euvm-tooling/src/lib.rs
euvm-tooling/src/sim.rs
euvm-tooling/src/tx.rs
euvm-tooling/tests/asm_tests.rs
euvm-tooling/tests/docs_tests.rs
euvm-tooling/tests/encode_tests.rs
euvm-tooling/tests/examples_tests.rs
euvm-tooling/tests/sim_tests.rs
euvm-tooling/tests/tx_tests.rs
examples/mine_dual_and.rs
examples/payment-builder/payment-builder.js
examples/tkv0_inject.rs
flake.nix
fly.euvm.toml
fly.toml
fuzz/Cargo.toml
fuzz/fuzz_targets/block_parse.rs
fuzz/fuzz_targets/ghostdag_order.rs
fuzz/fuzz_targets/handshake_decode.rs
fuzz/fuzz_targets/mempool_ops.rs
fuzz/fuzz_targets/merkle_path.rs
fuzz/fuzz_targets/netmsg_decode.rs
fuzz/fuzz_targets/pow_decode.rs
fuzz/fuzz_targets/pow_verify.rs
fuzz/fuzz_targets/sha256d_pow.rs
fuzz/fuzz_targets/sig_verify.rs
fuzz/fuzz_targets/tx_parse.rs
fuzz/oss-fuzz/build.sh
os/android-compat.nix
os/attested.nix
os/bloch-node.nix
os/browser.nix
os/cloud.nix
os/configuration.nix
os/desktop.nix
os/mobile.nix
os/package.nix
os/seal-gate.nix
pool-proxy/Cargo.toml
pool-proxy/src/bin/rehearsal-miner.rs
pool-proxy/src/btc_block.rs
pool-proxy/src/btc_rpc.rs
pool-proxy/src/codec.rs
pool-proxy/src/downstream.rs
pool-proxy/src/extranonce.rs
pool-proxy/src/jobstore.rs
pool-proxy/src/lib.rs
pool-proxy/src/main.rs
pool-proxy/src/merged_engine.rs
pool-proxy/src/merged_serve.rs
pool-proxy/src/mergedmining.rs
pool-proxy/src/metrics.rs
pool-proxy/src/pplns.rs
pool-proxy/src/router.rs
pool-proxy/src/rpc.rs
pool-proxy/src/server.rs
pool-proxy/src/types.rs
pool-proxy/src/upstream.rs
pool-proxy/src/validator.rs
pool-proxy/src/vardiff.rs
pool-proxy/tests/integration_pump.rs
pool.fly.toml
pool/Cargo.toml
pool/src/bin/keyshard.rs
pool/src/bin/miner.rs
pool/src/dashboard.rs
pool/src/job.rs
pool/src/keyshard.rs
pool/src/lib.rs
pool/src/main.rs
pool/src/payout.rs
pool/src/protocol.rs
pool/src/shares.rs
pool/src/state.rs
pool/src/stratum.rs
pool/src/upstream.rs
postern-os-build.fly.toml
repro-compare.sh
repro-manifest.sh
scripts/ci-banned-words.sh
scripts/falcon-clean-guard.sh
scripts/flake-lock.sh
scripts/hardened-clippy.sh
scripts/regtest-merged-rehearsal.sh
services/pq-shield-api/Cargo.toml
services/pq-shield-api/src/lib.rs
services/pq-shield-api/src/main.rs
spikes/prover-cost/Cargo.toml
spikes/prover-cost/rv32/.cargo/config.toml
spikes/prover-cost/rv32/Cargo.toml
spikes/prover-cost/rv32f/.cargo/config.toml
spikes/prover-cost/rv32f/Cargo.toml
spikes/prover-cost/rv32f/src/main.rs
spikes/prover-cost/rv32h/.cargo/config.toml
spikes/prover-cost/rv32h/Cargo.toml
spikes/prover-cost/rv32h/src/main.rs
spikes/prover-cost/rv32k/.cargo/config.toml
spikes/prover-cost/rv32k/Cargo.toml
spikes/prover-cost/rv32k/src/main.rs
src/analytics/mod.rs
src/attestation/mobile.rs
src/attestation/mod.rs
src/attestation/sev_snp.rs
src/bin/bloch-calibrate.rs
src/bin/bloch-cli.rs
src/bin/bloch-genesis2.rs
src/bin/bloch-migrate-addr-history.rs
src/bin/bloch-mine-genesis.rs
src/bin/bloch-mine-genesis2.rs
src/bin/bloch-snapshot-utxo.rs
src/bin/bloch-wallet.rs
src/bin/grind_genesis3.rs
src/coherence/mod.rs
src/coherence/verifier.rs
src/consensus/mod.rs
src/consensus/reachability.rs
src/dandelion.rs
src/euvm/miner.rs
src/euvm/mod.rs
src/lib.rs
src/main.rs
src/mempool/mod.rs
src/metrics/mod.rs
src/mining/mod.rs
src/network/mod.rs
src/network/pex_validator.rs
src/network/sync_rr.rs
src/pow/mod.rs
src/pow/sha256d.rs
src/reorg.rs
src/rpc/auth.rs
src/rpc/euvm_rpc.rs
src/rpc/mod.rs
src/storage/indexer.rs
src/storage/mod.rs
src/stratum/jobs.rs
src/stratum/mod.rs
src/stratum/protocol.rs
src/stratum/session.rs
src/stratum/submit.rs
src/stratum_v2/setup_connection.rs
src/stratum_v2/setup_connection_sri.rs
src/stratum_v2/tests/cert_tests.rs
src/stratum_v2/tests/config_tests.rs
src/stratum_v2/tests/handshake_tests.rs
src/stratum_v2/tests/keypair_tests.rs
src/stratum_v2/tests/listener_tests.rs
src/stratum_v2/tests/mod.rs
src/stratum_v2/tests/session_tests.rs
src/stratum_v2/tests/setup_connection_sri_tests.rs
src/stratum_v2/tests/setup_connection_tests.rs
src/sync/frontier.rs
src/sync/locator.rs
src/sync/mod.rs
src/sync/parent_fetch.rs
src/sync/peer_state.rs
src/transport/mod.rs
src/transport/stream.rs
src/transport/upgrade.rs
test.sh
tests/announce_then_pull.rs
tests/backfill_flood_lab.rs
tests/carryover_loader.rs
tests/coherence_block_serde.rs
tests/coherence_invariants.rs
tests/difficulty_ancestry_boundary_lab.rs
tests/dst_harness.rs
tests/dual_and_local.rs
tests/frontier_sync.rs
tests/g2_common/mod.rs
tests/genesis2_emission.rs
tests/genesis2_genesis_block.rs
tests/genesis2_genesis_block_mainnet.rs
tests/genesis2_pow_devnet.rs
tests/genesis2_pow_mainnet.rs
tests/ghostdag_differential.rs
tests/ghostdag_replay_snapshot.rs
tests/kat_address.rs
tests/kat_falcon1024.rs
tests/kat_hybrid_equivalence.rs
tests/kat_mldsa65.rs
tests/mempool_index_prop.rs
tests/parser_corpus_floor.rs
tests/peer_addr_churn_lab.rs
tests/reachability_persistence.rs
tests/reorg_hardening.rs
tests/security_audit.rs
tests/sighash_security.rs
tests/sprint1_bitcoin_format.rs
tests/sprint1b_storage_migration.rs
tests/sprint1d_tx_wire.rs
tests/sprint_a1_transport_tests.rs
tests/sprint_a2_stream_tests.rs
tests/sprint_a2_upgrade_tests.rs
tests/sprint_aa0_mining_header.rs
tests/sprint_aa1_stratum_tx.rs
tests/sprint_b5_sis_pow.rs
tests/sprint_b6_hybrid_sig.rs
tests/sprint_bb_merkle_newtype.rs
tests/sprint_dd_mined_undo.rs
tests/sprint_ee_convergence.rs
tests/sprint_ee_transport_convergence.rs
tests/sprint_gg_pre_ibd_mining.rs
tests/sprint_k_address_tests.rs
tests/sprint_m_auth_tests.rs
tests/sprint_n_mempool_tests.rs
tests/sprint_p_pex_tests.rs
tests/sprint_s_crypto_sizes.rs
tests/sprint_t1_seed_determinism.rs
tests/sprint_u1_undo_data.rs
tests/sprint_u2_rollback.rs
tests/sprint_u3_reorg.rs
tests/sprint_u4_reorg_e2e.rs
tests/sprint_v1_quickwins.rs
tests/sprint_y_integrity_chain.rs
tests/sync_frontier.rs
tests/sync_locator.rs
tests/sync_peer_state.rs
tests/sync_wire.rs
tests/tx_under_dual_and.rs
tests/wire_decoder_fuzz.rs
tests/wire_roundtrip_props.rs
tools/genesis4-ceremony/Cargo.toml
```
<!-- SPDX-APPENDIX-END -->
