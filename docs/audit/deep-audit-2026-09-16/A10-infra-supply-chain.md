# A10 — Infrastructure, CI/CD, supply chain, deployment, secrets and operational security

Repository: `/home/user/bloch-sis-pow` (HEAD of `main`, shallow clone of 103 commits, remote `origin` = github.com/tiagobeltraoacioli-sketch/bloch-sis-pow). Audit date 2026-09-16. Read-only; no repository file was modified, nothing was built with cargo.

## 1. Scope and method

**Read in full:** `.github/workflows/{security,tests,ustav}.yml`, `.gitlab-ci.yml`, every `scripts/*.sh` and `scripts/*.py` (44 files incl. selftests), `Dockerfile`, `Dockerfile.euvm`, `pool.Dockerfile`, `deploy/sp1-prover/Dockerfile`, `fuzz/oss-fuzz/Dockerfile`, `deploy/pow-estimator/Dockerfile`, `.dockerignore`, `.gitignore`, all of `deploy/` (deploy.sh, docker-compose.yml, hardening/, attestation/ incl. sign-image.sh + image-security-policy.json, rollback/ incl. the selftest, repro/, bootnodes/, monitoring/, akash/*.yaml, genesis2/*, sp1-prover/, genesis4-key-ceremony.sh, node{1,2}.sdl.yaml, and the eight runbooks), every `*.fly.toml`, `flake.nix`, all `os/*.nix` and `os/boot-harness/*`, `deny.toml`, `audit.toml`, `.cargo/audit.toml`, `osv-scanner.toml`, `.gitleaks.toml`, `.mailmap`, root `Cargo.toml`, `Cargo.lock` (scripted), `repro-manifest.sh`, `repro-compare.sh`, `REPRO.md`, `SECURITY_TOOLING.md`, `genesis/`, `checkpoints/`, `CARRYOVER-SNAPSHOT.md`, `carryover.tsv.gz(.sha256)`, `tools/genesis4-carryover/*`, `tools/doc-sweep/*`, `.claude/workflows/roadmap-execution.js`, `apps/explorer/wrangler.toml`, `apps/explorer/functions/rpc.js`, `fleet-recovery/`, `docs/PUBLIC-RELEASE-AUDIT.md`. Cross-checked runbook claims against `crates/bloch-pos-node/src/{main,rpc,metrics,genesis,keys,build}.rs`, `crates/bloch-pos-committee/src/params.rs`, `legacy/genesis3-node/src/bin/bloch-snapshot-utxo.rs`.

**Executed (read-only):** every pure-Python/bash CI guard and its selftest (`check-scanners-blocking`, `check-tests-blocking`, `check-deploy-image-pins`, `check-repro-inputs`, `check-iso-hardening`, `check-no-source-archives`, `check-comment-constants`, `deny-license-exceptions-guard`, `arm-lifecycle-epoch --verify`, `ci-banned-words.sh`, `hardened-clippy.selftest.sh`, `tools/doc-sweep/check_stale.py --ci`, `lifecycle-devnet-soak.selftest`), a Cargo.lock source/duplicate/typosquat analysis, sha256/sha3-256/shake-256 of the carryover, a regex-bypass probe of the two "blocking" guards, and `git log -G` / `--diff-filter=A` sweeps over every ref in the clone. `cargo-deny`, `cargo-audit`, `osv-scanner`, `gitleaks` and `minisign` are not installed in this sandbox, so those gates could not be executed; their configuration was reviewed instead.

**Attacker model:** someone targeting the 64-validator fleet (49 Fly machines + 15 classic hosts + 2 bootnodes) or the release pipeline: via a CI/PR, via a compromised build host or registry, via one leaked operator credential, or via an operator following a runbook that no longer matches the binary.

---

## 2. Findings

No Critical finding. No live credential was found in the working tree or in the reachable history.

### INF-01 — The live validator binary is built and shipped by a pipeline that exists only outside the repository — HIGH — status: partially KNOWN (`deploy/RELEASE-INTEGRITY.md` §8.1/§8.2), the floating-toolchain contradiction is NEW

- `deploy/FLAG-DAY-EPOCH-800.md:45-55`: the fleet image is `registry.fly.io/bloch-g4:g4-flagday-6a7301ea`, "built in rust:1-bookworm", produced by "inherit[ing] the previous fleet image and replac[ing] exactly one file, the node binary", with `carryover.tsv`, `mainnet.manifest`, `start.sh` inside. **None of `Dockerfile` for `bloch-g4`, a `fly.toml` for app `bloch-g4`, or `start.sh` exists in the repository** (`grep -rn 'bloch-g4|start.sh'` finds only the runbook). `deploy/RELEASE-INTEGRITY.md:2 (§2)` pins the compiler to `1.94.1` and `§3` says the publishable hash "is defined only for the canonical containerized build"; §8.1 admits "No `bloch-pos` release container exists yet". The image that 49/64 validators run was therefore built on a floating `rust:1` tag, layered on an unversioned base, by a process no file describes.
- `.gitlab-ci.yml` `pos-release-integrity` proves same-path determinism on the *runner*, not the artifact the fleet runs; the GitHub pipeline has no equivalent at all (see INF-05).
- **Attack scenario:** a compromised operator workstation, Fly build context or registry credential ships an arbitrary `bloch-pos` to 49 validators; no reference hash, SBOM, or Dockerfile exists against which an auditor (or the §4 fleet sweep) can compare. The G8 "published == fleet, reproducible" gate cannot be evaluated by anyone but the operator.
- **Recommendation:** commit the `bloch-g4` Dockerfile/fly config/`start.sh`; build FROM a digest-pinned image with the `1.94.1` toolchain, `--locked`, `BLOCH_BUILD_COMMIT`, at `/build`; publish `(commit, stamp, sha256)` + the OCI digest per release; run the §4 sweep and file it. Until then, mark G8 as not met in the runbooks.
- Confidence: high (all statements from files; the runbook's own admission).

### INF-02 — One credential class controls the majority of validator keys — HIGH — status: KNOWN (`deploy/SSH-ROLE-SEPARATION.md`, FLAG-DAY-EPOCH-800 "Known gaps"), consolidated here

- `deploy/SSH-ROLE-SEPARATION.md:5-12`: "one SSH key and one account (`ubuntu@`) reach all 65 hosts … That key can do anything any of those 65 hosts can do". `deploy/bootnodes/verify-bootnodes.sh:31` still defaults to `$HOME/.ssh/edgevana_verify_ro` with `BLOCH_FLEET_KEY` as fallback, i.e. the split has not happened.
- `deploy/FLAG-DAY-EPOCH-800.md:62`: 49 validators are Fly machines under one app (`bloch-g4`) with **no public IP**: they are reachable only through the Fly account (`fly ssh console`). One Fly API token = 49 keystores + 49 volumes.
- `deploy/KEYSTORE-AT-REST.md:17`: "Every keystore on the live fleet today is `BPOSKEY1` (plaintext)"; `deploy/FLAG-DAY-EPOCH-2700.md` required sealing before epoch 2700 (2026-09-12 21:31 UTC; `params.rs:1207` confirms `LEAK_RECOVERY_ACTIVATION_EPOCH = 2_700`). Nothing in the repository records whether the rollout completed; `deploy/FLEET-INVENTORY.md` is entirely "TO BE FILLED".
- **Attack scenario:** theft of the fleet SSH key or the Fly token from one laptop yields ≥49 validator private keys; the attacker can double-sign (the exact 2026-08-21 incident shape) or run a majority of the committee. `deploy/BACKUP-AND-HOST-LOSS.md` cannot be executed in that case because fencing needs the same credential.
- **Recommendation:** implement the role split with hardware-backed keys and `from=`/`command=` restrictions now; put the Fly org behind hardware 2FA and a scoped deploy token; record the sealed-keystore sweep (magic bytes per host) in `FLEET-INVENTORY.md`; export `bloch_pos_keystore_sealed` (it already exists, see INF-08) and alert on 0.
- Confidence: high on the repo statements; fleet state itself is unverifiable from here.

### INF-03 — GitLab's `check` stage is red on `main`, so its `test` stage never runs; the "both pipelines gate the live crates" claim is false — MEDIUM — NEW

- `bash scripts/ci-banned-words.sh` exits 1 on this tree: a **real trademark hit** at `tools/faucet/README.md:131` (a literal instruction to use a third-party trademarked name), plus the gate's own selftest fixtures (`scripts/ci-banned-words.selftest.sh:10,72,82,86`; the script excludes itself and the negation filter but not the selftest), plus two earned-word hits (`crates/bloch-euvm/docs/euvm-harness.md:101`, `docs/whitepaper/ED2-CRYPTO-SECURITY.md:147`). `.gitlab-ci.yml` `trademark-gate` is `check` stage, no `allow_failure`.
- `python3 scripts/check-comment-constants.py` exits 1 (3 contradictions: `kirpich/limits.rs:9`, `net.rs:505`, `p2p.rs:336`) and `check-comment-constants.selftest.py` fails with "the real workspace does not pass the guard". `comment-constant-guard` is `check` stage, `allow_failure: false`. `deploy/FLAG-DAY-LIFECYCLE.md` §12 documents this red.
- `.gitlab-ci.yml:280-296` itself states the consequence (finding N-2): a red non-allow_failure job in `check` means `test` — `build-and-test`, `consensus-tests`, `fuzz-build`, `workspace-tests` — "NEVER RAN, on every single pipeline, silently". `scripts/check-tests-blocking.py` still prints "cargo test gates 8 live crates on both pipelines" because it inspects YAML text, not outcomes.
- **Attack/impact:** every GitLab-only gate in `check`/`test` is currently non-informative; the effective test gate is GitHub `tests.yml` alone. A regression that only a GitLab-only job would catch (INF-05 list) ships green.
- **Recommendation:** fix the two red jobs (exclude the selftest from the trademark scan or move its fixtures to data; fix/allow the three comment claims); add a job-outcome check (pipeline API) rather than a text check; mirror the GitLab-only gates to GitHub.
- Confidence: high (executed here; stage semantics per GitLab docs and the file's own comment).

### INF-04 — GitHub and GitLab pipelines diverge; the pipeline this clone actually pushes to is the weaker one — MEDIUM — NEW

- GitHub runs 3 workflows (security, tests, ustav). GitLab-only blocking gates: `pos-release-integrity`, `rollback-package-integrity`, `falcon-clean-guard`, `deny-license-exceptions`, `comment-constant-guard`, `trademark-gate`, `no-source-archives`, `iso-hardening-guard`, `deploy-image-pins`, `repro-inputs-guard`, `doc-sweep`, `fuzz-build`, `consensus-tests`.
- `.github/workflows/security.yml:161-176` osv-scanner `--lockfile` list omits `crates/coherence-prover/script/Cargo.lock` and `crates/coherence-prover/service/Cargo.lock`; `.gitlab-ci.yml:495-501` and `scripts/audit-all-lockfiles.sh:42-46` include them (finding N-3 was applied to two of three places). The GitHub `cargo-audit` job does cover them via the script.
- The only git remote of this checkout is GitHub; `.gitlab-ci.yml:11-27` says the macOS runner is offline and a self-hosted Linux runner replaced it — whether it is registered and green is unknown.
- **Recommendation:** add the two lockfiles to `security.yml`; port the pure-Python guards (they need no toolchain) and `pos-release-integrity`/`rollback-package-integrity` to GitHub; make the `check-*-blocking` guards read both files' *job lists* for parity.
- Confidence: high.

### INF-05 — `deny.toml` duplicate allowlist no longer matches `Cargo.lock`; the blocking `supply-chain` gate is very likely red — MEDIUM — NEW

- `deny.toml:97` `multiple-versions = "deny"`, skip list of 33 exact versions + `skip-tree = ["windows-sys@0.60.2"]`. A scan of the committed `Cargo.lock` (876 packages) finds **78 crate names with >1 version; 46 non-`windows*` families are not covered by any skip entry**, e.g. `ark-ff`/`ark-std`/`ark-serialize` ×4 (via `ruint`, `zkhash`), `syn` 1.0.109/2.0.117, `itertools` ×3, `sha3` 0.10.9/0.11.0 (0.10 is used by every first-party crate incl. `bloch-pos-committee`; 0.11 via `alloy-primitives`), `chacha20` 0.9.1/0.10.2, `hashbrown` 0.12.3/0.17.0, `indexmap` 1/2, `axum` 0.7/0.8, `bincode` 1/2, `tower` 0.4/0.5, `x509-parser` 0.17/0.18 (`libp2p-tls` vs `bloch`), `generic-array`, `ff`/`group`, `toml_edit` ×3, `winnow` ×3.
- `SECURITY_TOOLING.md:304-316` says on 2026-09-06 `cargo deny --offline check bans` was "ok, zero warnings" and that `itertools@0.12.1` / `syn@1.0.109` skip entries were **removed because the lock no longer matched them** — the current lock contains both again (`syn 1.0.109` ← `ark-ff-macros`, `derivative`, `sp1-derive`; `itertools 0.12.1` ← `bindgen`, `p3-*`). The lock moved after that measurement (PR #11 era) and the allowlist did not.
- Could not execute cargo-deny here. Either the gate is red (compounding INF-03: `supply-chain` is `check` stage) or cargo-deny's evaluated graph excludes these — either way the allowlist is not the "exact-version pins" the file claims.
- **Recommendation:** run `cargo deny check bans` on `main`; re-derive the skip list; consider `skip-tree` on the SP1/arkworks roots; add a CI step that fails when a skip entry matches nothing.
- Confidence: medium-high (lockfile facts certain; gate outcome inferred).

### INF-06 — SP1 prover image: pipe-to-shell installers, floating base images, whole-repo `COPY` — MEDIUM — NEW

- `deploy/sp1-prover/Dockerfile:25` `curl … https://sh.rustup.rs | sh -s -- -y`; `:30-31` `curl -L https://sp1up.succinct.xyz | bash && sp1up` (comment: "Pin SP1UP_VERSION … once you settle"); `:17,45` `FROM nvidia/cuda:${CUDA}-devel-ubuntu22.04` / `-runtime-ubuntu22.04` — tag-only, no digest (the guard `check-deploy-image-pins.py` scans YAML, not Dockerfiles); `:35` `COPY . .` (see INF-13). The image is the process that receives "the FULL PRIVATE WITNESS" (`deploy/sp1-prover/README.md:35`). `crates/coherence-prover/README.md:37` repeats the pipe-to-shell.
- **Attack scenario:** compromise of `sp1up.succinct.xyz` or a repointed CUDA tag yields a prover that exfiltrates witnesses or emits accepted-but-wrong proofs (node-side verification is still stubbed per the README, so wrong proofs are currently rejected anyway).
- **Recommendation:** pin `SP1UP_VERSION` and verify its release checksum; pin both CUDA images by digest; restrict `COPY` to the crates needed; add Dockerfiles to the pin guard.
- Confidence: high.

### INF-07 — Alerting has holes and the alert docs contradict the exporter — MEDIUM — NEW

- `crates/bloch-pos-node/src/metrics.rs:351,357,459` **export** `bloch_pos_equivocations_observed_total`, `bloch_pos_finality_rewinds_refused_total`, `bloch_pos_keystore_sealed`. `deploy/monitoring/rules.yml:38-79,148-170` and `README.md` say these "do not exist yet — expected from patch node-b" and label the rules `status: "DISABLED"`. A label does not disable a Prometheus rule, so the three rules are live — good — but an operator reading the docs will believe there is no coverage.
- No rule at all for: restart loops (`bloch_pos_process_starts_total` — the README calls `resets()` over it "the restart/OOM-loop alarm"), `bloch_pos_store_append_failures_total` (called the "point-of-no-return signal"), `bloch_pos_validator_not_started_total` (keystore present but validator could not arm — a silent observer), `bloch_pos_validator_active == 0` on a validator host, heartbeat staleness, `bloch_pos_blocks_rejected_total` bursts, `bloch_pos_net_shed_*`. **Missed proposals/attestations have no metric.** Fork detection is manual (`BlochFinalityStalled` description says cross-check by hand). Cert expiry: n/a (no TLS on the node), but the explorer/Caddy/cloudflared paths have none either.
- `prometheus.yml:47` scrapes placeholder `127.0.0.1:9600`; `rules.yml:118` uses `mountpoint="REPLACE_ME…"` — if an operator forgets, the disk alert and every node alert go dark with no "absent()" guard.
- **Recommendation:** add the missing rules, an `absent(bloch_pos_heartbeat_unix)` rule, and a `validator_active==0` rule for validator hosts; fix the README/rules text; add a missed-duty counter to the node.
- Confidence: high.

### INF-08 — Runbooks name a CLI and an RPC method that do not exist, on the host-loss fencing path — MEDIUM — NEW

- `deploy/BACKUP-AND-HOST-LOSS.md` Step 1.2: `bloch-pos-cli getvalidatorstatus --rpc-bind <node-A-rpc> --index <N>`; `deploy/FLAG-DAY-EPOCH-2700.md` §Verification: `bloch-pos-cli getchaininfo --rpc-bind …`. `crates/bloch-pos-node/Cargo.toml:40-42` declares one binary, `bloch-pos`; no `bloch-pos-cli` exists anywhere. `rpc.rs` methods are `getvalidator`, `getvalidators`, `getvalidatorbykey`, `getvalidatorcount`, `getvalidatoradmission` … — there is no `getvalidatorstatus`. `bloch-pos` has no client subcommand (`main.rs` subcommands: buildinfo, genesis, keygen, keys, run, submit-tx, validator-deposit, validator-lifecycle, ws-*, …).
- `genesis/README.md` runs the node with `--rpc-port 16400`; `main.rs:1218` `DEFAULT_P2P_LISTEN = "/ip4/127.0.0.1/tcp/16400"` — same port as the libp2p listener under `dual`/`libp2p`.
- **Impact:** the one step that prevents a second 2026-08-21 double-sign ("prove the old host is dead … via two independently-operated nodes' RPC") cannot be executed as written; an operator at 03:00 improvises.
- **Recommendation:** replace with `curl` + `getvalidator` examples that exist; add a runbook-vs-CLI check (grep for `bloch-pos-cli` in CI).
- Confidence: high.

### INF-09 — No rollback is currently possible, and the release signing flow is unspecified — MEDIUM — KNOWN (`deploy/RELEASE-INTEGRITY.md` §8.7), restated because it is load-bearing

- `install.sh` (generated by `deploy/rollback/make-rollback-package.sh:166-172`) fails closed without `/etc/bloch/rollback-signing.pub`; §8.7: "No release signing key exists yet, and no box has one pinned … a rollback package assembled today cannot be applied by any box". §7 step 3 references "the same signing flow as the `SHA256SUMS` re-signing precedent" — no file in the repository describes that flow or names a key.
- **Recommendation:** generate the minisign keypair under the §5.4 custody rule, distribute the pubkey to all hosts, and record the fingerprint in `RELEASE-INTEGRITY.md`; document the release-signing flow.
- Confidence: high.

### INF-10 — Bootnodes expose the full unauthenticated PoS JSON-RPC (incl. `sendrawtransaction`) on `:8080`, contradicting the published posture — MEDIUM — status: KNOWN in `docs/THIRD-PARTY-QUICKSTART.md` (correction 2026-09-02), contradicted elsewhere

- `docs/THIRD-PARTY-QUICKSTART.md:113-120,641-648`: "both published bootnodes answer JSON-RPC on `:8080` from the open internet, and `sendrawtransaction` is reachable there"; `deploy/bootnodes/bootnodes.txt:57` says "both RPC-bound to 127.0.0.1"; `scripts/ws-ceremony-drill.sh:33` and `docs/integration/BLOCH-G4-TECHNICAL-INTEGRATION-REFERENCE-v2.md:1500` depend on `139.180.166.5:8080,139.180.173.231:8080`. The PoS node has no `--rpc-api-key` (only the G3 node does), and the RPC surface includes `getnewaddress` and `sendrawtransaction` (`rpc.rs`).
- **Attack scenario:** mempool spam / resource exhaustion on the two nodes every third party is told to peer with; bootnode outage = the public onboarding path.
- **Recommendation:** decide and record the exposure; if kept, front it with a read-only allowlisting proxy (the pattern already in `apps/explorer/functions/rpc.js`) and rate limits; fix `bootnodes.txt`.
- Confidence: high on the documents; live state not checked.

### INF-11 — The `check-*-blocking` guards are bypassable by trivial spellings and cover only five jobs — LOW — NEW

- `scripts/check-scanners-blocking.py:87-92` / `check-tests-blocking.py:70-75` regexes miss (verified with the guards' own patterns): `continue-on-error: True`, `continue-on-error: ${{ true }}`, `allow_failure: True`, `allow_failure: {exit_codes: [...]}`, `rules: - when: manual|never`, `if: false`, `… || true`, `…; true`. Required sets exclude `clippy-hardened`, `lifecycle-flag-day-guards` and every GitLab-only gate. The selftests (`9 cases`, `15 cases`) pass — they test the shapes the author thought of.
- **Recommendation:** parse YAML (PyYAML is available on GitHub runners; vendor a minimal parser for GitLab), normalize booleans, treat `rules:` and `if:` as escapes, extend required sets.
- Confidence: high.

### INF-12 — Scanner binaries are pinned by version, not by hash; a pre-existing binary on the self-hosted runner is trusted blindly — LOW — NEW

- `scripts/ci-install-scanner.sh:45-49`: `if command -v "$tool" … already present … exit 0` — no version check, on a persistent shell runner. `:82-84` `go install …@v1.9.2` (mutable git tag; module sumdb helps only if the proxy is used). `:60-69` checksums come from the same GitHub release (documented as not a compromise defence). `GITLEAKS_VERSION=8.18.4` / `OSV_VERSION=v1.9.2` are two-tool pins with no `sha256` in-repo.
- **Recommendation:** record expected sha256 of each release asset in the script; require `$tool --version` to equal the pin even when pre-installed.
- Confidence: high.

### INF-13 — `.dockerignore` does not exclude key material; only `COPY . .` makes it bite — LOW — NEW

- `.dockerignore` lists `target/`, `.git/`, `mobile/`, `desktop/`, `os/`, `explorer/`, `fuzz/`, `deploy/`, `docs/`, `*.md`, `flake.nix`. Missing: `**/*.key`, `validator.key`, `cosign.key`, `*.pem`, `.env*`, `bench/` (the directory `.gitignore:76-85` warns held 41 `BPOSKEY1` throwaway keys), `deploy/rollback/dist/` (excluded only because `deploy/` is), `.prova-runs/`. The three main Dockerfiles use explicit `COPY` paths so are unaffected; `deploy/sp1-prover/Dockerfile:35` `COPY . .` would bake any of those local files into a pushed image.
- Confidence: high.

### INF-14 — Image-pin guard exemptions are loose and its own docs are stale — LOW — NEW

- `scripts/check-deploy-image-pins.py:62-72`: any `image:` line containing `TODO:` is exempt. `deploy/node1.sdl.yaml:6` and `node2.sdl.yaml:6` (`image: bloch:v0.1.0  # TODO: publish…`) are unpinned and green; `deploy/deploy.sh` still deploys `node1.sdl.yaml`. The Akash SDLs now carry digests (`7aee5dd…`, `bc893b7…`, `009ab1b…`, `ae6202a7…`) but the comment above each (`deploy/akash/deploy.yaml:15-22`) still says "No digest is recorded as verified/known … one is not guessed or fetched here" — the digests' provenance is recorded nowhere. `.gitlab-ci.yml:278` and the script docstring still say the job "is RED"; it passes.
- Confidence: high.

### INF-15 — Retired-but-deployable configs publish unauthenticated RPC; explorer upstream is plain HTTP via a third-party DNS — LOW — NEW (explorer part is KNOWN in `wrangler.toml`)

- `deploy/akash/deploy.yaml:25-53`, `deploy-16cpu.yaml`, `deploy-member.yaml`: `--rpc-bind 0.0.0.0` + `expose 16210 global`, `--rpc-api-key` commented out; `node{1,2}.sdl.yaml`: RPC published as port 80 globally; `deploy/docker-compose.yml`: host-published 16210 with `0.0.0.0` bind. All Genesis-3, but nothing prevents `deploy/deploy.sh deploy-node1` from running them.
- `apps/explorer/wrangler.toml:59` `BLOCH_RPC_URL = "http://136-244-82-226.sslip.io/"`: plaintext, resolver operated by a third party; an on-path or DNS attacker can feed the public explorer false chain data (integrity only; admitted in the file).
- Confidence: high.

### INF-16 — `scripts/prova-relanca.sh` executes a wrapper from world-writable `/private/tmp` — LOW — NEW

- `scripts/prova-relanca.sh:73,87-88,211-212`: `CARGO_LOCK="${BLOCH_CARGO_LOCK:-/private/tmp/bloch-cargo-lock.sh}"`; if executable it is run as `"$CARGO_LOCK" "$RUNNER"`. On the shared build box the header describes ("8 cores, jobs=2, several agents"), any local user can plant that file and run code as the operator. Also `RUSTC_BOOTSTRAP=1` (`:198`) to use `-Z unstable-options` on stable.
- **Recommendation:** default to a path under the repo or `$HOME`, verify owner/mode before executing.
- Confidence: high.

### INF-17 — The attested/appliance image keeps sshd enabled with NixOS defaults; the persist-volume encryption design is internally inconsistent — LOW — NEW

- `os/configuration.nix:32` `services.openssh.enable = lib.mkDefault true` is shared by `bloch-os-attested` and `bloch-os-attested-aarch64` (`flake.nix:174-199`), which do **not** import `os/installer-hardening.nix` (`:37-39` scopes it to the ISOs). NixOS' default `PasswordAuthentication = true` and `openFirewall = true` therefore apply to the sealed image. No account has a password today, so login is impossible, but port 22 is an exposed pre-attestation listener on the image whose whole point is minimal surface.
- `os/attested.nix:120-127`: comment says "`tpm2` here means: the encryption key is … sealed to the TPM2" while the option is `Encrypt = "key-file"`; `:137-140` expects `tpm2-device=auto` unlock. The file marks the block UNTESTED.
- Confidence: high.

### INF-18 — Nix modules that cannot work as shipped — LOW — mostly KNOWN (admitted TODOs)

- `os/health-watchdog.nix:51,107`: `systemctl restart` from a `DynamicUser` service with no polkit rule → denied; the watchdog will log failures forever and never restart (admitted "operator follow-up").
- `os/bloch-pos-node.nix:28-35`: package default falls back to the Genesis-3 `bloch` derivation, so `ExecStart=${pkg}/bin/bloch-pos` does not exist (admitted).
- `os/seal-gate.nix:18,28` builds `crates/postern-seal-companion`, which is not in this repository (`ls crates/`); `os/cloud.nix` (not wired into the flake) depends on it.
- `postern-os-build.fly.toml:10` Nix build host from unpinned `debian:stable-slim`, Nix installed at runtime.
- Confidence: high.

### INF-19 — History claims (`catalog-dev.secret.pem`, "55 findings", leaked PAT) cannot be verified from this clone; CI never scans history — LOW — status: KNOWN (`.gitleaks.toml:18-26`, `docs/EVOLUTION.md:63,251`)

- `git rev-parse --is-shallow-repository` = true; 103 commits, 4 refs. `.gitleaks.toml` says the full history (2,216 commits) carries `catalog-dev.secret.pem` ("a postern-store demo signing key … in history and NOT in the tree"); `git log --all -- '*catalog-dev.secret.pem*'` finds nothing here. `docs/EVOLUTION.md:63`: "Leaked GitLab PAT — Still unrotated — open security debt" (the token itself never entered the repo per `docs/PUBLIC-RELEASE-AUDIT.md`). `.gitignore:76-85` says 41 `BPOSKEY1` keys exist on a working branch not present here. Both CI secret scans run `--no-git`.
- **Recommendation:** the lead should run `gitleaks detect` (git mode) on an unshallowed clone with all refs; confirm the PAT rotation and the fate of the `bench/` branch.
- Confidence: high that it is unverifiable here.

### INF-20 — Minor key-handling and hygiene items — LOW — NEW

- `deploy/genesis4-key-ceremony.sh:157` exports `BLOCH_KEYSTORE_PASSPHRASE` into the environment of every `bloch-pos keygen` child (readable in `/proc/<pid>/environ` by the same user); `deploy/KEYSTORE-AT-REST.md` ranks the file path first for exactly that reason. Acceptable on an air-gapped host; should use `--passphrase-file` on a `0600` tmpfs file.
- `tools/genesis4-carryover/test_build_carryover.py:43,81` uses `tempfile.mktemp` (race-prone) and a founder home path.
- `scripts/check-validator-lifecycle-mutations.py:52` and `.github/workflows/ustav.yml:18-27` hardcode `1.94.1` instead of reading `rust-toolchain.toml` (drift when the pin bumps).
- `.gitlab-ci.yml:337` uses `sudo apt-get install -y minisign` on the shell runner — CI has passwordless sudo; verify that merge-request pipelines from forks cannot reach this runner.
- Confidence: high.

### INF-21 — A checked-in agent workflow with a stale, founder-specific context — INFO — NEW

- `.claude/workflows/roadmap-execution.js` is force-tracked (`.gitignore:104 !.claude/workflows/`) and allow-listed in `.gitleaks.toml:38`. `:12` hardcodes `/Users/tiagoacioli/dev/BlochSISPoW-project` and `:15` branch `euvm/integrate`; the context describes the Genesis-3 era. If run under a Workflow harness it spawns 8 audit + 4 plan + 4 implement + 1 synthesis agent calls (`model: 'fable'`, `effort: 'high'`). The prompts instruct "DO NOT modify files … return diffs", but that is a prompt, not a sandbox: the agents can do whatever the harness's tools allow, and the repository content they read is a prompt-injection surface. No secret is embedded.
- Confidence: high.

### INF-22 — Documentation rot that would mislead an operator — INFO — NEW

- `crates/bloch-pos-node/src/genesis.rs:277,308,489,528,547,551,678` describe "452,133 rows", "425,599 of the 452,133 outputs", "18,122,599,999.99999941" — the shipped file has 452,726 rows and `CARRYOVER_TOTAL_BLOCH = 18_146_400_000` (`tokenomics_v4.rs:200,236`); the guard cannot see unbound prose numbers.
- `pool.fly.toml:24` points at `https://blochv-node.fly.dev` whose RPC `[[services]]` block was removed from `fly.toml` (retired anyway). `REPRO.md:148` still says a `mainnet-guard` placeholder job exists (removed per `.gitlab-ci.yml:756`). `fleet-recovery/README.md` carries a "redacted" banner yet keeps `node4 136.244.82.226` (also public in `wrangler.toml`). `deploy/FLEET-INVENTORY.md` is entirely placeholders.
- Confidence: high.

### Carryover-specific verification (no finding)

`carryover.tsv.gz` sha256 `4d1e27…83be` matches `carryover.tsv.gz.sha256`; decompressed: 54,780,151 bytes, 452,726 rows, sha256 `84ddbb…83f6`, sha3-256 `3d6724…308d`, shake-256 set root `7c756e…dbdf` — all four equal `CARRYOVER-SNAPSHOT.md`. `vout` distribution: 452,688 × `0`, 38 × `16777216`, exactly as the document admits. Producer `legacy/genesis3-node/src/bin/bloch-snapshot-utxo.rs:42-66` deliberately reproduces the LE/BE misread by default (`--canonical-vout` opts out, unit-tested `default_decode_reproduces_the_published_bug_for_vout_1`); the node loader `genesis.rs:640-645` accepts any canonical `u32` and recomputes the set root over its own canonical re-serialisation, so the bug is deterministic on every node. `tools/genesis4-carryover/build_carryover.py` is marked RETIRED, discards `vout`, and does not reproduce the live file (applies neither the ×100/21 split nor the same row set).

---

## 3. Secrets-sweep results

| Location | Type | First 6 chars | Tree / history | Assessment |
|---|---|---|---|---|
| (none) | PEM/OpenSSH private key | — | neither (all refs in clone, `-G` over diffs) | none found |
| (none) | ghp_/glpat-/github_pat_/fo1_/FlyV1/AKIA/xox/AIza/JWT | — | neither | none found; `docs/PUBLIC-RELEASE-AUDIT.md:34` contains only the regex text |
| (none) | BIP-39 phrase / xprv | — | neither | only wallet code and docs mention mnemonics |
| `catalog-dev.secret.pem` | demo signing key (per `.gitleaks.toml:21`) | n/a | history only, **not reachable in this shallow clone** | UNCONFIRMED — lead must scan an unshallowed clone |
| GitLab PAT | personal access token | n/a | never in repo (`docs/PUBLIC-RELEASE-AUDIT.md` §0); `docs/EVOLUTION.md:63` "still unrotated" | rotation status unknown — treat as live until confirmed |
| `bench/**/validator.key` (41 × `BPOSKEY1`) | throwaway validator keys (per `.gitignore:76-85`) | n/a | on a working branch not present in this clone | throwaway per the note; verify the branch is not pushed to a public remote |
| `scripts/regtest-merged-rehearsal.sh:57-58` | bitcoind regtest `rpcuser/rpcpassword` = `rehear…` | `rehear` | tree | regtest-only default; not a secret |
| `apps/explorer/wrangler.toml:59` | archival node IP as `BLOCH_RPC_URL` | `http:/` | tree | public by design; plaintext (INF-15) |
| `deploy/bootnodes/bootnodes.txt:67-68`, `scripts/ws-ceremony-drill.sh:33` | bootnode IPs `139.180.…` | `139.18` | tree | public by design; `:8080` RPC exposure (INF-10) |
| `fly.toml`, `deploy/genesis2/*`, `deploy/akash/*` | miner/payout addresses `bloch1q…` | `bloch1` | tree | public addresses |
| `.git/config` | remote URL | — | local | no embedded credential |
| `tools/{indexer,faucet}/.env.example` | example env | — | tree | placeholders only |

## 4. Dependency inventory summary (`Cargo.lock`)

- 876 `[[package]]` entries, 764 distinct names: 862 from crates.io, 14 workspace path crates (`bloch`, `bloch-btc-wallet`, `bloch-crypto`, `bloch-euvm`, `bloch-ffg`, `bloch-pos-committee`, `bloch-pos-node`, `bloch-pq-vault`, `bloch-sis-pow`, `bloch-ustav`, `coherence-core`, `genesis4-ceremony`, `libp2p-yamux` (vendored fork), `pqcrypto-internals` (vendored fork)), **0 git sources, 0 non-crates.io registries**, every registry entry has a checksum. `deny.toml [sources]` denies unknown git/registry — consistent.
- Typosquat heuristic (edit-distance vs ~150 popular names): no suspicious near-names. Unusual but legitimate: `wasm32-unknown-unknown-openbsd-libc` (upstream pqcrypto dep), `hex_lit`, `dunce`, `zkhash`, `twirp-rs`.
- Duplicates: 78 names with >1 version; `deny.toml` skip list covers 33 exact versions + `windows-sys@0.60.2` subtree; **46 non-windows families uncovered** (INF-05).
- Vendored forks, provenance: `crates/pqcrypto-internals` = upstream 0.2.11 + one-file change (`src/lib.rs` seeded-RNG override), repository `Groundstate100/pqcrypto-fork`, C sources pinned by hash in `VENDOR.toml` and checked by `tests/vendor_pin.rs`; `crates/libp2p-yamux` = upstream 0.47.0 with the yamux-0.12 backend removed, `yamux >=0.13.10,<0.14`, guarded by `tests/lockfile_guard.rs`. Both are documented; neither carries an upstream commit hash for the base it was copied from (only version numbers).
- Ignored advisories (identical in `audit.toml` and `.cargo/audit.toml`; mirrored in `deny.toml` and `osv-scanner.toml`, every OSV entry `ignoreUntil = 2026-12-01`, `deny.toml` skip list "REVIEW BY 2026-12-05"): vulnerability-class — `RUSTSEC-2026-0118`, `-0119` (hickory-proto DoS, libp2p-pinned); unsound — `RUSTSEC-2026-0002`, `-0253` (lru, SP1-pinned); coherence-prover lockfiles only — `RUSTSEC-2026-0220`, `RUSTSEC-2025-0137` (ruint), `RUSTSEC-2026-0009` (time DoS), GHSA-7gcf-g7xr-8hxj (serde_with); GHSA-only via SP1 — `GHSA-vj64-rjf3-w3v7` (p3-challenger, CVSS 8.9), `GHSA-3g92-f9ch-qjcm`; unmaintained — pqcrypto-falcon/mldsa/traits/internals/kyber, bincode 1, paste, proc-macro-error2, rustls-pemfile, backoff, instant, ansi_term, derivative, number_prefix. Beyond the two documented hickory entries, the vulnerability-class ignores are the three coherence-prover ones (ruint ×2, time) and the p3-challenger GHSA — all argued as host-side only; none expired yet (first expiry 2026-12-01).
- Unpinned/mutable external inputs outside Cargo: `flake.nix` (`nixos-25.05` branch, `mobile-nixos` branch, no `flake.lock` — `check-repro-inputs.py` red by design), `sp1up.succinct.xyz` and `sh.rustup.rs` installers, `nvidia/cuda` tags, `debian:stable-slim` (build host), `gcr.io/oss-fuzz-base/base-builder-rust` (OSS-Fuzz, acceptable), `sagemath/sagemath:10.3` + `git clone --depth 1 malb/lattice-estimator` (pow-estimator, archive tooling).

## 5. Exposed ports per deploy config

| Config | Publicly reachable | Bound but not published | Notes |
|---|---|---|---|
| `fly.toml` (blochv-node, G3, retired) | 16110/tcp P2P | RPC 16210 on 127.0.0.1 | `--mine`; RPC service block removed (MED-6) |
| `blochv-node-{2..10}.fly.toml` (G3) | none (no `[[services]]`) | P2P 0.0.0.0:16110 inside VM, RPC loopback | dial-out only |
| `deploy/genesis2/*.fly.toml` | none | P2P `/ip6/::/tcp/16110`, RPC loopback | |
| `fly.euvm.toml` | none | everything loopback | isolated rehearsal |
| `pool.fly.toml` (retired) | 3335/tcp Stratum; 443/80 → 8650 dashboard (`force_https`, `auto_stop=false`) | — | upstream RPC URL is dead |
| `deploy/sp1-prover/fly.toml` | 443/80 → 8080 (`force_https`, bearer token required, scale-to-zero) | — | not a validator; auto-stop is fine here |
| `deploy/sp1-prover/akash-deploy.yaml` | 443, 80 (Caddy, digest-pinned) | prover 8080 internal only | |
| `postern-os-build.fly.toml` | none | — | `sleep infinity` build host |
| `deploy/akash/deploy.yaml`, `deploy-16cpu.yaml`, `deploy-member.yaml` | 16110 P2P **and 16210 RPC, unauthenticated** | — | G3, `--rpc-api-key` commented out |
| `deploy/akash/worker-40cpu.yaml`, `deploy-genesis2*.yaml`, `deploy/genesis2/akash-node.yaml` | 16110 P2P | RPC loopback | |
| `deploy/node1.sdl.yaml`, `node2.sdl.yaml` | **RPC 16210 as port 80**, 16110 | — | unpinned image, `TODO:`-exempt |
| `deploy/docker-compose.yml` | host 16210/16211/16212 RPC (0.0.0.0), 16110-16112 | — | local testnet |
| `deploy/hardening/docker-compose.hardened.yml` | host 16110 only | RPC loopback | |
| `os/bloch-node.nix` / `os/bloch-pos-node.nix` | none by default (`IPAddressDeny=any`, firewall closed; P2P port opened only for libp2p/dual) | RPC/metrics 127.0.0.1 | |
| `os/cloud.nix` | 16510/tcp seal gate, 51820/udp WireGuard | sshd (wg0 only) | not wired into the flake |
| `os/configuration.nix` (attested image) | **22/tcp sshd** (openssh module opens firewall) | — | INF-17 |
| Live fleet (per runbooks, not in repo) | bootnodes 19100 devnet P2P + **8080 full RPC**; Fly `bloch-g4` no public IP | RPC 16310/16400 loopback | INF-10, INF-02 |

## 6. Positive observations

- GitHub Actions: every `uses:` is pinned to a full commit SHA (including the tagless `dtolnay/rust-toolchain` branch tips), `permissions: contents: read` at top level, triggers are `push`/`pull_request`/`workflow_dispatch` — **no `pull_request_target`, no secrets referenced anywhere**, so fork PRs cannot reach anything.
- Tool versions pinned in both pipelines (`cargo-audit 0.22.2`, `cargo-deny 0.20.2`, `cargo-geiger 0.13.0`, `cargo-fuzz 0.13.2`, `gitleaks 8.18.4`, `osv-scanner v1.9.2`), the `|| true` swallow on installs was removed, scanners fail closed when absent, and each guard ships a selftest that must fail before it may pass — the selftests all pass here except the one that honestly reports the workspace is red.
- The three primary Dockerfiles pin base images by digest, run as uid 10001, disable core dumps at the entrypoint, default RPC to loopback; `deploy/hardening` drops all capabilities, read-only rootfs, resource limits.
- `deploy/rollback/make-rollback-package.sh` + `install.sh`: detached minisign signature verified against an out-of-band key **before** `sha256sum -c`, manifest covers every file that reaches root, trusted comment binds the signature to the package, no `--unsigned` escape, and the selftest replays swapped-binary/recomputed-manifest, tampered `install.sh`, stripped signature, wrong key, pasted signature and missing pinned key.
- `deploy/attestation/sign-image.sh` refuses to generate a key, requires an absolute existing `COSIGN_KEY`, and `cosign.key`/`*.pem`/`*.minisign.key` are gitignored; `image-security-policy.json` is reject-by-default with `matchRepoDigestOrExact`.
- systemd hardening spine in `os/*.nix` is thorough (`IPAddressDeny=any`, `ProtectProc=invisible`, `MemoryDenyWriteExecute`, syscall filters, `CapabilityBoundingSet=[]`, `LimitCORE=0`, `LoadCredential=` for the passphrase); `installer-hardening.nix` correctly `mkForce`s the installer profile's sshd/empty-password defaults and the guard verifies it structurally.
- `Cargo.lock` has no git or foreign-registry sources; the two forks are vendored with written rationale and regression tests; `[patch.crates-io]` removed the vulnerable yamux 0.12 line entirely; advisory acceptances are dated, mirrored across four tools, and expire.
- Carryover snapshot integrity can be recomputed in full from the repository (all four digests and the row count match), and the historical vout defect is preserved deterministically and unit-tested rather than silently "fixed".
- The key ceremony script refuses to run with any sign of network access, refuses to overwrite, verifies the sealed magic bytes of every keystore, and emits per-row digests.
- The repository's own documentation is unusually candid about its gaps (REPRO ladder rung 1, no release container, single SSH key, unfilled inventory), which made this audit faster and is itself a control.

## 7. Residual risk / not covered

- `cargo-deny`, `cargo-audit`, `osv-scanner`, `gitleaks`, `minisign`, Nix and `cargo build/test` were not run here (tools absent or excluded by the brief); INF-05 and the rollback selftest are inferred from configuration.
- The clone is shallow (103 commits, 4 refs): history-only claims (`catalog-dev.secret.pem`, 55 gitleaks findings, the `bench/` keys) and any secret in other branches are unverifiable. A full-history scan on an unshallowed clone with all remotes (GitLab + GitHub) is required.
- Live state was not contacted: GitLab runner registration, whether the epoch-2700 keystore sealing completed on all 64 hosts, whether the leaked PAT was rotated, current `:8080` exposure on the bootnodes, Fly account 2FA, and what image the `bloch-g4` machines run today.
- Not reviewed in depth: `pool/`, `pool-proxy/`, `services/pq-shield-api/`, `euvm-tooling/`, `apps/site`, `apps/posternpool-site`, `sdk/`, RPC method semantics (`getnewaddress`, `sendrawtransaction` on observers), the OSS-Fuzz project configuration beyond its Dockerfile, and the Cloudflare Pages project settings outside `wrangler.toml`.
