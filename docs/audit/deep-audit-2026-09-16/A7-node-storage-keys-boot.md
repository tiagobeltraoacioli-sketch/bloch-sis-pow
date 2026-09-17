# A7 — bloch-pos node: storage, keystore, slashing protection, boot gate, ceremony, release integrity

Auditor: A7 (node storage / keys / boot). Date: 2026-09-16. Repository: `/home/user/bloch-sis-pow` (read-only; no build or test run).

## 1. Scope & method

**Read in full:** `crates/bloch-pos-node/src/{store.rs, keys.rs, slashprot.rs, ws_boot.rs, ws_tool.rs, main.rs, validator_deposit.rs, validator_lifecycle.rs, devnet_tools.rs, codec.rs}`, `crates/bloch-pos-node/build.rs`, `crates/bloch-pos-node/rust-toolchain.toml`, `crates/bloch-pos-node/Cargo.toml`, `tests/{keystore_at_rest.rs, keys_seal_cli.rs, validator_deposit_cli.rs, cold_start.rs}`, `tools/genesis4-ceremony/{Cargo.toml, README.md, src/main.rs}` plus the parser/validation regions of `src/lib.rs`, `deploy/genesis4-key-ceremony.sh`, `scripts/pos-release-integrity.sh`, `scripts/pos-release-integrity.selftest.py` (header + assertion skeleton), `deploy/RELEASE-INTEGRITY.md`, `os/bloch-pos-node.nix`. **Targeted reads** of `engine.rs` (keystore/store/slashprot wiring in `run`, `attest`, `propose`, `ingest_replay`, `apply_block`, doppelganger, `enforce_ws_anchor`, store append/rewrite error handling), `bloch-pos-committee/src/ws.rs` (`verify_envelope_with_shape_policy`, `matches_policy` only), `genesis.rs` (`Manifest::load`, caps), `rpc.rs` (`build_info_json`), `pqcrypto-internals/build.rs`.

**Prior-audit context read:** `deploy/KEYSTORE-AT-REST.md`, `docs/specs/BLOCH-GENESIS-KEYS.md`, `docs/specs/BLOCH-FALCON-ONLINE-SIGNING.md`, `checkpoints/README.md`, `checkpoints/DECISIONS-2026-09-02.md`, `deploy/BACKUP-AND-HOST-LOSS.md`, `deploy/FLAG-DAY-EPOCH-2700.md`, `deploy/FLAG-DAY-LIFECYCLE.md` §3.4, `deploy/FLAG-DAY-EPOCH-800.md` ("Fixed during this rollout"), `SECURITY.md`, `docs/audit/groundstate_audit.md` (ERA-1, PoW-era), `docs/audit/CERTIK-PRE-AUDIT-DOSSIER.md` §3–§5.

**Method.** Adversarial walk of every file-handling, key-handling and CLI path from four positions: (a) read access to the host filesystem or backups, (b) write access to the data dir, (c) a careless operator, (d) a peer feeding the store. Every prior-finding claim in a code comment (I-H1, round-3 "keystore lows", M-6, M-8, H-1, H-2, R6 HIGH-8, NEW-2, O07) was checked against the code that is supposed to implement it. Findings are labelled NEW or KNOWN with the reference. Confidence is stated per finding; nothing below was executed.

**Verified-as-requested:** `ws_boot::boot` calls `ws::verify_envelope_with_shape_policy` (ws_boot.rs:719–728) after an explicit `shape_policy_of` refusal (ws_boot.rs:716–718); `ws-envelope` and `ws-verify` call the same function (ws_tool.rs:923, 939, 1363). The bare `verify_envelope` is used only in tests, in `ws-sign`'s 1-of-1 self-check (ws_tool.rs:753) and in `probe_signatures` (ws_tool.rs:1138) — both diagnostic, neither an acceptance path. The lib.rs request is satisfied.

---

## 2. Findings (ordered by severity)

No Critical or High finding was identified inside this scope. The slashing-protection ordering, the sealed-keystore format, the data-dir lock and the boot gate are implemented as their comments claim (see §4). The Medium findings are defense-in-depth gaps and operator foot-guns with plausible impact on the live fleet.

### KS-01 — `keygen` silently overwrites an existing `validator.key` (no `create_new`, no lock, no confirmation)
- **Severity:** Medium. **Status:** NEW.
- **Refs:** `keys.rs:409–434` (`save_with`), `keys.rs:377–390` (`generate_with`), `main.rs:876–905` (`keygen`).
- **Description.** `Keystore::save_with` opens `dir/validator.key` with `.write(true).create(true).truncate(true)`; `keygen` performs no existence check and does not take `store::DirLock`. Running `bloch-pos keygen --dir <live datadir> --index N` (with any passphrase or the plaintext opt-in in the environment) replaces a validator's hybrid secret key and RANDAO seed with a fresh throwaway pair in one line. The tooling around it knows: `devnet.sh:60` guards with `[ -f "$d/validator.key" ] ||`, `genesis4-key-ceremony.sh:118–123` refuses an existing output dir; the binary itself does not. `ws-keygen` (ws_tool.rs:353–355) *does* refuse to overwrite a `.sk`, so the crate's own convention is inconsistent.
- **Scenario.** Operator provisioning a replacement host re-runs the "generate" step from the runbook against the wrong `--dir`, or a rollout script's idempotency check uses the wrong path. The genesis validator's RANDAO seed is gone; `BLOCH-GENESIS-KEYS.md` §2 states a genesis validator that loses its seed cannot propose until a re-commit lands. Recovery depends on the single sealed offline copy that `deploy/BACKUP-AND-HOST-LOSS.md` allows.
- **Evidence.** `let mut f = fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&path)?;` (keys.rs:422–427). No `exists()`/`create_new` anywhere on the `keygen` path.
- **Recommendation.** `create_new(true)` in `generate_with`'s save path (refuse with `AlreadyExists` naming the file), a `--force` only if genuinely needed, and take `DirLock` as `keys seal` does. Keep `save_with`'s truncating open only for the `seal_in_place` temp-file path (which already uses its own).
- **Confidence:** High (code path is unambiguous).

### KS-02 — Production passphrase file (`BLOCH_KEYSTORE_PASSPHRASE_FILE`) is not mode-checked; only the `keys seal --passphrase-file` path is
- **Severity:** Medium. **Status:** NEW.
- **Refs:** `keys.rs:266–303` (`Unlock::from_sources`), `keys.rs:1009–1035` (`read_passphrase_file`), `os/bloch-pos-node.nix:184–187`.
- **Description.** `read_passphrase_file` (used by `keys seal --passphrase-file` and by `keys seal` reading the env var, main.rs:776–791) refuses a file with any group/other bits. `Unlock::from_sources` — the path every `run`, `keygen`, `keygen-public`, `genesis`, `validator-deposit sign`, `validator-lifecycle exit` and `transfer-v2` invocation actually takes — does a bare `fs::read(&path)` with no mode or ownership check. The docs (`KEYSTORE-AT-REST.md` "a `0600` file") describe a property nothing enforces. A world-readable passphrase file beside a 0600 keystore is refused by one tool and accepted by the node.
- **Scenario.** Operator provisions `/etc/bloch/nNN.pass` with `echo > file` under a 022 umask (0644) and points the unit at it. Any local account, and any backup/snapshot that includes `/etc`, now holds the unlock secret; the keystore's own 0600 check gives a false sense that the pair is protected. `LoadCredential=` paths are 0400 and owned by the service user, so an `0o077` check is compatible with the documented preferred deployment.
- **Evidence.** `let raw = Zeroizing::new(fs::read(&path).map_err(|e| { ... PermissionDenied ...})?);` (keys.rs:273–286) — no `metadata().permissions()` call, unlike keys.rs:1013–1024.
- **Recommendation.** Apply the same `mode & 0o077 != 0 → PermissionDenied` check in `from_sources` (and optionally an owner == euid check); keep the error kind non-`NotFound` per the existing contract. Add a test mirroring `a_world_readable_passphrase_file_is_refused` for the env-var path.
- **Confidence:** High.

### KS-03 — No minimum passphrase length on the `keygen` / env path; the mainnet ceremony sealed 64 keystores through it
- **Severity:** Medium. **Status:** NEW.
- **Refs:** `keys.rs:117` (`MIN_SEAL_PASSPHRASE_CHARS = 12`, applied only in `seal_in_place`, keys.rs:854–862), `keys.rs:196–201` (`Unlock::passphrase`), `keys.rs:304–309` (env value accepted if non-empty), `deploy/genesis4-key-ceremony.sh:152–158`.
- **Description.** `keys seal` refuses passphrases under 12 characters. `Unlock::from_sources` → `Unlock::passphrase` accepts any non-empty string, and `Keystore::generate` seals under it. `genesis4-key-ceremony.sh` reads the passphrase with `read -s`, checks only `[ -n "$KEYPASS" ]` and confirmation match, exports it and runs `keygen` 64 times. Argon2id 64 MiB/t=3 makes a guess cost ~0.2–1 s per core; it does not turn a short or dictionary passphrase into a secret. `KEYSTORE-AT-REST.md` itself says a validator identity behind eight characters "is still a dictionary away."
- **Scenario.** Attacker with a backup, snapshot or stolen disk holding the sealed keystores (the exact adversary I-H1 was closed against) runs an offline dictionary attack; with a weak ceremony passphrase, all 64 genesis validator keys and RANDAO seeds fall together (one passphrase seals all 64 by design of the script).
- **Evidence.** `[ -n "$KEYPASS" ] || { echo "FATAL: an empty passphrase is not a passphrase."; exit 1; }` is the only strength check in the script; `if !p.is_empty() { return Ok(Unlock::passphrase(p)); }` (keys.rs:305–307).
- **Recommendation.** Enforce `MIN_SEAL_PASSPHRASE_CHARS` (or higher, e.g. 20) in `generate_with`/`seal()` for every write path, and in the ceremony script (`${#KEYPASS} -ge 20`). Consider a one-time re-seal of the fleet keystores under a stronger passphrase if the ceremony passphrase does not meet the bar (`keys seal` refuses an already-sealed file, so a `keys reseal` verb would be needed — see KS-04/KS-13 on tooling gaps).
- **Confidence:** High on the code; the actual strength of the ceremony passphrase is unknowable from the repo.

### KS-04 — Slashing protection has no import/export and no "minimum slot" initialization; the host-loss runbook's fencing step cannot be executed with the shipped tools
- **Severity:** Medium. **Status:** partially KNOWN (`deploy/BACKUP-AND-HOST-LOSS.md` Step 2.2 describes the need; R6 HIGH-8 added the doppelganger window) — the tooling gap and its interaction with the window are NEW.
- **Refs:** `slashprot.rs:197–232` (`open_with`: missing file ⇒ `Watermarks::default()`), `slashprot.rs:95–102`, `engine.rs:4795–4818` and `engine.rs:1696–1732` (doppelganger: 2 epochs, in-memory, `--no-doppelganger-check`), `deploy/BACKUP-AND-HOST-LOSS.md` Step 2.2.
- **Description.** The watermark record is a single 4-tuple with no interchange format (nothing EIP-3076-like) and no CLI to create one. A fresh data dir opens with all watermarks `None`, so a restored key signs at the first duty the clock reaches. The runbook says the operator must "initialize a fresh one that refuses to sign anything at or before the highest slot/epoch this validator index is known to have attested or proposed" — there is no `slashprot init --min-slot` / `--min-target-epoch`, and the binary format (`BPOSSLP2`, SHAKE-256 digest over the body, keyed to pubkey-sha3 + genesis digest) is not something an operator can hand-write. The only remaining guard is the doppelganger observation window, which (i) is not persisted (`doppelganger_halted` is process memory; a restart clears it), (ii) cannot see a twin that boots inside the same 2-epoch window (both observe, both stay mute, both then start), and (iii) is disabled by a flag the test harnesses use routinely.
- **Scenario.** The 2026-08-21 incident shape: a host believed dead comes back after the replacement was provisioned from the sealed copy with a fresh data dir; both restart within a maintenance window; neither sees the other during observation; both sign — the double-signing that `slashing.rs` burns stake for.
- **Evidence.** `Err(e) if e.kind() == io::ErrorKind::NotFound => (Watermarks::default(), None),` (slashprot.rs:230). `grep -n "import\|export\|min-slot" slashprot.rs main.rs` → nothing.
- **Recommendation.** Add `bloch-pos slashprot init --dir <datadir> --min-attestation-slot S --min-target-epoch E --min-proposal-slot S` (bound to the keystore identity), and `slashprot export/import` in a documented interchange (EIP-3076 JSON is the industry form). Persist the doppelganger halt (a marker file in the data dir) so a restart does not un-halt.
- **Confidence:** High.

### KS-05 — Interactive passphrase entry: echo not restored on signal, `tcsetattr` restore result ignored, and `Stdin`'s buffer retains the passphrase
- **Severity:** Low. **Status:** NEW.
- **Refs:** `keys.rs:1042–1082` (`read_passphrase_from_tty`).
- **Description.** ECHO is cleared with `TCSAFLUSH`, `read_line` runs, and the restore happens only on the normal return path (`unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &saved) };`, rc discarded). Ctrl-C during the prompt terminates the process before the restore, leaving the terminal with echo off. `io::stdin().lock().read_line` goes through std's global `BufReader`, so a copy of the passphrase remains in that non-zeroized buffer for the life of the process (the `Zeroizing<String>` only covers the caller's copy). A panic between set and restore has the same effect as the signal case.
- **Recommendation.** Use a RAII guard that restores termios in `Drop`, install a minimal SIGINT handler for the prompt window (or `SA_RESTART`-free read that maps EINTR to restore-then-error), read from the raw fd with a small `Zeroizing` buffer instead of `Stdin`'s `BufReader`. The `rpassword`-style pattern is the reference.
- **Confidence:** High (behavior follows from the code; not executed).

### KS-06 — `ws-sign` / `ws-signer-set` key-file hygiene: non-zeroized hex copy of the secret, no mode check on `.sk`, `.sk` write not fsynced
- **Severity:** Low. **Status:** NEW.
- **Refs:** `ws_tool.rs:120–123` (`read_hex_file`), `ws_tool.rs:726` (`let sk = Zeroizing::new(read_hex_file(&key_path)?)`), `ws_tool.rs:125–146` (`write_file`), `ws_tool.rs:337–366` (`ws-keygen`).
- **Description.** `read_hex_file` does `fs::read_to_string` into a plain `String` and `unhex`es it; only the decoded `Vec` is wrapped in `Zeroizing` — the hex text (which is the secret) is freed un-wiped. Nothing checks the `.sk` mode before reading it (the validator keystore path does). `write_file(secret=true)` creates the `.sk` 0600 with `create_new` (good) but does not `sync_all`; a crash after `ws-keygen` prints "wrote" can leave an empty/partial `.sk` whose `.pk` has already been handed to the set assembler.
- **Recommendation.** Read the `.sk` into `Zeroizing<Vec<u8>>` and decode in place; refuse `.sk` with group/other bits; `sync_all` before reporting success.
- **Confidence:** High.

### KS-07 — Block log has no per-frame checksum; a zero-filled tail is classified as corruption (boot refusal, no repair tool); a replayed block that fails `apply_block` is dropped along with everything after it
- **Severity:** Low. **Status:** partially KNOWN (store.rs:22–24 states "at most one truncated trailing frame"); the zero-fill and mid-log cases are NEW.
- **Refs:** `store.rs:22–24`, `store.rs:739–779` (`read_all`), `store.rs:696–733` (`append`: single `write_all` + `sync_data`), `engine.rs:3226–3242` (`apply refused: {e}` → `return false`), `engine.rs:10773` (test doc: "the head stays at genesis, the node having refused to replay").
- **Description.** Framing is `u32 LE len ‖ envelope`; integrity of a frame body is only what `decode_envelope` and the transition enforce. (i) After a power loss on XFS or ext4 `data=writeback`, the tail can be extended with zeros to the new size: `read_all` reads `len = 0`, `decode_envelope(&[])` fails, and the node refuses to boot with `InvalidData` — correct fail-closed posture, but there is no `store repair`/truncate-to-last-good-frame command, so recovery is a manual `truncate` by an operator who must find the offset. (ii) A frame that decodes but fails `apply_block` (bit rot in a body, or a hand-edited log) is skipped with a log line; the rest of the log then parks as orphans and the node comes up far behind its real head and re-syncs from peers. Safety is preserved (peers' blocks are re-validated by the real `HybridVerifier`), but the silent truncation of local history is observable only by reading stderr, and the ws boot decision is then made against a shorter local finality than the node actually had.
- **Recommendation.** Add a per-frame SHAKE-256/32 (or CRC) trailer so a zero/garbage tail is distinguishable from a torn append and a mid-log corruption is a named error; ship `bloch-pos store check|repair --dir` that truncates only a trailing damaged frame with operator confirmation; make a replay `apply_block` failure fatal (fail-closed, like the decode failure) rather than a skip.
- **Confidence:** Medium-High (filesystem crash semantics are stated from general knowledge; the code paths are verified).

### KS-08 — `keys seal` / `keys inspect` run as another user leave root-owned `validator.key` / `LOCK`, so the next node start fails
- **Severity:** Low. **Status:** NEW.
- **Refs:** `keys.rs:937–966` (temp file created and renamed over `validator.key` as the invoking user), `main.rs:864–873` (`keys inspect` acquires and releases `DirLock`, which creates `dir/LOCK`), `store.rs:496–523`, `store.rs:535–552`.
- **Description.** The runbook (`FLAG-DAY-EPOCH-2700.md` step 3b) has the operator run `keys seal` with the node stopped; on the fleet this is a `sudo` invocation in practice. The sealed inode is created by the invoking uid (root), so after the rename `validator.key` is `root:root 0600` and the service user gets `exists but cannot be read ... refusing to start as an observer` (loud, correct) — an outage on the next start. `keys inspect`, documented as opening nothing, creates `LOCK` if absent; a root-owned `LOCK` makes the service's `open_lock_file` fail with EACCES and `DirLock::acquire` refuse. Both are loud rather than silent, which is why this is Low.
- **Recommendation.** In `seal_in_place`, `fchown` the temp file to the original file's uid/gid (or refuse when euid ≠ owner unless `--as-owner`); make `keys inspect` probe the lock without creating it (try `flock` on an existing `LOCK` only).
- **Confidence:** High.

### KS-09 — Source-digest scope gaps: a compiled C include (`.macros`) and dot-directories are outside the hash; toolchain env not captured
- **Severity:** Low. **Status:** NEW (the general "not against a motivated liar" limit is KNOWN, build.rs:57–65).
- **Refs:** `build.rs:72` (`SOURCE_EXT`), `build.rs:99–113` (skips names starting with `.`, skips symlinks), `pqcrypto-internals/build.rs:60–74`, `pqcrypto-internals/cfiles/keccak4x/KeccakP-1600-times4-SIMD256.c:805`.
- **Description.** `KeccakP-1600-times4-SIMD256.c` is compiled into every x86_64 binary and `#include "KeccakP-1600-unrolling.macros"`; the `.macros` extension is not in `SOURCE_EXT`, so editing that file changes the compiled Keccak (used by SHAKE/SHA3 in the PQ suite) without moving `source_digest`. Any `.cargo/config.toml` (`[build] rustflags`, `[patch]`, `[source] replace-with`) would be invisible for the same reason (none exists today — verified). `CC`, `CFLAGS`, `RUSTFLAGS` and `cc`-crate target flags are not part of the digest either. `build_info_json` states the scope honestly (rpc.rs:2483–2489), so this is a gap in what the digest can prove, not a false claim.
- **Recommendation.** Add `macros`, `inc`, `S`-adjacent includes (or simpler: hash every regular file under `crates/` except a deny-list) and include `.cargo/**` explicitly; record `RUSTFLAGS`/`CFLAGS` presence in a stamp so a non-clean build is marked. Update the `source_digest_scope` string in step.
- **Confidence:** High.

### KS-10 — Non-atomic writes: `save_with` truncates `validator.key` in place; `meta.bin` written with `fs::write` and no fsync
- **Severity:** Low. **Status:** NEW.
- **Refs:** `keys.rs:409–434`, `store.rs:668–674`.
- **Description.** `save_with` opens the final path with `truncate(true)` and writes directly; a crash mid-write leaves a truncated keystore (compounding KS-01 when the file was a live key). `meta.bin` is written once at first open via `fs::write` with no `sync_all`/dir fsync; a crash on first boot can leave an empty `meta.bin`, which the next open refuses as "belongs to a different network or schema" (fail-closed, but the message is misleading for a first-boot crash).
- **Recommendation.** Temp file + fsync + rename + dir fsync for both (the pattern `slashprot::write_durably`, `ws_boot::save_latest` and `seal_in_place` already use).
- **Confidence:** High.

### KS-11 — Header-supplied KDF cost is honored down to the Argon2 floor with no minimum or warning; caps still allow minutes of CPU per open
- **Severity:** Low (hygiene). **Status:** caps KNOWN (audit round 3 "keystore lows", keys.rs:99–112); the missing floor/warning is NEW.
- **Refs:** `keys.rs:99–112`, `keys.rs:636–645`, `keys.rs:683` (`kdf.derive` runs before the AEAD tag can reject).
- **Description.** Reading always uses the file's parameters. Because the parameters are AAD, a downgrade against an existing sealed file is not exploitable (the tag fails). But a keystore sealed by other tooling at `m=8 KiB, t=1` loads silently with no "weak KDF" warning, and `keys inspect` prints the cost without judging it. At the caps (1 GiB, t=64, p=16) a substituted header costs the node a large allocation and long CPU time before the tag rejects it — an attacker with data-dir write can already delete the file, so this is availability noise, not a vulnerability.
- **Recommendation.** Warn (or refuse under a `--strict-kdf` default for `run`) when the file's cost is below `KdfParams::PRODUCTION`; have `keys inspect` flag it.
- **Confidence:** High.

### KS-12 — Toolchain pin is crate-scoped; documented root-level build commands bypass it
- **Severity:** Low / Info. **Status:** KNOWN in intent (`rust-toolchain.toml` header explains the scoping); the interaction with the documented commands is NEW.
- **Refs:** `crates/bloch-pos-node/rust-toolchain.toml`, `Dockerfile:13` (comment: `cargo build --release -p bloch-pos-node` from the root), `scripts/pos-release-integrity.sh:96,170–176,186–190` (mitigates by `cd "$NODE_DIR"`).
- **Description.** rustup resolves `rust-toolchain.toml` from the *current directory*, not from the package being built. `cargo build -p bloch-pos-node` from the repo root uses the ambient default toolchain; only `cd crates/bloch-pos-node && cargo build` honours the pin. The release script does the latter and asserts the active rustc, so releases are covered; ad-hoc fleet builds from the root are not. The Dockerfile's builder image is `rust:1.94` so it matches by coincidence of version, not by the pin.
- **Recommendation.** Either add a root `rust-toolchain.toml` (the header argues against it for the frozen G3 crate — that argument is now historical, G3 is retired) or make every documented build command `cd` into the crate.
- **Confidence:** High.

### KS-13 — Stale documentation: `KEYSTORE-AT-REST.md` says "No re-seal tool" and "Option A is the only one an operator can actually execute"
- **Severity:** Info. **Status:** NEW (doc drift).
- **Refs:** `deploy/KEYSTORE-AT-REST.md` "Not covered by this change"; `main.rs:742–833` (`keys seal` shipped in `d953fcc`); `deploy/FLAG-DAY-EPOCH-2700.md` §1 "Status: LANDED"; `deploy/FLAG-DAY-LIFECYCLE.md` §3.4 (fleet sealed as the 2700 exit criterion).
- **Recommendation.** Update the rollout note so an operator does not choose Option A (plaintext + opt-in) on the strength of a sentence that is no longer true.

### KS-14 — Ceremony script exports the passphrase into the environment of 64 child processes
- **Severity:** Info. **Status:** NEW.
- **Refs:** `deploy/genesis4-key-ceremony.sh:157` (`export BLOCH_KEYSTORE_PASSPHRASE="$KEYPASS"`), `keys.rs:230–248` (env warning).
- **Description.** The script header says the passphrase is "never written anywhere but a 0600 file" and "never passed as an argument"; it is, however, placed in the process environment of every `keygen`/`keygen-public` child (`/proc/<pid>/environ`, `ps eww`). On an air-gapped single-user machine this is acceptable and the exposure class is documented in keys.rs, but the script also triggers the loud env-var warning 64 times on stderr (stdout is redirected, stderr is not), which trains operators to ignore that warning. A `BLOCH_KEYSTORE_PASSPHRASE_FILE` on a 0600 tmpfs file would be consistent with the node's preferred path.

### KS-15 — `scripts/ws-ceremony-drill.sh` leaves throwaway signer `.sk` files in its work dir
- **Severity:** Info. **Status:** NEW.
- **Refs:** `scripts/ws-ceremony-drill.sh:29,144,241` (no `trap`/cleanup).
- **Description.** Disposable drill keys only; the runbook says to run the drill "on the exact binary the ceremony will use", i.e. possibly on a signer's machine — leftover `.sk` files there are clutter an operator could confuse with real keys. Add a `trap 'rm -rf "$WORK"' EXIT` when the work dir was auto-created.

### KS-16 — WS boot refusal + `Restart=on-failure` is a replay-every-5-seconds crash loop
- **Severity:** Info. **Status:** NEW.
- **Refs:** `engine.rs:5077` (`Err(msg) => return Err(PermissionDenied)`), `main.rs:1572–1575` (`exit(1)`), `os/bloch-pos-node.nix:212–213`.
- **Description.** `ERR_WS_REQUIRE_CHECKPOINT`/`ERR_WS_STALE` are the mechanism working, but they are raised only *after* the full O(chain) replay (engine.rs:5006–5012 explains why). Under a supervisor that restarts on failure the host replays the whole log every 5 s until an operator intervenes. Loud, but a self-inflicted CPU/IO load. A distinct exit code (e.g. 3) that the unit maps to `RestartPreventExitStatus=` would stop the loop.

### KS-17 — `--allow-plaintext-keystore` is matched anywhere in argv
- **Severity:** Info. **Status:** NEW.
- **Refs:** `main.rs:102–104`.
- **Description.** `args.iter().any(|a| a == "--allow-plaintext-keystore")` also matches the token when it appears as the *value* of another flag. Harmless in practice; noted for completeness of the CLI-parsing review. The same pattern is used for `--allow-finality-rewind` and `--no-doppelganger-check` (main.rs:1459–1466).

### KS-18 — Doppelganger protection is in-memory, window-bounded and flag-bypassable
- **Severity:** Info. **Status:** KNOWN (R6 HIGH-8; engine.rs:226–245, 1149–1163 state the trade-offs).
- **Refs:** `engine.rs:1696–1732`, `engine.rs:4795–4818`, `tests/cold_start.rs:192`, `scripts/lifecycle-devnet-soak.py:330`.
- **Description.** Recorded here because it is the only guard covering the fresh-datadir case (KS-04). Two copies of one key that boot within the same 2-epoch window never detect each other; `doppelganger_halted` does not survive a restart; devnet harnesses run with `--no-doppelganger-check`, so a copy-pasted harness line is one way the flag reaches a real unit.

---

## 3. Safety-weakening flags / subcommands and whether the fleet deploy scripts pass them

The repository contains **no unit files for the live fleet**. `os/bloch-pos-node.nix` is a template whose own `package` option says it "will NOT produce a `bloch-pos` binary" yet; the `Dockerfile` `CMD` (line 110) is Genesis-3-shaped and is not a `bloch-pos` invocation; `deploy/docker-compose.yml` states there is no compose file for `bloch-pos`; `deploy/FLEET-INVENTORY.md` is "TO BE FILLED". Fleet flags therefore cannot be verified from the tree; the table records what the repo's own scripts, tests and docs pass, and what the docs claim about the fleet.

| Flag / env / subcommand | Effect | Where the repo passes it | Fleet (per docs; not verifiable from the tree) |
|---|---|---|---|
| `--allow-plaintext-keystore`, `BLOCH_KEYSTORE_ALLOW_PLAINTEXT=1` | Reads/writes `BPOSKEY1` (secret + RANDAO seed in the clear) | `crates/bloch-pos-node/devnet.sh:47,60`; `scripts/devnet-transporte-misto.sh:62,81`; `scripts/transporte-postura-prova.sh:44,55`; `scripts/lifecycle-devnet-soak.py:140`; `tests/cold_start.rs:98`; `keys_seal_cli.rs`, `keystore_at_rest.rs` (throwaway keys) | `KEYSTORE-AT-REST.md` documented it as the interim "Option A" for every fleet host; `FLAG-DAY-EPOCH-2700.md` step 3e says start **without** it; `FLAG-DAY-LIFECYCLE.md` §3.4 lists "all 64 sealed (`BPOSKEY2`)" as the 2700 exit criterion, met. Confirm by the RELEASE-INTEGRITY §4 sweep, not by this table. |
| `BLOCH_KEYSTORE_PASSPHRASE=<text>` | Passphrase in `/proc/<pid>/environ` (loud warning) | `deploy/genesis4-key-ceremony.sh:157` (air-gapped); tests | nix template uses `LoadCredential=` + `_FILE` (preferred). Unknown for real units. |
| `--no-doppelganger-check`, `BLOCH_NO_DOPPELGANGER=1` | Skips the 2-epoch observation before duties | `tests/cold_start.rs:192`; `scripts/lifecycle-devnet-soak.py:330` | `FLAG-DAY-EPOCH-2700.md` §3: "not recommended". Unknown for real units. |
| `--allow-finality-rewind`, `BLOCH_ALLOW_FINALITY_REWIND=1` | Lifts the finality latch (R3 M-1) | none | none documented |
| `--transport devnet` (default), `--listen-addr <routable>` | Unauthenticated TCP mesh, no admission control | devnet scripts; `docs/THIRD-PARTY-QUICKSTART.md:362` (loopback bind) | Fleet runs the devnet mesh (H-2 posture, documented in `main.rs:1283–1292`); firewalling is the control. Out of A7 scope; listed for completeness. |
| `--rpc-bind <non-loopback>`, `--metrics-bind <non-loopback>` | Unauthenticated RPC (has `sendrawtransaction`) / metrics exposed | none (all scripts bind 127.0.0.1) | nix template hard-codes 127.0.0.1 |
| `--ws-checkpoint`, `--ws-signer-set` | Root-of-trust inputs (unauthenticated files; fingerprint printed) | none | none yet (no signed checkpoint exists per `checkpoints/README.md`) |
| `--stop-at-slot` | Exits at a slot (harness) | devnet scripts, `cold_start.rs`, `scripts/replay-determinismo.sh` | n/a |
| `--behind-proxy`, `--max-peers` | libp2p scoring/tuning only | none | n/a |
| `keygen` | Generates a throwaway key; **overwrites** an existing `validator.key` (KS-01) | ceremony script (guarded by dir check), devnet scripts (guarded by `-f` check) | ceremony used it for the 64 mainnet keys |
| `keys inspect` | Creates `LOCK` in the data dir if absent (KS-08) | runbook step | operator action |
| `devnet-equivocate` | Signs an equivocating block with the keystore | `devnet_tools.rs:516–528` refuses any manifest with a cohort or a carryover commitment and checks `meta.bin` against it (verified) | cannot target the mainnet manifest |
| `ws-signer-set --min-external 0` / non-§6 shapes | Writes a set the tool warns about | `ws_tool.rs:533–540` warns; `ws_boot::boot` shape gate refuses at boot (NEW-2, verified) | n/a |
| `BLOCH_P2P_TRACE` | Verbose p2p tracing | none | none |

---

## 4. Positive observations (claims verified against code)

- **Slashing protection is structurally before the signature.** Both consensus signatures go through the guard closure: attestations at `engine.rs:1783–1794`, proposals at `engine.rs:2016–2022`. `write_durably` does temp → `sync_all` → `rename` → directory `sync_all` before `sign()` runs (slashprot.rs:292–368); `watermark_is_durable_before_the_signature_exists` reads the file through a fresh descriptor from inside the closure. No other `Keystore::sign` call produces a slashable message (deposit/possession/exit signatures; devnet tools are manifest-gated). Disk-full is a `Refusal::Io` with no signature (fail-closed).
- **Watermark file is bound to key + network (M-8)** and a V1/V2 relabel is refused by the digest (`a_relabelled_record_is_corrupt_not_a_version_change`). A corrupt file refuses to open rather than resetting.
- **Data-dir lock (H-1) is sound:** `O_EXCL` + `flock(LOCK_EX|LOCK_NB)` + inode/dev re-verification after locking, never unlinked on unix, bounded retries, pid written for the operator (store.rs:469–612). It is acquired in `Store::open` before any data-dir byte is read (store.rs:643–648), and `engine::run` opens the store before slashing protection (engine.rs:4625–4644), so the lock covers the watermark file under `run`. `keys seal` takes the same lock (keys.rs:889) and its refusal is tested.
- **Sealed keystore format is correct:** Argon2id (64 MiB / t=3 / p=1) over a 32-byte random salt, XChaCha20-Poly1305 with a fresh 24-byte random nonce per seal (both from `/dev/urandom`), the entire public header (magic, KDF id, costs, salt, nonce, index, length-prefixed pubkey — 85 + len bytes, verified against `codec::put_bytes`) as AAD, so index/pubkey re-pointing and parameter downgrade break the tag (`rewriting_the_validator_index_breaks_the_tag`). Header-supplied costs are capped before allocation (1 GiB / t=64 / p=16). One error message for wrong passphrase vs. tampering (no oracle).
- **Observer-mode contract is narrow and tested:** `Ok(None)` only for an absent file; no configuration refusal is kinded `NotFound` (keys.rs:266–303, 500–546); group/other-readable keystores are refused.
- **Secret hygiene:** `Keystore` implements neither `Debug` nor `Clone`; no `{:?}` over key material anywhere in the crate (grep); `keygen`/`keygen-public`/`keys inspect` print only pubkey SHA3, RANDAO commitment and header facts (`inspect_reports_public_fields_only_on_both_formats`, and the CLI tests search stdout/stderr for the seed bytes); `seal_in_place` verifies the sealed bytes round-trip (constant-time on the secret) before installing, keeps a handle to the old inode and zero-fills it best-effort, and re-loads the installed file.
- **RANDAO seed** never leaves the keystore struct except as a copy to `RandaoChain::generate`; future generations are derived from seed ‖ signing secret so a revealed chain tail does not predict the next generation (`randao_seed_for`, tested).
- **Boot replay is fully validated:** `ingest_replay` → `ingest_one` → `self.tr.apply_block` under the real `HybridVerifier` (engine.rs:3233–3235); `tr_probe` (accept-all) is used only for the producer's own pricing probe. A tampered `blocks.log` cannot make the node accept an invalid block. Replay is exempt only from the wall-clock rules (`Source::Replay`).
- **Store serving path is bounded:** the `blocks.idx` sidecar is derived state with every inconsistency (torn, ahead, lying, unordered) falling back to a full scan; frame lengths are capped at 8 MiB; `read_all` refuses a decode failure mid-log rather than skipping. `append` is fsynced before the block is broadcast; `rewrite` is temp + fsync + rename + dir fsync (M-6) and rebuilds the index. Disk-full on append/rewrite is `FATAL … exit(1)` with a metric incremented first.
- **WS boot is fail-closed at every step:** missing signer set, undecodable files, shape mismatch (`verify_envelope_with_shape_policy` **is** the function called — lib.rs request satisfied), `arrangement_window` lower bound, `Acceptance::Conflict`, `RequireCheckpoint`/`RefuseStale` — all return `Err` and the process exits 1; `ws_latest.bin` is written atomically and refused across networks; a published checkpoint never reorganizes own finality (`published_checkpoint_never_overrides_own_finality`); duplicate-key arrangements and saturating `adopted_epoch` are refused at the decoder (DECISIONS memo corrections 1–2 are implemented and tested).
- **ws_tool refuses to write what a node would refuse:** `ws-envelope` runs `combine` (digest binding, quorum, external minimum, window), then the shape-policy verifier on both the in-memory and the re-decoded file bytes; `ws-sign` self-verifies under `--pubkey`; `ws-verify` prints the freshness line when a clock is available. `published_artifacts_carry_no_key_material` asserts the `.sk` is 0600 and absent from every artifact.
- **Ceremony tool (`tools/genesis4-ceremony`) is deterministic:** no RNG, no clock, no environment reads (grep); strict TSV parsers with contiguous indices, raw-key length, lowercase-hex canonical forms; refuses duplicate pubkeys, duplicate RANDAO commitments, zero commitments, sub-minimum stake, cohort > liquidity; digest of the carryover verified against the published value before building.
- **`genesis4-key-ceremony.sh`** refuses a networked host (ICMP/TCP/DNS/default-route), refuses to overwrite, sets `umask 077`, verifies every keystore is `BPOSKEY2` and 0600 before emitting the cohort, and emits per-row digests.
- **Release integrity:** the script `cd`s into the crate so the toolchain pin applies, asserts the active rustc, resolves `--locked` against the root lock, diffs the lock before and after two clean builds, requires bit-identical binaries and a live `--version` stamp; the lock guard is certified by a selftest that must go red on a rewritten root lock and on a resurrected per-member lock. `build.rs` stamps commit source (`git`/`asserted`/`none`) and tree state (`clean`/`modified`/`unverified`/`unknown`) separately, and the source digest is computed from bytes with sorted, length-prefixed, workspace-relative paths.
- **`validator-deposit sign` / `validator-lifecycle exit` / `transfer-v2`:** output files are `create_new` 0600 + `sync_all` (never overwritten), allow-listed flags, inputs capped at 100 KB, existing counterparty signatures verified before the keystore is opened, manifest domain checked before the keystore is opened.

---

## 5. Test-coverage gaps

- No test that `keygen` refuses (or is expected to refuse) an existing `validator.key` — because it does not (KS-01).
- No test that the node's `BLOCH_KEYSTORE_PASSPHRASE_FILE` path rejects a group/other-readable file (KS-02); `a_world_readable_passphrase_file_is_refused` covers only `read_passphrase_file`.
- No test enforcing a minimum passphrase length on `generate_with` / env (KS-03); `keystore_at_rest.rs` uses a long passphrase, so a regression to 1-char acceptance is invisible.
- `store.rs` has **no** test for `read_all` on a truncated trailing frame, a zero-filled tail, or a corrupt mid-log frame (fail-closed claim in the comment is untested), and no crash-consistency test for `append`/`rewrite`/`meta.bin` (KS-07, KS-10).
- No test that a replayed block failing `apply_block` is handled as intended (the engine test at 10773 covers "head stays at genesis"; nothing asserts the operator-visible outcome or the interaction with the WS gate).
- `slashprot.rs`: no test of `Refusal::Io` (disk full / unwritable dir) leaving the in-memory watermark unchanged and producing no signature; no cross-process lock test (documented as not drivable in-process).
- `keys.rs`: `read_passphrase_from_tty` has no test (needs a pty); the `keys_seal_cli` test only proves the non-tty refusal.
- No test that `keys seal`/`keys inspect` preserve ownership or that `inspect` leaves the directory unchanged (KS-08).
- Doppelganger: no test for two instances booting inside the same window, and no test that a halt survives a restart (it does not, by design — KS-18).
- `build.rs`: no test that the digest scope covers every file `pqcrypto-internals/build.rs` compiles (KS-09); `pos-release-integrity.selftest.py` certifies the lock guard only.
- `cold_start.rs` runs with `--allow-plaintext-keystore` and `--no-doppelganger-check`, so no integration test drives `run` with a sealed keystore and the observation window (documented trade-off in the test header; `keystore_at_rest.rs` covers keygen/keygen-public only, not `run`).
- `ws_tool.rs`: `ws-checkpoint`'s RPC path (`view_of`, boundary scan, two-endpoint disagreement) is exercised only against canned JSON for the finalized gate; the disagreement refusal is untested.

---

## 6. Residual risk / not covered

- **Fleet configuration is not in the repository.** Whether any live unit still carries `BLOCH_KEYSTORE_ALLOW_PLAINTEXT=1`, `--no-doppelganger-check`, a world-readable passphrase file, or a root-owned keystore can only be established by the RELEASE-INTEGRITY §4 `/proc` sweep and a per-host `keys inspect`. `FLAG-DAY-LIFECYCLE.md` §3.4 asserts the fleet is sealed; this audit did not and could not verify it.
- **Process-level attacker.** Secrets are `Zeroizing` in the keystore module, but the PQ signing primitives in `bloch-crypto`/`pqcrypto` receive `&self.secret` and may copy it into non-zeroized internal structures; that crate is another auditor's. Nothing protects the key from a same-uid attacker reading the address space (documented in `KEYSTORE-AT-REST.md`).
- **Two copies of one key in two data dirs** are outside the lock's reach by design; the doppelganger window is the only guard (KS-04/KS-18).
- **Datadir write attacker.** With write access to the data dir an attacker can delete `ws_latest.bin` (fallback to the genesis anchor), delete `slashing_protection.bin` (re-arm double-signing — the runbook says so), or replace `blocks.log` with a valid alternative history. Replay re-validates signatures, so only a quorum-signed history is accepted; that is the long-range attack the WS checkpoint exists for, and no signed checkpoint has been published yet (`checkpoints/README.md`: "UNSIGNED").
- **`/dev/urandom` via `File::open`** (keys.rs:1150–1154) for salts, nonces and the RANDAO seed; the keypair itself comes from `bloch-crypto`'s RNG. Not assessed: behaviour on a freshly booted VM before the CRNG is seeded (`getrandom` would block; `/dev/urandom` does not on older kernels). The 64 mainnet seeds were generated on a long-running host per the ceremony script, so this is theoretical.
- **Cryptographic semantics of the WS envelope** (`ws.rs`), fork choice, finality latch, p2p/RPC framing and the genesis state derivation are other auditors' scopes and were touched only where this scope depends on them (shape-policy call, `matches_policy` reading, replay verifier choice).
- **Nothing was executed.** All statements about crash/filesystem semantics (zero-fill on XFS, `data=writeback`) are from general knowledge, not from a reproduction on this tree.
