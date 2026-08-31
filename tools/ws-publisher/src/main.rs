// SPDX-License-Identifier: AGPL-3.0-or-later

//! `bloch-ws-publisher` — CLI over the four stations in lib.rs.
//!
//! Argument style is the node's (`--flag value`, hand-rolled), and every
//! subcommand that can refuse prints the full reason: the operator reading a
//! failed timer log and the exchange reading a failed verification both get
//! the same attributable message discipline as `EnvelopeReject`.

use std::env;
use std::fs;
use std::process::{exit, Command};
use std::time::{SystemTime, UNIX_EPOCH};

use bloch_pos_committee::ws::{self, WS_FRESH_EPOCHS, WS_PERIOD_EPOCHS};
use ws_publisher::*;

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        Some("stage") => cmd_stage(&args[1..]),
        Some("sign") => cmd_sign(&args[1..]),
        Some("seal") => cmd_seal(&args[1..]),
        Some("verify") => cmd_verify(&args[1..]),
        Some("status") => cmd_status(&args[1..]),
        Some("digest") => cmd_digest(&args[1..]),
        _ => {
            eprint!("{USAGE}");
            2
        }
    };
    exit(code);
}

const USAGE: &str = "\
bloch-ws-publisher — weak-subjectivity checkpoint publication pipeline

USAGE:
  bloch-ws-publisher stage   --dir <root> --finalized-epoch <n>
                             --network-id <id> --genesis-root <hex32>
                             (--payload <file> | --producer '<cmd with {epoch} {out}>')
                             [--finalized-root <hex32>] [--epoch <n>]
      Unattended station (timer). Computes the due publication epoch,
      validates the producer's payload, writes the signing request.
      Touches no keys. Prints one machine-readable line:
      NOTHING_DUE | ALREADY_PUBLISHED epoch=… | ALREADY_STAGED epoch=… digest=…
      | STAGED epoch=… digest=…

  bloch-ws-publisher sign    --payload <file> --secret-key <file> --out <file>
                             [--signer-set <file> --signer-index <k>]
      Attended station, run by ONE keyholder on their own machine. The only
      subcommand that reads a secret key. With --signer-set/--signer-index
      the signature is checked against the published key before writing.

  bloch-ws-publisher seal    --dir <root> --epoch <n> --signer-set <file>
                             --network-id <id> --genesis-root <hex32>
                             [--sig <index>:<file>]...
      Assembles the envelope from collected signatures (default: every
      signatures/<epoch>/sig-<index>.bin under --dir) and verifies it exactly
      as a booting node would. Only a verifying envelope is written.

  bloch-ws-publisher verify  --checkpoint <file> --signer-set <file>
                             --network-id <id> --genesis-root <hex32>
                             [--wall-epoch <n> | --genesis-unix <secs>]
      The third-party station: reproduce the node's boot-time accept/reject
      for a published checkpoint. Exit 0 = genuine under the supplied
      arrangement and pins; anything else = do not use.

  bloch-ws-publisher status  --dir <root> [--finalized-epoch <n>]
                             [--wall-epoch <n> | --genesis-unix <secs>]
      What is due, staged, sealed; freshness of the newest sealed epoch.

  bloch-ws-publisher digest  --file <payload | envelope>
      Print the ws_digest of an artifact — the 64 hex characters
      announcements quote and phone calls compare.
";

// ---------------------------------------------------------------------------
// Argument helpers (node style)
// ---------------------------------------------------------------------------

fn arg_value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).map(String::as_str)
}

fn need<'a>(args: &'a [String], flag: &str) -> Result<&'a str, String> {
    arg_value(args, flag).ok_or_else(|| format!("missing required {flag}"))
}

fn parse_u64(s: &str, what: &str) -> Result<u64, String> {
    s.parse().map_err(|_| format!("{what}: not a number: {s:?}"))
}

/// Network id: decimal or 0x-hex, matching how the id is quoted in docs.
fn parse_network_id(s: &str) -> Result<u32, String> {
    let r = if let Some(hexpart) = s.strip_prefix("0x") {
        u32::from_str_radix(hexpart, 16)
    } else {
        s.parse()
    };
    r.map_err(|_| format!("--network-id: not a u32: {s:?}"))
}

fn parse_hex32(s: &str, what: &str) -> Result<[u8; 32], String> {
    let v = hex::decode(s).map_err(|_| format!("{what}: not hex: {s:?}"))?;
    v.try_into().map_err(|_| format!("{what}: need exactly 32 bytes (64 hex chars)"))
}

fn pins_from(args: &[String]) -> Result<ChainPins, String> {
    Ok(ChainPins {
        network_id: parse_network_id(need(args, "--network-id")?)?,
        genesis_root: parse_hex32(need(args, "--genesis-root")?, "--genesis-root")?,
    })
}

/// Wall-clock epoch for freshness judgements: `--wall-epoch` verbatim, or
/// derived from `--genesis-unix` and the system clock via the committee
/// crate's `wallclock_epoch` (the standard NTP caveat applies and is the
/// caller's, exactly as it is the node's).
fn wall_epoch_from(args: &[String]) -> Result<Option<u64>, String> {
    if let Some(w) = arg_value(args, "--wall-epoch") {
        return Ok(Some(parse_u64(w, "--wall-epoch")?));
    }
    if let Some(g) = arg_value(args, "--genesis-unix") {
        let genesis = parse_u64(g, "--genesis-unix")?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        return Ok(Some(ws::wallclock_epoch(genesis, now)));
    }
    Ok(None)
}

fn fail(msg: impl std::fmt::Display) -> i32 {
    eprintln!("error: {msg}");
    1
}

// ---------------------------------------------------------------------------
// stage
// ---------------------------------------------------------------------------

fn cmd_stage(args: &[String]) -> i32 {
    let inner = || -> Result<i32, String> {
        let layout = Layout::new(need(args, "--dir")?);
        let pins = pins_from(args)?;
        let finalized_epoch = parse_u64(need(args, "--finalized-epoch")?, "--finalized-epoch")?;
        let finalized_root = match arg_value(args, "--finalized-root") {
            Some(h) => Some(parse_hex32(h, "--finalized-root")?),
            None => None,
        };
        let epoch_override = match arg_value(args, "--epoch") {
            Some(e) => Some(parse_u64(e, "--epoch")?),
            None => None,
        };
        let req = StageRequest {
            layout: &layout,
            finalized_epoch,
            finalized_root,
            pins,
            epoch_override,
        };

        // Find the target before running the producer, so a NOTHING_DUE tick
        // costs nothing and a producer is only invoked for a real epoch.
        let target = match epoch_override {
            Some(e) => e,
            None => match due_epoch(finalized_epoch) {
                Some(e) => e,
                None => {
                    println!("NOTHING_DUE finalized_epoch={finalized_epoch}");
                    return Ok(0);
                }
            },
        };

        let payload = match (arg_value(args, "--payload"), arg_value(args, "--producer")) {
            (Some(p), None) => fs::read(p).map_err(|e| format!("--payload {p}: {e}"))?,
            (None, Some(cmd)) => run_producer(cmd, target)?,
            _ => return Err("exactly one of --payload or --producer is required".into()),
        };

        match stage(&req, &payload).map_err(|e| e.to_string())? {
            StageOutcome::NothingDue => println!("NOTHING_DUE finalized_epoch={finalized_epoch}"),
            StageOutcome::AlreadyPublished { epoch } => println!("ALREADY_PUBLISHED epoch={epoch}"),
            StageOutcome::AlreadyStaged { epoch, digest } => {
                println!("ALREADY_STAGED epoch={epoch} digest={}", hex::encode(digest))
            }
            StageOutcome::Staged { epoch, digest } => {
                println!("STAGED epoch={epoch} digest={}", hex::encode(digest));
                println!("signing request: {}", layout.signing_request(epoch).display());
            }
        }
        Ok(0)
    };
    inner().unwrap_or_else(fail)
}

/// Run the payload producer: `{epoch}` and `{out}` in the command line are
/// substituted, the command runs under `sh -c`, and the payload is read back
/// from the `{out}` file. The producer is the checkpoint tool; this pipeline
/// only schedules and judges it.
fn run_producer(template: &str, epoch: u64) -> Result<Vec<u8>, String> {
    let out = env::temp_dir().join(format!("ws-payload-{epoch}-{}.bin", std::process::id()));
    let cmd = template
        .replace("{epoch}", &epoch.to_string())
        .replace("{out}", &out.display().to_string());
    let status = Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .status()
        .map_err(|e| format!("producer failed to start: {e}"))?;
    if !status.success() {
        return Err(format!("producer exited with {status}: {cmd}"));
    }
    let payload = fs::read(&out).map_err(|e| format!("producer wrote no {}: {e}", out.display()))?;
    let _ = fs::remove_file(&out);
    Ok(payload)
}

// ---------------------------------------------------------------------------
// sign
// ---------------------------------------------------------------------------

fn cmd_sign(args: &[String]) -> i32 {
    let inner = || -> Result<i32, String> {
        let payload_path = need(args, "--payload")?;
        let sk_path = need(args, "--secret-key")?;
        let out_path = need(args, "--out")?;
        let payload = fs::read(payload_path).map_err(|e| format!("--payload: {e}"))?;
        let sk = fs::read(sk_path).map_err(|e| format!("--secret-key: {e}"))?;

        let expect_pk = match (arg_value(args, "--signer-set"), arg_value(args, "--signer-index")) {
            (Some(set_path), Some(idx)) => {
                let set = decode_signer_set_file(&fs::read(set_path).map_err(|e| e.to_string())?)
                    .map_err(|e| e.to_string())?;
                let k: usize = idx.parse().map_err(|_| "--signer-index: not a number")?;
                let signer =
                    set.signers.get(k).ok_or(format!("--signer-index {k}: not in the set"))?;
                Some(signer.pubkey)
            }
            (None, None) => None,
            _ => return Err("--signer-set and --signer-index go together".into()),
        };

        let sig = sign_payload(&payload, &sk, expect_pk.as_ref()).map_err(|e| e.to_string())?;
        fs::write(out_path, &sig).map_err(|e| format!("--out: {e}"))?;
        let cp = decode_checkpoint(&payload).map_err(|e| e.to_string())?;
        println!(
            "signed epoch={} digest={} sig_bytes={} -> {}",
            cp.epoch,
            hex::encode(cp.ws_digest()),
            sig.len(),
            out_path
        );
        println!("return ONLY this signature file to the coordinator.");
        Ok(0)
    };
    inner().unwrap_or_else(fail)
}

// ---------------------------------------------------------------------------
// seal
// ---------------------------------------------------------------------------

fn cmd_seal(args: &[String]) -> i32 {
    let inner = || -> Result<i32, String> {
        let layout = Layout::new(need(args, "--dir")?);
        let epoch = parse_u64(need(args, "--epoch")?, "--epoch")?;
        let pins = pins_from(args)?;
        let set_path = need(args, "--signer-set")?;
        let set_bytes = fs::read(set_path).map_err(|e| format!("--signer-set: {e}"))?;
        let set = decode_signer_set_file(&set_bytes).map_err(|e| e.to_string())?;

        // Explicit --sig index:file pairs, else scan signatures/<epoch>/.
        let mut sigs: Vec<(u8, Vec<u8>)> = Vec::new();
        let explicit: Vec<&String> = {
            let mut v = Vec::new();
            let mut it = args.iter();
            while let Some(a) = it.next() {
                if a == "--sig" {
                    v.push(it.next().ok_or("--sig needs <index>:<file>")?);
                }
            }
            v
        };
        if !explicit.is_empty() {
            for spec in explicit {
                let (idx, path) =
                    spec.split_once(':').ok_or(format!("--sig {spec}: want <index>:<file>"))?;
                let index: u8 = idx.parse().map_err(|_| format!("--sig {spec}: bad index"))?;
                sigs.push((index, fs::read(path).map_err(|e| format!("--sig {spec}: {e}"))?));
            }
        } else {
            let dir = layout.signatures_dir(epoch);
            let entries = fs::read_dir(&dir)
                .map_err(|e| format!("no collected signatures at {}: {e}", dir.display()))?;
            for entry in entries {
                let entry = entry.map_err(|e| e.to_string())?;
                let name = entry.file_name().to_string_lossy().into_owned();
                let Some(idx) =
                    name.strip_prefix("sig-").and_then(|r| r.strip_suffix(".bin"))
                else {
                    continue;
                };
                let index: u8 =
                    idx.parse().map_err(|_| format!("{name}: index is not a u8"))?;
                sigs.push((index, fs::read(entry.path()).map_err(|e| e.to_string())?));
            }
            if sigs.is_empty() {
                return Err(format!(
                    "no sig-<index>.bin files under {} — collect the keyholders' \
                     signatures there or pass --sig <index>:<file>",
                    dir.display()
                ));
            }
            sigs.sort_by_key(|(i, _)| *i);
        }

        let outcome =
            seal(&layout, epoch, &set, &set_bytes, sigs, &pins).map_err(|e| e.to_string())?;
        println!(
            "SEALED epoch={} digest={} signatures={} -> {}",
            outcome.epoch,
            hex::encode(outcome.digest),
            outcome.signature_count,
            outcome.envelope_path.display()
        );
        if outcome.arrangement_past_review {
            eprintln!(
                "WARNING: the signer arrangement is past its 12-month review deadline \
                 (inside grace). The review ADR is overdue; envelopes will be REFUSED \
                 after the grace period (ws.rs dead-man's switch)."
            );
        }
        println!(
            "publish everything under {} to ALL channels (see \
             docs/specs/BLOCH-WS-PUBLICATION-PIPELINE.md §4), and quote the digest \
             in the announcement.",
            layout.publish_dir(epoch).display()
        );
        Ok(0)
    };
    inner().unwrap_or_else(fail)
}

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------

fn cmd_verify(args: &[String]) -> i32 {
    let inner = || -> Result<i32, String> {
        let env_bytes =
            fs::read(need(args, "--checkpoint")?).map_err(|e| format!("--checkpoint: {e}"))?;
        let set_bytes =
            fs::read(need(args, "--signer-set")?).map_err(|e| format!("--signer-set: {e}"))?;
        let pins = pins_from(args)?;
        let wall = wall_epoch_from(args)?;

        let report = match verify_files(&env_bytes, &set_bytes, &pins, wall) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("NOT GENUINE: {e}");
                eprintln!("Do not boot a node from this artifact.");
                return Ok(1);
            }
        };
        let cp = &report.checkpoint;
        println!("GENUINE under the supplied signer arrangement and chain pins.");
        println!("  epoch:              {}", cp.epoch);
        println!("  block_root:         {}", hex::encode(cp.block_root));
        println!("  state_root:         {}", hex::encode(cp.state_root));
        println!("  validator_set_root: {}", hex::encode(cp.validator_set_root));
        println!("  ws_digest:          {}", hex::encode(report.digest));
        println!(
            "  quorum:             {} of {} required signatures verified, {} external \
             (minimum {})",
            report.signature_count, report.threshold, report.external_count, report.min_external
        );
        if report.arrangement_past_review {
            println!(
                "  WARNING: signer arrangement past its 12-month review deadline (inside \
                 grace) — check for a renewal announcement."
            );
        }
        match report.freshness {
            None => println!(
                "  freshness:          NOT CHECKED (pass --wall-epoch or --genesis-unix); \
                 a checkpoint older than {WS_PERIOD_EPOCHS} epochs must not be booted from"
            ),
            Some(Freshness::Fresh { age }) => {
                println!("  freshness:          fresh (age {age} epochs, soft limit {WS_FRESH_EPOCHS})")
            }
            Some(Freshness::Stale { age }) => println!(
                "  freshness:          STALE (age {age} epochs, past the soft limit \
                 {WS_FRESH_EPOCHS}, hard limit {WS_PERIOD_EPOCHS}) — usable, but fetch a \
                 newer one if any exists"
            ),
            Some(Freshness::Expired { age }) => {
                println!(
                    "  freshness:          EXPIRED (age {age} epochs >= {WS_PERIOD_EPOCHS}) — \
                     DO NOT boot from this checkpoint"
                );
                return Ok(1);
            }
        }
        println!();
        println!(
            "Final step (out of band): compare the ws_digest above against at least two \
             independent publication channels before use."
        );
        Ok(0)
    };
    inner().unwrap_or_else(fail)
}

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

fn cmd_status(args: &[String]) -> i32 {
    let inner = || -> Result<i32, String> {
        let layout = Layout::new(need(args, "--dir")?);
        let latest = layout.latest_sealed().map_err(|e| e.to_string())?;
        match latest {
            Some(e) => println!("latest sealed epoch: {e}"),
            None => println!("latest sealed epoch: none — no checkpoint has ever been sealed"),
        }
        if let Some(f) = arg_value(args, "--finalized-epoch") {
            let finalized = parse_u64(f, "--finalized-epoch")?;
            match due_epoch(finalized) {
                None => println!("due: nothing (first interval not complete)"),
                Some(due) => {
                    let staged = layout.payload_bin(due).exists();
                    let sealed = layout.envelope_bin(due).exists();
                    println!(
                        "due: epoch {due} — staged: {staged}, sealed: {sealed}{}",
                        if sealed { "" } else if staged { "  <- signing ceremony outstanding" } else { "  <- stage it" }
                    );
                }
            }
        }
        if let (Some(latest), Some(wall)) = (latest, wall_epoch_from(args)?) {
            match freshness(latest, wall) {
                Freshness::Fresh { age } => println!("freshness: fresh (age {age})"),
                Freshness::Stale { age } => println!(
                    "freshness: STALE (age {age} >= soft limit {WS_FRESH_EPOCHS}) — \
                     the cadence has slipped; fix the pipeline before it matters"
                ),
                Freshness::Expired { age } => println!(
                    "freshness: EXPIRED (age {age} >= {WS_PERIOD_EPOCHS}) — LIVENESS EVENT: \
                     fresh sync is degraded until a new checkpoint is published"
                ),
            }
        }
        Ok(0)
    };
    inner().unwrap_or_else(fail)
}

// ---------------------------------------------------------------------------
// digest
// ---------------------------------------------------------------------------

fn cmd_digest(args: &[String]) -> i32 {
    let inner = || -> Result<i32, String> {
        let bytes = fs::read(need(args, "--file")?).map_err(|e| format!("--file: {e}"))?;
        // Accept either the bare payload or a sealed envelope.
        let cp = decode_checkpoint(&bytes)
            .or_else(|_| decode_envelope_file(&bytes).map(|e| e.checkpoint))
            .map_err(|e| format!("neither a payload nor an envelope: {e}"))?;
        println!("{}", hex::encode(cp.ws_digest()));
        Ok(0)
    };
    inner().unwrap_or_else(fail)
}
