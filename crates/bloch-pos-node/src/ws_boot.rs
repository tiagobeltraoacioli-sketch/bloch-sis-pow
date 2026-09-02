// SPDX-License-Identifier: AGPL-3.0-or-later

//! Weak-subjectivity boot wiring — the node-side consumer of
//! `bloch_pos_committee::ws` (BLOCH-WEAK-SUBJECTIVITY.md §4).
//!
//! The pure crate decides; this module supplies what the decision functions
//! declare as inputs and acts on what they return. Nothing here re-derives a
//! rule that `ws.rs` already states: the window, the anti-rollback order, the
//! four boot states, the never-reorg cross-check and the genesis anchor are
//! all called, not copied.
//!
//! ## What is wired, at boot, in order
//!
//! 1. **`ws_latest`** (§4.1): the highest-epoch checkpoint this node has ever
//!    verified, persisted as `ws_latest.bin` (the 154 canonical bytes) in the
//!    data dir. When none exists the **genesis anchor is the first
//!    checkpoint** ([`ws::genesis_anchor`]): trusting it is trusting the
//!    genesis manifest, the same trust every node of the network already
//!    makes to exist at all — which is exactly why a fresh devnet still boots
//!    with no flags.
//! 2. **`--ws-checkpoint <file>`**: a [`CheckpointEnvelope`] loaded from disk
//!    and verified m-of-n under the real hybrid suite
//!    ([`ws::verify_envelope`] through [`WsHybridVerifier`] →
//!    `bloch_crypto`). This devnet build bakes no Phase A signer keys, so the
//!    arrangement comes from `--ws-signer-set <file>`; a release build will
//!    hard-code the §6 sets and the flag becomes an override.
//! 3. **Anti-rollback** ([`ws::accept`]): an envelope older than `ws_latest`
//!    is logged and ignored; the same epoch with a different digest is
//!    [`Acceptance::Conflict`] and refuses the boot loudly — a stolen old
//!    quorum signature must not refresh a node backward, and an equivocal
//!    publication must never be silently overwritten.
//! 4. **Cross-check** ([`ws::cross_check`]): a published checkpoint NEVER
//!    reorganizes a node that has finality of its own. A conflict is a
//!    screaming alarm and the node keeps its database; only the newcomer and
//!    the long-offline can be moved by the signers.
//! 5. **The four boot states** ([`ws::boot_decision`], §4.2): `Resume` /
//!    `ResumeStaleWarn` proceed (the latter warns), `RequireCheckpoint` and
//!    `RefuseStale` refuse to sync unless a sufficiently fresh anchor exists —
//!    and the refusal is the mechanism working, so the error message says so
//!    and tells the operator where a checkpoint comes from.
//!
//! After boot the engine enforces the anchor forward: when its own finality
//! first reaches the anchor's epoch it compares roots ([`ws::cross_check`]
//! again, from live state). A node that had no finality of its own at boot
//! treats a mismatch as fatal — a fresh node must never keep following a
//! chain that contradicts its trust anchor; a node that booted on its own
//! finality treats it as the WS_CONFLICT alarm, never a reorg.
//!
//! ## Checkpoint-sync state download (§4.3.2) — WIRED
//!
//! An admitted non-genesis anchor is now a *sync starting point*, not only a
//! floor: after this gate passes, the engine's acquisition phase
//! (`engine::run`, using `crate::state_sync`) obtains the checkpoint's
//! committed state — from a local artifact (`--state-snapshot`) or from
//! peers in verified chunks (`--state-sync`) — and installs it only after
//! the recomputed state root reproduces the checkpoint's `state_root`
//! (`transition::snapshot::restore` is the sole constructor and carries the
//! check; no transport is trusted). Without either flag the node still
//! replays from genesis under the anchor, and says how to do better.
//!
//! ## Honestly not wired (devnet stage)
//!
//! The `RefuseStale` recovery can still only establish "checkpoint descends
//! from local history" against blocks the node already has: a node WITH own
//! (stale) finality whose fresh checkpoint lies beyond its local head halts
//! for the operator — adopting it would abandon local history, and
//! `--ws-accept-reorg` is not implemented. State download moves fresh
//! installs and nodes without finality of their own; it does not overrule
//! anyone's database.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use bloch_pos_committee::staking::{HybridKeyVerifier, HYBRID_PK_BYTES};
use bloch_pos_committee::ws::{
    self, Acceptance, BootDecision, CheckpointEnvelope, CrossCheck, Reconciliation, Signer,
    SignerSet, WeakSubjectivityCheckpoint,
};

use crate::codec::{DecodeErr, Reader};

// ---------------------------------------------------------------------------
// The hybrid verifier the envelope check runs under
// ---------------------------------------------------------------------------

/// The real ML-DSA-65 ‖ Falcon-1024 verifier for checkpoint envelopes.
///
/// `ws::verify_envelope` receives the halves pre-split at the fixed points
/// (the AND-composition lives in `staking::verify_hybrid`, called — not
/// copied); each half goes to its own primitive in `bloch_crypto`. Distinct
/// from [`crate::keys::HybridVerifier`], which is keyed by validator index
/// against the genesis registry — checkpoint signers are not validators.
pub struct WsHybridVerifier;

impl HybridKeyVerifier for WsHybridVerifier {
    fn verify_mldsa65(&self, pubkey: &[u8], signing_root: &[u8; 32], sig: &[u8]) -> bool {
        bloch_crypto::crypto::verify_mldsa65_raw(pubkey, signing_root, sig)
    }
    fn verify_falcon1024(&self, pubkey: &[u8], signing_root: &[u8; 32], sig: &[u8]) -> bool {
        bloch_crypto::crypto::falcon::verify(pubkey, signing_root, sig)
    }
}

/// Devnet network id, derived from the genesis-manifest digest: each devnet
/// is its own network, so a checkpoint from one can never verify on another
/// (`WrongNetwork`/`WrongGenesisRoot` by construction). The mainnet manifest
/// format — a superset that does not exist yet — will carry an explicit,
/// published network id instead.
pub fn network_id_of(genesis_digest: &[u8; 32]) -> u32 {
    u32::from_le_bytes(genesis_digest[..4].try_into().unwrap())
}

// ---------------------------------------------------------------------------
// File forms. The checkpoint's canonical 154 bytes are the committee crate's;
// everything here only frames them (same division of labor as codec.rs).
// ---------------------------------------------------------------------------

const WS_ENVELOPE_MAGIC: &[u8; 8] = b"BPOSWSE1";
const WS_SIGNER_SET_MAGIC: &[u8; 8] = b"BPOSWSS1";
/// `signer_index` is a u8 in the envelope, so no artifact can carry more.
const MAX_SIGNERS: usize = 256;

/// Decode the canonical checkpoint bytes. The committee crate's
/// `canonical_serialize` is the single authority on the layout; this decoder
/// proves itself against it on every call by re-serializing and comparing —
/// a drift between the two cannot silently mint a second byte layout.
pub fn decode_checkpoint(bytes: &[u8]) -> Result<WeakSubjectivityCheckpoint, DecodeErr> {
    if bytes.len() != ws::WS_CHECKPOINT_BYTES {
        return Err(DecodeErr("checkpoint: wrong length"));
    }
    let mut r = Reader::new(bytes);
    let cp = WeakSubjectivityCheckpoint {
        version: r.u16()?,
        network_id: r.u32()?,
        genesis_root: r.h32()?,
        epoch: r.u64()?,
        block_root: r.h32()?,
        state_root: r.h32()?,
        validator_set_root: r.h32()?,
        issued_at: r.u64()?,
        signer_set_id: r.u32()?,
    };
    r.finish()?;
    if cp.canonical_serialize() != bytes {
        return Err(DecodeErr("checkpoint: decoder disagrees with canonical_serialize"));
    }
    Ok(cp)
}

/// Encode a distribution envelope: magic ‖ canonical checkpoint ‖ signature
/// list. This is the node's file framing of the spec's `wscheckpoint-*.bin`
/// artifact family; the digest signers sign is over the canonical bytes only.
/// Not called on the node's boot path — the *publication* side (the signing
/// ceremony of §6, `ws_tool`) writes these files and the boot path only
/// reads them. Living next to its decoder, with the round-trip tests below,
/// is what keeps the two from drifting into two formats.
pub fn encode_envelope_file(env: &CheckpointEnvelope) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(WS_ENVELOPE_MAGIC);
    out.extend_from_slice(&env.checkpoint.canonical_serialize());
    out.extend_from_slice(&(env.signatures.len() as u32).to_le_bytes());
    for (index, sig) in &env.signatures {
        out.push(*index);
        crate::codec::put_bytes(&mut out, sig);
    }
    out
}

pub fn decode_envelope_file(bytes: &[u8]) -> Result<CheckpointEnvelope, DecodeErr> {
    let mut r = Reader::new(bytes);
    if r.take(8)? != WS_ENVELOPE_MAGIC {
        return Err(DecodeErr("not a checkpoint envelope file"));
    }
    let checkpoint = decode_checkpoint(r.take(ws::WS_CHECKPOINT_BYTES)?)?;
    let n = r.u32()? as usize;
    if n > MAX_SIGNERS {
        return Err(DecodeErr("envelope: signature count over cap"));
    }
    let mut signatures = Vec::with_capacity(n);
    for _ in 0..n {
        let index = r.take(1)?[0];
        signatures.push((index, r.bytes()?));
    }
    r.finish()?;
    Ok(CheckpointEnvelope { checkpoint, signatures })
}

/// Encode a signer arrangement (written by the ceremony side, `ws_tool`;
/// a release build will additionally hard-code the §6 arrangements next to
/// its pinned genesis, and this file form then becomes a test fixture).
/// Pubkeys are the RAW hybrid halves (`HYBRID_PK_BYTES`), the form
/// `ws::Signer` carries — not the 4-byte suite envelope.
pub fn encode_signer_set_file(set: &SignerSet) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(WS_SIGNER_SET_MAGIC);
    out.extend_from_slice(&set.id.to_le_bytes());
    out.extend_from_slice(&(set.threshold as u32).to_le_bytes());
    out.extend_from_slice(&(set.min_external as u32).to_le_bytes());
    out.extend_from_slice(&set.adopted_epoch.to_le_bytes());
    out.extend_from_slice(&(set.signers.len() as u32).to_le_bytes());
    for s in &set.signers {
        out.push(u8::from(s.external));
        out.extend_from_slice(&s.pubkey);
    }
    out
}

pub fn decode_signer_set_file(bytes: &[u8]) -> Result<SignerSet, DecodeErr> {
    let mut r = Reader::new(bytes);
    if r.take(8)? != WS_SIGNER_SET_MAGIC {
        return Err(DecodeErr("not a signer-set file"));
    }
    let id = r.u32()?;
    let threshold = r.u32()? as usize;
    let min_external = r.u32()? as usize;
    let adopted_epoch = r.u64()?;
    let n = r.u32()? as usize;
    if n > MAX_SIGNERS {
        return Err(DecodeErr("signer set: count over cap"));
    }
    let mut signers = Vec::with_capacity(n);
    for _ in 0..n {
        let external = match r.take(1)?[0] {
            0 => false,
            1 => true,
            _ => return Err(DecodeErr("signer set: external flag not 0/1")),
        };
        let mut pubkey = [0u8; HYBRID_PK_BYTES];
        pubkey.copy_from_slice(r.take(HYBRID_PK_BYTES)?);
        signers.push(Signer { pubkey, external });
    }
    r.finish()?;
    if threshold == 0 || threshold > signers.len() || min_external > threshold {
        return Err(DecodeErr("signer set: incoherent quorum shape"));
    }
    Ok(SignerSet { id, signers, threshold, min_external, adopted_epoch })
}

// ---------------------------------------------------------------------------
// ws_latest persistence (§4.1)
// ---------------------------------------------------------------------------

const WS_LATEST_FILE: &str = "ws_latest.bin";

/// Load the stored `ws_latest`, refusing a file that belongs to another
/// network — the same §3.1 refusal-not-migration rule the meta marker
/// applies.
pub fn load_latest(
    dir: &Path,
    network_id: u32,
    genesis_root: &[u8; 32],
) -> io::Result<Option<WeakSubjectivityCheckpoint>> {
    let path = dir.join(WS_LATEST_FILE);
    let bytes = match fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let bad = |m: String| io::Error::new(io::ErrorKind::InvalidData, m);
    let cp = decode_checkpoint(&bytes)
        .map_err(|e| bad(format!("{}: {e}", path.display())))?;
    if cp.network_id != network_id || &cp.genesis_root != genesis_root {
        return Err(bad(format!(
            "{} belongs to a different network; refusing (delete it yourself if that is \
             really what you want)",
            path.display()
        )));
    }
    Ok(Some(cp))
}

/// Persist `ws_latest` (write-to-temp + rename, like the block-log rewrite).
pub fn save_latest(dir: &Path, cp: &WeakSubjectivityCheckpoint) -> io::Result<()> {
    let tmp = dir.join("ws_latest.bin.tmp");
    fs::write(&tmp, cp.canonical_serialize())?;
    fs::rename(&tmp, dir.join(WS_LATEST_FILE))
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

/// CLI-supplied weak-subjectivity inputs.
pub struct WsConfig {
    pub checkpoint: Option<PathBuf>,
    pub signer_set: Option<PathBuf>,
}

/// What the engine carries out of a successful boot: the anchor it must
/// enforce once its own finality reaches `anchor_epoch`.
#[derive(Debug)]
pub struct WsOutcome {
    pub anchor_epoch: u64,
    pub anchor_root: [u8; 32],
    /// True when the node had no finality of its own at boot: the anchor is
    /// then its ONLY defense, and a later contradiction is fatal. False for a
    /// node that booted on its own finality — there a contradiction is the
    /// WS_CONFLICT alarm, never a reorg and never an exit.
    pub anchor_is_hard: bool,
    /// Prominent messages the engine prints (collected so tests can assert
    /// on them instead of scraping stderr).
    pub warnings: Vec<String>,
    /// The full admitted anchor artifact. `anchor_epoch`/`anchor_root` above
    /// are its enforcement view; checkpoint-sync state download needs the
    /// rest — above all `state_root`, which is what a downloaded state must
    /// reproduce (`state_sync::import`).
    pub checkpoint: WeakSubjectivityCheckpoint,
}

fn hex32(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn window_days() -> u64 {
    ws::WS_PERIOD_EPOCHS / ws::EPOCHS_PER_DAY
}

/// The whole boot sequence described in the module docs. `local_root_at`
/// returns this node's own finalized checkpoint root at an epoch (`None` if
/// its finality has not reached it); `is_canonical` answers whether a block
/// root is on the node's replayed canonical chain.
#[allow(clippy::too_many_arguments)]
pub fn boot(
    cfg: &WsConfig,
    data_dir: &Path,
    network_id: u32,
    genesis_root: &[u8; 32],
    genesis_anchor: &WeakSubjectivityCheckpoint,
    wall_epoch: u64,
    has_local_finality: bool,
    local_finalized: (u64, [u8; 32]),
    local_root_at: impl Fn(u64) -> Option<[u8; 32]>,
    is_canonical: impl Fn(&[u8; 32]) -> bool,
) -> io::Result<Result<WsOutcome, String>> {
    let mut warnings = Vec::new();

    // 1. ws_latest, with the genesis anchor as the first checkpoint when no
    //    other has ever been verified (§4.1 precedence, source 3).
    let mut anchor = match load_latest(data_dir, network_id, genesis_root)? {
        Some(cp) => cp,
        None => {
            save_latest(data_dir, genesis_anchor)?;
            *genesis_anchor
        }
    };

    // 2. Operator-supplied envelope (§4.1 precedence, source 1).
    let mut published: Option<WeakSubjectivityCheckpoint> = None;
    if let Some(path) = &cfg.checkpoint {
        let bad = |m: String| io::Error::new(io::ErrorKind::InvalidData, m);
        let env = decode_envelope_file(&fs::read(path)?)
            .map_err(|e| bad(format!("{}: {e}", path.display())))?;
        let Some(set_path) = &cfg.signer_set else {
            return Err(bad(
                "--ws-checkpoint given but no signer arrangement is known: this devnet \
                 build bakes no Phase A keys, so pass --ws-signer-set <file> (release \
                 builds will carry the arrangement of BLOCH-WEAK-SUBJECTIVITY.md §6)"
                    .into(),
            ));
        };
        let set = decode_signer_set_file(&fs::read(set_path)?)
            .map_err(|e| bad(format!("{}: {e}", set_path.display())))?;
        let ok = ws::verify_envelope(&env, &set, network_id, genesis_root, &WsHybridVerifier)
            .map_err(|e| {
                bad(format!(
                    "checkpoint envelope {} REFUSED: {e:?} (ws digest {})",
                    path.display(),
                    hex32(&env.checkpoint.ws_digest())
                ))
            })?;
        if ok.arrangement_past_review {
            warnings.push(format!(
                "WARNING: signer arrangement {} is past its 12-month review deadline \
                 (inside grace). The review ADR is overdue — §6.3.",
                set.id
            ));
        }
        let cp = env.checkpoint;

        // 4 (order matters): the cross-check against OWN finality comes
        // before admission. A published checkpoint that contradicts what this
        // node itself finalized is an alarm and is NOT admitted as an anchor;
        // it can never reorganize us (§5's structural limit).
        if has_local_finality {
            match ws::cross_check(local_root_at(cp.epoch), &cp) {
                CrossCheck::Consistent => {
                    warnings.push(format!(
                        "ws checkpoint at epoch {} is consistent with own finality",
                        cp.epoch
                    ));
                    published = Some(cp);
                }
                CrossCheck::AheadOfLocal => published = Some(cp),
                CrossCheck::Conflict { local_root, published_root } => {
                    warnings.push(format!(
                        "########################################################\n\
                         WS_CONFLICT: the published checkpoint contradicts this \
                         node's OWN finality at epoch {}.\n  local finalized root: {}\n  \
                         published root:       {}\nA checkpoint can never override a \
                         running node's finality — NOT reorganizing, KEEPING this \
                         database. Alert the operator and the publication channels: \
                         either the signers published a false checkpoint or this node \
                         is on a forged branch.\n\
                         ########################################################",
                        cp.epoch,
                        hex32(&local_root),
                        hex32(&published_root),
                    ));
                }
            }
        } else {
            published = Some(cp);
        }

        // 3. Anti-rollback against the stored ws_latest (§4.1).
        if let Some(cp) = published {
            match ws::accept(Some(&anchor), &cp) {
                Acceptance::Store => {
                    save_latest(data_dir, &cp)?;
                    anchor = cp;
                }
                Acceptance::Ignore => warnings.push(format!(
                    "ws checkpoint at epoch {} is not newer than stored ws_latest \
                     (epoch {}); logged and ignored (anti-rollback, §4.1)",
                    cp.epoch, anchor.epoch
                )),
                Acceptance::Conflict => {
                    return Ok(Err(format!(
                        "WS_CONFLICT (equivocal checkpoint): the supplied checkpoint \
                         carries the same epoch {} as the stored ws_latest but a \
                         different digest.\n  stored digest:   {}\n  incoming digest: {}\n\
                         Two validly-signed checkpoints for one epoch mean a \
                         quietly-replaced publication or an equivocal quorum — never a \
                         silent overwrite. Refusing to start; verify the digest across \
                         independent publication channels before trusting either \
                         artifact.",
                        cp.epoch,
                        hex32(&anchor.ws_digest()),
                        hex32(&cp.ws_digest()),
                    )));
                }
            }
        }
    }

    // 5. The four boot states (§4.2).
    let (fin_epoch, fin_root) = local_finalized;
    let age = wall_epoch.saturating_sub(fin_epoch);
    let anchor_age = wall_epoch.saturating_sub(anchor.epoch);
    let gate: Result<(), String> = match ws::boot_decision(has_local_finality, age) {
        BootDecision::Resume => Ok(()),
        BootDecision::ResumeStaleWarn => {
            warnings.push(format!(
                "WARNING: this node's finalized knowledge is {age} epochs old — inside \
                 the weak-subjectivity window ({} epochs) but past the freshness \
                 threshold ({}). Resuming from own finality, but fetch a fresh \
                 checkpoint (--ws-checkpoint) before following any peer that offers a \
                 competing finalized branch.",
                ws::WS_PERIOD_EPOCHS,
                ws::WS_FRESH_EPOCHS,
            ));
            Ok(())
        }
        BootDecision::RequireCheckpoint => {
            if anchor_age < ws::WS_PERIOD_EPOCHS {
                let which = if anchor.signer_set_id == ws::WS_GENESIS_SIGNER_SET_ID {
                    "the genesis anchor".to_string()
                } else {
                    format!("checkpoint epoch {}", anchor.epoch)
                };
                warnings.push(format!(
                    "fresh node: syncing under {which} (age {anchor_age} of {} epochs)",
                    ws::WS_PERIOD_EPOCHS
                ));
                Ok(())
            } else {
                Err(require_checkpoint_message(&anchor, anchor_age))
            }
        }
        BootDecision::RefuseStale => {
            if anchor_age < ws::WS_PERIOD_EPOCHS {
                // Recovery (§4.2): a fresh verified checkpoint exists. Descent
                // can only be established against blocks this node already
                // has — header-sync-forward does not exist at this milestone.
                let descends = is_canonical(&anchor.block_root);
                match ws::reconcile(&anchor, fin_root, descends) {
                    Reconciliation::ContinueForward => {
                        warnings.push(format!(
                            "own finality is {age} epochs old (beyond the {}-epoch \
                             window) but a fresh checkpoint at epoch {} descends from \
                             local history: continuing forward under it.",
                            ws::WS_PERIOD_EPOCHS,
                            anchor.epoch
                        ));
                        Ok(())
                    }
                    Reconciliation::HaltForOperator {
                        local_finalized_root,
                        checkpoint_root,
                    } => Err(format!(
                        "ERR_WS_STALE recovery halted: the fresh checkpoint does not \
                         verifiably descend from this node's finalized head, and the \
                         node will NOT silently discard its database — whichever side \
                         is wrong, that is how evidence disappears.\n  \
                         local finalized root: {}\n  checkpoint root:      {}\n\
                         Either local history was forged while the node was away, or \
                         the published checkpoint is wrong (or, at this devnet stage, \
                         the checkpoint is simply beyond the local head and \
                         header-sync-forward is not implemented). Resuming requires an \
                         explicit operator decision: compare both roots against \
                         operators you trust, then move the data dir aside by hand. \
                         (--ws-accept-reorg is not implemented yet.)",
                        hex32(&local_finalized_root),
                        hex32(&checkpoint_root),
                    )),
                }
            } else {
                Err(format!(
                    "ERR_WS_STALE: this node's own finalized knowledge is {age} epochs \
                     old — at or beyond the weak-subjectivity window of {} epochs \
                     (≈ {} days at the mainnet slot cadence). Every validator that \
                     signed this database's finality markers may already have \
                     withdrawn, and could sign a conflicting continuation for free; \
                     the local markers are no longer a defense, so no peer can be \
                     safely followed. This refusal is the mechanism working, not a \
                     fault. Recover by obtaining a recent signed checkpoint OUT OF \
                     BAND (see below) and restarting with --ws-checkpoint <file>.\n\n{}",
                    ws::WS_PERIOD_EPOCHS,
                    window_days(),
                    where_checkpoints_come_from(),
                ))
            }
        }
    };

    Ok(match gate {
        Ok(()) => Ok(WsOutcome {
            anchor_epoch: anchor.epoch,
            anchor_root: anchor.block_root,
            anchor_is_hard: !has_local_finality,
            warnings,
            checkpoint: anchor,
        }),
        Err(msg) => Err(msg),
    })
}

fn require_checkpoint_message(anchor: &WeakSubjectivityCheckpoint, anchor_age: u64) -> String {
    let which = if anchor.signer_set_id == ws::WS_GENESIS_SIGNER_SET_ID {
        "the genesis anchor".to_string()
    } else {
        format!("a checkpoint at epoch {}", anchor.epoch)
    };
    format!(
        "ERR_WS_REQUIRE_CHECKPOINT: refusing to sync — and this is the mechanism \
         working, not a fault.\n\n\
         This node has no finalized history of its own, and its only trust anchor \
         ({which}) is {anchor_age} epochs old — at or beyond the weak-subjectivity \
         window of {} epochs (≈ {} days at the mainnet slot cadence). Under proof of \
         stake, validators who exited and withdrew long ago can sign a complete forged \
         history at zero cost; beyond the window, nothing inside the protocol lets a \
         syncing node tell that forgery from the chain the network actually lived. A \
         recent checkpoint obtained OUT OF BAND is the only sound way in.\n\n{}",
        ws::WS_PERIOD_EPOCHS,
        window_days(),
        where_checkpoints_come_from(),
    )
}

fn where_checkpoints_come_from() -> String {
    "To obtain a checkpoint (BLOCH-WEAK-SUBJECTIVITY.md §2.3, §4.1):\n  \
     1. Fetch the latest signed checkpoint envelope from a channel you trust: the \
     Foundation site, the GitHub/GitLab release pages, the explorer front page, or \
     the announcement channel.\n  \
     2. Compare its 64-hex ws digest across AT LEAST TWO independent channels — \
     agreement across independent operators is the evidence, not the artifact's \
     say-so.\n  \
     3. Restart with:  --ws-checkpoint <file>   (on devnet builds also \
     --ws-signer-set <file>, since no signer arrangement is baked in)."
        .to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use bloch_pos_committee::ws::{
        WS_FORMAT_VERSION, WS_PERIOD_EPOCHS, WS_PHASE_A_MIN_EXTERNAL, WS_PHASE_A_SIGNERS,
        WS_PHASE_A_THRESHOLD,
    };

    const NET: u32 = 0xD3_00_00_01;
    const GEN: [u8; 32] = [0x61; 32];

    fn checkpoint(epoch: u64) -> WeakSubjectivityCheckpoint {
        WeakSubjectivityCheckpoint {
            version: WS_FORMAT_VERSION,
            network_id: NET,
            genesis_root: GEN,
            epoch,
            block_root: [0x22; 32],
            state_root: [0x33; 32],
            validator_set_root: [0x44; 32],
            issued_at: 1_800_000_000,
            signer_set_id: 1,
        }
    }

    fn genesis_anchor() -> WeakSubjectivityCheckpoint {
        ws::genesis_anchor(NET, GEN, [0x33; 32], [0u8; 32], 1_800_000_000)
    }

    fn tmpdir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("bloch-ws-boot-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn no_flags() -> WsConfig {
        WsConfig { checkpoint: None, signer_set: None }
    }

    // -- codecs -------------------------------------------------------------

    #[test]
    fn checkpoint_bytes_round_trip_and_reject_junk() {
        let cp = checkpoint(512);
        let bytes = cp.canonical_serialize();
        assert_eq!(decode_checkpoint(&bytes).unwrap(), cp);
        // Wrong length fails.
        assert!(decode_checkpoint(&bytes[..bytes.len() - 1]).is_err());
        let mut longer = bytes.to_vec();
        longer.push(0);
        assert!(decode_checkpoint(&longer).is_err());
    }

    #[test]
    fn envelope_file_round_trips_and_rejects_trailing() {
        let env = CheckpointEnvelope {
            checkpoint: checkpoint(256),
            signatures: vec![(0, vec![0xAB; 100]), (2, vec![0xCD; 200])],
        };
        let bytes = encode_envelope_file(&env);
        let back = decode_envelope_file(&bytes).unwrap();
        assert_eq!(back.checkpoint, env.checkpoint);
        assert_eq!(back.signatures, env.signatures);
        let mut junk = bytes.clone();
        junk.push(0);
        assert!(decode_envelope_file(&junk).is_err(), "encode(x) ‖ junk must not decode");
    }

    #[test]
    fn signer_set_file_round_trips() {
        let set = SignerSet {
            id: 1,
            signers: vec![
                Signer { pubkey: [1; HYBRID_PK_BYTES], external: false },
                Signer { pubkey: [2; HYBRID_PK_BYTES], external: true },
            ],
            threshold: 2,
            min_external: 1,
            adopted_epoch: 7,
        };
        let bytes = encode_signer_set_file(&set);
        let back = decode_signer_set_file(&bytes).unwrap();
        assert_eq!(back.id, set.id);
        assert_eq!(back.threshold, set.threshold);
        assert_eq!(back.min_external, set.min_external);
        assert_eq!(back.adopted_epoch, set.adopted_epoch);
        assert_eq!(back.signers.len(), 2);
        assert_eq!(back.signers[1].pubkey, set.signers[1].pubkey);
        assert!(back.signers[1].external);
        // An incoherent quorum shape is refused at decode, not at verify.
        let mut bad = set;
        bad.threshold = 3; // > signers.len()
        assert!(decode_signer_set_file(&encode_signer_set_file(&bad)).is_err());
    }

    // -- the real hybrid suite, end to end ----------------------------------

    /// Strip the 4-byte suite envelope bloch-crypto wraps around keys and
    /// signatures, asserting the suite is the hybrid one.
    fn strip(bytes: &[u8]) -> Vec<u8> {
        let (suite, body) = bloch_crypto::crypto::split_envelope(bytes).expect("enveloped");
        assert_eq!(suite, bloch_crypto::crypto::SUITE_MLDSA65_FALCON1024);
        body.to_vec()
    }

    /// A Phase-A-shaped 2-of-3 envelope signed by REAL ML-DSA-65 ‖
    /// Falcon-1024 keys verifies through the node's `WsHybridVerifier`, and
    /// the m-of-n rules hold under it: quorum without the external signer
    /// fails, and one tampered signature rejects the whole envelope.
    #[test]
    fn real_hybrid_phase_a_envelope_verifies() {
        let cp = checkpoint(256);
        let digest = cp.ws_digest();

        let mut signers = Vec::new();
        let mut secrets = Vec::new();
        for _ in 0..3 {
            let (pk, sk) = bloch_crypto::crypto::generate_keypair();
            let raw = strip(&pk);
            let mut pubkey = [0u8; HYBRID_PK_BYTES];
            pubkey.copy_from_slice(&raw);
            signers.push(pubkey);
            secrets.push(sk);
        }
        let set = SignerSet {
            id: 1,
            signers: vec![
                Signer { pubkey: signers[0], external: false },
                Signer { pubkey: signers[1], external: false },
                Signer { pubkey: signers[2], external: true },
            ],
            threshold: WS_PHASE_A_THRESHOLD,
            min_external: WS_PHASE_A_MIN_EXTERNAL,
            adopted_epoch: 0,
        };
        assert!(set.matches_policy(
            WS_PHASE_A_THRESHOLD,
            WS_PHASE_A_SIGNERS,
            WS_PHASE_A_MIN_EXTERNAL
        ));

        let sig_of = |i: usize| -> Vec<u8> {
            strip(&bloch_crypto::crypto::sign(&secrets[i], &digest).expect("sign"))
        };

        // Internal 0 + external 2: valid quorum.
        let env = CheckpointEnvelope {
            checkpoint: cp,
            signatures: vec![(0, sig_of(0)), (2, sig_of(2))],
        };
        ws::verify_envelope(&env, &set, NET, &GEN, &WsHybridVerifier).expect("must verify");

        // Round-trip the artifact through its file form and verify again —
        // the path the --ws-checkpoint flag exercises.
        let back = decode_envelope_file(&encode_envelope_file(&env)).unwrap();
        ws::verify_envelope(&back, &set, NET, &GEN, &WsHybridVerifier)
            .expect("file round-trip must still verify");

        // Two internal keys: m reached, external minimum not (§2.2 rule 4).
        let env_internal = CheckpointEnvelope {
            checkpoint: cp,
            signatures: vec![(0, sig_of(0)), (1, sig_of(1))],
        };
        assert!(matches!(
            ws::verify_envelope(&env_internal, &set, NET, &GEN, &WsHybridVerifier),
            Err(ws::EnvelopeReject::ExternalQuorumNotReached { .. })
        ));

        // One flipped bit in the external signature rejects the envelope.
        let mut tampered = sig_of(2);
        tampered[0] ^= 1;
        let env_bad = CheckpointEnvelope {
            checkpoint: cp,
            signatures: vec![(0, sig_of(0)), (2, tampered)],
        };
        assert!(matches!(
            ws::verify_envelope(&env_bad, &set, NET, &GEN, &WsHybridVerifier),
            Err(ws::EnvelopeReject::BadSignature { index: 2 })
        ));
    }

    // -- boot orchestration -------------------------------------------------

    #[test]
    fn fresh_node_boots_under_fresh_genesis_anchor_and_persists_it() {
        let dir = tmpdir("fresh");
        let out = boot(
            &no_flags(),
            &dir,
            NET,
            &GEN,
            &genesis_anchor(),
            0, // wall epoch: launch day
            false,
            (0, GEN),
            |_| None,
            |_| false,
        )
        .unwrap()
        .expect("fresh node inside the trust-once window must sync");
        assert_eq!(out.anchor_epoch, 0);
        assert_eq!(out.anchor_root, GEN);
        assert!(out.anchor_is_hard);
        // Item 5: the genesis anchor became the first stored checkpoint.
        let stored = load_latest(&dir, NET, &GEN).unwrap().expect("persisted");
        assert_eq!(stored, genesis_anchor());
    }

    #[test]
    fn fresh_node_with_stale_anchor_refuses_and_says_where_to_get_one() {
        let dir = tmpdir("stale-fresh");
        let refusal = boot(
            &no_flags(),
            &dir,
            NET,
            &GEN,
            &genesis_anchor(),
            WS_PERIOD_EPOCHS, // the chain outgrew the trust-once window
            false,
            (0, GEN),
            |_| None,
            |_| false,
        )
        .unwrap()
        .expect_err("a fresh node with only a stale anchor must not sync");
        assert!(refusal.contains("ERR_WS_REQUIRE_CHECKPOINT"));
        assert!(refusal.contains("--ws-checkpoint"));
        assert!(refusal.contains("TWO independent channels"));
        assert!(refusal.contains("not a fault"));
    }

    /// The cold-start cliff, in the exact epochs the live chain will pass
    /// through — the arithmetic the 2026-09-05 deadline rests on, made
    /// mechanical so nobody has to re-derive it from a calendar.
    ///
    /// Genesis-4 launched at epoch 0 on 2026-08-13. A fresh install carries
    /// only the release-baked genesis anchor, so its `anchor_age` IS the wall
    /// epoch. The last wall epoch at which that anchor still admits a fresh
    /// node is `WS_PERIOD_EPOCHS - 1 = 2015`; at 2016 the same install is
    /// refused. Nothing about the chain changes at that boundary — what
    /// changes is that the only anchor a fresh node has stops being inside
    /// the window.
    ///
    /// Publishing a signed checkpoint at epoch 1536 moves the cliff to
    /// `1536 + 2016 = 3552`, and this test proves the move rather than
    /// asserting it.
    #[test]
    fn genesis_anchor_expires_at_epoch_2016_and_a_1536_checkpoint_moves_it_to_3552() {
        // 1. The genesis anchor, one epoch before the cliff: admitted.
        let dir = tmpdir("cliff-2015");
        let out = boot(
            &no_flags(), &dir, NET, &GEN, &genesis_anchor(),
            WS_PERIOD_EPOCHS - 1, // wall epoch 2015
            false, (0, GEN), |_| None, |_| false,
        )
        .unwrap()
        .expect("at wall epoch 2015 the genesis anchor still admits a fresh node");
        assert_eq!(out.anchor_epoch, 0);

        // 2. One epoch later: the same fresh install is refused. This is the
        //    event dated 2026-09-05 07:07 UTC — 16-minute epochs from a
        //    2026-08-13 21:31 UTC genesis.
        let dir = tmpdir("cliff-2016");
        let refusal = boot(
            &no_flags(), &dir, NET, &GEN, &genesis_anchor(),
            WS_PERIOD_EPOCHS, // wall epoch 2016
            false, (0, GEN), |_| None, |_| false,
        )
        .unwrap()
        .expect_err("at wall epoch 2016 a fresh node has no anchor inside the window");
        assert!(refusal.contains("ERR_WS_REQUIRE_CHECKPOINT"), "{refusal}");

        // 3. With a verified epoch-1536 checkpoint stored as ws_latest, the
        //    same wall epoch 2016 is unremarkable: age 480 of 2016.
        let dir = tmpdir("cliff-1536");
        save_latest(&dir, &checkpoint(1536)).unwrap();
        let out = boot(
            &no_flags(), &dir, NET, &GEN, &genesis_anchor(),
            WS_PERIOD_EPOCHS, false, (0, GEN), |_| None, |_| false,
        )
        .unwrap()
        .expect("an epoch-1536 anchor is 480 epochs old at wall 2016 — well inside");
        assert_eq!(out.anchor_epoch, 1536);
        assert!(
            out.warnings.iter().any(|w| w.contains("age 480 of 2016")),
            "{:?}",
            out.warnings
        );

        // 4. And the 1536 anchor has its own cliff, 2016 epochs later.
        let dir = tmpdir("cliff-3552");
        save_latest(&dir, &checkpoint(1536)).unwrap();
        let refusal = boot(
            &no_flags(), &dir, NET, &GEN, &genesis_anchor(),
            1536 + WS_PERIOD_EPOCHS, // wall epoch 3552
            false, (0, GEN), |_| None, |_| false,
        )
        .unwrap()
        .expect_err("a checkpoint buys exactly one window, not permanence");
        assert!(refusal.contains("ERR_WS_REQUIRE_CHECKPOINT"), "{refusal}");
        assert!(refusal.contains("a checkpoint at epoch 1536"), "{refusal}");
    }

    #[test]
    fn own_finality_resumes_and_warns_when_stale_inside_window() {
        let dir = tmpdir("resume");
        // Fresh: age 0.
        let out = boot(
            &no_flags(), &dir, NET, &GEN, &genesis_anchor(),
            10, true, (10, [0x55; 32]), |_| None, |_| false,
        )
        .unwrap()
        .expect("fresh own finality resumes");
        assert!(!out.anchor_is_hard);

        // Stale but inside the window: resumes with a prominent warning.
        let out = boot(
            &no_flags(), &dir, NET, &GEN, &genesis_anchor(),
            ws::WS_FRESH_EPOCHS + 5, true, (5, [0x55; 32]), |_| None, |_| false,
        )
        .unwrap()
        .expect("inside the window still resumes");
        assert!(out.warnings.iter().any(|w| w.contains("WARNING")));
    }

    #[test]
    fn beyond_window_refuses_without_a_fresh_checkpoint() {
        let dir = tmpdir("refuse-stale");
        let refusal = boot(
            &no_flags(), &dir, NET, &GEN, &genesis_anchor(),
            WS_PERIOD_EPOCHS + 7, true, (7, [0x55; 32]), |_| None, |_| false,
        )
        .unwrap()
        .expect_err("beyond the window with no checkpoint must refuse");
        assert!(refusal.contains("ERR_WS_STALE"));
        assert!(refusal.contains("--ws-checkpoint"));
    }

    #[test]
    fn anti_rollback_ignores_older_and_refuses_equivocal() {
        let dir = tmpdir("rollback");
        // Seed ws_latest at epoch 512.
        save_latest(&dir, &checkpoint(512)).unwrap();

        // Older incoming (epoch 256) via the pure rule the boot path calls.
        assert_eq!(
            ws::accept(Some(&checkpoint(512)), &checkpoint(256)),
            Acceptance::Ignore
        );
        // Same epoch, different digest: Conflict — and boot turns that into a
        // refusal (exercised end-to-end in ws_conflict_refuses_boot below).
        let mut equivocal = checkpoint(512);
        equivocal.block_root = [0xEE; 32];
        assert_eq!(ws::accept(Some(&checkpoint(512)), &equivocal), Acceptance::Conflict);

        // The stored artifact survives untouched.
        assert_eq!(load_latest(&dir, NET, &GEN).unwrap().unwrap(), checkpoint(512));
    }

    /// End-to-end: a validly-signed envelope for the SAME epoch as the stored
    /// ws_latest but a different digest refuses the boot loudly.
    #[test]
    fn ws_conflict_refuses_boot() {
        let dir = tmpdir("conflict");
        // The stored latest is the genesis anchor (epoch 0); craft an
        // equivocal "epoch 0" checkpoint signed by a real 1-of-1 arrangement.
        save_latest(&dir, &genesis_anchor()).unwrap();

        let (pk, sk) = bloch_crypto::crypto::generate_keypair();
        let raw = strip(&pk);
        let mut pubkey = [0u8; HYBRID_PK_BYTES];
        pubkey.copy_from_slice(&raw);
        let set = SignerSet {
            id: 9,
            signers: vec![Signer { pubkey, external: true }],
            threshold: 1,
            min_external: 1,
            adopted_epoch: 0,
        };
        let mut cp = checkpoint(0);
        cp.signer_set_id = 9;
        let env = CheckpointEnvelope {
            checkpoint: cp,
            signatures: vec![(0, strip(&bloch_crypto::crypto::sign(&sk, &cp.ws_digest()).unwrap()))],
        };
        let env_path = dir.join("env.bin");
        let set_path = dir.join("set.bin");
        fs::write(&env_path, encode_envelope_file(&env)).unwrap();
        fs::write(&set_path, encode_signer_set_file(&set)).unwrap();

        let cfg = WsConfig { checkpoint: Some(env_path), signer_set: Some(set_path) };
        let refusal = boot(
            &cfg, &dir, NET, &GEN, &genesis_anchor(),
            1, false, (0, GEN), |_| None, |_| false,
        )
        .unwrap()
        .expect_err("an equivocal same-epoch checkpoint must refuse the boot");
        assert!(refusal.contains("WS_CONFLICT"));
        assert!(refusal.contains("equivocal"));
        // The stored artifact was not overwritten.
        assert_eq!(load_latest(&dir, NET, &GEN).unwrap().unwrap(), genesis_anchor());
    }

    /// A published checkpoint that contradicts OWN finality raises the alarm,
    /// is not admitted as the anchor, and never blocks the node from
    /// resuming on its own finality — the §5 structural limit.
    #[test]
    fn published_checkpoint_never_overrides_own_finality() {
        let dir = tmpdir("cross-check");
        let (pk, sk) = bloch_crypto::crypto::generate_keypair();
        let raw = strip(&pk);
        let mut pubkey = [0u8; HYBRID_PK_BYTES];
        pubkey.copy_from_slice(&raw);
        let set = SignerSet {
            id: 3,
            signers: vec![Signer { pubkey, external: true }],
            threshold: 1,
            min_external: 1,
            adopted_epoch: 0,
        };
        let mut cp = checkpoint(64);
        cp.signer_set_id = 3;
        let env = CheckpointEnvelope {
            checkpoint: cp,
            signatures: vec![(0, strip(&bloch_crypto::crypto::sign(&sk, &cp.ws_digest()).unwrap()))],
        };
        let env_path = dir.join("env.bin");
        let set_path = dir.join("set.bin");
        fs::write(&env_path, encode_envelope_file(&env)).unwrap();
        fs::write(&set_path, encode_signer_set_file(&set)).unwrap();
        let cfg = WsConfig { checkpoint: Some(env_path), signer_set: Some(set_path) };

        // The node's own finalized root at epoch 64 differs from cp's.
        let own_root = [0x99; 32];
        let out = boot(
            &cfg, &dir, NET, &GEN, &genesis_anchor(),
            70, true, (70, own_root),
            move |e| if e <= 70 { Some(own_root) } else { None },
            |_| false,
        )
        .unwrap()
        .expect("a conflicting published checkpoint must not stop a fresh node's resume");
        assert!(out.warnings.iter().any(|w| w.contains("WS_CONFLICT")));
        assert!(out.warnings.iter().any(|w| w.contains("NOT reorganizing")));
        // Not admitted: the anchor is still the genesis anchor.
        assert_eq!(out.anchor_epoch, 0);
        assert!(!out.anchor_is_hard);
        assert_eq!(load_latest(&dir, NET, &GEN).unwrap().unwrap(), genesis_anchor());
    }
}
