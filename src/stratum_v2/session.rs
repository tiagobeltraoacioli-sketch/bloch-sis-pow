// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Per-connection session state machine for Stratum V2.
//
// A session traverses these states in order:
//
//   Handshaking
//     | (NOISE_NX completes)
//   AwaitingSetupConnection
//     | (SetupConnection received + decoded - Sprint 9-alpha)
//     | (policy evaluated - Sprint 9-beta)
//     | (response encoded + encrypted + written - Sprint 9-gamma)
//   Live
//     | (disconnect, error, or idle timeout)
//   Closed
//
// Sprint 8c-alpha: single-read+close skeleton.
// Sprint 8d-alpha: phased IO loop (drive_session_io) with plaintext echo.
// Sprint 8d-beta1: plug NoiseCodec into the loop.
// Sprint 9-alpha: parse `SetupConnection` from the decrypted phase-1
//   plaintext.
// Sprint 9-beta: run the decoded request through the policy layer.
// Sprint 9-gamma (this commit): build `SetupConnectionSuccess` or
//   `SetupConnectionError` via `setup_connection_encode`, encrypt
//   via `NoiseCodec`, write to the socket. On Success the session
//   advances to Phase-2; on Error it closes after the error frame
//   has been delivered. This closes out the Sprint 9 series — the
//   SetupConnection handshake is now fully end-to-end implementable
//   by any SV2-compliant initiator.

use crate::stratum::submit::AcceptBlockFn;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use stratum_core::noise_sv2::NoiseCodec;
use tokio::sync::broadcast;

use crate::stratum::{TemplateContext, TipChanged};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::setup_connection::{
    SetupConnectionRequest, KNOWN_FLAG_MASK,
};
use super::setup_connection_decode::{
    decode_setup_connection, DecodeError, DecodedSetupConnection,
};
use super::setup_connection_encode::{encode_setup_response, EncodeError};
use super::setup_connection_sri::{
    outcome_to_response_descriptor, SetupConnectionResponseDescriptor,
};

/// Total time a session can take from TCP accept to reaching `Live` state.
pub const SESSION_SETUP_DEADLINE: Duration = Duration::from_secs(30);

/// Timeout for receiving the first post-handshake message (SetupConnection).
pub const SETUP_CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);

/// Idle timeout between reads in the live loop.
/// TODO(Sprint 10+): expose via StratumV2Config.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(10);

/// Size of the read buffer for encrypted frames.
pub const READ_BUFFER_SIZE: usize = 65_600;

/// The state an active SV2 session is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Handshaking,
    AwaitingSetupConnection,
    Live,
    Closed,
}

/// Per-session runtime handle.
pub struct Sv2Session {
    pub id:        u64,
    pub peer_addr: SocketAddr,
    state:         SessionState,
    codec:         Option<NoiseCodec>,
    session_count: Arc<AtomicUsize>,
    /// Broadcast receiver for tip-change events. Sprint 10-gamma:
    /// accepted and threaded into `drive_session_io`. Actual consumption
    /// (push NewMiningJob on recv) arrives in Sprint 10-delta.
    tip_rx:        Option<broadcast::Receiver<TipChanged>>,
    /// DAG / Storage / Mempool handles required to build templates.
    /// Sprint 10-delta-Etapa-1: plumbed through but not yet consumed.
    node_ctx:      Option<Arc<TemplateContext>>,
    /// Callback into the node's accept_block path. Shared with V1.
    /// Sprint 10-epsilon Phase 1: plumbed but not yet consumed.
    accept_block: Option<Arc<AcceptBlockFn>>,
}

impl Sv2Session {
    pub fn new(
        id:            u64,
        peer_addr:     SocketAddr,
        codec:         NoiseCodec,
        session_count: Arc<AtomicUsize>,
        tip_rx:        broadcast::Receiver<TipChanged>,
        node_ctx:      Option<Arc<TemplateContext>>,
        accept_block:  Option<Arc<AcceptBlockFn>>,
    ) -> Self {
        Self {
            id,
            peer_addr,
            state: SessionState::AwaitingSetupConnection,
            codec: Some(codec),
            session_count,
            tip_rx: Some(tip_rx),
            node_ctx,
            accept_block,
        }
    }

    pub fn state(&self) -> SessionState {
        self.state
    }

    pub async fn run(mut self, stream: TcpStream) {
        log::info!(
            "stratum_v2: session {} from {} entered state {:?}",
            self.id, self.peer_addr, self.state
        );

        let codec = self.codec.take();
        let node_ctx = self.node_ctx.take();
        let tip_rx = self.tip_rx.take();
        let accept_block = self.accept_block.take();

        let final_state = drive_session_io(
            stream,
            codec,
            self.id,
            SETUP_CONNECTION_TIMEOUT,
            DEFAULT_IDLE_TIMEOUT,
            tip_rx,
            node_ctx,
            accept_block,
        )
        .await;

        self.state = match final_state {
            Ok(s) => s,
            Err(e) => {
                log::warn!(
                    "stratum_v2: session {} io error: {}",
                    self.id, e
                );
                SessionState::Closed
            }
        };

        log::info!(
            "stratum_v2: session {} from {} closed",
            self.id, self.peer_addr
        );
    }
}

impl Drop for Sv2Session {
    fn drop(&mut self) {
        self.session_count.fetch_sub(1, Ordering::Relaxed);
    }
}

fn crypto_err<E: core::fmt::Debug>(e: E, ctx: &str) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("noise {} failed: {:?}", ctx, e),
    )
}

fn encode_err(e: EncodeError) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("setup-response encode failed: {e}"),
    )
}

/// Standalone IO driver for a Stratum V2 session.
///
/// Phase 1 (`AwaitingSetupConnection`):
///   1. Read one encrypted frame.
///   2. Decrypt, decode as `SetupConnection`.
///   3. Validate via policy layer with `KNOWN_FLAG_MASK`.
///   4. Encode response (`SetupConnectionSuccess` or `SetupConnectionError`).
///   5. Encrypt + write the response frame.
///   6. On Error descriptor, close after write.
///      On Success descriptor, advance to Phase-2.
///
/// Phase 2 (`Live`):
///   tokio::select! loop multiplexing:
///     - socket reads (dispatched on msg_type to subprotocol handlers)
///     - TipChanged broadcast (push NewMiningJob per channel — Phase 4b)
///     - idle timeout (session returns to Live after idle_timeout)
pub(crate) async fn drive_session_io(
    mut stream: TcpStream,
    mut codec: Option<NoiseCodec>,
    session_id: u64,
    first_read_timeout: Duration,
    idle_timeout: Duration,
    mut tip_rx: Option<broadcast::Receiver<TipChanged>>,
    node_ctx: Option<Arc<TemplateContext>>,
    accept_block: Option<Arc<AcceptBlockFn>>,
) -> std::io::Result<SessionState> {
    let mut read_buf = vec![0u8; READ_BUFFER_SIZE];

    // ---------- Phase 1: first message = SetupConnection -----------------
    let setup = match tokio::time::timeout(first_read_timeout, stream.read(&mut read_buf)).await {
        Err(_elapsed) => {
            log::warn!(
                "stratum_v2: session {} timed out awaiting SetupConnection",
                session_id
            );
            return Ok(SessionState::Closed);
        }
        Ok(Ok(0)) => {
            log::info!(
                "stratum_v2: session {} peer closed before SetupConnection",
                session_id
            );
            return Ok(SessionState::Closed);
        }
        Ok(Err(e)) => {
            log::warn!(
                "stratum_v2: session {} first-read error: {}",
                session_id, e
            );
            return Err(e);
        }
        Ok(Ok(n)) => {
            let mut frame: Vec<u8> = read_buf[..n].to_vec();
            match process_inbound_setup(&mut frame, &mut codec, session_id) {
                Ok(decoded) => decoded,
                Err(SetupPhaseError::Crypto(e)) => return Err(e),
                Err(SetupPhaseError::Decode(d)) => {
                    log::warn!(
                        "stratum_v2: session {} SetupConnection decode failed: {}; closing",
                        session_id, d
                    );
                    return Ok(SessionState::Closed);
                }
            }
        }
    };

    log::info!(
        "stratum_v2: session {} received SetupConnection: \
         protocol={} min_version={} max_version={} flags=0x{:08x} \
         endpoint=\"{}:{}\" vendor=\"{}\" hardware=\"{}\" firmware=\"{}\" device=\"{}\"",
        session_id,
        setup.protocol,
        setup.min_version,
        setup.max_version,
        setup.flags,
        setup.endpoint_host,
        setup.endpoint_port,
        setup.vendor,
        setup.hardware_version,
        setup.firmware,
        setup.device_id,
    );

    // ---------- Sprint 9-beta: policy evaluation ------------------------
    let request = SetupConnectionRequest {
        protocol: setup.protocol,
        min_version: setup.min_version,
        max_version: setup.max_version,
        flags: setup.flags,
    };
    let outcome = request.validate(KNOWN_FLAG_MASK);
    let descriptor = outcome_to_response_descriptor(&outcome);

    let is_success = matches!(
        descriptor,
        SetupConnectionResponseDescriptor::Success { .. }
    );

    match &descriptor {
        SetupConnectionResponseDescriptor::Success {
            used_version,
            used_flags,
        } => {
            log::info!(
                "stratum_v2: session {} policy accepted: used_version={} used_flags=0x{:08x}",
                session_id, used_version, used_flags
            );
        }
        SetupConnectionResponseDescriptor::Error { error_code } => {
            log::warn!(
                "stratum_v2: session {} policy rejected: error_code=\"{}\"",
                session_id, error_code
            );
        }
    }

    // ---------- Sprint 9-gamma: encode + encrypt + write ---------------
    //
    // Build the SV2 response frame, encrypt it in place via NoiseCodec,
    // and flush it to the socket before deciding whether to advance
    // or close. Even on policy Error we transmit the Error frame so
    // the initiator can report a useful diagnostic; only after that
    // do we tear down the TCP connection.
    let mut response_frame = encode_setup_response(&descriptor).map_err(encode_err)?;

    if let Some(c) = codec.as_mut() {
        c.encrypt(&mut response_frame).map_err(|e| crypto_err(e, "encrypt-setup-response"))?;
    }
    stream.write_all(&response_frame).await?;

    log::debug!(
        "stratum_v2: session {} phase-1 response written ({} bytes on wire)",
        session_id,
        response_frame.len()
    );

    if !is_success {
        return Ok(SessionState::Closed);
    }

    // ---------- Phase 2: select!-driven message loop ---------------------
    // Sprint 10-delta Phase 4a: multiplex socket reads, TipChanged events,
    // and idle timeout via tokio::select!. The tip_rx arm currently only
    // logs; per-channel NewMiningJob push arrives in Phase 4b.
    //
    // When tip_rx is None (unit tests without a live broadcast), the
    // TipChanged arm disables itself via std::future::pending(), which
    // never resolves — the idiomatic way to keep a select! arm inert.
    let mut channels = crate::stratum_v2::channel::ChannelRegistry::new();

    // Phase 4b: monotonic per-session job_id counter. Each TipChanged
    // event yields one job_id per channel; we increment before each push.
    let mut next_job_id: u32 = 1;

    loop {
        tokio::select! {
            // Branch 1: socket read (with idle timeout).
            read_outcome = tokio::time::timeout(idle_timeout, stream.read(&mut read_buf)) => {
                match read_outcome {
                    Err(_elapsed) => {
                        log::debug!(
                            "stratum_v2: session {} idle timeout in live loop",
                            session_id
                        );
                        return Ok(SessionState::Live);
                    }
                    Ok(Ok(0)) => {
                        log::debug!(
                            "stratum_v2: session {} peer disconnected post-setup",
                            session_id
                        );
                        return Ok(SessionState::Live);
                    }
                    Ok(Ok(n)) => {
                        let mut frame: Vec<u8> = read_buf[..n].to_vec();
                        let wire_len = frame.len();
                        if let Some(c) = codec.as_mut() {
                            c.decrypt(&mut frame).map_err(|e| crypto_err(e, "decrypt"))?;
                        }
                        log::trace!(
                            "stratum_v2: session {} live: wire={} plaintext={}",
                            session_id,
                            wire_len,
                            frame.len(),
                        );

                        if frame.len() < 6 {
                            log::warn!(
                                "stratum_v2: session {} received short frame ({} bytes), ignoring",
                                session_id, frame.len()
                            );
                            continue;
                        }

                        let msg_type = frame[2];
                        match msg_type {
                            0x10 => {
                                dispatch_open_standard_channel(
                                    session_id,
                                    &frame,
                                    &mut channels,
                                    codec.as_mut(),
                                    &mut stream,
                                ).await?;
                            }
                            0x1a => {
                                dispatch_submit_shares_standard(
                                    session_id,
                                    &frame,
                                    &mut channels,
                                    codec.as_mut(),
                                    &mut stream,
                                    accept_block.as_ref(),
                                ).await?;
                            }
                            other => {
                                log::debug!(
                                    "stratum_v2: session {} unhandled msg_type=0x{:02x} (len={}), ignoring",
                                    session_id, other, frame.len()
                                );
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        log::warn!(
                            "stratum_v2: session {} live-loop read error: {}",
                            session_id, e
                        );
                        return Err(e);
                    }
                }
            }

            // Branch 2: tip changed (no-op when tip_rx is None).
            tip_evt = async {
                match tip_rx.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                match tip_evt {
                    Ok(tip) => {
                        push_new_jobs_on_tip_change(
                            session_id,
                            &tip,
                            node_ctx.as_deref(),
                            &mut channels,
                            &mut next_job_id,
                            codec.as_mut(),
                            &mut stream,
                        ).await?;
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        log::warn!(
                            "stratum_v2: session {} tip broadcast lagged, dropped {} events",
                            session_id, n
                        );
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        log::warn!(
                            "stratum_v2: session {} tip broadcast closed; disabling tip arm",
                            session_id
                        );
                        // Take the receiver out so the arm falls through
                        // to std::future::pending() on next iteration.
                        tip_rx = None;
                    }
                }
            }
        }
    }
}

async fn dispatch_open_standard_channel(
    session_id: u64,
    frame:      &[u8],
    channels:   &mut crate::stratum_v2::channel::ChannelRegistry,
    codec:      Option<&mut NoiseCodec>,
    stream:     &mut tokio::net::TcpStream,
) -> std::io::Result<()> {
    use crate::stratum_v2::open_channel_decode::decode_open_standard_channel;
    use crate::stratum_v2::open_channel_encode::{
        encode_open_standard_channel_success,
        encode_open_mining_channel_error,
        ChannelErrorCode,
    };
    use crate::stratum_v2::channel::{
        ChannelState, compute_initial_target, derive_extranonce_prefix,
        MAX_CHANNELS_PER_SESSION,
    };
    use tokio::io::AsyncWriteExt;

    let decoded = match decode_open_standard_channel(frame) {
        Ok(d) => d,
        Err(e) => {
            log::warn!(
                "stratum_v2: session {} open-channel decode failed: {}",
                session_id, e
            );
            return Ok(());
        }
    };

    log::info!(
        "stratum_v2: session {} OpenStandardMiningChannel: request_id={} user={:?} nominal_hs={}",
        session_id, decoded.request_id, decoded.user_identity, decoded.nominal_hash_rate,
    );

    async fn send_frame(
        mut frame: Vec<u8>,
        codec: Option<&mut NoiseCodec>,
        stream: &mut tokio::net::TcpStream,
    ) -> std::io::Result<()> {
        if let Some(c) = codec {
            c.encrypt(&mut frame).map_err(|e| crypto_err(e, "encrypt-mining"))?;
        }
        stream.write_all(&frame).await
    }

    if channels.len() >= MAX_CHANNELS_PER_SESSION {
        let err_frame = encode_open_mining_channel_error(
            decoded.request_id,
            ChannelErrorCode::TooManyChannels,
        ).map_err(|e| std::io::Error::new(
            std::io::ErrorKind::Other, format!("encode error: {}", e)
        ))?;
        return send_frame(err_frame, codec, stream).await;
    }

    let channel_id = channels.allocate_id();
    let extranonce_prefix = derive_extranonce_prefix(channel_id);
    let initial_target = compute_initial_target(
        &decoded.max_target,
        decoded.nominal_hash_rate,
        &[0u8; 32],
    );

    let state = ChannelState::new(
        channel_id,
        decoded.user_identity.clone(),
        decoded.nominal_hash_rate,
        initial_target,
        extranonce_prefix.clone(),
    );

    if let Err(e) = channels.insert(state) {
        log::warn!("stratum_v2: session {} failed to insert channel: {}", session_id, e);
        let err_frame = encode_open_mining_channel_error(
            decoded.request_id,
            ChannelErrorCode::Custom("channel-registry-error"),
        ).map_err(|e| std::io::Error::new(
            std::io::ErrorKind::Other, format!("encode error: {}", e)
        ))?;
        return send_frame(err_frame, codec, stream).await;
    }

    let success_frame = encode_open_standard_channel_success(
        decoded.request_id,
        channel_id,
        &initial_target,
        &extranonce_prefix,
        0,
    ).map_err(|e| std::io::Error::new(
        std::io::ErrorKind::Other, format!("encode error: {}", e)
    ))?;

    log::info!(
        "stratum_v2: session {} channel {} opened (total: {})",
        session_id, channel_id, channels.len()
    );

    send_frame(success_frame, codec, stream).await
}

/// Errors that can end Phase-1 processing.
enum SetupPhaseError {
    Crypto(std::io::Error),
    Decode(DecodeError),
}

/// Decrypt (if codec present) and decode the phase-1 frame as a
/// `SetupConnection`. Returns the owned decoded struct on success.
fn process_inbound_setup(
    frame: &mut Vec<u8>,
    codec: &mut Option<NoiseCodec>,
    session_id: u64,
) -> Result<DecodedSetupConnection, SetupPhaseError> {
    let wire_len = frame.len();

    if let Some(c) = codec.as_mut() {
        c.decrypt(frame).map_err(|e| SetupPhaseError::Crypto(crypto_err(e, "decrypt")))?;
        log::debug!(
            "stratum_v2: session {} phase-1 decrypted wire={} plaintext={}",
            session_id, wire_len, frame.len()
        );
    } else {
        log::trace!(
            "stratum_v2: session {} phase-1 plaintext path ({} bytes)",
            session_id, wire_len
        );
    }

    decode_setup_connection(frame.as_mut_slice()).map_err(SetupPhaseError::Decode)
}

// ───────────────────────── Phase 4b helper ─────────────────────────
//
// On each TipChanged event, build a fresh Template once, then iterate
// the per-session ChannelRegistry and push one NewMiningJob per channel.
// Each channel has its own extranonce_prefix, so the merkle_root differs
// per channel even though coinb1/coinb2/merkle_branch are shared.
//
// Design notes:
//   - node_ctx None -> no-op with log. Happens in unit tests that wire
//     tip_rx but no DAG/mempool handle.
//   - Template build uses `crate::stratum_v2::template_adapter::build_template_for_sv2`,
//     which diverges from V1 by reading tip.parents directly from the
//     event rather than d.tips() (avoids N-way DAG-read contention
//     across V2 sessions).
//   - miner_spk: Phase 6 resolves the real payout address from the
//     first channel's user_identity via crate::address::Address::parse.
//     Sessions with no channels or unparseable user_identity skip the
//     job push (fail-closed; see the let miner_spk block below).
//   - min_ntime = None. Miner rolls wall clock within spec.
//
async fn push_new_jobs_on_tip_change(
    session_id:   u64,
    tip:          &crate::stratum::TipChanged,
    node_ctx:     Option<&crate::stratum::TemplateContext>,
    channels:     &mut crate::stratum_v2::channel::ChannelRegistry,
    next_job_id:  &mut u32,
    mut codec:    Option<&mut NoiseCodec>,
    stream:       &mut tokio::net::TcpStream,
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    use crate::stratum_v2::mining_job::encode_new_mining_job;
    use crate::stratum_v2::template_adapter::{
        build_template_for_sv2, compute_merkle_root_for_channel,
    };

    let ctx = match node_ctx {
        Some(c) => c,
        None => {
            log::debug!(
                "stratum_v2: session {} tip h={} but node_ctx is None; skipping push",
                session_id, tip.height
            );
            return Ok(());
        }
    };

    if channels.is_empty() {
        log::trace!(
            "stratum_v2: session {} tip h={} but no open channels; skipping push",
            session_id, tip.height
        );
        return Ok(());
    }

    // Build the Template once per tip event — reused across all channels
    // in this session (only the merkle_root differs per-channel via the
    // extranonce_prefix).
    //
    // we synthesize a 20-byte hash from a fixed session-scoped tag.

    // Sprint 10-epsilon Phase 6 -- real miner_spk from user_identity.
    //
    // Use the first channel's user_identity as the payout recipient
    // for this session's coinbase. Multi-channel sessions where
    // channels authorized with distinct identities all receive
    // jobs pointing at the first channel's address -- tracked as
    // CHECKME-epsilon-multichannel-spk. Solo mining in practice
    // has one channel per session, so this is fine.
    //
    // Fail-closed policy: if the first channel's user_identity is
    // not a parseable bloch1q/bloch1t address (e.g. the miner sent
    // a worker name like "rig1" instead of an address), we skip
    // the NewMiningJob push entirely. The miner will see no jobs
    // and must reconnect with a valid address. This is deliberate:
    // falling back to an operator-owned address would route block
    // rewards away from the miner without their consent, and
    // falling back to a throwaway address would burn rewards on
    // any block found. Better to loudly refuse than silently
    // mis-route coinbase outputs.
    let miner_spk: [u8; 20] = match channels.iter().next() {
        Some(ch) => match crate::address::Address::parse(&ch.user_identity) {
            Ok(addr) => *addr.hash(),
            Err(e) => {
                log::warn!(
                    "stratum_v2: session {} skipping job push -- channel {} user_identity {:?} is not a valid BLOCH address: {:?}",
                    session_id, ch.channel_id, ch.user_identity, e
                );
                return Ok(());
            }
        },
        None => {
            // No channels opened yet. Defensive early return; the
            // outer push loop would also no-op on zero channels,
            // but we avoid constructing a template that no one
            // will consume.
            log::debug!(
                "stratum_v2: session {} no channels open at push time; skipping template build",
                session_id
            );
            return Ok(());
        }
    };

    let session_job_id = format!("sv2-s{}-h{}", session_id, tip.height);

    let template: std::sync::Arc<crate::stratum::Template> = match build_template_for_sv2(
        tip,
        ctx,
        &miner_spk,
        session_job_id,
    ) {
        Ok(t)  => std::sync::Arc::new(t),
        Err(e) => {
            log::warn!(
                "stratum_v2: session {} template build failed at tip h={}: {}",
                session_id, tip.height, e
            );
            return Ok(());
        }
    };

    // Collect channel snapshots so we can release the borrow on `channels`
    // before mutating session state during the per-channel push loop.
    // Each snapshot is small (channel_id + extranonce_prefix clone).
    let snapshots: Vec<(u32, Vec<u8>)> = channels
        .iter()
        .map(|ch| (ch.channel_id, ch.extranonce_prefix.clone()))
        .collect();

    let num_pushed = snapshots.len();

    for (channel_id, extranonce_prefix) in snapshots {
        // Channels store variable-length extranonce_prefix (B032, max 32).
        // compute_merkle_root_for_channel expects exactly 8 bytes — the
        // V1 extranonce_total size. For Phase 4b we pad/truncate to 8.
        // CHECKME-4b-extranonce: revisit once SV2 channels negotiate
        // full-length extranonces distinct from V1's 8-byte slot.
        let mut en8 = [0u8; 8];
        let take = extranonce_prefix.len().min(8);
        en8[..take].copy_from_slice(&extranonce_prefix[..take]);

        let merkle_root = compute_merkle_root_for_channel(&template, &en8);

        let job_id = *next_job_id;
        *next_job_id = next_job_id.wrapping_add(1);

        let mut frame = match encode_new_mining_job(
            channel_id,
            job_id,
            None, // min_ntime; miner rolls wall clock
            template.version,
            &merkle_root,
        ) {
            Ok(f) => f,
            Err(e) => {
                log::warn!(
                    "stratum_v2: session {} NewMiningJob encode failed ch={} job={}: {}",
                    session_id, channel_id, job_id, e
                );
                continue;
            }
        };

        if let Some(c) = codec.as_deref_mut() {
            c.encrypt(&mut frame)
                .map_err(|e| crypto_err(e, "encrypt-new-mining-job"))?;
        }
        stream.write_all(&frame).await?;

        // Sprint 10-epsilon Phase 2.b: cache the full job record
        // (template + extranonce_prefix + merkle_root) on the channel,
        // not just the job_id. The SubmitShares path in ε.5 needs the
        // exact template committed at push time to reconstruct the
        // 80-byte mining header byte-identically.
        //
        // push_job() also updates last_job_id internally, preserving
        // the Phase 4c validator semantics. Safe: snapshots already
        // consumed, so this mutable borrow doesn't alias.
        if let Some(ch) = channels.get_mut(channel_id) {
            ch.push_job(crate::stratum_v2::channel::Sv2CachedJob {
                job_id,
                template:          template.clone(),
                extranonce_prefix: en8,
                merkle_root,
            });
        }

        log::debug!(
            "stratum_v2: session {} pushed NewMiningJob ch={} job={} h={} bytes={}",
            session_id, channel_id, job_id, tip.height, frame.len()
        );
    }

    log::info!(
        "stratum_v2: session {} tip h={} pushed {} NewMiningJob(s)",
        session_id, tip.height, num_pushed
    );

    Ok(())
}

// ───────────────────── Phase 4c: SubmitSharesStandard ─────────────────────
//
// Decodes msg_type 0x1a, looks up the channel, checks whether submitted
// job_id matches channel.last_job_id, logs outcome. No PoW check, no
// wire response — those land in Epsilon.

async fn dispatch_submit_shares_standard(
    session_id:   u64,
    frame:        &[u8],
    channels:     &mut crate::stratum_v2::channel::ChannelRegistry,
    codec:        Option<&mut NoiseCodec>,
    stream:       &mut tokio::net::TcpStream,
    accept_block: Option<&Arc<AcceptBlockFn>>,
) -> std::io::Result<()> {
    // Sprint 10-epsilon Phase 5.b — full SV2 submit pipeline.
    //
    // Pipeline on a miner-submitted SubmitSharesStandard:
    //   1. Decode frame.
    //   2. Look up channel + cached job via ChannelRegistry::get →
    //      ChannelState::find_job. Ring buffer search accepts any
    //      job still in scope, not just the most recent one
    //      (replaces prior validate_share_against_channel which
    //      only compared against channel.last_job_id).
    //   3. Reconstruct Block via reconstruct_block_for_sv2_submit
    //      (ε.4 helper). Returns pow_hash already computed.
    //   4. Check pow_hash against block target (bits_to_target of
    //      the cached template). Solo policy: only accept shares
    //      that meet the full block target; otherwise emit
    //      "difficulty-too-low". Share accounting (accepting
    //      below-target shares for difficulty statistics) is out
    //      of scope for ε.5.b — see CHECKME-epsilon-shares-sum.
    //   5. Call accept_block with the reconstructed Block.
    //   6. Emit SubmitSharesSuccess on success or
    //      SubmitSharesError with the appropriate error_code on
    //      any earlier step.
    //
    // Error codes follow Stratum V2 spec convention:
    //   invalid-channel-id   → channel not registered
    //   invalid-job-id       → job not in ring buffer (rolled out)
    //   difficulty-too-low   → pow_hash > block target
    //   other                → reconstruction bug or accept_block
    //                          error (our side, not the miner's)
    use crate::stratum_v2::submit_shares::decode_submit_shares_standard;
    use crate::stratum_v2::submit_responses::{
        encode_submit_shares_success, encode_submit_shares_error,
    };
    use crate::stratum_v2::block_reconstruct::{
        reconstruct_block_for_sv2_submit, BlockReconstructError,
    };
    use crate::core::{bits_to_target, sha256d_pow_valid};
    use tokio::io::AsyncWriteExt;

    // Decoder failure — frame is malformed, we don't know
    // channel_id or sequence_number reliably enough to address a
    // response back. Log and drop. Miner retries on next poll.
    let decoded = match decode_submit_shares_standard(frame) {
        Ok(d) => d,
        Err(e) => {
            log::warn!(
                "stratum_v2: session {} submit-shares decode failed: {}; ignoring",
                session_id, e
            );
            return Ok(());
        }
    };

    // Helper: encrypt + write one frame. Kept local to this fn
    // so it can move `codec` and `stream` references freely
    // across the match arms below without lifetime juggling.
    async fn send_frame(
        mut frame: Vec<u8>,
        codec: Option<&mut NoiseCodec>,
        stream: &mut tokio::net::TcpStream,
    ) -> std::io::Result<()> {
        if let Some(c) = codec {
            c.encrypt(&mut frame)
                .map_err(|e| crypto_err(e, "encrypt-submit-shares-response"))?;
        }
        stream.write_all(&frame).await
    }

    // Helper: encode + send an error response, mapping the
    // SubmitResponseEncodeError into io::Error for uniformity.
    let encode_io_err = |e: crate::stratum_v2::submit_responses::SubmitResponseEncodeError| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("stratum_v2: submit response encode error: {:?}", e),
        )
    };

    // --- Step 2: look up channel + cached job ---------------------
    let channel = match channels.get(decoded.channel_id) {
        Some(c) => c,
        None => {
            log::warn!(
                "stratum_v2: session {} submit for unknown channel {}; responding invalid-channel-id",
                session_id, decoded.channel_id
            );
            let err_frame = encode_submit_shares_error(
                decoded.channel_id,
                decoded.sequence_number,
                "invalid-channel-id",
            ).map_err(encode_io_err)?;
            return send_frame(err_frame, codec, stream).await;
        }
    };

    let cached = match channel.find_job(decoded.job_id) {
        Some(j) => j,
        None => {
            log::warn!(
                "stratum_v2: session {} submit with unknown/rolled-out job_id {} on ch={}; responding invalid-job-id",
                session_id, decoded.job_id, decoded.channel_id
            );
            let err_frame = encode_submit_shares_error(
                decoded.channel_id,
                decoded.sequence_number,
                "invalid-job-id",
            ).map_err(encode_io_err)?;
            return send_frame(err_frame, codec, stream).await;
        }
    };

    // --- Step 3: reconstruct block --------------------------------
    //
    // Per the AA.0 projection invariant (see core::BlockHeader and
    // block_reconstruct tests), we deliberately pass the CACHED
    // template.version here rather than decoded.version. Version
    // rolling (SV2 version masks) is out of scope for ε.5.b and
    // will land in ε.6+ — see CHECKME-epsilon-version-rolling.
    let reconstructed = match reconstruct_block_for_sv2_submit(
        cached,
        cached.template.version,
        decoded.ntime,
        decoded.nonce,
    ) {
        Ok(r) => r,
        Err(e) => {
            // All three BlockReconstructError variants indicate a
            // defect on our side (template construction, coinbase
            // parsing, or merkle cache corruption) — not a miner
            // misbehaving. We map all of them to "other" per spec
            // and log loudly so the node operator notices.
            log::error!(
                "stratum_v2: session {} block reconstruction failed on ch={} job={}: {}",
                session_id, decoded.channel_id, decoded.job_id, e
            );
            match e {
                BlockReconstructError::MalformedCoinbase(_)
                | BlockReconstructError::NotACoinbase
                | BlockReconstructError::MerkleRootMismatch { .. } => {}
            }
            let err_frame = encode_submit_shares_error(
                decoded.channel_id,
                decoded.sequence_number,
                "other",
            ).map_err(encode_io_err)?;
            return send_frame(err_frame, codec, stream).await;
        }
    };

    // --- Step 4: PoW check against block target -------------------
    // Per-chain endianness rule (core::sha256d_le_fork_height_for — Genesis-2
    // flag-day at SHA256D_LE_FORK_HEIGHT, Genesis-3 little-endian from height
    // 0): at/above the chain's fork height the hash is compared Bitcoin
    // little-endian, matching V1 and consensus, so a standard SV2 miner's
    // share validates.
    let block_target = bits_to_target(cached.template.bits);
    if !sha256d_pow_valid(&reconstructed.pow_hash, &block_target, cached.template.height) {
        log::debug!(
            "stratum_v2: session {} ch={} seq={} job={} below block target (bits=0x{:08x}); responding difficulty-too-low",
            session_id, decoded.channel_id, decoded.sequence_number,
            decoded.job_id, cached.template.bits,
        );
        let err_frame = encode_submit_shares_error(
            decoded.channel_id,
            decoded.sequence_number,
            "difficulty-too-low",
        ).map_err(encode_io_err)?;
        return send_frame(err_frame, codec, stream).await;
    }

    // --- Step 5: forward to accept_block --------------------------
    //
    // If accept_block is None the session was constructed without
    // a node-side callback (e.g. --sv2-enable without --stratum).
    // Shouldn't happen in a real deployment but we handle it
    // defensively as "other" rather than unwrap.
    let cb = match accept_block {
        Some(cb) => cb,
        None => {
            log::error!(
                "stratum_v2: session {} passed PoW check on ch={} seq={} job={} but accept_block callback is None; share lost",
                session_id, decoded.channel_id, decoded.sequence_number, decoded.job_id
            );
            let err_frame = encode_submit_shares_error(
                decoded.channel_id,
                decoded.sequence_number,
                "other",
            ).map_err(encode_io_err)?;
            return send_frame(err_frame, codec, stream).await;
        }
    };

    match cb(reconstructed.block) {
        Ok(accepted_hash) => {
            log::info!(
                "stratum_v2: ⛏  BLOCK FOUND — session {} ch={} seq={} job={} hash={}",
                session_id, decoded.channel_id, decoded.sequence_number,
                decoded.job_id, accepted_hash
            );
            let ok_frame = encode_submit_shares_success(
                decoded.channel_id,
                decoded.sequence_number,
                /* new_submits_accepted_count = */ 1,
                /* new_shares_sum             = */ 0, // CHECKME-epsilon-shares-sum
            ).map_err(encode_io_err)?;
            send_frame(ok_frame, codec, stream).await
        }
        Err(reason) => {
            log::error!(
                "stratum_v2: session {} accept_block rejected block on ch={} seq={} job={}: {}",
                session_id, decoded.channel_id, decoded.sequence_number,
                decoded.job_id, reason
            );
            let err_frame = encode_submit_shares_error(
                decoded.channel_id,
                decoded.sequence_number,
                "other",
            ).map_err(encode_io_err)?;
            send_frame(err_frame, codec, stream).await
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum ShareValidation {
    Accepted { job_id: u32 },
    UnknownChannel,
    StaleJob { channel_last: Option<u32>, submitted: u32 },
}

// Retained for potential future use as a cheap pre-validation
// before paying the cost of block reconstruction (e.g. for share
// rate-limiting in ε.5.c+). The submit dispatcher above performs
// its own validation inline because it needs the `&Sv2CachedJob`
// reference from ChannelState::find_job, which this helper does
// not return.
#[allow(dead_code)]
pub(crate) fn validate_share_against_channel(
    channels: &crate::stratum_v2::channel::ChannelRegistry,
    submit:   &crate::stratum_v2::submit_shares::DecodedSubmitSharesStandard,
) -> ShareValidation {
    let channel = match channels.get(submit.channel_id) {
        Some(c) => c,
        None    => return ShareValidation::UnknownChannel,
    };
    if channel.last_job_id == Some(submit.job_id) {
        ShareValidation::Accepted { job_id: submit.job_id }
    } else {
        ShareValidation::StaleJob {
            channel_last: channel.last_job_id,
            submitted:    submit.job_id,
        }
    }
}

#[cfg(test)]
mod share_validation_tests {
    use super::*;
    use crate::stratum_v2::channel::{ChannelState, ChannelRegistry};
    use crate::stratum_v2::submit_shares::DecodedSubmitSharesStandard;

    fn mk_submit(channel_id: u32, job_id: u32) -> DecodedSubmitSharesStandard {
        DecodedSubmitSharesStandard {
            channel_id, sequence_number: 0, job_id,
            nonce: 0, ntime: 0, version: 0,
        }
    }

    fn mk_channel(channel_id: u32, last_job_id: Option<u32>) -> ChannelState {
        let mut ch = ChannelState::new(
            channel_id, "test-user".to_string(), 1.0,
            [0u8; 32], vec![0x42; 8],
        );
        ch.last_job_id = last_job_id;
        ch
    }

    #[test]
    fn accepted_when_job_id_matches() {
        let mut reg = ChannelRegistry::new();
        reg.insert(mk_channel(1, Some(42))).unwrap();
        assert_eq!(
            validate_share_against_channel(&reg, &mk_submit(1, 42)),
            ShareValidation::Accepted { job_id: 42 }
        );
    }

    #[test]
    fn rejected_when_channel_unknown() {
        let reg = ChannelRegistry::new();
        assert_eq!(
            validate_share_against_channel(&reg, &mk_submit(99, 1)),
            ShareValidation::UnknownChannel
        );
    }

    #[test]
    fn rejected_when_job_id_stale() {
        let mut reg = ChannelRegistry::new();
        reg.insert(mk_channel(1, Some(42))).unwrap();
        assert_eq!(
            validate_share_against_channel(&reg, &mk_submit(1, 41)),
            ShareValidation::StaleJob { channel_last: Some(42), submitted: 41 }
        );
    }

    #[test]
    fn rejected_when_channel_has_no_last_job() {
        let mut reg = ChannelRegistry::new();
        reg.insert(mk_channel(1, None)).unwrap();
        assert_eq!(
            validate_share_against_channel(&reg, &mk_submit(1, 1)),
            ShareValidation::StaleJob { channel_last: None, submitted: 1 }
        );
    }
}

