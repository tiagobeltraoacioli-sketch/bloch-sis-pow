//! Sprint A2 Phase 1 — AsyncRead/AsyncWrite adapter
//!
//! Wraps an inner byte stream `S` (typically a TCP socket) with the
//! post-quantum AEAD stream from Sprint A1. The result implements
//! `AsyncRead + AsyncWrite + Unpin` so it can feed libp2p's multiplexer
//! (yamux) and behaviour layers transparently.
//!
//! # Wire format
//!
//! Frames on the wire use the format defined by `frame_seal`:
//!
//!   `[u32 big-endian ciphertext length] [ciphertext (includes AEAD tag)]`
//!
//! # State machine for reading
//!
//! The reader maintains a small state machine because `poll_read` can be
//! called at any time with a buffer of any size:
//!
//! - **Length**: we haven't got all 4 length-prefix bytes yet — keep
//!   reading into a 4-byte buffer
//! - **Ciphertext**: we have the length, now reading that many bytes
//!   into a growing Vec — once complete, decrypt
//! - **Plaintext(Vec, usize)**: we have plaintext bytes buffered from a
//!   previous frame; drain them into the caller's buffer; when drained,
//!   go back to Length
//!
//! Partial reads are handled naturally: we keep the state, return
//! `Poll::Pending` or `Poll::Ready(Ok(n))` with `n < buf.len()` as appropriate.
//!
//! # State machine for writing
//!
//! Writing is simpler:
//!
//! - Take the plaintext the caller wants to send
//! - Call `frame_seal` to produce the complete frame bytes
//! - Write those bytes to the inner stream, possibly across multiple
//!   `poll_write` calls
//! - `poll_flush` forwards to the inner stream's flush
//!
//! Because AEAD sealing consumes counter state and is not replayable, we
//! can't just call it every time `poll_write` is called with the same
//! plaintext — we seal once, then write the resulting bytes.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::io::{AsyncRead, AsyncWrite};
use pin_project_lite::pin_project;

use crate::transport::{TxStream, RxStream, TransportError, TAG_SIZE};

/// Maximum plaintext payload size per frame we will seal or open.
/// Matches the reasonable block/transaction sizes plus headroom. Frames
/// larger than this are rejected at open time — prevents a malicious peer
/// from triggering unbounded memory allocation by sending a fake length
/// prefix of u32::MAX.
pub const MAX_FRAME_PAYLOAD: usize = 8 * 1024 * 1024; // 8 MiB

// ── Read state ───────────────────────────────────────────────────────────────

/// Internal reader state.
enum ReadState {
    /// Accumulating the 4-byte length prefix.
    Length {
        buf:  [u8; 4],
        /// Number of bytes already read into buf (0..=4).
        have: usize,
    },
    /// Accumulating the ciphertext body.
    Ciphertext {
        buf:  Vec<u8>,
        /// Number of bytes already read into buf (0..=buf.capacity()).
        have: usize,
        /// Total expected ciphertext length.
        want: usize,
    },
    /// Plaintext from a decrypted frame, being drained into caller buffers.
    Plaintext {
        buf:    Vec<u8>,
        /// Offset into `buf` of the next unread byte.
        cursor: usize,
    },
}

impl ReadState {
    fn initial() -> Self {
        ReadState::Length { buf: [0u8; 4], have: 0 }
    }
}

// ── Write state ──────────────────────────────────────────────────────────────

/// A single sealed frame awaiting delivery to the inner stream.
///
/// AEAD sealing consumes the tx nonce counter and is NOT replayable, so a
/// caller's buffer must be sealed exactly ONCE (H3). If the inner stream
/// returns `Poll::Pending` (or accepts only part of the frame), we keep the
/// already-sealed bytes here and resume from `cursor` on the next poll — we
/// never re-seal or re-enqueue the caller's buffer, which would deliver the
/// payload twice and desync the AEAD nonce/sequence.
struct PendingFrame {
    /// Complete wire frame: 4-byte length prefix + ciphertext (incl. tag).
    bytes: Vec<u8>,
    /// Offset within `bytes` of the first byte not yet accepted by the
    /// inner stream (cursor for partial writes).
    cursor: usize,
    /// Plaintext payload length sealed into this frame. Reported to the
    /// `poll_write` caller once the frame is fully handed to the inner
    /// stream, so the caller's progress accounting matches what was sent.
    payload_len: usize,
}

impl PendingFrame {
    fn is_drained(&self) -> bool {
        self.cursor >= self.bytes.len()
    }
}

/// Internal writer state. We buffer at most one outgoing frame at a time.
/// `None` means "no frame in progress — poll_write is free to seal one".
struct WriteState {
    pending: Option<PendingFrame>,
}

impl WriteState {
    fn new() -> Self {
        Self { pending: None }
    }
}

/// Drive `frame` into `inner` as far as possible without sealing anything.
/// Returns `Ready(Ok(()))` once every byte of the frame has been accepted.
fn drain_frame<S>(
    mut inner: Pin<&mut S>,
    cx: &mut Context<'_>,
    frame: &mut PendingFrame,
) -> Poll<io::Result<()>>
where
    S: AsyncWrite,
{
    while !frame.is_drained() {
        let slice = &frame.bytes[frame.cursor..];
        match inner.as_mut().poll_write(cx, slice) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(0)) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "inner write returned 0",
                )));
            }
            Poll::Ready(Ok(n)) => {
                frame.cursor += n;
            }
        }
    }
    Poll::Ready(Ok(()))
}

// ── KyberStream ──────────────────────────────────────────────────────────────

pin_project! {
    /// AEAD-framed async stream over an inner `AsyncRead + AsyncWrite`.
    pub struct KyberStream<S> {
        #[pin]
        inner: S,
        tx:    TxStream,
        rx:    RxStream,
        read_state:  ReadState,
        write_state: WriteState,
    }
}

impl<S> KyberStream<S> {
    /// Construct a new framed stream on top of `inner` using the supplied
    /// session keys (derived from the Sprint A1 handshake).
    pub fn new(inner: S, tx: TxStream, rx: RxStream) -> Self {
        Self {
            inner,
            tx,
            rx,
            read_state:  ReadState::initial(),
            write_state: WriteState::new(),
        }
    }

    /// Consume self and return the inner stream — useful for tests that
    /// want to inspect raw bytes post-handshake.
    pub fn into_inner(self) -> S {
        self.inner
    }
}

// ── AsyncRead impl ───────────────────────────────────────────────────────────

impl<S> AsyncRead for KyberStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if out.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let mut this = self.project();

        loop {
            match this.read_state {
                ReadState::Length { buf, have } => {
                    // Read up to 4 bytes of length prefix.
                    while *have < 4 {
                        let slot = &mut buf[*have..4];
                        match this.inner.as_mut().poll_read(cx, slot) {
                            Poll::Pending => return Poll::Pending,
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Ready(Ok(0)) => {
                                if *have == 0 {
                                    // Clean EOF at a frame boundary.
                                    return Poll::Ready(Ok(0));
                                } else {
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::UnexpectedEof,
                                        "eof mid length prefix",
                                    )));
                                }
                            }
                            Poll::Ready(Ok(n)) => { *have += n; }
                        }
                    }
                    // Have 4 bytes of length.
                    let ct_len = u32::from_be_bytes(*buf) as usize;
                    // Reject oversized frames to prevent DoS via fake length.
                    if ct_len > MAX_FRAME_PAYLOAD + TAG_SIZE || ct_len < TAG_SIZE {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("invalid frame length {}", ct_len),
                        )));
                    }
                    *this.read_state = ReadState::Ciphertext {
                        buf:  vec![0u8; ct_len],
                        have: 0,
                        want: ct_len,
                    };
                }

                ReadState::Ciphertext { buf, have, want } => {
                    while *have < *want {
                        let slot = &mut buf[*have..*want];
                        match this.inner.as_mut().poll_read(cx, slot) {
                            Poll::Pending => return Poll::Pending,
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Ready(Ok(0)) => {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "eof mid ciphertext",
                                )));
                            }
                            Poll::Ready(Ok(n)) => { *have += n; }
                        }
                    }
                    // Full ciphertext in buf. Decrypt.
                    let plaintext_len = (*want).saturating_sub(TAG_SIZE) as u32;
                    let aad = plaintext_len.to_be_bytes();
                    let pt = this.rx
                        .open(buf, &aad)
                        .map_err(transport_err_to_io)?;
                    *this.read_state = ReadState::Plaintext { buf: pt, cursor: 0 };
                }

                ReadState::Plaintext { buf, cursor } => {
                    let available = buf.len() - *cursor;
                    if available == 0 {
                        // Drained; reset and loop back to read next frame.
                        *this.read_state = ReadState::initial();
                        continue;
                    }
                    let n = available.min(out.len());
                    out[..n].copy_from_slice(&buf[*cursor..*cursor + n]);
                    *cursor += n;
                    return Poll::Ready(Ok(n));
                }
            }
        }
    }
}

// ── AsyncWrite impl ──────────────────────────────────────────────────────────

impl<S> AsyncWrite for KyberStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut this = self.project();

        // Phase 1 — a previously sealed frame is still outstanding: finish
        // writing THAT frame and report its payload length. We must NEVER
        // seal `buf` here: per the AsyncWrite contract, after Pending the
        // caller retries with the same buffer, and that buffer is exactly
        // what the pending frame already contains. Re-sealing it (the old
        // behaviour) delivered the payload to the peer twice and advanced
        // the AEAD nonce/sequence counter out of sync (finding H3).
        if let Some(frame) = this.write_state.pending.as_mut() {
            match drain_frame(this.inner.as_mut(), cx, frame) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    // Honesty caveat: this assumes the caller follows the
                    // AsyncWrite retry contract (same buffer after Pending).
                    // We cap at buf.len() so we never report more bytes than
                    // the caller offered this call, but if a caller retries
                    // with a *different* buffer, its accounting is undefined
                    // — as with any buffering AsyncWrite adapter.
                    let n = frame.payload_len.min(buf.len());
                    this.write_state.pending = None;
                    return Poll::Ready(Ok(n));
                }
            }
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // Phase 2 — idle: seal the caller's buffer into a new frame,
        // exactly once. Cap per-frame payload to keep memory bounded.
        let payload = if buf.len() > MAX_FRAME_PAYLOAD {
            &buf[..MAX_FRAME_PAYLOAD]
        } else {
            buf
        };

        // Seal: ciphertext = encrypt(payload, aad=length_prefix).
        let ct = this.tx
            .seal(payload, &(payload.len() as u32).to_be_bytes())
            .map_err(transport_err_to_io)?;

        // Prepend length.
        let mut framed = Vec::with_capacity(4 + ct.len());
        framed.extend_from_slice(&(ct.len() as u32).to_be_bytes());
        framed.extend_from_slice(&ct);

        let mut frame = PendingFrame {
            bytes:       framed,
            cursor:      0,
            payload_len: payload.len(),
        };

        // Try to drain immediately. On Pending we PARK the sealed frame —
        // the retry (Phase 1) resumes from `cursor` without re-sealing.
        match drain_frame(this.inner.as_mut(), cx, &mut frame) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(frame.payload_len)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => {
                this.write_state.pending = Some(frame);
                Poll::Pending
            }
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let mut this = self.project();

        // Drain any pending frame first. NOTE: on completion we deliberately
        // KEEP the (now fully drained) frame in the pending slot: its
        // payload_len has not yet been reported to the poll_write caller.
        // The next poll_write retry will see it drained and report it
        // WITHOUT sealing anything new — dropping the slot here would make
        // the retrying writer re-seal the same payload (double delivery).
        if let Some(frame) = this.write_state.pending.as_mut() {
            match drain_frame(this.inner.as_mut(), cx, frame) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {}
            }
        }

        this.inner.poll_flush(cx)
    }

    fn poll_close(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let mut this = self.project();

        // Drain any pending frame before closing. As in poll_flush, keep the
        // drained frame parked so an interleaved poll_write retry can still
        // report it instead of re-sealing.
        if let Some(frame) = this.write_state.pending.as_mut() {
            match drain_frame(this.inner.as_mut(), cx, frame) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {}
            }
        }

        this.inner.poll_close(cx)
    }
}

// ── Error conversion ─────────────────────────────────────────────────────────

fn transport_err_to_io(e: TransportError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

// ── Regression tests: H3 seal-once under backpressure ────────────────────────

#[cfg(test)]
mod seal_once_tests {
    use super::*;
    use crate::transport::{frame_open, RxStream, TxStream, STREAM_KEY_SIZE};
    use futures::executor::block_on;
    use futures::io::AsyncWriteExt;
    use std::collections::VecDeque;

    /// Mock inner AsyncWrite driven by a script: `None` = return
    /// Poll::Pending (after waking, so block_on re-polls), `Some(n)` =
    /// accept at most `n` bytes (partial write). Once the script is
    /// exhausted, every write is accepted in full. All accepted bytes are
    /// recorded in `written` for wire-level inspection.
    struct FlakyWriter {
        script:  VecDeque<Option<usize>>,
        written: Vec<u8>,
        /// Total number of poll_write calls observed (sanity/diagnostics).
        polls: usize,
    }

    impl FlakyWriter {
        fn new(script: Vec<Option<usize>>) -> Self {
            Self { script: script.into(), written: Vec::new(), polls: 0 }
        }
    }

    impl AsyncWrite for FlakyWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.polls += 1;
            match self.script.pop_front() {
                Some(None) => {
                    // Simulate backpressure; wake immediately so the
                    // single-threaded executor retries the write future.
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                Some(Some(cap)) => {
                    let n = buf.len().min(cap).max(1);
                    self.written.extend_from_slice(&buf[..n]);
                    Poll::Ready(Ok(n))
                }
                None => {
                    self.written.extend_from_slice(buf);
                    Poll::Ready(Ok(buf.len()))
                }
            }
        }
        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// FlakyWriter only writes, but KyberStream::new wants rx keys too.
    fn keys() -> (TxStream, RxStream) {
        let key = [0x42u8; STREAM_KEY_SIZE];
        (TxStream::new(key), RxStream::new(key))
    }

    /// Decode every complete frame present in `wire` with a receiver that
    /// shares the sender's key. Panics on trailing garbage. Returns the
    /// decrypted payloads in order; `rx.counter()` afterwards equals the
    /// number of frames, so callers can assert sequence advancement.
    fn decode_all(rx: &mut RxStream, wire: &[u8]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut off = 0;
        while off < wire.len() {
            let (consumed, pt) = frame_open(rx, &wire[off..])
                .expect("frame must decrypt in order with the shared key");
            off += consumed;
            out.push(pt);
        }
        assert_eq!(off, wire.len(), "no partial/trailing bytes on the wire");
        out
    }

    /// H3 regression: the inner sink returns Pending on the first attempt
    /// and then accepts the frame in small partial chunks. The payload must
    /// be sealed exactly once — before the fix, the retry path re-sealed
    /// the caller's buffer after draining the first frame, so the peer
    /// received the payload TWICE and the tx counter advanced by two.
    ///
    /// This test fails on the pre-fix code (decode_all yields 2 frames)
    /// and passes with the fix (exactly 1 frame, counter advanced by 1).
    #[test]
    fn backpressure_does_not_double_deliver() {
        let (tx, _rx_unused) = keys();
        let (_tx_unused, mut rx) = keys();

        // Pending first (parks the sealed frame), then partial writes.
        let inner = FlakyWriter::new(vec![None, Some(3), None, Some(7), Some(11)]);
        let mut stream = KyberStream::new(inner, tx, RxStream::new([0u8; STREAM_KEY_SIZE]));

        let payload = b"H3: seal exactly once under backpressure";
        block_on(async {
            stream.write_all(payload).await.expect("write_all");
            stream.flush().await.expect("flush");
        });

        let wire = stream.into_inner().written;
        let frames = decode_all(&mut rx, &wire);

        assert_eq!(
            frames.len(),
            1,
            "payload must appear in exactly ONE frame on the wire \
             (double delivery = H3 regression)"
        );
        assert_eq!(frames[0], payload, "single frame carries one payload copy");
        assert_eq!(
            rx.counter(),
            1,
            "receiver sequence must advance by exactly one for one write"
        );
    }

    /// H3 regression, multiple queued writes: under sustained backpressure
    /// every write must arrive in order, each exactly once, with the
    /// sequence counter advancing exactly once per write. With the pre-fix
    /// double-seal, each backpressured write burned TWO tx counters and put
    /// two payload copies on the wire, so the frame count and rx counter
    /// both diverged from the number of writes.
    #[test]
    fn multiple_writes_under_sustained_backpressure_in_order_once() {
        let (tx, _r) = keys();
        let (_t, mut rx) = keys();

        // Sustained backpressure: Pendings and tiny partial accepts
        // interleaved across all three writes.
        let inner = FlakyWriter::new(vec![
            None, Some(2), None, Some(5), None, None, Some(4), Some(1),
            None, Some(8), None, Some(3), None, Some(6),
        ]);
        let mut stream = KyberStream::new(inner, tx, RxStream::new([0u8; STREAM_KEY_SIZE]));

        let payloads: [&[u8]; 3] = [b"first frame", b"second frame", b"third frame"];
        block_on(async {
            for p in payloads {
                stream.write_all(p).await.expect("write_all");
            }
            stream.flush().await.expect("flush");
        });

        let wire = stream.into_inner().written;
        let frames = decode_all(&mut rx, &wire);

        assert_eq!(frames.len(), 3, "exactly one frame per write, no duplicates");
        for (i, p) in payloads.iter().enumerate() {
            assert_eq!(&frames[i], p, "frame {} delivered in order, once", i);
        }
        assert_eq!(rx.counter(), 3, "sequence advanced exactly once per write");
    }
}
