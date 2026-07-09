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

/// Internal writer state. We buffer at most one outgoing frame at a time.
struct WriteState {
    /// Sealed frame bytes pending write to the inner stream.
    /// Empty means "no frame in progress — poll_write is free to start one".
    pending: Vec<u8>,
    /// Offset within `pending` of the first unwritten byte.
    cursor:  usize,
}

impl WriteState {
    fn new() -> Self {
        Self { pending: Vec::new(), cursor: 0 }
    }
    fn is_idle(&self) -> bool {
        self.cursor >= self.pending.len()
    }
    fn reset(&mut self) {
        self.pending.clear();
        self.cursor = 0;
    }
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
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let mut this = self.project();

        // If we have nothing pending, seal the caller's buffer into a new frame.
        // Note: we intentionally seal the WHOLE buf at once (up to a cap) so
        // the caller sees a single poll_write consume a known chunk.
        if this.write_state.is_idle() {
            // Cap per-frame payload to keep memory bounded.
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

            this.write_state.pending = framed;
            this.write_state.cursor  = 0;

            // Consumed from caller's perspective.
            // We'll now drain `pending` into the inner stream across potentially
            // multiple poll_write calls, but we must report progress based on the
            // caller's buffer, not the inner stream. Pattern: keep looping until
            // pending is fully written, then return Ok(payload.len()). If inner
            // goes Pending, we return Pending — the caller will retry with the
            // same buffer, and on retry we see pending is NOT idle and just
            // continue draining without re-sealing.
            let sealed_payload_len = payload.len();

            // Try to drain immediately.
            while !this.write_state.is_idle() {
                let slice = &this.write_state.pending[this.write_state.cursor..];
                match this.inner.as_mut().poll_write(cx, slice) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "inner write returned 0",
                        )));
                    }
                    Poll::Ready(Ok(n)) => {
                        this.write_state.cursor += n;
                    }
                }
            }
            this.write_state.reset();
            return Poll::Ready(Ok(sealed_payload_len));
        }

        // Pending is in progress — caller retrying. Continue draining.
        while !this.write_state.is_idle() {
            let slice = &this.write_state.pending[this.write_state.cursor..];
            match this.inner.as_mut().poll_write(cx, slice) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "inner write returned 0",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    this.write_state.cursor += n;
                }
            }
        }
        // Frame fully written. Tell the caller they can move on.
        // We don't actually know the original payload length here, so we
        // report 0 and rely on the caller to have made progress on their
        // previous call. This is safe because our first branch above
        // reports the real progress when sealing starts.
        this.write_state.reset();
        // Hm — returning Ok(0) here could loop the caller. Better: signal
        // that the previous call is done by returning Ok(buf.len()) of the
        // buffer they gave us this time (we'll just seal it now).
        // Actually, simpler: since is_idle() is now true, re-enter the function.
        // But we can't re-enter easily; instead, proxy to the top branch logic.
        // Easiest correct answer: return to top of poll_write. Since we can't
        // recurse safely here, we return Ok(0) only if buf is empty, else we
        // seal the buf now inline.
        //
        // Inline re-seal path:
        let payload = if buf.len() > MAX_FRAME_PAYLOAD {
            &buf[..MAX_FRAME_PAYLOAD]
        } else {
            buf
        };
        let ct = this.tx
            .seal(payload, &(payload.len() as u32).to_be_bytes())
            .map_err(transport_err_to_io)?;
        let mut framed = Vec::with_capacity(4 + ct.len());
        framed.extend_from_slice(&(ct.len() as u32).to_be_bytes());
        framed.extend_from_slice(&ct);
        this.write_state.pending = framed;
        this.write_state.cursor  = 0;
        let sealed_payload_len = payload.len();
        while !this.write_state.is_idle() {
            let slice = &this.write_state.pending[this.write_state.cursor..];
            match this.inner.as_mut().poll_write(cx, slice) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "inner write returned 0",
                    )));
                }
                Poll::Ready(Ok(n)) => { this.write_state.cursor += n; }
            }
        }
        this.write_state.reset();
        Poll::Ready(Ok(sealed_payload_len))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let mut this = self.project();

        // Drain any pending frame first.
        while !this.write_state.is_idle() {
            let slice = &this.write_state.pending[this.write_state.cursor..];
            match this.inner.as_mut().poll_write(cx, slice) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "inner write returned 0 during flush",
                    )));
                }
                Poll::Ready(Ok(n)) => { this.write_state.cursor += n; }
            }
        }
        this.write_state.reset();

        this.inner.poll_flush(cx)
    }

    fn poll_close(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let mut this = self.project();

        // Drain any pending frame before closing.
        while !this.write_state.is_idle() {
            let slice = &this.write_state.pending[this.write_state.cursor..];
            match this.inner.as_mut().poll_write(cx, slice) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "inner write returned 0 during close",
                    )));
                }
                Poll::Ready(Ok(n)) => { this.write_state.cursor += n; }
            }
        }
        this.write_state.reset();

        this.inner.poll_close(cx)
    }
}

// ── Error conversion ─────────────────────────────────────────────────────────

fn transport_err_to_io(e: TransportError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}
