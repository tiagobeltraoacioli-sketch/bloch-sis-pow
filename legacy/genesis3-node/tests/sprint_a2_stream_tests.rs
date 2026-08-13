//! Sprint A2 Phase 1 — KyberStream roundtrip tests.
//!
//! Verifies the AsyncRead/AsyncWrite adapter in isolation, using an
//! in-memory duplex channel rather than a real TCP socket.

#[cfg(test)]
mod a2_stream_tests {
    use bloch::transport::stream::*;
    use bloch::transport::{TxStream, RxStream, STREAM_KEY_SIZE};

    use futures::io::{AsyncReadExt, AsyncWriteExt};
    use futures::executor::block_on;
    use futures::future::join;

    /// Build two halves of a duplex pipe. Writes on A appear as reads on B
    /// and vice versa. Uses tokio_util's duplex-like pattern via `async_io`.
    /// For simplicity we use a tokio::io::duplex then wrap with futures compat.
    /// But to keep deps light, we use std::io::Cursor with split-by-shared-buffer
    /// via `futures::io::AsyncRead` impls of `Vec<u8>`-backed channels.
    ///
    /// Easiest approach: use `futures::io::AsyncReadExt::chain` + a pair of
    /// `futures::channel::mpsc::unbounded` channels.
    ///
    /// Even simpler: use `async_std::io::MemoryPipe` — but we don't have async_std.
    ///
    /// Simplest that works with dependencies we already have: write a tiny
    /// byte-oriented duplex ourselves using `futures::channel::mpsc`.
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    /// One end of an in-memory duplex pipe. Reads pull from `incoming`,
    /// writes push to `outgoing`.
    struct PipeEnd {
        incoming: Arc<Mutex<VecDeque<u8>>>,
        outgoing: Arc<Mutex<VecDeque<u8>>>,
    }

    impl futures::io::AsyncRead for PipeEnd {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<std::io::Result<usize>> {
            let mut q = self.incoming.lock().unwrap();
            if q.is_empty() {
                // In a real async system we'd register the waker and return
                // Pending. For these tests we drive both halves in lockstep
                // via block_on + join, so "pending" means "we'll make progress
                // next round" — we return Ready(Ok(0)) only when the sender
                // is gone. Here we return Pending with a trivial waker wake.
                // Simpler: yield by returning Pending immediately; the joined
                // future will schedule us again.
                _cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            let n = q.len().min(buf.len());
            for i in 0..n {
                buf[i] = q.pop_front().unwrap();
            }
            Poll::Ready(Ok(n))
        }
    }

    impl futures::io::AsyncWrite for PipeEnd {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            let mut q = self.outgoing.lock().unwrap();
            for b in buf { q.push_back(*b); }
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn duplex_pair() -> (PipeEnd, PipeEnd) {
        let a_to_b = Arc::new(Mutex::new(VecDeque::new()));
        let b_to_a = Arc::new(Mutex::new(VecDeque::new()));
        (
            PipeEnd { incoming: b_to_a.clone(), outgoing: a_to_b.clone() },
            PipeEnd { incoming: a_to_b,         outgoing: b_to_a },
        )
    }

    /// Build matching TxStream/RxStream pairs with the same key material,
    /// simulating what would come out of a Sprint A1 handshake.
    fn make_session_keys() -> ([u8; STREAM_KEY_SIZE], [u8; STREAM_KEY_SIZE]) {
        // Two distinct keys, one per direction.
        let k_i2r = [1u8; STREAM_KEY_SIZE];
        let k_r2i = [2u8; STREAM_KEY_SIZE];
        (k_i2r, k_r2i)
    }

    fn make_pair() -> (KyberStream<PipeEnd>, KyberStream<PipeEnd>) {
        let (a, b) = duplex_pair();
        let (k_i2r, k_r2i) = make_session_keys();

        // Side A (initiator): tx=i2r, rx=r2i
        let a_stream = KyberStream::new(a, TxStream::new(k_i2r), RxStream::new(k_r2i));
        // Side B (responder): tx=r2i, rx=i2r
        let b_stream = KyberStream::new(b, TxStream::new(k_r2i), RxStream::new(k_i2r));

        (a_stream, b_stream)
    }

    #[test]
    fn single_message_roundtrip() {
        let (mut a, mut b) = make_pair();

        block_on(async {
            let write_fut = async {
                a.write_all(b"hello world").await.unwrap();
                a.flush().await.unwrap();
            };
            let read_fut = async {
                let mut buf = [0u8; 11];
                b.read_exact(&mut buf).await.unwrap();
                assert_eq!(&buf, b"hello world");
            };
            join(write_fut, read_fut).await;
        });
    }

    #[test]
    fn multiple_messages_roundtrip() {
        let (mut a, mut b) = make_pair();

        block_on(async {
            let write_fut = async {
                for i in 0..5u8 {
                    let msg = format!("msg-{}", i);
                    a.write_all(msg.as_bytes()).await.unwrap();
                    a.flush().await.unwrap();
                }
            };
            let read_fut = async {
                let mut received = Vec::<u8>::new();
                while received.len() < 25 { // "msg-0" through "msg-4" = 5*5 = 25
                    let mut buf = [0u8; 32];
                    let n = b.read(&mut buf).await.unwrap();
                    received.extend_from_slice(&buf[..n]);
                }
                let s = std::str::from_utf8(&received[..25]).unwrap();
                // All 5 messages should be concatenated.
                assert!(s.contains("msg-0"));
                assert!(s.contains("msg-4"));
            };
            join(write_fut, read_fut).await;
        });
    }

    #[test]
    fn bidirectional_traffic() {
        let (mut a, mut b) = make_pair();

        block_on(async {
            let a_fut = async {
                a.write_all(b"ping").await.unwrap();
                a.flush().await.unwrap();
                let mut buf = [0u8; 4];
                a.read_exact(&mut buf).await.unwrap();
                assert_eq!(&buf, b"pong");
            };
            let b_fut = async {
                let mut buf = [0u8; 4];
                b.read_exact(&mut buf).await.unwrap();
                assert_eq!(&buf, b"ping");
                b.write_all(b"pong").await.unwrap();
                b.flush().await.unwrap();
            };
            join(a_fut, b_fut).await;
        });
    }

    #[test]
    fn larger_payload_roundtrip() {
        // 64 KB payload exercises multi-frame writes if poll_write ever
        // sees more than it can fit in one frame.
        let (mut a, mut b) = make_pair();
        let payload: Vec<u8> = (0..65536u32).map(|i| (i & 0xff) as u8).collect();
        let payload_clone = payload.clone();

        block_on(async {
            let write_fut = async {
                a.write_all(&payload_clone).await.unwrap();
                a.flush().await.unwrap();
            };
            let read_fut = async {
                let mut received = vec![0u8; payload.len()];
                b.read_exact(&mut received).await.unwrap();
                assert_eq!(received, payload);
            };
            join(write_fut, read_fut).await;
        });
    }

    #[test]
    fn wrong_key_fails_to_decrypt() {
        let (a, b) = duplex_pair();
        // Side A uses key X for tx, but side B expects key Y for rx.
        let wrong_rx_key = [99u8; STREAM_KEY_SIZE];
        let mut a_stream = KyberStream::new(a, TxStream::new([1u8; STREAM_KEY_SIZE]), RxStream::new([2u8; STREAM_KEY_SIZE]));
        let mut b_stream = KyberStream::new(b, TxStream::new([2u8; STREAM_KEY_SIZE]), RxStream::new(wrong_rx_key));

        block_on(async {
            let write_fut = async {
                a_stream.write_all(b"secret").await.unwrap();
                a_stream.flush().await.unwrap();
            };
            let read_fut = async {
                let mut buf = [0u8; 6];
                // Should fail with InvalidData (AEAD tag mismatch).
                let err = b_stream.read_exact(&mut buf).await.unwrap_err();
                assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
            };
            join(write_fut, read_fut).await;
        });
    }
}
