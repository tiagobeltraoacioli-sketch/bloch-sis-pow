//! Tests for `stratum_v2::session`.
//!
//! 8c-alpha: SessionState enum invariants.
//! 8d-alpha: drive_session_io phased loop (plaintext path via codec=None).
//! 8d-beta1: NoiseCodec round-trip through drive_session_io (codec=Some).

use crate::stratum_v2::handshake::{
    perform_handshake, ACT1_SIZE, ACT2_SIZE, DEFAULT_CERT_VALIDITY_SECS,
};
use crate::stratum_v2::session::{drive_session_io, SessionState};
use std::time::{Duration, Instant};
use stratum_core::noise_sv2::Initiator;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

// -------------------- 8c-alpha: SessionState enum ----------------------

#[test]
fn session_states_are_ordered() {
    let states = [
        SessionState::Handshaking,
        SessionState::AwaitingSetupConnection,
        SessionState::Live,
        SessionState::Closed,
    ];

    for (i, s1) in states.iter().enumerate() {
        for (j, s2) in states.iter().enumerate() {
            if i == j {
                assert_eq!(s1, s2);
            } else {
                assert_ne!(s1, s2, "states at idx {} and {} should differ", i, j);
            }
        }
    }
}

#[test]
fn session_state_debug_readable() {
    let s = SessionState::AwaitingSetupConnection;
    assert_eq!(format!("{:?}", s), "AwaitingSetupConnection");
}

#[test]
fn session_state_copy_semantics() {
    let original = SessionState::Live;
    let snapshot = original;
    assert_eq!(original, snapshot);
}

// -------------------- 8d-alpha: plaintext path (codec=None) ------------

async fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let accept = tokio::spawn(async move { listener.accept().await.unwrap().0 });
    let client = TcpStream::connect(addr).await.unwrap();
    let server = accept.await.unwrap();
    (server, client)
}

#[tokio::test]
async fn drive_session_io_closes_on_first_read_timeout() {
    let (server, _client) = tcp_pair().await;

    let first_timeout = Duration::from_millis(200);
    let idle = Duration::from_secs(5);

    let start = Instant::now();
    let state = drive_session_io(server, None, 1, first_timeout, idle, None, None, None)
        .await
        .unwrap();
    let elapsed = start.elapsed();

    assert_eq!(state, SessionState::Closed);
    assert!(
        elapsed >= first_timeout,
        "returned before phase-1 timeout: {:?} < {:?}",
        elapsed, first_timeout
    );
    assert!(
        elapsed < Duration::from_millis(800),
        "phase-1 timeout fired too late: {:?}",
        elapsed
    );
}

#[tokio::test]
#[ignore = "Sprint 8d contract — Phase-2 no longer echoes frames (Sprint 10-beta replaced echo with Mining Protocol dispatch). Will be replaced in 10-gamma with a real OpenStandardMiningChannel round-trip."]
async fn drive_session_io_echoes_and_loops_after_first_message() {
    let (server, mut client) = tcp_pair().await;

    let task = tokio::spawn(async move {
        drive_session_io(
            server,
            None,
            2,
            Duration::from_millis(500),
            Duration::from_millis(500),
            None,
            None,
            None,
        )
        .await
    });

    let m1 = b"setup-connection-placeholder";
    client.write_all(m1).await.unwrap();
    let mut echoed1 = vec![0u8; m1.len()];
    client.read_exact(&mut echoed1).await.unwrap();
    assert_eq!(&echoed1, m1, "phase 1 echo mismatch");

    let m2 = b"subsequent-mining-frame";
    client.write_all(m2).await.unwrap();
    let mut echoed2 = vec![0u8; m2.len()];
    client.read_exact(&mut echoed2).await.unwrap();
    assert_eq!(&echoed2, m2, "phase 2 echo mismatch");

    drop(client);
    let state = task.await.unwrap().unwrap();
    assert_eq!(state, SessionState::Closed);
}

#[tokio::test]
async fn drive_session_io_closes_fast_on_peer_disconnect() {
    let (server, client) = tcp_pair().await;

    let start = Instant::now();
    let task = tokio::spawn(async move {
        drive_session_io(
            server,
            None,
            3,
            Duration::from_secs(5),
            Duration::from_secs(5),
            None,
            None,
            None,
        )
        .await
    });

    drop(client);

    let state = task.await.unwrap().unwrap();
    let elapsed = start.elapsed();

    assert_eq!(state, SessionState::Closed);
    assert!(
        elapsed < Duration::from_secs(1),
        "peer disconnect not detected fast: {:?}",
        elapsed
    );
}

// -------------------- 8d-beta1: crypto round-trip ----------------------

// Copy of the authority_bytes helper from handshake_tests (duplicated
// because cross-test-module imports require an extra pub). Same seed
// pattern so the tests are self-contained.
fn authority_bytes(seed: u8) -> ([u8; 32], [u8; 32]) {
    use secp256k1::{Secp256k1, SecretKey};
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[seed; 32]).unwrap();
    let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);
    let secret_bytes: [u8; 32] = *sk.as_ref();
    let (xonly, _parity) = pk.x_only_public_key();
    let pub_bytes = xonly.serialize();
    (pub_bytes, secret_bytes)
}

/// End-to-end crypto test: full NOISE_NX handshake followed by an
/// encrypted round-trip through drive_session_io. If this passes, the
/// NoiseCodec integration is correct.
#[tokio::test]
#[ignore = "Sprint 8d contract — Phase-2 no longer echoes frames (Sprint 10-beta replaced echo with Mining Protocol dispatch). Will be replaced in 10-gamma with a real OpenStandardMiningChannel round-trip."]
async fn drive_session_io_crypto_roundtrip_with_real_handshake() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let (auth_pub, auth_sec) = authority_bytes(0x55);

    // Server: handshake (responder), then drive_session_io with codec.
    let server_task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let codec = perform_handshake(
            &mut socket,
            &auth_pub,
            &auth_sec,
            DEFAULT_CERT_VALIDITY_SECS,
            Duration::from_secs(5),
        )
        .await
        .expect("responder handshake");

        drive_session_io(
            socket,
            Some(codec),
            100,
            Duration::from_secs(2),
            Duration::from_secs(2),
            None,
            None,
            None,
        )
        .await
    });

    // Client: handshake (initiator).
    let mut client_sock = TcpStream::connect(addr).await.unwrap();
    let mut initiator = Initiator::from_raw_k(auth_pub).expect("initiator");

    let act1 = initiator.step_0().expect("init step_0");
    assert_eq!(act1.len(), ACT1_SIZE);
    client_sock.write_all(&act1).await.unwrap();

    let mut act2 = [0u8; ACT2_SIZE];
    client_sock.read_exact(&mut act2).await.unwrap();
    let mut client_codec = initiator.step_2(act2).expect("init step_2");

    // ---- Encrypted round-trip 1: phase-1 path ----------------------------
    let plaintext_1 = b"hello-encrypted-world".to_vec();
    let mut frame_out = plaintext_1.clone();
    client_codec.encrypt(&mut frame_out).expect("client encrypt");
    let ct1_len = frame_out.len();
    assert!(
        ct1_len > plaintext_1.len(),
        "ciphertext should include MAC tag"
    );
    client_sock.write_all(&frame_out).await.unwrap();

    let mut frame_in = vec![0u8; ct1_len];
    client_sock.read_exact(&mut frame_in).await.unwrap();
    client_codec.decrypt(&mut frame_in).expect("client decrypt");
    assert_eq!(
        frame_in, plaintext_1,
        "phase-1 decrypted echo must match plaintext"
    );

    // ---- Encrypted round-trip 2: live-loop path --------------------------
    let plaintext_2 = b"another-frame-in-the-live-loop".to_vec();
    let mut frame_out2 = plaintext_2.clone();
    client_codec.encrypt(&mut frame_out2).expect("client encrypt 2");
    let ct2_len = frame_out2.len();
    client_sock.write_all(&frame_out2).await.unwrap();

    let mut frame_in2 = vec![0u8; ct2_len];
    client_sock.read_exact(&mut frame_in2).await.unwrap();
    client_codec.decrypt(&mut frame_in2).expect("client decrypt 2");
    assert_eq!(
        frame_in2, plaintext_2,
        "phase-2 decrypted echo must match plaintext"
    );

    // ---- Clean shutdown --------------------------------------------------
    drop(client_sock);
    let state = server_task.await.expect("server task").expect("io result");
    assert_eq!(state, SessionState::Closed);
}
