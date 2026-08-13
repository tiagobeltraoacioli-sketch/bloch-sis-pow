use std::time::Duration;

use stratum_core::noise_sv2::Initiator;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::stratum_v2::handshake::{
    perform_handshake, ACT1_SIZE, ACT2_SIZE, DEFAULT_CERT_VALIDITY_SECS,
};

// secp256k1 0.29 for local keypair generation (compatible with our wider project).
// We only use it here to derive deterministic test authority bytes.
use secp256k1::{Secp256k1, SecretKey};

fn authority_bytes(seed: u8) -> ([u8; 32], [u8; 32]) {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[seed; 32]).unwrap();
    let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);
    let secret_bytes: [u8; 32] = *sk.as_ref();
    // x-only pubkey (32 bytes)
    let (xonly, _parity) = pk.x_only_public_key();
    let pub_bytes = xonly.serialize();
    (pub_bytes, secret_bytes)
}

#[tokio::test]
async fn handshake_happy_path() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let (auth_pub, auth_sec) = authority_bytes(0x11);

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
        .expect("server handshake");
        drop(codec);
        "server done"
    });

    let mut client = TcpStream::connect(addr).await.unwrap();
    let mut initiator = Initiator::from_raw_k(auth_pub).expect("initiator");

    let act1 = initiator.step_0().expect("init step_0");
    assert_eq!(act1.len(), ACT1_SIZE);
    client.write_all(&act1).await.unwrap();

    let mut act2 = [0u8; ACT2_SIZE];
    client.read_exact(&mut act2).await.unwrap();
    let _client_codec = initiator.step_2(act2).expect("init step_2");

    let result = server_task.await.expect("server task");
    assert_eq!(result, "server done");
}

#[tokio::test]
async fn handshake_rejects_short_act1() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let (auth_pub, auth_sec) = authority_bytes(0x33);

    let server_task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        perform_handshake(
            &mut socket,
            &auth_pub,
            &auth_sec,
            DEFAULT_CERT_VALIDITY_SECS,
            Duration::from_secs(2),
        )
        .await
    });

    let mut client = TcpStream::connect(addr).await.unwrap();
    client.write_all(&[0u8; 30]).await.unwrap();
    drop(client);

    let result = server_task.await.expect("server task");
    assert!(result.is_err(), "must fail on truncated act1");
}

#[tokio::test]
async fn handshake_times_out_on_slow_client() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let (auth_pub, auth_sec) = authority_bytes(0x44);

    let server_task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        perform_handshake(
            &mut socket,
            &auth_pub,
            &auth_sec,
            DEFAULT_CERT_VALIDITY_SECS,
            Duration::from_millis(200),
        )
        .await
    });

    let _client = TcpStream::connect(addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;

    let result = server_task.await.expect("server task");
    assert!(result.is_err(), "must time out when client is silent");
    if let Err(e) = result {
        let msg = format!("{}", e);
        assert!(
            msg.contains("timeout") || msg.contains("time"),
            "error should mention timeout, got: {}",
            msg
        );
    }
}
