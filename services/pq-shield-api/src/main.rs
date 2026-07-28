//! pq-shield-api binary — a NON-CUSTODIAL developer HTTP service over `bloch-pq-vault`.
//!
//! Construction + verification only. Never holds a private key; never signs.
//!
//! Run:      cargo run -p pq-shield-api          (binds 127.0.0.1:8787 by default)
//! Bind:     PQ_SHIELD_BIND=0.0.0.0:8787 cargo run
//!
//! This is a STANDALONE service — it is its own cargo workspace and does NOT link
//! the Bloch chain node. Do not colocate it on a founder/chain node.

use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    let app = pq_shield_api::router();

    let bind = std::env::var("PQ_SHIELD_BIND").unwrap_or_else(|_| "127.0.0.1:8787".to_string());
    let addr: SocketAddr = bind.parse().unwrap_or_else(|e| {
        eprintln!("invalid PQ_SHIELD_BIND `{bind}`: {e}");
        std::process::exit(1);
    });

    println!("pq-shield-api :: NON-CUSTODIAL (never signs, never holds a key)");
    println!("listening on http://{addr}  —  GET / for docs, GET /health for liveness");

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| {
            eprintln!("failed to bind {addr}: {e}");
            std::process::exit(1);
        });

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("server error");
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    println!("\nshutting down pq-shield-api");
}
