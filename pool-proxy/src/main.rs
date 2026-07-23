//! bloch-pool-proxy — thin binary entry point.
//!
//! Initialises logging, loads config from the environment, and hands off to
//! [`server::ProxyServer::run`], which blocks until a shutdown signal. All
//! real logic lives in the library crate so it can be unit-tested.

use std::process::ExitCode;

use bloch_pool_proxy::server::{self, ProxyServer};

#[tokio::main]
async fn main() -> ExitCode {
    // `RUST_LOG=info` by default if the caller set nothing.
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info"),
    )
    .init();

    let cfg = match server::config_from_env() {
        Ok(cfg) => cfg,
        Err(e) => {
            log::error!("configuration error: {}", e);
            eprintln!("configuration error: {}", e);
            return ExitCode::FAILURE;
        }
    };

    if let Err(e) = ProxyServer::new(cfg).run().await {
        log::error!("fatal: {}", e);
        eprintln!("fatal: {}", e);
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}
