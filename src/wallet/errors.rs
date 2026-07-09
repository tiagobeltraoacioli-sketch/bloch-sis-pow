//! Wallet-specific error types.
//!
//! Uses `thiserror` for ergonomic #[derive(Error)] support and clean
//! Display impls. All error values are non-sensitive (no key material
//! leaks even if printed/logged).

use thiserror::Error;

#[derive(Debug, Error)]
pub enum WalletError {
    // ── Crypto / signing errors ──────────────────────────────────────────────

    #[error("cryptographic error: {0}")]
    Crypto(String),

    #[error("invalid seed phrase: {0}")]
    InvalidSeedPhrase(String),

    #[error("wrong password")]
    WrongPassword,

    #[error("password too weak: {0}")]
    WeakPassword(String),

    #[error("unsupported keyfile version: {0}")]
    UnsupportedVersion(u32),

    // ── Transaction building errors ──────────────────────────────────────────

    #[error("insufficient funds: need {needed} sats, have {have}")]
    InsufficientFunds { needed: u64, have: u64 },

    #[error("arithmetic overflow")]
    Overflow,

    #[error("address does not match wallet network")]
    NetworkMismatch,

    // ── I/O and parsing ──────────────────────────────────────────────────────

    #[error("I/O error: {0}")]
    Io(String),

    #[error("parse error: {0}")]
    Parse(String),

    // ── Network / RPC errors ─────────────────────────────────────────────────

    #[error("network error: {0}")]
    Network(String),

    #[error("RPC error: {0}")]
    RpcError(String),

    #[error("bad response from node: {0}")]
    BadResponse(String),
}
