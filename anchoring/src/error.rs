// SPDX-License-Identifier: MIT OR Apache-2.0
//! Crate-wide error type.

use thiserror::Error;

/// Errors surfaced by the anchoring framework.
#[derive(Debug, Error)]
pub enum AnchorError {
    /// A commitment / script_pubkey / txid had the wrong byte length.
    #[error("bad length: expected {expected} bytes, got {got}")]
    BadLength { expected: usize, got: usize },

    /// Hex decoding failed.
    #[error("hex decode error: {0}")]
    Hex(#[from] hex::FromHexError),

    /// The transaction bytes could not be parsed with the minimal codec.
    #[error("transaction decode error: {0}")]
    TxDecode(String),

    /// The outputs of a transaction did not carry a valid anchor commitment.
    #[error("no valid Bloch anchor commitment found in transaction outputs")]
    NoAnchor,

    /// The RPC transport failed (network, IO, etc.).
    #[error("rpc transport error: {0}")]
    Transport(String),

    /// The node returned a JSON-RPC error (including the `result.error`
    /// non-standard shape documented in the roadmap §1.2).
    #[error("rpc returned error: {0}")]
    Rpc(String),

    /// A response was missing an expected field or had the wrong type.
    #[error("unexpected rpc response shape: {0}")]
    BadResponse(String),

    /// The caller-supplied signer failed to build the raw transaction.
    #[error("signer error: {0}")]
    Signer(String),

    /// Timed out waiting for the requested number of confirmations.
    #[error("timed out after {attempts} polls waiting for {wanted} confirmations (last seen: {seen})")]
    ConfirmationTimeout {
        attempts: u32,
        wanted: u32,
        seen: u64,
    },
}

/// Convenience result alias.
pub type Result<T> = std::result::Result<T, AnchorError>;
