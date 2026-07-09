//! Shared type definitions for BLOCH.
//!
//! This module exists to give common domain primitives (heights, hashes,
//! identifiers, etc.) a single home that can be imported by `consensus`,
//! `metrics`, `rpc`, and the upcoming `ffg` modules without circular deps.

pub mod heights;

pub use heights::{BlockCount, BlockHeight};
