//! postern-wallet — standalone Bloch-SIS CLI wallet (the postmarketOS
//! package target). Built only with `--features wallet-cli`:
//!
//! ```sh
//! cargo build -p bloch-crypto --no-default-features --features wallet-cli
//! ```
//!
//! Thin shim over `bloch_crypto::wallet::cli::main` so the wallet ships
//! without the full node's dependency tree (no rocksdb/libp2p/tokio/blst/
//! secp256k1). The `Balance`/`Send` subcommands talk JSON-RPC to a node over
//! plain `std::net::TcpStream`; keygen/address/sign are fully offline.

fn main() {
    bloch_crypto::wallet::cli::main();
}
