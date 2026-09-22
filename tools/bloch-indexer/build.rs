// SPDX-License-Identifier: AGPL-3.0-or-later

fn main() {
    // `src/lib.rs` includes the node's genesis decoder by path.  Mark this
    // consumer so tests coupled to the node engine stay with the node, while
    // the decoder's self-contained tests remain available here.
    println!("cargo:rustc-check-cfg=cfg(bloch_indexer)");
    println!("cargo:rustc-cfg=bloch_indexer");
}
