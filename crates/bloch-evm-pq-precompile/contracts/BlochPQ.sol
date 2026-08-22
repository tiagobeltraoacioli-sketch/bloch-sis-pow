// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.20;

/// @title BlochPQ — the Solidity side of BLOCH-L1-EVM-AUTHORIZATION §6.2.
/// @notice Verifies a `SUITE_MLDSA65_FALCON1024` signature and returns the
///         signer's Bloch address. This is the PQ replacement for `ecrecover`.
///
/// NOT COMPILED IN CI. There is no pinned `solc` in this repository and no
/// EVM to run the bytecode against, so this file is a normative reference:
/// `tests/permit_pattern.rs` models it statement for statement — same digest
/// bytes, same checks, same order — and compiling it with a pinned solc and
/// re-running those tests against a real EVM is an activation gate
/// (BLOCH-L1-EVM-PQ-PRECOMPILE.md §9), not something already done.
library BlochPQ {
    /// The reserved Bloch precompile block: 16 zero bytes, the `B1 0C` suite
    /// magic reused as a namespace, then a big-endian index.
    address internal constant PQ_VERIFY =
        0x00000000000000000000000000000000B10C0001;

    /// Enveloped hybrid public key: 4-byte suite header + 3,745-byte body.
    uint256 internal constant PK_LEN = 3749;

    /// @notice Recover the signer of `digest`, or `address(0)`.
    /// @dev The call NEVER reverts and reads no state, so `staticcall` is
    ///      correct and the `success` flag can only be false if the
    ///      precompile is absent — i.e. before the flag day. Treat that as
    ///      "no signer", never as "valid".
    ///
    ///      The precompile returns the ADDRESS, not a bool, because a
    ///      contract cannot derive one: a Bloch address is
    ///      `SHA3-256(envelopedPk)[0..20]` and Solidity's `keccak256` is
    ///      Keccak-256, a different padding rule. With a bool, every caller
    ///      would have to trust an address handed to it beside the signature.
    function recover(bytes32 digest, bytes memory pk, bytes memory sig)
        internal
        view
        returns (address)
    {
        if (pk.length != PK_LEN) return address(0);
        bytes memory input =
            abi.encodePacked(digest, uint256(pk.length), uint256(sig.length), pk, sig);
        (bool ok, bytes memory out) = PQ_VERIFY.staticcall(input);
        if (!ok || out.length != 32) return address(0);
        return address(uint160(uint256(bytes32(out))));
    }

    /// @notice Gas the precompile will charge for this call, so a caller can
    ///         budget without guessing. Mirrors `pq_verify_gas`.
    function gasFor(uint256 pkLen, uint256 sigLen) internal pure returns (uint256) {
        uint256 len = 96 + pkLen + sigLen;
        return 72748 + 39 * ((len + 31) / 32);
    }
}
