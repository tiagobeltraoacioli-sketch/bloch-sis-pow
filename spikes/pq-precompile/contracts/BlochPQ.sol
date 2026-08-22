// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.20;

/// @title BlochPQ — the safe way to call the hybrid-verification precompile.
/// @notice Spec: docs/specs/BLOCH-L1-EVM-PQ-PRECOMPILE.md. The EVM is NOT at
///         L1; this compiles against nothing that runs today.
/// @dev    The precompile is `pure` in effect and reached by STATICCALL, so a
///         library function marked `view` is enough and no state is touched.
library BlochPQ {
    /// Reserved Bloch precompile block: 16 zero bytes, the envelope magic
    /// `B1 0C`, then a u16 index. `pq_verify` is index 1. Written through
    /// uint160 because an all-lowercase address literal fails solc's checksum.
    address internal constant PQ_VERIFY = address(uint160(0xB10C0001));

    /// Fixed by the suite: enveloped ML-DSA-65 ‖ Falcon-1024 public key.
    uint256 internal constant PK_BYTES = 3749;
    uint256 internal constant SIG_MIN_BYTES = 3314;
    uint256 internal constant SIG_MAX_BYTES = 4775;

    /// @notice The signer's Bloch address, or `address(0)` if the signature is
    ///         not valid for `digest` under `pk`.
    /// @dev    ecrecover-shaped ON PURPOSE. A bare `bool` return would let a
    ///         caller check "somebody signed this" and forget to check WHO —
    ///         the oldest hole in signature-checked contracts. Here the caller
    ///         cannot use the result without comparing an address.
    ///         `address(0)` is the failure value: a public key hashing to 20
    ///         zero bytes is a 2^-160 event and is treated as unusable.
    function recover(bytes32 digest, bytes memory pk, bytes memory sig)
        internal
        view
        returns (address)
    {
        if (pk.length != PK_BYTES) return address(0);
        if (sig.length < SIG_MIN_BYTES || sig.length > SIG_MAX_BYTES) return address(0);

        // The precompile's framing, byte for byte: msg32 ‖ u256 ‖ u256 ‖ pk ‖ sig,
        // and nothing after it.
        bytes memory input = abi.encodePacked(digest, pk.length, sig.length, pk, sig);

        (bool ok, bytes memory ret) = PQ_VERIFY.staticcall(input);
        // `ok` is false only on out-of-gas / missing precompile: the precompile
        // itself never reverts, it returns the zero word.
        if (!ok || ret.length != 32) return address(0);
        return abi.decode(ret, (address));
    }

    /// @notice True iff `signer` (a Bloch 20-byte address) signed `digest`.
    function verify(address signer, bytes32 digest, bytes memory pk, bytes memory sig)
        internal
        view
        returns (bool)
    {
        return signer != address(0) && recover(digest, pk, sig) == signer;
    }
}
