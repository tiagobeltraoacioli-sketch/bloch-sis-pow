// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.20;

import {BlochPQ} from "./BlochPQ.sol";

/// @title PQPermitToken — signature-authorized allowances without ecrecover.
///
/// @notice THIS IS NOT EIP-2612 AND CANNOT BE. EIP-2612's
///         `permit(address,address,uint256,uint256,uint8,bytes32,bytes32)`
///         carries the signature in `(v, r, s)` — 65 bytes. A
///         `SUITE_MLDSA65_FALCON1024` signature is ~4,589 bytes and needs a
///         3,749-byte public key beside it, because the suite is not
///         recoverable. There is no encoding of one into the other.
///
///         Consequences, so nobody finds them out by integrating:
///         - the selector differs, so every router, aggregator and
///           permit-forwarder that calls the 2612 selector reverts here;
///         - a stock `UniswapV2ERC20` redeployed on Bloch exposes a `permit`
///           that NO Bloch wallet can satisfy — a dead entry point, not an
///           error message. Supporting permit in the Postern DEX is a SOURCE
///           FORK of `UniswapV2ERC20` and of the router paths that call it;
///         - the type hash is `PermitPQ(...)`, deliberately NOT `Permit(...)`,
///           so no signature can ever cross between the two families.
///
///         And read BLOCH-L1-EVM-PQ-PRECOMPILE.md §7 before reaching for this
///         at all: for the ordinary "approve then swap" case, PQ permit is
///         *worse* than two transactions. Its real use is the case where the
///         signer is not the sender — relayed and sponsored calls, contract
///         wallets, multisig, bridge validator sets.
contract PQPermitToken {
    string public constant name = "PQ Permit Demo";
    string public constant version = "1";

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => uint256) public nonces;

    bytes32 public constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    /// NOT `Permit(...)`. See the contract notice.
    bytes32 public constant PERMIT_PQ_TYPEHASH = keccak256(
        "PermitPQ(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
    );

    event Approval(address indexed owner, address indexed spender, uint256 value);

    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                block.chainid,
                address(this)
            )
        );
    }

    /// @notice The exact 32 bytes a wallet must sign.
    /// @dev `public view` on purpose: a wallet must be able to recompute the
    ///      digest from the structured fields and show the user what is being
    ///      authorized. Signing 32 opaque bytes is how a permit signature
    ///      becomes indistinguishable from anything else the same key signs.
    function permitDigest(
        address owner,
        address spender,
        uint256 value,
        uint256 nonce,
        uint256 deadline
    ) public view returns (bytes32) {
        bytes32 structHash =
            keccak256(abi.encode(PERMIT_PQ_TYPEHASH, owner, spender, value, nonce, deadline));
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(), structHash));
    }

    /// @notice Grant `spender` an allowance of `value` on `owner`'s balance,
    ///         authorized by `owner`'s ML-DSA-65 ‖ Falcon-1024 signature.
    /// @param pk  the enveloped hybrid public key (3,749 bytes)
    /// @param sig the enveloped hybrid signature (~4,593 bytes)
    function permitPQ(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        bytes calldata pk,
        bytes calldata sig
    ) external {
        require(block.timestamp <= deadline, "PQPermit: expired");
        bytes32 digest = permitDigest(owner, spender, value, nonces[owner], deadline);
        address signer = BlochPQ.recover(digest, pk, sig);
        require(signer != address(0), "PQPermit: bad signature");
        require(signer == owner, "PQPermit: wrong signer");
        // Consumed BEFORE the state it authorizes, so a replay of the same
        // bytes recomputes a different digest and fails at `recover`.
        nonces[owner] += 1;
        allowance[owner][spender] = value;
        emit Approval(owner, spender, value);
    }

    function transferFrom(address from, address to, uint256 value) external returns (bool) {
        uint256 a = allowance[from][msg.sender];
        require(a >= value, "PQPermit: allowance");
        require(balanceOf[from] >= value, "PQPermit: balance");
        allowance[from][msg.sender] = a - value;
        balanceOf[from] -= value;
        balanceOf[to] += value;
        return true;
    }

    /// Test scaffolding only.
    function mint(address to, uint256 value) external {
        balanceOf[to] += value;
    }
}
