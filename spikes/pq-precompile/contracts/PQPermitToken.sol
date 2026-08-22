// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.20;

import {BlochPQ} from "./BlochPQ.sol";

/// @title PQPermitToken — signature-authorised approval WITHOUT ecrecover.
///
/// @notice This is the §6.2 existence proof: the ecrecover-shaped contract
///         pattern, re-keyed to ML-DSA-65 ‖ Falcon-1024. It is deliberately a
///         minimal ERC-20; the point is `permitPQ`, not the token.
///
/// @dev THIS IS NOT EIP-2612 AND CANNOT BE. Read this before integrating:
///
///  1. **Different selector.** EIP-2612 is
///     `permit(address,address,uint256,uint256,uint8,bytes32,bytes32)`. A
///     4,589-byte signature and a 3,749-byte public key do not fit in
///     `(v,r,s)` — 65 bytes — so the PQ function is
///     `permitPQ(address,address,uint256,uint256,bytes,bytes)`, a DIFFERENT
///     selector. Any router, aggregator, or periphery contract that calls the
///     2612 selector (Uniswap V2's `removeLiquidityWithPermit`, every
///     `permit2`-shaped integration) will hit the fallback and revert. That is
///     the intended behaviour: a dead 2612 entry point that silently accepted
///     something would be worse.
///
///  2. **No `DOMAIN_SEPARATOR` compatibility claim.** The EIP-712 *digest
///     construction* is kept verbatim — `\x19\x01 ‖ domainSeparator ‖
///     structHash`, keccak256 throughout — so wallets and tooling can display
///     and reproduce it with existing EIP-712 code. Only the signature
///     algorithm differs. The typehash string is `PermitPQ(...)`, not
///     `Permit(...)`: a 2612 signature must never be replayable here, nor the
///     reverse.
///
///  3. **keccak256, not SHA3-256, and that is load-bearing.** Bloch's §6.1
///     transaction signing root is `SHA3-256(DS_EVM_TX ‖ fields)`. Contract
///     message digests are keccak256. The two hash functions are different
///     functions, so a signature produced for a permit can never also be a
///     valid transaction authorisation, and vice versa. Do not "unify" these.
///
///  4. **The public key travels in calldata, every time.** The precompile is
///     pure: it reads no account state, so it cannot look a public key up by
///     address. A `permitPQ` call therefore carries 3,749 + ~4,593 bytes.
///     Price it before you design around it (spec §7).
contract PQPermitToken {
    string public constant name = "PQ Permit Demo";
    string public constant symbol = "PQPD";
    uint8 public constant decimals = 18;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    /// Replay protection. Incremented on every accepted permit.
    mapping(address => uint256) public nonces;

    bytes32 public immutable DOMAIN_SEPARATOR;

    /// keccak256("PermitPQ(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)")
    bytes32 public constant PERMIT_PQ_TYPEHASH =
        keccak256("PermitPQ(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

    event Approval(address indexed owner, address indexed spender, uint256 value);
    event Transfer(address indexed from, address indexed to, uint256 value);

    constructor(uint256 supply) {
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(name)),
                keccak256("1"),
                block.chainid,          // binds the signature to THIS chain
                address(this)           // ...and to THIS contract
            )
        );
        totalSupply = supply;
        balanceOf[msg.sender] = supply;
        emit Transfer(address(0), msg.sender, supply);
    }

    /// @notice The digest a Bloch wallet must sign. Exposed so the wallet can
    ///         RECOMPUTE it from the structured fields instead of blind-signing
    ///         32 opaque bytes handed to it by a dapp.
    function permitDigest(
        address owner,
        address spender,
        uint256 value,
        uint256 nonce,
        uint256 deadline
    ) public view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(abi.encode(PERMIT_PQ_TYPEHASH, owner, spender, value, nonce, deadline))
            )
        );
    }

    /// @notice EIP-2612's semantics, PQ authorisation.
    /// @param pk  the owner's ENVELOPED hybrid public key (3,749 bytes)
    /// @param sig the ENVELOPED hybrid signature over `permitDigest(...)`
    function permitPQ(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        bytes calldata pk,
        bytes calldata sig
    ) external {
        require(block.timestamp <= deadline, "PQPermit: expired");

        // The nonce is read, used in the digest, and consumed. Every field the
        // approval depends on is inside the digest: owner, spender, value,
        // nonce, deadline, plus chainId and this contract via the domain.
        uint256 nonce = nonces[owner];
        bytes32 digest = permitDigest(owner, spender, value, nonce, deadline);

        // The whole point of the front, in one line.
        require(BlochPQ.verify(owner, digest, pk, sig), "PQPermit: bad signature");

        unchecked { nonces[owner] = nonce + 1; }
        allowance[owner][spender] = value;
        emit Approval(owner, spender, value);
    }

    // ── plain ERC-20 below; nothing PQ-specific ──────────────────────────────
    function approve(address spender, uint256 value) external returns (bool) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    function transfer(address to, uint256 value) external returns (bool) {
        _move(msg.sender, to, value);
        return true;
    }

    function transferFrom(address from, address to, uint256 value) external returns (bool) {
        uint256 a = allowance[from][msg.sender];
        require(a >= value, "PQPermit: allowance");
        if (a != type(uint256).max) allowance[from][msg.sender] = a - value;
        _move(from, to, value);
        return true;
    }

    function _move(address from, address to, uint256 value) private {
        require(balanceOf[from] >= value, "PQPermit: balance");
        unchecked {
            balanceOf[from] -= value;
            balanceOf[to] += value;
        }
        emit Transfer(from, to, value);
    }
}
