# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright (c) Bloch community contributors
#
# blochclient — community Python client for the Bloch JSON-RPC surface.
#
# HISTORICAL — GENESIS-3. This client targets the Genesis-3 proof-of-work
# JSON-RPC surface; that chain stopped permanently at height 39,918 on
# 2026-08-13. The live chain is Genesis-4, proof of stake, whose RPC exposes a
# different and much smaller method set.
#
# SCAFFOLD / generated / pre-production / UNAUDITED. Permissively-licensed
# community tooling with no privileged access ("ownerless" retracted, ADR-036).
# Under Genesis-4 the security question is concentration, not hashrate: all 64
# validators are run by one entity, 93.94% of the carryover sits at a single
# address, and 56.05 B of the 57.15 B BLOCH issued at genesis is held by the
# founder and the Foundation. BLCH is neutral protocol gas, NOT a security; the
# "17% premine" is Genesis-3 tokenomics V2 — under Genesis-4 the founder holds
# 27.04% of the 100 B cap. Plans, not promises.

from .client import BlochClient, DEFAULT_RPC_URL, DEFAULT_RPC_PORT
from .errors import BlochRpcError, BlochTransportError
from .signer import Signer
from .units import (
    SATS_PER_BLOCH,
    BLOCH_DECIMALS,
    MAX_SATS,
    MAINNET_PREFIX,
    TESTNET_PREFIX,
    bloch_to_sats,
    sats_to_bloch,
    format_bloch,
    parse_sats,
    format_sats,
    address_network,
)
from . import models

__version__ = "0.6.0"

__all__ = [
    "BlochClient",
    "DEFAULT_RPC_URL",
    "DEFAULT_RPC_PORT",
    "BlochRpcError",
    "BlochTransportError",
    "Signer",
    "SATS_PER_BLOCH",
    "BLOCH_DECIMALS",
    "MAX_SATS",
    "MAINNET_PREFIX",
    "TESTNET_PREFIX",
    "bloch_to_sats",
    "sats_to_bloch",
    "format_bloch",
    "parse_sats",
    "format_sats",
    "address_network",
    "models",
    "__version__",
]
