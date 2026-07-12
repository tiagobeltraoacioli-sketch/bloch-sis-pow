# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright (c) Bloch community contributors
#
# blochclient — community Python client for the Bloch JSON-RPC surface.
#
# SCAFFOLD / generated / pre-production / UNAUDITED. Bloch is ownerless and
# neutral; this SDK is permissively-licensed community tooling with no
# privileged access. Base is experimental mainnet-beta (k=4 trivially
# forgeable, 51%-attackable). BLCH is neutral protocol gas, NOT a security,
# worthless by design as anything but gas; 17% premine disclosed. Plans, not
# promises.

from .client import BlochClient, DEFAULT_RPC_URL, DEFAULT_RPC_PORT
from .errors import BlochRpcError, BlochTransportError
from .signer import Signer
from .units import (
    SATS_PER_BLOCH,
    BLOCH_DECIMALS,
    MAINNET_PREFIX,
    TESTNET_PREFIX,
    bloch_to_sats,
    sats_to_bloch,
    format_bloch,
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
    "MAINNET_PREFIX",
    "TESTNET_PREFIX",
    "bloch_to_sats",
    "sats_to_bloch",
    "format_bloch",
    "address_network",
    "models",
    "__version__",
]
