# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright (c) Bloch community contributors
#
# Unit helpers: satoshis <-> BLCH display, plus a light address-network guess.
#
# The integer satoshi value is the ONLY source of truth on-chain
# (1 BLCH = 100_000_000 satoshis). The float `*_bloch` fields the node returns
# are display-only and MUST NOT be used for accounting. These helpers keep the
# truth as an int so no precision is lost.

from __future__ import annotations

from decimal import Decimal
from typing import Optional

SATS_PER_BLOCH = 100_000_000
BLOCH_DECIMALS = 8

MAINNET_PREFIX = "bloch1q"
TESTNET_PREFIX = "bloch1t"


def bloch_to_sats(bloch: str) -> int:
    """Parse a human BLCH string (e.g. "1.5") into integer satoshis.

    Rejects more than 8 decimal places and non-numeric input.
    """
    s = str(bloch).strip()
    negative = s.startswith("-")
    if negative:
        s = s[1:]
    if "." in s:
        whole, frac = s.split(".", 1)
    else:
        whole, frac = s, ""
    if not (whole + frac).isdigit() and (whole or frac):
        raise ValueError(f"invalid BLCH amount: {bloch!r}")
    if len(frac) > BLOCH_DECIMALS:
        raise ValueError(f"too many decimal places (max {BLOCH_DECIMALS}): {bloch!r}")
    frac_padded = frac.ljust(BLOCH_DECIMALS, "0")
    sats = int(whole or "0") * SATS_PER_BLOCH + int(frac_padded or "0")
    return -sats if negative else sats


def sats_to_bloch(sats: int, *, trim: bool = False) -> str:
    """Format integer satoshis as a BLCH display string with 8 decimals."""
    negative = sats < 0
    abs_v = -sats if negative else sats
    whole, frac = divmod(abs_v, SATS_PER_BLOCH)
    frac_str = str(frac).rjust(BLOCH_DECIMALS, "0")
    if trim:
        frac_str = frac_str.rstrip("0")
    body = f"{whole}.{frac_str}" if frac_str else f"{whole}"
    return f"-{body}" if negative else body


def format_bloch(sats: int) -> str:
    """Convenience: e.g. "1.50000000 BLCH"."""
    return f"{sats_to_bloch(sats)} BLCH"


def address_network(address: str) -> Optional[str]:
    """Cheap prefix guess: "mainnet" / "testnet" / None. Not a full validation —
    use the node's validateaddress RPC for the authoritative answer."""
    if address.startswith(MAINNET_PREFIX):
        return "mainnet"
    if address.startswith(TESTNET_PREFIX):
        return "testnet"
    return None


# Decimal alias kept for callers that prefer exact decimal math on display.
def sats_to_decimal(sats: int) -> Decimal:
    return Decimal(sats) / Decimal(SATS_PER_BLOCH)
