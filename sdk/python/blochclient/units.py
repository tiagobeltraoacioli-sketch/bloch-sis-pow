# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright (c) Bloch community contributors
#
# Unit helpers: satoshis <-> BLCH display, plus a light address-network guess.
#
# The satoshi amount is the ONLY source of truth on-chain
# (1 BLCH = 100_000_000 satoshis). The float `*_bloch` fields the node returns
# are display-only and MUST NOT be used for accounting. These helpers keep the
# truth as a Python int so no precision is lost.
#
# On the wire a satoshi amount is a DECIMAL STRING, not a JSON number: the
# Genesis-4 supply cap is 10^19 sat, about 1110x JavaScript's exact-integer
# limit of 2^53, so a JSON number is silently rounded by any IEEE-754 reader.
# Python's json module happens to parse integers exactly, so Python was never
# the victim — but it shares the wire, and `parse_sats` below accepts both the
# string form and the legacy bare-int form.
# See docs/specs/BLOCH-SATOSHI-ENCODING.md.

from __future__ import annotations

from decimal import Decimal
from typing import Optional, Union

SATS_PER_BLOCH = 100_000_000
BLOCH_DECIMALS = 8

# Genesis-4 total supply in satoshis: 100,000,000,000 BLCH x 10^8. Mirrors
# TOTAL_SUPPLY_SAT in crates/bloch-pos-committee/src/tokenomics_v4.rs.
MAX_SATS = 10_000_000_000_000_000_000

MAINNET_PREFIX = "bloch1q"
TESTNET_PREFIX = "bloch1t"


def parse_sats(value: Union[str, int]) -> int:
    """Parse a wire satoshi amount into an exact int.

    Accepts the canonical decimal string ("1688654952300000000") and the legacy
    bare int emitted by Genesis-3 nodes. Rejects floats (a float has already
    lost the value), negatives, non-canonical leading zeros, and anything above
    the supply cap.
    """
    if isinstance(value, bool) or isinstance(value, float):
        raise TypeError(
            f"satoshi amounts must be a decimal string or int, not {type(value).__name__} "
            "(a float has already lost precision)"
        )
    if isinstance(value, int):
        text = str(value)
    elif isinstance(value, str):
        text = value
    else:
        raise TypeError(f"satoshi amounts must be a decimal string or int, not {type(value).__name__}")
    if not text:
        raise ValueError("empty satoshi amount")
    if text.startswith("-"):
        raise ValueError(f"negative satoshi amount rejected (amounts are unsigned): {text!r}")
    if not text.isdigit():
        raise ValueError(f"not a base-10 satoshi amount: {text!r}")
    if len(text) > 1 and text[0] == "0":
        raise ValueError(f"leading zeros are not canonical: {text!r}")
    sats = int(text)
    if sats > MAX_SATS:
        raise ValueError(f"satoshi amount {text} exceeds the total supply {MAX_SATS}")
    return sats


def format_sats(sats: int) -> str:
    """Render an int satoshi amount in the canonical wire form (decimal string)."""
    if sats < 0:
        raise ValueError("satoshi amounts are unsigned")
    if sats > MAX_SATS:
        raise ValueError(f"satoshi amount {sats} exceeds the total supply {MAX_SATS}")
    return str(sats)


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
