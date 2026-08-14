# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright (c) Bloch community contributors
#
# Static scaffold assets emitted verbatim by generate.py. These are the
# hand-written support files (transport errors, unit helpers, the Signer seam,
# packaging metadata, READMEs, licenses). They are NOT derived from the spec, so
# they carry the SPDX header but not the "@generated" banner.

# ── Shared honesty / licensing rails (Markdown) ─────────────────────────────
RAILS = """\
## Status & honesty rails (read before you rely on this)

- **SCAFFOLD / generated / pre-production / UNAUDITED.** This client is
  machine-generated from `docs/openapi.yaml` and has not completed a security
  audit. Expect rough edges; pin a commit and review before production use.
- **HISTORICAL — GENESIS-3.** This client targets the Genesis-3 proof-of-work
  JSON-RPC surface, and that chain stopped permanently at height 39,918 on
  2026-08-13. The live chain is **Genesis-4, proof of stake** (30 s slots,
  32-slot epochs, finality by epoch), whose RPC exposes a different and much
  smaller method set. Do not point this client at the live chain.
- **This SDK grants no special rights** and makes no promises of support.
  ("Ownerless / no company behind the base protocol" was retracted — see
  `docs/adr/ADR-036-retract-ownerless-adopt-foundation.md`.)
- **The security question is concentration, not hashrate.** The old caveat here
  — k = 4, witness trivially forgeable, the chain 51%-attackable — described
  Genesis-3 and was true of it. Under Genesis-4: **all 64 validators are run by
  one entity**, **93.94% of the carryover sits at a single address**, and
  **56.05 B of the 57.15 B BLOCH issued at genesis is held by the founder and
  the Foundation**. One operator can halt the chain and one holder can outvote
  every other. A third party cannot yet join — the transport is a
  point-to-point TCP full mesh with a fixed peer list, no discovery and no
  authentication, and `Deposit`/`Delegate` are refused at every node's mempool.
- **BLCH is neutral protocol gas.** It is **NOT a security**, share, or claim
  on anyone's revenue — no yield, dividend, or profit is offered or implied.
  The "17% premine" is Genesis-3 tokenomics V2 and no longer describes the
  supply: under Genesis-4 the founder holds **27.04% of the 100 B cap**
  (`FOUNDER_TOTAL_BLOCH` in
  `crates/bloch-pos-committee/src/tokenomics_v4.rs`) and the Foundation a
  further **29.00%**.
- **Plans, not promises.** Anything forward-looking here is a plan and may
  change or never ship.

This is the community edition. It is not, and must not be described as, any
branded/commercial distribution.
"""

# ── Licenses (copied from sdk/typescript/) ──────────────────────────────────
LICENSE_MIT = """\
MIT License

Copyright (c) Bloch community contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

LICENSE_APACHE = """\
                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

This project is dual-licensed under MIT OR Apache-2.0, at your option.

The full text of the Apache License, Version 2.0 is available at:

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations under
the License.
"""

# ════════════════════════════════════════════════════════════════════════════
#  PYTHON STATIC FILES
# ════════════════════════════════════════════════════════════════════════════
PY_ERRORS = '''\
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright (c) Bloch community contributors
#
# Errors raised by the Bloch client. Bloch reports method failures in TWO
# shapes and this SDK normalizes both into BlochRpcError:
#   1. the standard top-level `error` object (transport/auth: -32001/-32002)
#   2. the non-standard string `result.error` (HTTP 200, most method failures)

from __future__ import annotations

from typing import Any, Optional


class BlochRpcError(Exception):
    """A Bloch RPC call failed. `source` distinguishes the two error shapes."""

    def __init__(
        self,
        message: str,
        *,
        method: str,
        source: str,
        code: Optional[int] = None,
        http_status: Optional[int] = None,
        data: Any = None,
    ) -> None:
        super().__init__(message)
        self.method = method
        self.source = source  # "result-error" | "jsonrpc-error"
        self.code = code
        self.http_status = http_status
        self.data = data

    @property
    def is_unauthorized(self) -> bool:
        """True for the unauthorized transport error (-32001 / HTTP 401)."""
        return self.code == -32001 or self.http_status == 401

    @property
    def is_rate_limited(self) -> bool:
        """True for the rate-limit transport error (-32002 / HTTP 429)."""
        return self.code == -32002 or self.http_status == 429


class BlochTransportError(Exception):
    """Network failure, non-2xx without a JSON-RPC error, or malformed body."""

    def __init__(
        self,
        message: str,
        *,
        method: str,
        http_status: Optional[int] = None,
    ) -> None:
        super().__init__(message)
        self.method = method
        self.http_status = http_status
'''

PY_UNITS = '''\
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
'''

PY_SIGNER = '''\
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright (c) Bloch community contributors
#
# Signer seam for the write path.
#
# This SDK deliberately does NOT implement Bloch's hybrid Falcon-1024 || ML-DSA-65
# transaction signing. The client's only write, `send_raw_transaction`, takes an
# ALREADY-SIGNED raw transaction hex. Bring your own signer/tx-builder and hand
# the finished hex to the client. This Protocol documents the seam so higher-level
# tooling can depend on a stable interface.

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class Signer(Protocol):
    """Produces a hybrid post-quantum signature over a message digest.

    Implementations wrap Falcon-1024 || ML-DSA-65 keys. Intentionally not
    provided here — this is only the type seam.
    """

    def public_key(self) -> bytes:
        """Return the encoded public key material."""
        ...

    def sign(self, message: bytes) -> bytes:
        """Return the hybrid signature over `message`."""
        ...
'''

PY_INIT = '''\
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

__version__ = "@VERSION@"

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
'''

PY_PYPROJECT = '''\
# SPDX-License-Identifier: MIT OR Apache-2.0
[build-system]
requires = ["setuptools>=61.0"]
build-backend = "setuptools.build_meta"

[project]
name = "blochclient"
version = "@VERSION@"
description = "Community, generated Python client for the Bloch (bloch-sis) JSON-RPC API. SCAFFOLD / unaudited / pre-production."
readme = "README.md"
requires-python = ">=3.8"
license = { text = "MIT OR Apache-2.0" }
authors = [{ name = "Bloch community contributors" }]
keywords = ["bloch", "blockdag", "json-rpc", "blockchain", "sdk"]
classifiers = [
    "Development Status :: 3 - Alpha",
    "License :: OSI Approved :: MIT License",
    "License :: OSI Approved :: Apache Software License",
    "Programming Language :: Python :: 3",
    "Typing :: Typed",
]
dependencies = []

[tool.setuptools.packages.find]
where = ["."]
include = ["blochclient*"]

[tool.setuptools.package-data]
blochclient = ["py.typed"]
'''

PY_README = '''\
# blochclient (Python) — community Bloch JSON-RPC client

Typed Python client for the **Bloch (bloch-sis)** JSON-RPC 2.0 API. It is
**generated** from `docs/openapi.yaml` by `sdk/codegen/generate.py` — the spec
drives the client; regenerate on any spec change.

''' + RAILS + '''

## Install

```bash
pip install -e sdk/python
# or just add sdk/python to your PYTHONPATH — the package has zero deps.
```

## Usage

```python
from blochclient import BlochClient, BlochRpcError, parse_sats, sats_to_bloch

client = BlochClient("http://127.0.0.1:16210")

height = client.get_block_count()
info = client.get_network_info()          # -> NetworkInfo (TypedDict)
bal = client.get_balance("bloch1q...")    # -> Balance

# Amounts arrive as DECIMAL STRINGS. parse_sats() gives you an exact int and
# also accepts the legacy bare-int form from Genesis-3 nodes.
sats = parse_sats(bal["satoshis"])
print(sats_to_bloch(sats), "BLCH")

try:
    client.get_transaction("deadbeef")     # bad hash
except BlochRpcError as e:
    # Both failure shapes land here:
    #   e.source == "result-error"  (HTTP 200, string result.error)
    #   e.source == "jsonrpc-error" (top-level error; e.is_unauthorized / e.is_rate_limited)
    print("rpc failed:", e)
```

### The two error shapes

Bloch reports failures in two places and the client normalizes both into
`BlochRpcError`:

- **Top-level `error`** — transport/auth only: `-32001` unauthorized (HTTP 401),
  `-32002` rate limited (HTTP 429). `source == "jsonrpc-error"`.
- **`result.error` string** — most method failures (HTTP 200). `source ==
  "result-error"`.

Network / malformed-response problems raise `BlochTransportError`.

### Amounts

A satoshi amount is a **decimal string** on the wire, not a JSON number. The
supply cap is 10^19 satoshis — about 1110x JavaScript's exact-integer limit of
2^53 — so a JSON number is silently rounded by any IEEE-754 reader, and real
Bloch balances are already ~187x past that limit. Python's `int` is
arbitrary-precision, so Python was never the victim; it shares the wire.

Run every amount through `parse_sats()` (accepts the string form and the legacy
bare int from Genesis-3 nodes, returns an exact `int`, rejects negatives and
anything above the cap) and `format_sats()` on the way out. The `*_bloch` float
companions are display-only and lossy — never use them for accounting. Rule:
`docs/specs/BLOCH-SATOSHI-ENCODING.md`.

### Writes and signing

The only write is `send_raw_transaction(hex)`, which takes an **already-signed**
raw transaction. This SDK does **not** implement Bloch's hybrid
Falcon-1024 || ML-DSA-65 signing — see `signer.py` for the `Signer` seam and
bring your own tx-builder. When the node runs with write-auth enabled and you
call from a non-local IP, pass `api_key=...` (or `bearer=True`).

## Regenerating

```bash
python3 sdk/codegen/generate.py
```

`models.py` and `client.py` carry a `@generated` banner and must not be edited
by hand.

## License

Dual-licensed under **MIT OR Apache-2.0**. See `LICENSE-MIT` and `LICENSE-APACHE`.
'''

PY_GITIGNORE = '''\
__pycache__/
*.pyc
*.egg-info/
build/
dist/
.mypy_cache/
.ruff_cache/
'''

# ════════════════════════════════════════════════════════════════════════════
#  GO STATIC FILES
# ════════════════════════════════════════════════════════════════════════════
GO_ERRORS = '''\
// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) Bloch community contributors
//
// Errors returned by the Bloch client. Bloch reports method failures in TWO
// shapes and this SDK surfaces both:
//   1. standard top-level `error` object (transport/auth: -32001/-32002)
//   2. non-standard string `result.error` (HTTP 200, most method failures)

package blochclient

import "fmt"

// RPCError is a Bloch method/transport RPC failure. Source distinguishes the
// two error shapes: "result-error" or "jsonrpc-error".
type RPCError struct {
	Method     string
	Source     string
	Code       int
	HTTPStatus int
	Message    string
}

func (e *RPCError) Error() string {
	return fmt.Sprintf("bloch rpc %s failed (%s): %s", e.Method, e.Source, e.Message)
}

// IsUnauthorized reports the unauthorized transport error (-32001 / HTTP 401).
func (e *RPCError) IsUnauthorized() bool {
	return e.Code == -32001 || e.HTTPStatus == 401
}

// IsRateLimited reports the rate-limit transport error (-32002 / HTTP 429).
func (e *RPCError) IsRateLimited() bool {
	return e.Code == -32002 || e.HTTPStatus == 429
}

// TransportError is a network failure, a non-2xx without a JSON-RPC error, or a
// malformed response body.
type TransportError struct {
	Method     string
	HTTPStatus int
	Message    string
}

func (e *TransportError) Error() string {
	return fmt.Sprintf("bloch transport error calling %s: %s", e.Method, e.Message)
}
'''

GO_SATOSHIS = '''\
// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) Bloch community contributors
// @generated (static asset) by sdk/codegen — do not edit by hand.
//
// The Satoshis wire codec: uint64 in memory, decimal string in JSON.

package blochclient

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// Satoshis is a satoshi amount (1 BLCH = 100_000_000 sat): an unsigned 64-bit
// integer in memory, a **decimal string** on the JSON wire.
//
// Why a string, not just uint64: the Genesis-4 supply cap is 100,000,000,000
// BLCH = 10^19 satoshis — 108% of int64's positive range and ~1110x
// JavaScript's exact-integer limit 2^53 (9,007,199,254,740,991). A bare JSON
// number above 2^53 is silently rounded by every IEEE-754 JSON reader, so
// widening this SDK's integer would fix Go while leaving every JS consumer of
// the same wire reading wrong balances. The amount therefore travels as a
// decimal string ("satoshis": "10000000000000000000"); uint64 is the
// in-memory consequence. See docs/specs/BLOCH-SATOSHI-ENCODING.md.
//
// Unmarshalling accepts the canonical string form and, from legacy Genesis-3
// nodes only, a bare JSON integer. The legacy form is parsed from the raw
// JSON token — never through a float64 — so this decoder loses no precision
// either way; the hazard is other readers, not this one.
type Satoshis uint64

// MaxSats is the Genesis-4 total supply in satoshis:
// 100,000,000,000 BLCH x 10^8 sat/BLCH. No valid amount can exceed it, and
// the codec rejects anything above it in both directions. It mirrors
// TOTAL_SUPPLY_SAT in crates/bloch-pos-committee/src/tokenomics_v4.rs — if
// that constant moves, regenerate the SDKs.
const MaxSats Satoshis = 10_000_000_000_000_000_000

// MarshalJSON emits the canonical decimal-string form, e.g. "12345".
func (s Satoshis) MarshalJSON() ([]byte, error) {
	if s > MaxSats {
		return nil, fmt.Errorf("satoshis %d exceeds the total supply %d", uint64(s), uint64(MaxSats))
	}
	return []byte(`"` + strconv.FormatUint(uint64(s), 10) + `"`), nil
}

// UnmarshalJSON accepts the canonical decimal string ("123") or, for legacy
// Genesis-3 nodes, a bare JSON integer (123). It rejects negatives, signs,
// non-integers, leading zeros, and anything above MaxSats. JSON null leaves
// the value untouched (standard library convention).
func (s *Satoshis) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		return nil
	}
	if len(data) > 0 && data[0] == '"' {
		var str string
		if err := json.Unmarshal(data, &str); err != nil {
			return fmt.Errorf("satoshis: %w", err)
		}
		v, err := ParseSatoshis(str)
		if err != nil {
			return err
		}
		*s = v
		return nil
	}
	// Legacy bare-number form: parse the raw token, never via float64.
	v, err := ParseSatoshis(string(data))
	if err != nil {
		return err
	}
	*s = v
	return nil
}

// ParseSatoshis parses a canonical decimal satoshi string: base-10 digits
// only, no sign, no leading zeros, at most MaxSats.
func ParseSatoshis(str string) (Satoshis, error) {
	if str == "" {
		return 0, fmt.Errorf("satoshis: empty amount")
	}
	if str[0] == '-' {
		return 0, fmt.Errorf("satoshis: negative amount %q rejected (amounts are unsigned)", str)
	}
	for i := 0; i < len(str); i++ {
		if str[i] < '0' || str[i] > '9' {
			return 0, fmt.Errorf("satoshis: %q is not a base-10 integer", str)
		}
	}
	if len(str) > 1 && str[0] == '0' {
		return 0, fmt.Errorf("satoshis: leading zeros in %q are not canonical", str)
	}
	u, err := strconv.ParseUint(str, 10, 64)
	if err != nil {
		// Digits are already validated, so the only failure left is range.
		return 0, fmt.Errorf("satoshis: %q exceeds the total supply %d", str, uint64(MaxSats))
	}
	if Satoshis(u) > MaxSats {
		return 0, fmt.Errorf("satoshis: %q exceeds the total supply %d", str, uint64(MaxSats))
	}
	return Satoshis(u), nil
}

// String returns the canonical decimal form (same digits as the wire).
func (s Satoshis) String() string {
	return strconv.FormatUint(uint64(s), 10)
}

// Uint64 returns the raw satoshi count.
func (s Satoshis) Uint64() uint64 {
	return uint64(s)
}

// Bloch formats the amount as a BLCH display string with 8 decimals.
func (s Satoshis) Bloch() string {
	return SatsToBloch(s)
}
'''

GO_UNITS = '''\
// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) Bloch community contributors
//
// Unit helpers: satoshis <-> BLCH display, plus a light address-network guess.
// The satoshi amount (Satoshis, uint64 / decimal string on the wire — see
// satoshis.go) is the ONLY on-chain truth (1 BLCH = 100_000_000 satoshis);
// the float *_bloch fields are display-only.

package blochclient

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	// SatsPerBloch is the number of satoshis in one whole BLCH.
	SatsPerBloch = 100_000_000
	// BlochDecimals is the number of decimal places in a BLCH display value.
	BlochDecimals = 8

	MainnetPrefix = "bloch1q"
	TestnetPrefix = "bloch1t"
)

// SatsToBloch formats a satoshi amount as a BLCH display string with 8 decimals.
func SatsToBloch(sats Satoshis) string {
	whole := uint64(sats) / SatsPerBloch
	frac := uint64(sats) % SatsPerBloch
	return fmt.Sprintf("%d.%08d", whole, frac)
}

// FormatBloch renders satoshis as e.g. "1.50000000 BLCH".
func FormatBloch(sats Satoshis) string {
	return SatsToBloch(sats) + " BLCH"
}

// BlochToSats parses a human BLCH string (e.g. "1.5") into a satoshi amount.
// It rejects negatives, more than 8 decimal places, non-numeric input, and
// anything above the total supply (MaxSats).
func BlochToSats(bloch string) (Satoshis, error) {
	s := strings.TrimSpace(bloch)
	if strings.HasPrefix(s, "-") {
		return 0, fmt.Errorf("negative BLCH amount rejected (amounts are unsigned): %q", bloch)
	}
	whole, frac := s, ""
	if i := strings.IndexByte(s, '.'); i >= 0 {
		whole, frac = s[:i], s[i+1:]
	}
	if len(frac) > BlochDecimals {
		return 0, fmt.Errorf("too many decimal places (max %d): %q", BlochDecimals, bloch)
	}
	frac = frac + strings.Repeat("0", BlochDecimals-len(frac))
	if whole == "" {
		whole = "0"
	}
	w, err := strconv.ParseUint(whole, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid BLCH amount: %q", bloch)
	}
	f, err := strconv.ParseUint(frac, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid BLCH amount: %q", bloch)
	}
	// w*SatsPerBloch + f with overflow/supply checks (MaxSats < 2^64).
	if w > (uint64(MaxSats)-f)/SatsPerBloch {
		return 0, fmt.Errorf("BLCH amount %q exceeds the total supply", bloch)
	}
	return Satoshis(w*SatsPerBloch + f), nil
}

// AddressNetwork is a cheap prefix guess: "mainnet", "testnet", or "". Use the
// node's validateaddress RPC for the authoritative answer.
func AddressNetwork(address string) string {
	switch {
	case strings.HasPrefix(address, MainnetPrefix):
		return "mainnet"
	case strings.HasPrefix(address, TestnetPrefix):
		return "testnet"
	default:
		return ""
	}
}
'''

GO_SIGNER = '''\
// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) Bloch community contributors
//
// Signer seam for the write path.
//
// This SDK deliberately does NOT implement Bloch's hybrid
// Falcon-1024 || ML-DSA-65 transaction signing. The client's only write,
// SendRawTransaction, takes an ALREADY-SIGNED raw transaction hex. Bring your
// own signer/tx-builder and hand the finished hex to the client. This interface
// documents the seam so higher-level tooling can depend on a stable type.

package blochclient

// Signer produces a hybrid post-quantum signature over a message digest.
// Implementations wrap Falcon-1024 || ML-DSA-65 keys. Intentionally not
// provided here — this is only the type seam.
type Signer interface {
	// PublicKey returns the encoded public key material.
	PublicKey() []byte
	// Sign returns the hybrid signature over message.
	Sign(message []byte) ([]byte, error)
}
'''

GO_SATOSHIS_TEST = '''\
// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) Bloch community contributors
// @generated (static asset) by sdk/codegen — do not edit by hand.

package blochclient

import (
	"encoding/json"
	"testing"
)

// supplyCap is the Genesis-4 total supply, 100,000,000,000 BLCH at 8 decimals.
const supplyCapDigits = "10000000000000000000"

func TestSatoshisRoundTrip(t *testing.T) {
	cases := []struct {
		name  string
		value Satoshis
		json  string
	}{
		{"zero", 0, `"0"`},
		{"one", 1, `"1"`},
		{"one BLCH", 100_000_000, `"100000000"`},
		{"js safe limit", 9_007_199_254_740_991, `"9007199254740991"`},
		{"js safe limit + 2", 9_007_199_254_740_993, `"9007199254740993"`},
		{"largest carryover address", 1_688_654_952_300_000_000, `"1688654952300000000"`},
		{"past int64", 9_223_372_036_854_775_808, `"9223372036854775808"`},
		{"supply cap", MaxSats, `"` + supplyCapDigits + `"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			enc, err := json.Marshal(tc.value)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if string(enc) != tc.json {
				t.Fatalf("marshal = %s, want %s", enc, tc.json)
			}
			var back Satoshis
			if err := json.Unmarshal(enc, &back); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if back != tc.value {
				t.Fatalf("round-trip = %d, want %d", uint64(back), uint64(tc.value))
			}
		})
	}
}

// The supply cap must survive a struct round-trip, not just a bare scalar.
func TestSatoshisSupplyCapInStruct(t *testing.T) {
	type balance struct {
		Satoshis Satoshis `json:"satoshis"`
	}
	enc, err := json.Marshal(balance{Satoshis: MaxSats})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `{"satoshis":"` + supplyCapDigits + `"}`
	if string(enc) != want {
		t.Fatalf("marshal = %s, want %s", enc, want)
	}
	var back balance
	if err := json.Unmarshal(enc, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Satoshis != MaxSats {
		t.Fatalf("round-trip = %d, want %d", uint64(back.Satoshis), uint64(MaxSats))
	}
	// 10^19 does not fit the int64 this type used to be; prove the new type
	// carries it rather than saturating.
	if uint64(back.Satoshis) <= 9_223_372_036_854_775_807 {
		t.Fatalf("supply cap %d did not survive as a u64-range value", uint64(back.Satoshis))
	}
}

func TestSatoshisRejectsNegative(t *testing.T) {
	for _, bad := range []string{`"-1"`, `-1`, `"-10000000000000000000"`, `-9007199254740993`} {
		var s Satoshis
		if err := json.Unmarshal([]byte(bad), &s); err == nil {
			t.Fatalf("unmarshal(%s) accepted a negative amount as %d", bad, uint64(s))
		}
	}
}

func TestSatoshisRejectsAboveSupply(t *testing.T) {
	// One satoshi past the cap, and the largest u64 (which is 1.84x the cap).
	for _, bad := range []string{`"10000000000000000001"`, `"18446744073709551615"`, `"99999999999999999999"`} {
		var s Satoshis
		if err := json.Unmarshal([]byte(bad), &s); err == nil {
			t.Fatalf("unmarshal(%s) accepted %d, above the supply cap", bad, uint64(s))
		}
	}
	if _, err := json.Marshal(MaxSats + 1); err == nil {
		t.Fatal("marshal accepted an amount above the supply cap")
	}
}

func TestSatoshisRejectsMalformed(t *testing.T) {
	for _, bad := range []string{`""`, `"1.5"`, `"0x10"`, `"+1"`, `"007"`, `" 1"`, `"1 "`, `"1e19"`, `1.5`, `true`, `[]`} {
		var s Satoshis
		if err := json.Unmarshal([]byte(bad), &s); err == nil {
			t.Fatalf("unmarshal(%s) accepted a malformed amount as %d", bad, uint64(s))
		}
	}
}

// Legacy Genesis-3 nodes emit satoshis as bare JSON numbers. Accept them, and
// parse from the raw token so nothing passes through a float64.
func TestSatoshisAcceptsLegacyNumberForm(t *testing.T) {
	var s Satoshis
	if err := json.Unmarshal([]byte(`1688654952300000000`), &s); err != nil {
		t.Fatalf("legacy number form rejected: %v", err)
	}
	if uint64(s) != 1_688_654_952_300_000_000 {
		t.Fatalf("legacy parse = %d, want 1688654952300000000", uint64(s))
	}
	// A value a float64 could not hold exactly still decodes exactly, because
	// the decoder never builds a float64.
	if err := json.Unmarshal([]byte(`9007199254740993`), &s); err != nil {
		t.Fatalf("legacy number form rejected: %v", err)
	}
	if uint64(s) != 9_007_199_254_740_993 {
		t.Fatalf("legacy parse = %d, want 9007199254740993 (float64 would give ...992)", uint64(s))
	}
}

// TestSatoshisSurvivesJavaScript is the reason this type is a string on the
// wire at all.
//
// The vectors below were MEASURED, not assumed, with node v22.16.0:
//
//	node -e 'console.log(JSON.stringify(JSON.parse(`{"v":9007199254740993}`)))'
//	  -> {"v":9007199254740992}     // one satoshi lost, silently
//	node -e 'console.log(JSON.stringify(JSON.parse(`{"v":"9007199254740993"}`)))'
//	  -> {"v":"9007199254740993"}   // byte-identical
//
// JavaScript parses every JSON number into an IEEE-754 double, exact only up
// to 2^53 - 1 = 9,007,199,254,740,991. The Genesis-4 supply cap is 10^19 sat,
// about 1110x that limit, and single real balances are already ~187x past it.
// So the numeric wire form is lossy for Bloch amounts no matter how wide the
// Go integer is — which is why widening int64 to uint64 is the consequence of
// the fix and not the fix itself.
//
// This test asserts our encoder emits exactly the bytes JavaScript gives back
// unchanged, and pins the measured corruption of the numeric form.
func TestSatoshisSurvivesJavaScript(t *testing.T) {
	vectors := []struct {
		sats Satoshis
		// jsStringRoundTrip: JSON.stringify(JSON.parse(`{"v":"<digits>"}`)) in node.
		jsStringRoundTrip string
		// jsNumberRoundTrip: JSON.stringify(JSON.parse(`{"v":<digits>}`)) in node.
		jsNumberRoundTrip string
		numberIsCorrupted bool
	}{
		{
			sats:              9_007_199_254_740_991,
			jsStringRoundTrip: `{"v":"9007199254740991"}`,
			jsNumberRoundTrip: `{"v":9007199254740991}`,
			numberIsCorrupted: false, // exactly 2^53 - 1: the last exact integer
		},
		{
			sats:              9_007_199_254_740_993,
			jsStringRoundTrip: `{"v":"9007199254740993"}`,
			jsNumberRoundTrip: `{"v":9007199254740992}`,
			numberIsCorrupted: true,
		},
		{
			sats:              9_999_999_999_999_999_999,
			jsStringRoundTrip: `{"v":"9999999999999999999"}`,
			jsNumberRoundTrip: `{"v":10000000000000000000}`,
			numberIsCorrupted: true,
		},
		{
			sats:              MaxSats,
			jsStringRoundTrip: `{"v":"` + supplyCapDigits + `"}`,
			jsNumberRoundTrip: `{"v":` + supplyCapDigits + `}`,
			numberIsCorrupted: false, // 10^19 happens to be representable; 10^19-1 is not
		},
	}
	type envelope struct {
		V Satoshis `json:"v"`
	}
	for _, v := range vectors {
		enc, err := json.Marshal(envelope{V: v.sats})
		if err != nil {
			t.Fatalf("marshal %d: %v", uint64(v.sats), err)
		}
		// Byte-for-byte: what we send is what JavaScript hands back untouched.
		if string(enc) != v.jsStringRoundTrip {
			t.Fatalf("encoded %s, JavaScript round-trips %s", enc, v.jsStringRoundTrip)
		}
		// And decoding what JavaScript produced returns the exact amount.
		var back envelope
		if err := json.Unmarshal([]byte(v.jsStringRoundTrip), &back); err != nil {
			t.Fatalf("decode JS output: %v", err)
		}
		if back.V != v.sats {
			t.Fatalf("JS round-trip changed %d into %d", uint64(v.sats), uint64(back.V))
		}
		// The numeric form: pin the measured loss so nobody "simplifies" the
		// encoding back to a JSON number.
		numeric := `{"v":` + v.sats.String() + `}`
		corrupted := numeric != v.jsNumberRoundTrip
		if corrupted != v.numberIsCorrupted {
			t.Fatalf("numeric form %s vs measured JS %s: corruption = %v, expected %v",
				numeric, v.jsNumberRoundTrip, corrupted, v.numberIsCorrupted)
		}
	}
}

func TestBlochToSatsBounds(t *testing.T) {
	// The whole supply, in BLCH, parses to exactly the cap.
	got, err := BlochToSats("100000000000.00000000")
	if err != nil {
		t.Fatalf("supply cap in BLCH rejected: %v", err)
	}
	if got != MaxSats {
		t.Fatalf("BlochToSats = %d, want %d", uint64(got), uint64(MaxSats))
	}
	if SatsToBloch(MaxSats) != "100000000000.00000000" {
		t.Fatalf("SatsToBloch(cap) = %q", SatsToBloch(MaxSats))
	}
	for _, bad := range []string{"-1", "100000000001", "1.000000001", "abc"} {
		if _, err := BlochToSats(bad); err == nil {
			t.Fatalf("BlochToSats(%q) was accepted", bad)
		}
	}
}
'''

GO_DOC = '''\
// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) Bloch community contributors

// Package blochclient is a community, generated Go client for the Bloch
// (bloch-sis) JSON-RPC 2.0 API.
//
// SCAFFOLD / generated / pre-production / UNAUDITED. It is generated from
// docs/openapi.yaml by sdk/codegen/generate.py — the spec drives the client;
// regenerate on any spec change.
//
// HISTORICAL — GENESIS-3. The spec describes the Genesis-3 proof-of-work
// JSON-RPC surface; that chain stopped permanently at height 39,918 on
// 2026-08-13. The live chain is Genesis-4, proof of stake, whose RPC exposes a
// different and much smaller method set. Permissively-licensed community
// tooling with no privileged access ("ownerless" retracted, ADR-036). Under
// Genesis-4 the security question is concentration, not hashrate: all 64
// validators are run by one entity, 93.94% of the carryover sits at a single
// address, and 56.05 B of the 57.15 B BLOCH issued at genesis is held by the
// founder and the Foundation. BLCH is neutral protocol gas, NOT a security;
// the "17% premine" is Genesis-3 tokenomics V2 — under Genesis-4 the founder
// holds 27.04% of the 100 B cap. Plans, not promises.
//
// Both Bloch failure shapes are surfaced: the standard top-level error object
// (transport/auth: -32001/-32002) as *RPCError with Source "jsonrpc-error", and
// the non-standard string result.error (HTTP 200) as *RPCError with Source
// "result-error". Network/decoding problems return *TransportError.
//
// The only write is SendRawTransaction, which takes an already-signed raw tx
// hex. Signing (hybrid Falcon-1024 || ML-DSA-65) is out of scope — see Signer.
package blochclient
'''

GO_MOD = '''\
module github.com/bloch-community/blochclient-go

go 1.21
'''

GO_README = '''\
# blochclient (Go) — community Bloch JSON-RPC client

Typed Go client for the **Bloch (bloch-sis)** JSON-RPC 2.0 API. It is
**generated** from `docs/openapi.yaml` by `sdk/codegen/generate.py` — the spec
drives the client; regenerate on any spec change.

''' + RAILS + '''

## Install

```bash
go get github.com/bloch-community/blochclient-go
```

(Or vendor `sdk/go` directly; the module has zero non-stdlib dependencies.)

## Usage

```go
package main

import (
	"fmt"
	"log"

	blochclient "github.com/bloch-community/blochclient-go"
)

func main() {
	c := blochclient.New("http://127.0.0.1:16210")

	height, err := c.GetBlockCount()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("height:", height)

	bal, err := c.GetBalance("bloch1q...")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(blochclient.SatsToBloch(bal.Satoshis), "BLCH")

	if _, err := c.GetTransaction("deadbeef"); err != nil {
		// Both failure shapes arrive as *RPCError:
		//   Source == "result-error"  (HTTP 200, string result.error)
		//   Source == "jsonrpc-error" (top-level error; IsUnauthorized/IsRateLimited)
		if rpcErr, ok := err.(*blochclient.RPCError); ok {
			fmt.Println("rpc failed:", rpcErr.Source, rpcErr.Message)
		}
	}
}
```

### The two error shapes

Bloch reports failures in two places; the client surfaces both as `*RPCError`:

- **Top-level `error`** — transport/auth only: `-32001` unauthorized (HTTP 401),
  `-32002` rate limited (HTTP 429). `Source == "jsonrpc-error"`; use
  `IsUnauthorized()` / `IsRateLimited()`.
- **`result.error` string** — most method failures (HTTP 200). `Source ==
  "result-error"`.

Network / malformed-response problems return `*TransportError`.

### Amounts

`Satoshis` is a `uint64` in memory and a **decimal string** on the wire
(`satoshis.go`). It is not `int64`, and not a JSON number, for two separate
reasons: the supply cap is 10^19 satoshis, which is 108% of `int64`'s positive
range, and — the reason that actually drove the design — about 1110x
JavaScript's exact-integer limit of 2^53, so a JSON number is silently rounded
by every browser reading the same response. Real Bloch balances are already
~187x past that limit.

`MarshalJSON` emits the string form and rejects amounts above the cap;
`UnmarshalJSON` accepts the string form and the legacy bare-number form from
Genesis-3 nodes, parsing the raw token rather than a float. Use
`ParseSatoshis`, `.Uint64()`, `.String()`, `SatsToBloch`, `BlochToSats`. The
`*_bloch` float companions are display-only and lossy — never use them for
accounting. Rule: `docs/specs/BLOCH-SATOSHI-ENCODING.md`.

### Writes and signing

The only write is `SendRawTransaction(hex)`, which takes an **already-signed**
raw transaction. This SDK does **not** implement Bloch's hybrid
Falcon-1024 || ML-DSA-65 signing — see `signer.go` for the `Signer` seam and
bring your own tx-builder. For write-auth on a non-local node, set
`client.APIKey` (and optionally `client.Bearer = true`).

## Regenerating

```bash
python3 sdk/codegen/generate.py
```

`models.go` and `client.go` carry a `@generated` banner and must not be edited
by hand.

## License

Dual-licensed under **MIT OR Apache-2.0**. See `LICENSE-MIT` and `LICENSE-APACHE`.
'''

GO_GITIGNORE = '''\
*.test
*.out
/vendor/
'''

# ════════════════════════════════════════════════════════════════════════════
#  CODEGEN README
# ════════════════════════════════════════════════════════════════════════════
CODEGEN_README = '''\
# Bloch SDK code generator

**The spec drives the clients. Regenerate on any spec change.**

`generate.py` reads the single source of truth — `docs/openapi.yaml` (OpenAPI
3.1.0 describing a **JSON-RPC 2.0** API over one `POST /` endpoint) — and
deterministically emits typed clients:

- `sdk/python/` — a typed Python package (`blochclient`)
- `sdk/go/` — a typed Go module (`blochclient`)

```bash
python3 sdk/codegen/generate.py
```

Re-running is idempotent: same spec in, byte-identical clients out.

## What it does

1. **Parses** `components.schemas` (the domain types) and the
   `x-json-rpc-methods` vendor extension (name -> positional params -> result
   schema). OpenAPI can't model JSON-RPC natively, so the real method surface
   lives in that extension.
2. **Emits typed models** from the schemas:
   - scalar schemas (`Hex32`, `Hex20`, `Address`) -> type aliases,
   - `Satoshis` -> a per-language codec, NOT an alias (see below),
   - object schemas -> Python `TypedDict`s / Go structs,
   - `oneOf`-of-objects -> a merged optional-field type (union shape),
   - `oneOf` with a `null` variant -> `Optional` / pointer,
   - inline nested objects (e.g. `Pools.pools`) -> hoisted synthetic models.
3. **Emits one typed wrapper per JSON-RPC method** that packs positional
   `params` into the `{jsonrpc, id, method, params}` envelope. Trailing optional
   params equal to their default are trimmed (matching the hand-written TS SDK).
4. **Ships a JSON-RPC transport** that normalizes BOTH Bloch error shapes:
   - the standard top-level `error` object (transport/auth: `-32001`/`-32002`),
   - the non-standard string `result.error` (HTTP 200, most method failures).
5. **Applies rails + licensing** from the start: SPDX headers on every file,
   `LICENSE-MIT` + `LICENSE-APACHE` in each package, honesty rails in each
   README, and a `@generated from docs/openapi.yaml` banner on the derived
   model/client files.

6. **Runs `gofmt -w`** over the emitted Go files when the Go toolchain is on
   PATH. The emitter writes single-space struct fields; gofmt column-aligns
   them, so this keeps regeneration byte-identical to what is committed. When
   `gofmt` is absent the output is still valid Go, just unaligned — the run
   prints which happened.

## Amounts are not a scalar alias

`Satoshis` is the one schema that does not become a plain type alias. The
Genesis-4 supply cap is 10^19 satoshis
(`crates/bloch-pos-committee/src/tokenomics_v4.rs`) — 108% of `i64::MAX` and
about 1110x JavaScript's exact-integer limit of 2^53 — so an amount travels the
wire as a **decimal string** and each language binds its own codec:

- Go: `type Satoshis uint64` with `MarshalJSON`/`UnmarshalJSON`, in
  `satoshis.go` (+ `satoshis_test.go`, both static assets).
- Python: `Satoshis = Union[str, int]` (the wire shape) with `parse_sats()` /
  `format_sats()` in `units.py`.

Do not "simplify" either back to a JSON number: it would fix nothing and break
every JavaScript consumer silently. Rule and rationale:
`docs/specs/BLOCH-SATOSHI-ENCODING.md`.

## Files

- `generate.py` — the generator (stdlib + PyYAML only).
- `static_assets.py` — verbatim scaffold (errors, unit helpers, the amount
  codec + its tests, the `Signer` seam, packaging metadata, READMEs, licenses).
  Not spec-derived, so these carry the SPDX header but not the `@generated`
  banner.

## Signing seam

Clients deliberately do **not** implement Bloch's hybrid
Falcon-1024 || ML-DSA-65 signing. The only write, `sendrawtransaction`, takes an
already-signed raw tx hex; each client exposes a `Signer` interface seam only.

## Rails

SCAFFOLD / generated / unaudited / pre-production. No privileged access
("ownerless" retracted — `docs/adr/ADR-036-retract-ownerless-adopt-foundation.md`).
The generated clients target the retired Genesis-3 chain. Under the live
Genesis-4 chain the security question is concentration, not hashrate: all 64
validators are run by one entity, 93.94% of the carryover sits at a single
address, and 56.05 B of the 57.15 B BLOCH issued at genesis is held by the
founder and the Foundation. BLCH is neutral protocol gas, NOT a security; the
"17% premine" is Genesis-3 tokenomics V2 — under Genesis-4 the founder holds
27.04% of the 100 B cap. Plans, not promises.
'''
