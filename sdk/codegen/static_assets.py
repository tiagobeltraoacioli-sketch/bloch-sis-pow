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
- **Bloch is ownerless and neutral.** There is no admin key, no privileged
  access, and no company behind the base protocol. This SDK is community
  tooling; it grants no special rights and makes no promises of support.
- **Base is experimental mainnet-beta.** Proof-of-work runs at a small
  structural width (k = 4 below the SF-1 activation height); at k = 4 the
  witness is **trivially forgeable** and the chain is **51%-attackable**. Do
  not treat confirmations as economically final.
- **BLCH is neutral protocol gas.** It is **NOT a security**, share, or claim
  on anyone's revenue — no yield, dividend, or profit is offered or implied.
  BLCH is worthless by design as anything other than gas. A **17% premine is
  disclosed**.
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
    "MAINNET_PREFIX",
    "TESTNET_PREFIX",
    "bloch_to_sats",
    "sats_to_bloch",
    "format_bloch",
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
from blochclient import BlochClient, BlochRpcError, sats_to_bloch

client = BlochClient("http://127.0.0.1:16210")

height = client.get_block_count()
info = client.get_network_info()          # -> NetworkInfo (TypedDict)
bal = client.get_balance("bloch1q...")    # -> Balance
print(sats_to_bloch(bal["satoshis"]), "BLCH")

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

GO_UNITS = '''\
// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) Bloch community contributors
//
// Unit helpers: satoshis <-> BLCH display, plus a light address-network guess.
// The integer satoshi value is the ONLY on-chain truth (1 BLCH = 100_000_000
// satoshis); the float *_bloch fields are display-only.

package blochclient

import (
	"fmt"
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

// SatsToBloch formats integer satoshis as a BLCH display string with 8 decimals.
func SatsToBloch(sats int64) string {
	neg := sats < 0
	if neg {
		sats = -sats
	}
	whole := sats / SatsPerBloch
	frac := sats % SatsPerBloch
	s := fmt.Sprintf("%d.%08d", whole, frac)
	if neg {
		return "-" + s
	}
	return s
}

// FormatBloch renders satoshis as e.g. "1.50000000 BLCH".
func FormatBloch(sats int64) string {
	return SatsToBloch(sats) + " BLCH"
}

// BlochToSats parses a human BLCH string (e.g. "1.5") into integer satoshis.
// It rejects more than 8 decimal places and non-numeric input.
func BlochToSats(bloch string) (int64, error) {
	s := strings.TrimSpace(bloch)
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	whole, frac := s, ""
	if i := strings.IndexByte(s, '.'); i >= 0 {
		whole, frac = s[:i], s[i+1:]
	}
	if len(frac) > BlochDecimals {
		return 0, fmt.Errorf("too many decimal places (max %d): %q", BlochDecimals, bloch)
	}
	frac = frac + strings.Repeat("0", BlochDecimals-len(frac))
	var w, f int64
	if whole != "" {
		if _, err := fmt.Sscanf(whole, "%d", &w); err != nil {
			return 0, fmt.Errorf("invalid BLCH amount: %q", bloch)
		}
	}
	if frac != "" {
		if _, err := fmt.Sscanf(frac, "%d", &f); err != nil {
			return 0, fmt.Errorf("invalid BLCH amount: %q", bloch)
		}
	}
	sats := w*SatsPerBloch + f
	if neg {
		sats = -sats
	}
	return sats, nil
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

GO_DOC = '''\
// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) Bloch community contributors

// Package blochclient is a community, generated Go client for the Bloch
// (bloch-sis) JSON-RPC 2.0 API.
//
// SCAFFOLD / generated / pre-production / UNAUDITED. It is generated from
// docs/openapi.yaml by sdk/codegen/generate.py — the spec drives the client;
// regenerate on any spec change. Bloch is ownerless and neutral; this SDK is
// permissively-licensed community tooling with no privileged access. The base
// is experimental mainnet-beta (k=4 trivially forgeable, 51%-attackable). BLCH
// is neutral protocol gas, NOT a security, worthless by design as anything but
// gas; a 17% premine is disclosed. Plans, not promises.
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
   - scalar schemas (`Hex32`, `Hex20`, `Address`, `Satoshis`) -> type aliases,
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

## Files

- `generate.py` — the generator (stdlib + PyYAML only).
- `static_assets.py` — verbatim scaffold (errors, unit helpers, the `Signer`
  seam, packaging metadata, READMEs, licenses). Not spec-derived, so these carry
  the SPDX header but not the `@generated` banner.

## Signing seam

Clients deliberately do **not** implement Bloch's hybrid
Falcon-1024 || ML-DSA-65 signing. The only write, `sendrawtransaction`, takes an
already-signed raw tx hex; each client exposes a `Signer` interface seam only.

## Rails

SCAFFOLD / generated / unaudited / pre-production. Bloch is ownerless and
neutral (no privileged access). Base is experimental mainnet-beta (k=4 trivially
forgeable, 51%-attackable). BLCH is neutral protocol gas, NOT a security,
worthless by design as anything but gas; 17% premine disclosed. Plans, not
promises.
'''
