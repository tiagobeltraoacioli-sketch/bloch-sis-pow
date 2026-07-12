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
