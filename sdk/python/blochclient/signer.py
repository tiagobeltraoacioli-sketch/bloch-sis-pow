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
