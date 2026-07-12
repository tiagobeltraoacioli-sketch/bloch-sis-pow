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
