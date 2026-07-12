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
