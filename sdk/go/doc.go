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
