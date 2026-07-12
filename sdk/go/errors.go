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
