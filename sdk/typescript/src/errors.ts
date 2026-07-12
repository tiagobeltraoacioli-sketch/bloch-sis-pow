// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) Bloch community contributors

/**
 * Raised when a Bloch RPC call fails.
 *
 * Bloch currently reports method failures in TWO shapes, and this SDK
 * normalizes both into this one error:
 *
 *  1. The non-standard "result.error" quirk — the node returns
 *     `{"jsonrpc":"2.0","result":{"error":"invalid hash"},"id":1}` for most
 *     per-method failures (documented in the roadmap §1.2 and openapi.yaml).
 *     `source` is `"result-error"` and `code` is undefined.
 *
 *  2. The standard JSON-RPC 2.0 `error` object — used by the Sprint-M auth /
 *     rate-limit layer, e.g. `{"error":{"code":-32001,"message":"..."}}`.
 *     `source` is `"jsonrpc-error"` and `code` is the numeric code
 *     (-32001 unauthorized / HTTP 401, -32002 rate-limited / HTTP 429).
 */
export class BlochRpcError extends Error {
  readonly method: string;
  readonly source: "result-error" | "jsonrpc-error";
  readonly code?: number;
  readonly httpStatus?: number;
  readonly data?: unknown;

  constructor(opts: {
    message: string;
    method: string;
    source: "result-error" | "jsonrpc-error";
    code?: number;
    httpStatus?: number;
    data?: unknown;
  }) {
    super(opts.message);
    this.name = "BlochRpcError";
    this.method = opts.method;
    this.source = opts.source;
    this.code = opts.code;
    this.httpStatus = opts.httpStatus;
    this.data = opts.data;
    Object.setPrototypeOf(this, BlochRpcError.prototype);
  }

  /** True when the failure is the Sprint-M unauthorized error (-32001 / 401). */
  get isUnauthorized(): boolean {
    return this.code === -32001 || this.httpStatus === 401;
  }

  /** True when the failure is the Sprint-M rate-limit error (-32002 / 429). */
  get isRateLimited(): boolean {
    return this.code === -32002 || this.httpStatus === 429;
  }
}

/** Raised when transport (network / non-2xx / malformed body) fails. */
export class BlochTransportError extends Error {
  readonly method: string;
  readonly httpStatus?: number;
  override readonly cause?: unknown;

  constructor(opts: {
    message: string;
    method: string;
    httpStatus?: number;
    cause?: unknown;
  }) {
    super(opts.message);
    this.name = "BlochTransportError";
    this.method = opts.method;
    this.httpStatus = opts.httpStatus;
    this.cause = opts.cause;
    Object.setPrototypeOf(this, BlochTransportError.prototype);
  }
}
