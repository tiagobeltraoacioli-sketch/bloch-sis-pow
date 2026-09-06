// SPDX-License-Identifier: MIT OR Apache-2.0
// Minimal JSON-RPC 2.0 client for the Bloch node RPC surface.
//
// Bloch quirks handled here (see src/rpc/mod.rs in the node):
//   * params are always a POSITIONAL array
//   * a successful HTTP 200 may still carry an APPLICATION error inside
//     `result.error` (a string), rather than the standard top-level `error`
//   * transport/auth failures use a real top-level `error` object (-32001/-32002)
//
// The transport is behind an interface so the faucet builds and runs offline:
// `HttpTransport` hits a real node; `StubTransport` returns fixtures so the whole
// getutxos -> build -> sendrawtransaction pipeline is exercisable with no node.

import { parseJsonExactIntegers } from "./sats.js";

//
// T-4 fix (audit finding): `HttpTransport.call` used to parse both the error
// body and the success body with `res.json()` — the exact rounding path
// `sats.ts` exists to avoid (see its module comment). Every satoshi amount
// from `getutxos` passed through an IEEE-754 double before `parseSats` could
// ever see it. `parseSats` itself always correctly REJECTED an already-
// rounded amount (never silent corruption), but the practical consequence
// was that the faucet could never operate against a funding wallet holding
// a UTXO above ~9.007e15 sat (~90,071,992 BLCH) — plausible given the
// Genesis-4 supply (1e19 sat) and the largest carried-over address alone
// (3.5e17 sat) — and would simply stop working with a confusing error.
// `parseJsonExactIntegers` (sats.ts) reads such a literal from its raw
// source text instead of through `JSON.parse`'s default double conversion.

export interface JsonRpcTransport {
  call(method: string, params: unknown[]): Promise<unknown>;
}

export class RpcError extends Error {
  constructor(
    message: string,
    readonly method: string,
    readonly code?: number,
  ) {
    super(message);
    this.name = "RpcError";
  }
}

export class HttpTransport implements JsonRpcTransport {
  constructor(
    private readonly url: string,
    private readonly apiKey?: string,
  ) {}

  async call(method: string, params: unknown[]): Promise<unknown> {
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (this.apiKey) headers["x-api-key"] = this.apiKey;
    const res = await fetch(this.url, {
      method: "POST",
      headers,
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    });
    if (!res.ok) {
      // Try to surface the node's structured error (-32001/-32002 etc.).
      let detail = `${res.status} ${res.statusText}`;
      try {
        const j = parseJsonExactIntegers(await res.text()) as { error?: { code?: number; message?: string } };
        if (j.error?.message) detail = j.error.message;
        throw new RpcError(detail, method, j.error?.code);
      } catch (e) {
        if (e instanceof RpcError) throw e;
        throw new RpcError(detail, method);
      }
    }
    // T-4 fix: NOT res.json() — see the module comment above.
    const body = parseJsonExactIntegers(await res.text()) as {
      result?: unknown;
      error?: { code?: number; message?: string };
    };
    if (body.error) throw new RpcError(body.error.message ?? "rpc error", method, body.error.code);
    return unwrapResult(body.result, method);
  }
}

/** Apply the `result.error` quirk: throw if the node buried an error in result. */
export function unwrapResult(result: unknown, method: string): unknown {
  if (result && typeof result === "object" && "error" in (result as Record<string, unknown>)) {
    const err = (result as Record<string, unknown>).error;
    if (typeof err === "string") throw new RpcError(err, method);
  }
  return result;
}

// ── Amounts ───────────────────────────────────────────────────────────────────
//
// AMOUNT ENCODING — canonical rule: docs/specs/BLOCH-SATOSHI-ENCODING.md
// (restated as BLOCH-RPC-V4 R3). Satoshi fields are decimal STRINGS on the
// V4 wire; live Genesis-3 nodes still send bare JSON numbers, so readers accept
// both. Measured reason: Genesis-4 supply is 100,000,000,000 BLCH = 1e19 sat,
// ~1110x Number.MAX_SAFE_INTEGER (9,007,199,254,740,991) — a satoshi value that
// passes through a JS number is silently rounded to the nearest double.

/** A satoshi amount exactly as it comes off the wire. Do NOT do math on it. */
export type WireSats = string | number;

/**
 * T-5 fix (audit finding): `parseSats` used to be defined here, independently
 * of `tools/indexer`'s implementation of the SAME normative rule, and the two
 * had diverged (this one accepted leading zeros and unbounded digit counts,
 * and enforced no upper bound at all). Re-exported from the vendored
 * canonical copy (`./sats.js` — see that file's header for why it is
 * vendored rather than imported across packages) so there is exactly one
 * satoshi-parsing implementation in this codebase, not two that silently
 * drift apart. Its signature (`parseSats(raw: unknown, context?: string)`)
 * is a strict superset of the old one — every existing call site here passes
 * a `WireSats | bigint`, which is assignable to `unknown`.
 */
export { parseSats } from "./sats.js";

// ── Typed convenience wrappers ────────────────────────────────────────────────

export interface Utxo {
  txid: string;
  index: number;
  /** Satoshis, wire form. Run through {@link parseSats} before any arithmetic. */
  value: WireSats;
  script_pubkey: string;
}

export interface GetUtxosResult {
  address: string;
  utxo_count: number;
  /** Satoshis, wire form. */
  satoshis: WireSats;
  /** Display-only float companion. LOSSY. */
  bloch: number;
  utxos: Utxo[];
}

export class RpcClient {
  constructor(private readonly transport: JsonRpcTransport) {}

  async getUtxos(address: string): Promise<GetUtxosResult> {
    return (await this.transport.call("getutxos", [address])) as GetUtxosResult;
  }

  async sendRawTransaction(rawHex: string): Promise<string> {
    const r = (await this.transport.call("sendrawtransaction", [rawHex])) as { txid: string };
    return r.txid;
  }

  async validateAddress(address: string): Promise<{ isvalid: boolean; network: string; checksum: boolean }> {
    return (await this.transport.call("validateaddress", [address])) as {
      isvalid: boolean;
      network: string;
      checksum: boolean;
    };
  }

  async getTxStatus(txid: string): Promise<{ status: string; confirmations: number; in_mempool: boolean }> {
    return (await this.transport.call("gettxstatus", [txid])) as {
      status: string;
      confirmations: number;
      in_mempool: boolean;
    };
  }

  async getNetworkInfo(): Promise<Record<string, unknown>> {
    return (await this.transport.call("getnetworkinfo", [])) as Record<string, unknown>;
  }
}

// ── Offline stub transport (dry-run) ──────────────────────────────────────────
//
// Returns just enough to exercise the pipeline without a live node. It fakes a
// funding wallet with a few UTXOs and echoes a deterministic txid on broadcast.
export class StubTransport implements JsonRpcTransport {
  private broadcastCount = 0;

  constructor(private readonly fundingAddress: string) {}

  async call(method: string, params: unknown[]): Promise<unknown> {
    switch (method) {
      case "getnetworkinfo":
        return { network: "testnet(stub)", chain: "bloch-sis", blocks: 0, syncing: false };
      case "validateaddress": {
        const addr = String(params[0] ?? "");
        const isTestnet = addr.startsWith("bloch1t");
        return { address: addr, isvalid: isTestnet, network: isTestnet ? "testnet" : "unknown", checksum: isTestnet };
      }
      case "getutxos": {
        const addr = String(params[0] ?? "");
        // Emits the canonical decimal-STRING form on purpose: the offline
        // selftest then exercises the real V4 wire encoding instead of the
        // legacy number form, which is where the arithmetic bugs hide.
        const values = [5_000_000_000n, 5_000_000_000n];
        const utxos: Utxo[] = [
          { txid: "aa".repeat(32), index: 0, value: values[0]!.toString(), script_pubkey: "11".repeat(20) },
          { txid: "bb".repeat(32), index: 1, value: values[1]!.toString(), script_pubkey: "11".repeat(20) },
        ];
        const satoshis = values.reduce((a, v) => a + v, 0n);
        return {
          address: addr,
          utxo_count: utxos.length,
          satoshis: satoshis.toString(),
          bloch: Number(satoshis) / 1e8, // display-only, lossy by design
          utxos,
        };
      }
      case "sendrawtransaction": {
        this.broadcastCount += 1;
        // Deterministic fake txid derived from the raw hex length + counter.
        const raw = String(params[0] ?? "");
        const tag = (raw.length ^ this.broadcastCount).toString(16).padStart(2, "0");
        return { txid: tag.repeat(32).slice(0, 64) };
      }
      case "gettxstatus":
        return { status: "pending", in_mempool: true, confirmations: 0, txid: String(params[0] ?? "") };
      default:
        return { error: `stub: unsupported method ${method}` };
    }
  }
}
