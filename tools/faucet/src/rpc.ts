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
        const j = (await res.json()) as { error?: { code?: number; message?: string } };
        if (j.error?.message) detail = j.error.message;
        throw new RpcError(detail, method, j.error?.code);
      } catch (e) {
        if (e instanceof RpcError) throw e;
        throw new RpcError(detail, method);
      }
    }
    const body = (await res.json()) as { result?: unknown; error?: { code?: number; message?: string } };
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
 * Parse a wire satoshi amount into an exact bigint.
 *
 * Rejects negatives, non-integers, and the `number` form above
 * Number.MAX_SAFE_INTEGER — such a number is not risky, it is ALREADY WRONG
 * (JSON.parse rounded it before this code ever saw it), so accepting it would
 * launder a corrupted amount into an exact-looking type.
 */
export function parseSats(v: WireSats | bigint, what = "satoshi value"): bigint {
  let out: bigint;
  if (typeof v === "bigint") {
    out = v;
  } else if (typeof v === "number") {
    if (!Number.isInteger(v)) throw new RangeError(`${what} is not an integer: ${v}`);
    if (!Number.isSafeInteger(v)) {
      throw new RangeError(
        `${what} ${v} exceeds Number.MAX_SAFE_INTEGER and is already corrupted by ` +
          `IEEE-754 rounding; the node must send it as a decimal string (RPC-V4 R3)`,
      );
    }
    out = BigInt(v);
  } else {
    const s = v.trim();
    if (!/^-?\d+$/.test(s)) throw new RangeError(`invalid ${what}: ${JSON.stringify(v)}`);
    out = BigInt(s);
  }
  if (out < 0n) throw new RangeError(`negative ${what}: ${out}`);
  return out;
}

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

  /**
   * `getutxos(script_hash, limit)`. The node takes a 32-byte script_hash as 64
   * hex, NOT an address — `rpc.rs` routes it through
   * `want_hex32(params, 0, "script_hash")`. Passing an address here was a
   * silent guarantee of failure against any real node.
   */
  async getUtxos(scriptHashHex: string): Promise<GetUtxosResult> {
    return (await this.transport.call("getutxos", [scriptHashHex])) as GetUtxosResult;
  }

  async sendRawTransaction(rawHex: string): Promise<string> {
    const r = (await this.transport.call("sendrawtransaction", [rawHex])) as { txid: string };
    return r.txid;
  }

  // NOTE ON WHAT IS *NOT* HERE. This client previously exposed
  // `validateaddress`, `gettxstatus` and `getnetworkinfo`. The Genesis-4 node
  // implements NONE of them — its whole dispatch table is `getchaininfo`,
  // `getblockcount`, `getblockbyslot`, `getblockbyid`, `getvalidator`,
  // `getvalidatorcount`, `getvalidatorstatus`, `getbalance`,
  // `getutxos`/`listunspent`, `gettxout`, `sendrawtransaction`,
  // `getmempoolinfo`, `getmetrics`, plus `gettransaction` and `getnewaddress`
  // which exist only to refuse. Calling the three removed names returned
  // "method not found", so the LIVE path could never have completed a drip.
  // Address validation is therefore local only (`address.ts` mirrors the
  // node's own checksum rule) and settlement is read with `gettxout`.

  /**
   * `gettxout(txid, vout)`. `finalized: true` is the settlement judgement —
   * there are no confirmations on this chain.
   */
  async getTxOut(txid: string, vout = 0): Promise<{ finalized?: boolean } & Record<string, unknown>> {
    return (await this.transport.call("gettxout", [txid, vout])) as {
      finalized?: boolean;
    } & Record<string, unknown>;
  }

  /** `getchaininfo` — height, epoch, justified/finalized checkpoints. */
  async getChainInfo(): Promise<Record<string, unknown>> {
    return (await this.transport.call("getchaininfo", [])) as Record<string, unknown>;
  }

  /**
   * `getblockbyslot(0).block_id` — the genesis block's id, which IS this
   * network's identity. Used by the startup preflight to bind the faucet to
   * one chain.
   *
   * Deliberately built from methods that already exist. `getchaininfo` carries
   * no genesis digest and no network id, and inventing an RPC name to carry one
   * is not this tool's decision to make (wire names are claimed from the PMO).
   * The genesis block id is already public, already stable, and already unique
   * per network, so nothing new is needed.
   */
  async getGenesisBlockId(): Promise<string> {
    const b = (await this.transport.call("getblockbyslot", [0])) as { block_id?: string };
    if (typeof b?.block_id !== "string" || !/^[0-9a-f]{64}$/i.test(b.block_id)) {
      throw new RpcError("getblockbyslot(0) returned no usable block_id", "getblockbyslot");
    }
    return b.block_id.toLowerCase();
  }
}

// ── Offline stub transport (dry-run) ──────────────────────────────────────────
//
// Returns just enough to exercise the pipeline without a live node. It fakes a
// funding wallet with a few UTXOs and echoes a deterministic txid on broadcast.
export class StubTransport implements JsonRpcTransport {
  private broadcastCount = 0;

  constructor(private readonly fundingScriptHash: string) {}

  async call(method: string, params: unknown[]): Promise<unknown> {
    switch (method) {
      case "getchaininfo":
        return { height: 0, epoch: 0, justified: null, finalized: null, stub: true };
      case "getutxos":
      case "listunspent": {
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
      case "getblockbyslot":
        // A stub chain has a stub genesis. The preflight refuses to accept it
        // as proof of anything: the genesis binding is only enforced in LIVE
        // mode, where this transport is not used.
        return { block_id: "00".repeat(32), slot: Number(params[0] ?? 0), height: 0, stub: true };
      case "gettxout":
        return { txid: String(params[0] ?? ""), vout: Number(params[1] ?? 0), finalized: false };
      default:
        return { error: `stub: unsupported method ${method}` };
    }
  }
}
