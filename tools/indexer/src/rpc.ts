// SPDX-License-Identifier: MIT OR Apache-2.0
// JSON-RPC 2.0 client for the Bloch node, plus a typed block/transaction model
// matching the node's `format_tx` output (src/rpc/mod.rs).
//
// The transport is an interface so the indexer can run either against a live
// node (`HttpTransport`) or against a scripted offline chain that reorgs
// (`StubChainTransport`, see stubchain.ts) — no node required to exercise the
// reorg logic.
//
// Satoshi amounts arrive here and nowhere else: `getBlockByHeight` normalizes
// every `outputs[].value` through `parseSats` (sats.ts) into a `bigint`, so no
// amount is ever a `number` past this boundary. Both wire forms are accepted —
// the Genesis-4 decimal string and the legacy Genesis-3 bare number.

import { parseSats, parseJsonExactIntegers } from "./sats.js";

export interface JsonRpcTransport {
  call(method: string, params: unknown[]): Promise<unknown>;
}

export class RpcError extends Error {
  constructor(message: string, readonly method: string, readonly code?: number) {
    super(message);
    this.name = "RpcError";
  }
}

/** The node buries application errors inside `result.error` (a string). */
export function unwrapResult(result: unknown, method: string): unknown {
  if (result && typeof result === "object" && "error" in (result as Record<string, unknown>)) {
    const err = (result as Record<string, unknown>).error;
    if (typeof err === "string") throw new RpcError(err, method);
  }
  return result;
}

export class HttpTransport implements JsonRpcTransport {
  constructor(private readonly url: string, private readonly apiKey?: string) {}
  async call(method: string, params: unknown[]): Promise<unknown> {
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (this.apiKey) headers["x-api-key"] = this.apiKey;
    const res = await fetch(this.url, {
      method: "POST",
      headers,
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    });
    if (!res.ok) {
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
    // NOT res.json(): that routes every JSON number through a double, which
    // silently rounds satoshi amounts above 2^53. parseJsonExactIntegers keeps
    // oversized integer literals as their raw digit strings for parseSats.
    const body = parseJsonExactIntegers(await res.text()) as {
      result?: unknown;
      error?: { code?: number; message?: string };
    };
    if (body.error) throw new RpcError(body.error.message ?? "rpc error", method, body.error.code);
    return unwrapResult(body.result, method);
  }
}

// ── Typed model (matches format_tx / getblockbyheight) ────────────────────────

export interface TxInput {
  prev_txid: string;
  prev_index: number;
  sequence?: number;
}
export interface TxOutput {
  index: number;
  /** Satoshis. `bigint`, always — see sats.ts / BLOCH-SATOSHI-ENCODING.md. */
  value: bigint;
  script_pubkey: string; // hex of the 20-byte pubkey hash
}
export interface Tx {
  txid: string;
  coinbase: boolean;
  inputs: TxInput[];
  outputs: TxOutput[];
}

/** A transaction as it appears on the wire, before amounts are parsed. */
interface WireTx {
  txid?: unknown;
  coinbase?: unknown;
  inputs?: Array<{ prev_txid?: unknown; prev_index?: unknown; sequence?: unknown }>;
  outputs?: Array<{ index?: unknown; value?: unknown; script_pubkey?: unknown }>;
}

/**
 * Normalize one wire transaction: amounts become `bigint` via `parseSats`
 * (accepting both the decimal-string and legacy bare-number forms); indices and
 * sequences stay `number`.
 */
export function normalizeTx(raw: WireTx, where = "tx"): Tx {
  const txid = String(raw.txid ?? "");
  return {
    txid,
    coinbase: raw.coinbase === true,
    inputs: (raw.inputs ?? []).map((i) => ({
      prev_txid: String(i.prev_txid ?? ""),
      prev_index: Number(i.prev_index ?? 0),
      sequence: i.sequence === undefined ? undefined : Number(i.sequence),
    })),
    outputs: (raw.outputs ?? []).map((o, i) => {
      const index = o.index === undefined ? i : Number(o.index);
      return {
        index,
        value: parseSats(o.value, `${where} ${txid}:${index} value`),
        script_pubkey: String(o.script_pubkey ?? ""),
      };
    }),
  };
}
export interface Block {
  hash: string;
  height: number;
  parents: string[];
  timestamp: number;
  transactions: Tx[];
}

export interface DagInfo {
  tip: string | null;
  tip_height: number;
  block_count: number;
  tips: string[];
  k: number;
}

export class RpcClient {
  constructor(private readonly transport: JsonRpcTransport) {}

  async getBlockCount(): Promise<number> {
    return (await this.transport.call("getblockcount", [])) as number;
  }

  async getDagInfo(): Promise<DagInfo> {
    return (await this.transport.call("getdaginfo", [])) as DagInfo;
  }

  /** Returns null when the height is not present (node error "height not found"). */
  async getBlockHash(height: number): Promise<string | null> {
    try {
      return (await this.transport.call("getblockhash", [height])) as string;
    } catch (e) {
      if (e instanceof RpcError && /not found/i.test(e.message)) return null;
      throw e;
    }
  }

  /** Returns null when the height is not present. Always requests verbose=true. */
  async getBlockByHeight(height: number): Promise<Block | null> {
    try {
      const raw = (await this.transport.call("getblockbyheight", [height, true])) as {
        hash: string;
        height: number;
        parents?: string[];
        timestamp?: number;
        transactions?: WireTx[];
      };
      return {
        hash: raw.hash,
        height: raw.height,
        parents: raw.parents ?? [],
        timestamp: raw.timestamp ?? 0,
        transactions: (raw.transactions ?? []).map((t) => normalizeTx(t, `block ${height}`)),
      };
    } catch (e) {
      if (e instanceof RpcError && /not found/i.test(e.message)) return null;
      throw e;
    }
  }
}
