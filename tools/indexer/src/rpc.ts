// SPDX-License-Identifier: MIT OR Apache-2.0
// JSON-RPC 2.0 client for the Bloch node, plus a typed block/transaction model
// matching the node's `format_tx` output (src/rpc/mod.rs).
//
// The transport is an interface so the indexer can run either against a live
// node (`HttpTransport`) or against a scripted offline chain that reorgs
// (`StubChainTransport`, see stubchain.ts) — no node required to exercise the
// reorg logic.

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

// ── Typed model (matches format_tx / getblockbyheight) ────────────────────────

export interface TxInput {
  prev_txid: string;
  prev_index: number;
  sequence?: number;
}
export interface TxOutput {
  index: number;
  value: number; // satoshis
  script_pubkey: string; // hex of the 20-byte pubkey hash
}
export interface Tx {
  txid: string;
  coinbase: boolean;
  inputs: TxInput[];
  outputs: TxOutput[];
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
        transactions?: Tx[];
      };
      return {
        hash: raw.hash,
        height: raw.height,
        parents: raw.parents ?? [],
        timestamp: raw.timestamp ?? 0,
        transactions: raw.transactions ?? [],
      };
    } catch (e) {
      if (e instanceof RpcError && /not found/i.test(e.message)) return null;
      throw e;
    }
  }
}
