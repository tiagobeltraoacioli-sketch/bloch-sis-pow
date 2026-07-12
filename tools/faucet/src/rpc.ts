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

// ── Typed convenience wrappers ────────────────────────────────────────────────

export interface Utxo {
  txid: string;
  index: number;
  value: number;
  script_pubkey: string;
}

export interface GetUtxosResult {
  address: string;
  utxo_count: number;
  satoshis: number;
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
        const utxos: Utxo[] = [
          { txid: "aa".repeat(32), index: 0, value: 5_000_000_000, script_pubkey: "11".repeat(20) },
          { txid: "bb".repeat(32), index: 1, value: 5_000_000_000, script_pubkey: "11".repeat(20) },
        ];
        const satoshis = utxos.reduce((a, u) => a + u.value, 0);
        return { address: addr, utxo_count: utxos.length, satoshis, bloch: satoshis / 1e8, utxos };
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
