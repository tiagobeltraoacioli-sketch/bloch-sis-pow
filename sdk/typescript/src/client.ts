// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) Bloch community contributors
//
// Typed JSON-RPC 2.0 client for Bloch, over the single `POST /` endpoint
// (default RPC port 16210). Handles BOTH failure shapes:
//   - the standard JSON-RPC `error` object (Sprint-M auth / rate limit), and
//   - the non-standard `result.error` quirk used for most method failures.

import { BlochRpcError, BlochTransportError } from "./errors.js";
import type {
  Address,
  AddressBalanceAtHeight,
  AddressInfo,
  AddressValidation,
  AddressValidationVerbose,
  Balance,
  Block,
  BlockSummary,
  BlockTimePercentiles,
  BroadcastResult,
  ChainStats,
  DagInfo,
  DifficultyHistory,
  FeeEstimate,
  FeeEstimateAdvanced,
  HashrateInfo,
  Hex32,
  Height,
  ListTransactionsOptions,
  ListTransactionsResult,
  MempoolInfo,
  MempoolStats,
  NetworkInfo,
  PeerInfo,
  PeersList,
  RawMempool,
  SupplyDistribution,
  Transaction,
  TransactionLookup,
  TxsByBlock,
  TxStatus,
  Utxo,
  UtxoList,
} from "./types.js";

/** Minimal fetch shape so the SDK need not depend on DOM lib types. */
export type FetchLike = (
  url: string,
  init: {
    method: string;
    headers: Record<string, string>;
    body: string;
    signal?: AbortSignal;
  },
) => Promise<{
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
  text(): Promise<string>;
}>;

export interface BlochClientOptions {
  /** Full node URL, e.g. "http://127.0.0.1:16210". Defaults to localhost:16210. */
  url?: string;
  /** Optional X-API-Key for Sprint-M write auth (sent on every request). */
  apiKey?: string;
  /** Send the key as `Authorization: Bearer <key>` instead of `X-API-Key`. */
  bearer?: boolean;
  /** Per-request timeout in ms (default 30_000). */
  timeoutMs?: number;
  /** Extra static headers. */
  headers?: Record<string, string>;
  /** Override the fetch implementation (default: global fetch). */
  fetch?: FetchLike;
}

export const DEFAULT_RPC_URL = "http://127.0.0.1:16210";
export const DEFAULT_RPC_PORT = 16210;

interface JsonRpcEnvelope {
  jsonrpc?: string;
  id?: number | string | null;
  result?: unknown;
  error?: { code?: number; message?: string; data?: unknown };
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * A typed client for the Bloch JSON-RPC surface.
 *
 * Every method maps to one node RPC. Read methods are always public; the only
 * write is {@link BlochClient.sendRawTransaction}. Failures throw
 * {@link BlochRpcError} (both error shapes normalized) or
 * {@link BlochTransportError} (network / malformed response).
 */
export class BlochClient {
  private readonly url: string;
  private readonly apiKey?: string;
  private readonly bearer: boolean;
  private readonly timeoutMs: number;
  private readonly staticHeaders: Record<string, string>;
  private readonly fetchImpl: FetchLike;
  private idCounter = 0;

  constructor(options: BlochClientOptions = {}) {
    this.url = options.url ?? DEFAULT_RPC_URL;
    if (options.apiKey !== undefined) this.apiKey = options.apiKey;
    this.bearer = options.bearer ?? false;
    this.timeoutMs = options.timeoutMs ?? 30_000;
    this.staticHeaders = options.headers ?? {};
    const f = options.fetch ?? (globalThis as { fetch?: unknown }).fetch;
    if (typeof f !== "function") {
      throw new Error(
        "No fetch implementation available. Pass `fetch` in BlochClientOptions or run on Node 18+.",
      );
    }
    this.fetchImpl = f as FetchLike;
  }

  /**
   * Low-level JSON-RPC call. Prefer the typed wrappers below; use this for
   * methods this SDK version does not yet wrap.
   */
  async call<T = unknown>(method: string, params: unknown[] = []): Promise<T> {
    const id = ++this.idCounter;
    const body = JSON.stringify({ jsonrpc: "2.0", method, params, id });

    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      ...this.staticHeaders,
    };
    if (this.apiKey !== undefined) {
      if (this.bearer) headers["Authorization"] = `Bearer ${this.apiKey}`;
      else headers["X-API-Key"] = this.apiKey;
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    let res: Awaited<ReturnType<FetchLike>>;
    try {
      res = await this.fetchImpl(this.url, {
        method: "POST",
        headers,
        body,
        signal: controller.signal,
      });
    } catch (cause) {
      throw new BlochTransportError({
        message: `RPC transport error calling ${method}: ${(cause as Error)?.message ?? cause}`,
        method,
        cause,
      });
    } finally {
      clearTimeout(timer);
    }

    // Sprint-M auth/rate-limit failures arrive as non-2xx with a JSON-RPC error.
    let parsed: unknown;
    const raw = await res.text();
    try {
      parsed = raw.length ? JSON.parse(raw) : undefined;
    } catch {
      throw new BlochTransportError({
        message: `RPC ${method}: response was not valid JSON (HTTP ${res.status})`,
        method,
        httpStatus: res.status,
      });
    }

    const envelope: JsonRpcEnvelope = isRecord(parsed) ? parsed : {};

    // Shape 1: standard JSON-RPC error object (Sprint-M auth / rate limit).
    if (isRecord(envelope.error)) {
      throw new BlochRpcError({
        message: String(envelope.error.message ?? "JSON-RPC error"),
        method,
        source: "jsonrpc-error",
        ...(typeof envelope.error.code === "number" ? { code: envelope.error.code } : {}),
        httpStatus: res.status,
        data: envelope.error.data,
      });
    }

    if (!res.ok) {
      throw new BlochTransportError({
        message: `RPC ${method}: HTTP ${res.status}`,
        method,
        httpStatus: res.status,
      });
    }

    const result = envelope.result;

    // Shape 2: the non-standard `result.error` quirk.
    if (isRecord(result) && typeof result["error"] === "string") {
      throw new BlochRpcError({
        message: result["error"],
        method,
        source: "result-error",
        data: result,
      });
    }

    return result as T;
  }

  // ── Chain state ─────────────────────────────────────────────────────────
  getNetworkInfo(): Promise<NetworkInfo> {
    return this.call<NetworkInfo>("getnetworkinfo");
  }
  getBlockCount(): Promise<number> {
    return this.call<number>("getblockcount");
  }
  getMempoolInfo(): Promise<MempoolInfo> {
    return this.call<MempoolInfo>("getmempoolinfo");
  }
  getDagInfo(): Promise<DagInfo> {
    return this.call<DagInfo>("getdaginfo");
  }
  getPeerInfo(): Promise<PeerInfo> {
    return this.call<PeerInfo>("getpeerinfo");
  }
  getPeers(): Promise<PeersList> {
    return this.call<PeersList>("getpeers");
  }

  // ── Blocks ──────────────────────────────────────────────────────────────
  getBlockHash(height: Height): Promise<Hex32> {
    return this.call<Hex32>("getblockhash", [height]);
  }
  /** Full block by hash. `verbose=true` expands transactions. */
  getBlock(hash: Hex32, verbose = false): Promise<Block> {
    return this.call<Block>("getblock", [hash, verbose]);
  }
  /** Full block by height. `verbose=true` expands transactions. */
  getBlockByHeight(height: Height, verbose = false): Promise<Block> {
    return this.call<Block>("getblockbyheight", [height, verbose]);
  }
  getRecentBlocks(count = 10): Promise<BlockSummary[]> {
    return this.call<BlockSummary[]>("getrecentblocks", [count]);
  }
  /** List txs in a block, by 64-hex hash or numeric height. */
  getTxsByBlock(blockIdentifier: Hex32 | number): Promise<TxsByBlock> {
    return this.call<TxsByBlock>("gettxsbyblock", [blockIdentifier]);
  }

  // ── Transactions ────────────────────────────────────────────────────────
  getTransaction(txid: Hex32): Promise<TransactionLookup> {
    return this.call<TransactionLookup>("gettransaction", [txid]);
  }
  getTxStatus(txid: Hex32): Promise<TxStatus> {
    return this.call<TxStatus>("gettxstatus", [txid]);
  }
  decodeRawTransaction(hexTx: string): Promise<Transaction> {
    return this.call<Transaction>("decoderawtransaction", [hexTx]);
  }
  getRawMempool(verbose = false): Promise<RawMempool> {
    return this.call<RawMempool>("getrawmempool", [verbose]);
  }

  // ── Addresses ───────────────────────────────────────────────────────────
  getBalance(address: Address): Promise<Balance> {
    return this.call<Balance>("getbalance", [address]);
  }
  getUtxos(address: Address): Promise<UtxoList> {
    return this.call<UtxoList>("getutxos", [address]);
  }
  /** Convenience: just the `utxos` array from getUtxos. */
  async getUtxoList(address: Address): Promise<Utxo[]> {
    return (await this.getUtxos(address)).utxos;
  }
  getAddressInfo(address: Address): Promise<AddressInfo> {
    return this.call<AddressInfo>("getaddressinfo", [address]);
  }
  getAddressBalanceAtHeight(address: Address, height: Height): Promise<AddressBalanceAtHeight> {
    return this.call<AddressBalanceAtHeight>("getaddressbalance_at_height", [address, height]);
  }
  listTransactions(address: Address, opts: ListTransactionsOptions = {}): Promise<ListTransactionsResult> {
    const params: unknown[] = [
      address,
      opts.limit ?? 20,
      opts.startHeight ?? 0,
    ];
    if (opts.endHeight !== undefined) params.push(opts.endHeight);
    // offset is positional after end_height; only include when needed.
    if (opts.offset !== undefined) {
      if (opts.endHeight === undefined) params.push(null);
      params.push(opts.offset);
    }
    return this.call<ListTransactionsResult>("listtransactions", params);
  }
  validateAddress(address: string): Promise<AddressValidation> {
    return this.call<AddressValidation>("validateaddress", [address]);
  }
  validateAddressVerbose(address: string): Promise<AddressValidationVerbose> {
    return this.call<AddressValidationVerbose>("validateaddressverbose", [address]);
  }

  // ── Broadcast (the only write) ──────────────────────────────────────────
  /**
   * Submit a signed, serialized transaction hex to the mempool. Requires
   * X-API-Key when the node runs with `--rpc-require-auth-for-writes`
   * (localhost bypasses auth).
   */
  sendRawTransaction(hexTx: string): Promise<BroadcastResult> {
    return this.call<BroadcastResult>("sendrawtransaction", [hexTx]);
  }

  // ── Fees ────────────────────────────────────────────────────────────────
  estimateFee(): Promise<FeeEstimate> {
    return this.call<FeeEstimate>("estimatefee");
  }
  estimateFeeAdvanced(): Promise<FeeEstimateAdvanced> {
    return this.call<FeeEstimateAdvanced>("estimatefeeadvanced");
  }

  // ── Analytics ───────────────────────────────────────────────────────────
  getChainStats(): Promise<ChainStats> {
    return this.call<ChainStats>("getchainstats");
  }
  getHashrate(): Promise<HashrateInfo> {
    return this.call<HashrateInfo>("gethashrate");
  }
  getSupplyDistribution(): Promise<SupplyDistribution> {
    return this.call<SupplyDistribution>("getsupplydistribution");
  }
  getDifficultyHistory(limit = 20): Promise<DifficultyHistory> {
    return this.call<DifficultyHistory>("getdifficultyhistory", [limit]);
  }
  getBlockTimePercentiles(window = 100): Promise<BlockTimePercentiles> {
    return this.call<BlockTimePercentiles>("getblocktimepercentiles", [window]);
  }
  getMempoolStats(): Promise<MempoolStats> {
    return this.call<MempoolStats>("getmempoolstats");
  }
}
