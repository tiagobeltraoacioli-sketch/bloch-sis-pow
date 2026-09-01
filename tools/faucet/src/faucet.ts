// SPDX-License-Identifier: MIT OR Apache-2.0
// Core faucet flow: validate a testnet address, select UTXOs from the funding
// wallet via getutxos, hand an unsigned job to the Signer, and broadcast the
// signed raw tx via sendrawtransaction.
//
// TESTNET-ONLY. The coins dispensed are test BLCH with NO value on a
// zero-security testnet.

import type { FaucetConfig } from "./config.js";
import { addressScriptHash, parseRecipient } from "./address.js";
import { RpcClient, RpcError, parseSats, type Utxo } from "./rpc.js";
import type { PaymentJob, Signer } from "./signer.js";

export interface DripSuccess {
  ok: true;
  txid: string;
  amountSats: number;
  toAddress: string;
  /** The 32-byte script_hash actually paid, as 64 hex. */
  scriptHash: string;
  dryRun: boolean;
  signer: string;
}

export interface DripFailure {
  ok: false;
  error: string;
  code?: string;
}

export type DripResult = DripSuccess | DripFailure;

export class Faucet {
  constructor(
    private readonly cfg: FaucetConfig,
    private readonly rpc: RpcClient,
    private readonly signer: Signer,
  ) {}

  /**
   * Greedy coin selection: enough UTXOs to cover amount + fee.
   *
   * All arithmetic is bigint. `Utxo.value` is the wire union `string | number`
   * (RPC-V4 R3), so the previous `b.value - a.value` / `total += u.value` gave
   * NaN and string concatenation respectively against a V4 node — and against a
   * legacy node it silently rounded any amount past 2^53 sat.
   */
  private selectUtxos(utxos: Utxo[], target: bigint): { selected: Utxo[]; total: bigint } | null {
    const parsed = utxos
      .map((u) => ({ u, v: parseSats(u.value, "utxo value") }))
      .sort((a, b) => (b.v === a.v ? 0 : b.v > a.v ? 1 : -1));
    const selected: Utxo[] = [];
    let total = 0n;
    for (const { u, v } of parsed) {
      selected.push(u);
      total += v;
      if (total >= target) return { selected, total };
    }
    return null;
  }

  async drip(to: string): Promise<DripResult> {
    // 1) Resolve the recipient. Two accepted forms — a 64-hex script_hash (what
    //    `bloch-pos spendkey` prints, and the ONLY form a native Genesis-4 key
    //    has) or a `bloch1t…` carryover address, which is zero-extended to 32
    //    bytes the way the chain does it.
    const rcpt = parseRecipient(to);
    if (!rcpt) {
      return {
        ok: false,
        error:
          "expected a 64-hex script_hash (from `bloch-pos spendkey`) or a bloch1t… address",
        code: "bad_address",
      };
    }
    // An address must be testnet-prefixed. A bare script_hash has no network
    // marker and cannot be checked — see `parseRecipient` for why that is safe
    // in the receiving direction.
    if (rcpt.kind === "address" && !rcpt.address!.startsWith("bloch1t")) {
      return {
        ok: false,
        error: "faucet is testnet-only; a bloch1q… mainnet address is refused",
        code: "not_testnet",
      };
    }

    // There is deliberately no node-side address check: the Genesis-4 RPC has
    // no `validateaddress` method. The local checksum in `address.ts` mirrors
    // the node's own rule, and the node remains the final authority when it
    // rejects the broadcast.

    if (!this.cfg.dryRun && this.cfg.fundingAddress === "") {
      return { ok: false, error: "FAUCET_FUNDING_ADDRESS is not configured", code: "misconfigured" };
    }

    // Config amounts are operator-set env ints; parseSats still range-checks
    // them so a fat-fingered FAUCET_AMOUNT_SATS fails loudly, not silently.
    const target = parseSats(this.cfg.amountSats, "FAUCET_AMOUNT_SATS") +
      parseSats(this.cfg.feeSats, "FAUCET_FEE_SATS");

    // 3) Fetch funding UTXOs — by script_hash, which is what the node takes.
    const fundingSh = this.cfg.fundingAddress
      ? addressScriptHash(this.cfg.fundingAddress) ?? this.cfg.fundingAddress
      : rcpt.scriptHashHex;
    let funding;
    try {
      funding = await this.rpc.getUtxos(fundingSh);
    } catch (e) {
      return { ok: false, error: `getutxos failed: ${errMsg(e)}`, code: "node_error" };
    }
    const pick = this.selectUtxos(funding.utxos, target);
    if (!pick) {
      return {
        ok: false,
        error:
          `faucet funding wallet has insufficient test BLCH ` +
          `(need ${target} sat, have ${parseSats(funding.satoshis, "funding balance")} sat)`,
        code: "faucet_empty",
      };
    }

    // 4) Build the unsigned job and hand it to the signer.
    const changeAddr = this.cfg.changeAddress || this.cfg.fundingAddress;
    const job: PaymentJob = {
      network: "testnet",
      toAddress: rcpt.address ?? rcpt.scriptHashHex,
      // The script hashes are what a signer actually needs: `submit-tx` takes
      // `--pay <script-hash-hex>:<sat>`, never an address.
      toScriptHash: rcpt.scriptHashHex,
      changeScriptHash: changeAddr
        ? addressScriptHash(changeAddr) ?? changeAddr
        : fundingSh,
      fundingScriptHash: fundingSh,
      amountSats: this.cfg.amountSats,
      feeSats: this.cfg.feeSats,
      changeAddress: changeAddr || this.cfg.fundingAddress || rcpt.scriptHashHex,
      fundingAddress: this.cfg.fundingAddress || rcpt.scriptHashHex,
      selectedUtxos: pick.selected,
    };

    let signed;
    try {
      signed = await this.signer.buildSignedPayment(job);
    } catch (e) {
      return { ok: false, error: `signing failed: ${errMsg(e)}`, code: "signer_error" };
    }

    // 5) Broadcast — unless dry-run, in which case we return the signer's
    //    (possibly synthetic) txid without touching the network.
    if (this.cfg.dryRun) {
      const txid = signed.txid ?? syntheticTxid(signed.rawHex);
      return {
        ok: true,
        txid,
        amountSats: this.cfg.amountSats,
        toAddress: job.toAddress,
        scriptHash: rcpt.scriptHashHex,
        dryRun: true,
        signer: this.signer.kind,
      };
    }

    try {
      const txid = await this.rpc.sendRawTransaction(signed.rawHex);
      return {
        ok: true,
        txid,
        amountSats: this.cfg.amountSats,
        toAddress: job.toAddress,
        scriptHash: rcpt.scriptHashHex,
        dryRun: false,
        signer: this.signer.kind,
      };
    } catch (e) {
      const code = e instanceof RpcError ? "broadcast_rejected" : "node_error";
      return { ok: false, error: `sendrawtransaction failed: ${errMsg(e)}`, code };
    }
  }
}

function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

function syntheticTxid(rawHex: string): string {
  // Only used in dry-run when the stub signer did not supply a txid.
  let h = 2166136261 >>> 0;
  for (let i = 0; i < rawHex.length; i++) {
    h = (h ^ rawHex.charCodeAt(i)) >>> 0;
    h = (h * 16777619) >>> 0;
  }
  return h.toString(16).padStart(8, "0").repeat(8).slice(0, 64);
}
