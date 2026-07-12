// SPDX-License-Identifier: MIT OR Apache-2.0
// Core faucet flow: validate a testnet address, select UTXOs from the funding
// wallet via getutxos, hand an unsigned job to the Signer, and broadcast the
// signed raw tx via sendrawtransaction.
//
// TESTNET-ONLY. The coins dispensed are test BLCH with NO value on a
// zero-security testnet.

import type { FaucetConfig } from "./config.js";
import { isTestnetAddress, parseAddress } from "./address.js";
import { RpcClient, RpcError, type Utxo } from "./rpc.js";
import type { PaymentJob, Signer } from "./signer.js";

export interface DripSuccess {
  ok: true;
  txid: string;
  amountSats: number;
  toAddress: string;
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

  /** Greedy coin selection: enough UTXOs to cover amount + fee. */
  private selectUtxos(utxos: Utxo[], target: number): { selected: Utxo[]; total: number } | null {
    const sorted = [...utxos].sort((a, b) => b.value - a.value);
    const selected: Utxo[] = [];
    let total = 0;
    for (const u of sorted) {
      selected.push(u);
      total += u.value;
      if (total >= target) return { selected, total };
    }
    return null;
  }

  async drip(toAddress: string): Promise<DripResult> {
    // 1) Local checksum + prefix check (must be testnet).
    const parsed = parseAddress(toAddress);
    if (!parsed) return { ok: false, error: "invalid or malformed address", code: "bad_address" };
    if (parsed.network !== "testnet" || !isTestnetAddress(toAddress)) {
      return { ok: false, error: "faucet is testnet-only; expected a bloch1t… address", code: "not_testnet" };
    }

    // 2) Ask the node too, when reachable (authoritative). Tolerate node-down.
    try {
      const v = await this.rpc.validateAddress(toAddress);
      if (!v.isvalid) return { ok: false, error: "node rejected address as invalid", code: "bad_address" };
      if (v.network !== "testnet") {
        return { ok: false, error: "node reports address is not testnet", code: "not_testnet" };
      }
    } catch (e) {
      if (!this.cfg.dryRun) {
        return { ok: false, error: `node validateaddress failed: ${errMsg(e)}`, code: "node_error" };
      }
      // dry-run: proceed on the local check alone.
    }

    if (!this.cfg.dryRun && this.cfg.fundingAddress === "") {
      return { ok: false, error: "FAUCET_FUNDING_ADDRESS is not configured", code: "misconfigured" };
    }

    const target = this.cfg.amountSats + this.cfg.feeSats;

    // 3) Fetch funding UTXOs.
    let funding;
    try {
      funding = await this.rpc.getUtxos(this.cfg.fundingAddress || toAddress);
    } catch (e) {
      return { ok: false, error: `getutxos failed: ${errMsg(e)}`, code: "node_error" };
    }
    const pick = this.selectUtxos(funding.utxos, target);
    if (!pick) {
      return {
        ok: false,
        error: `faucet funding wallet has insufficient test BLCH (need ${target} sat, have ${funding.satoshis} sat)`,
        code: "faucet_empty",
      };
    }

    // 4) Build the unsigned job and hand it to the signer.
    const job: PaymentJob = {
      network: "testnet",
      toAddress,
      amountSats: this.cfg.amountSats,
      feeSats: this.cfg.feeSats,
      changeAddress: this.cfg.changeAddress || this.cfg.fundingAddress || toAddress,
      fundingAddress: this.cfg.fundingAddress || toAddress,
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
        toAddress,
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
        toAddress,
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
