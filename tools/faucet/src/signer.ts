// SPDX-License-Identifier: MIT OR Apache-2.0
// Signing seam.
//
// The faucet NEVER holds a private key or reimplements Bloch's hybrid
// Falcon-1024 ‖ ML-DSA-65 signing + stratum serialisation. Instead it builds an
// unsigned "payment job" and hands it to a Signer that owns the key material.
//
//   * ExternalCommandSigner — spawns the operator-configured FAUCET_SIGNER_CMD
//     (e.g. the reference `bloch-wallet`), passing the job as JSON on stdin and
//     reading the signed raw-tx hex from stdout. This is the real path.
//   * StubSigner — for dry-run/offline builds. Produces a deterministic
//     placeholder hex; it is NOT a valid transaction and must never be
//     broadcast to a real node.

import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import type { Utxo } from "./rpc.js";

export interface PaymentJob {
  network: "testnet";
  toAddress: string;
  amountSats: number;
  feeSats: number;
  changeAddress: string;
  fundingAddress: string;
  selectedUtxos: Utxo[];
}

export interface SignerResult {
  rawHex: string;
  /** Optional: some signers can also return the txid they computed. */
  txid?: string;
}

export interface Signer {
  readonly kind: string;
  buildSignedPayment(job: PaymentJob): Promise<SignerResult>;
}

/**
 * Real signer: delegates the entire build+sign step to an external command.
 *
 * Contract with the command (documented in README):
 *   stdin  <- JSON.stringify(PaymentJob)
 *   stdout -> either raw signed tx hex, or a JSON object {"rawHex": "...", "txid?": "..."}
 *   exit 0 on success; non-zero => error (stderr surfaced)
 */
export class ExternalCommandSigner implements Signer {
  readonly kind = "external-command";
  constructor(private readonly cmd: string) {}

  buildSignedPayment(job: PaymentJob): Promise<SignerResult> {
    return new Promise((resolve, reject) => {
      // Run via the shell so operators can configure e.g. "bloch-wallet faucet-sign".
      const child = spawn(this.cmd, { shell: true, stdio: ["pipe", "pipe", "pipe"] });
      let out = "";
      let err = "";
      child.stdout.on("data", (d) => (out += d.toString()));
      child.stderr.on("data", (d) => (err += d.toString()));
      child.on("error", (e) => reject(new Error(`signer spawn failed: ${e.message}`)));
      child.on("close", (code) => {
        if (code !== 0) {
          reject(new Error(`signer exited ${code}: ${err.trim() || "no stderr"}`));
          return;
        }
        const trimmed = out.trim();
        try {
          const parsed = JSON.parse(trimmed) as SignerResult;
          if (parsed && typeof parsed.rawHex === "string") {
            resolve(parsed);
            return;
          }
        } catch {
          /* not JSON — treat stdout as raw hex */
        }
        if (/^[0-9a-fA-F]+$/.test(trimmed) && trimmed.length > 0) {
          resolve({ rawHex: trimmed.toLowerCase() });
        } else {
          reject(new Error("signer produced neither raw hex nor {rawHex} JSON"));
        }
      });
      child.stdin.write(JSON.stringify(job));
      child.stdin.end();
    });
  }
}

/**
 * Dry-run placeholder. Deterministic, clearly-not-real bytes. Used when no
 * FAUCET_SIGNER_CMD is configured so the faucet flow is still demonstrable.
 */
export class StubSigner implements Signer {
  readonly kind = "stub-dry-run";
  async buildSignedPayment(job: PaymentJob): Promise<SignerResult> {
    const digest = createHash("sha3-256")
      .update(JSON.stringify(job))
      .digest("hex");
    // Prefix with a recognisable marker so nobody mistakes this for a real tx.
    const rawHex = "deadbeef" + digest + digest;
    return { rawHex };
  }
}
