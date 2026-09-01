// SPDX-License-Identifier: MIT OR Apache-2.0
// Entry point: wire config -> transport -> rpc -> signer -> faucet -> server.

import { loadConfig } from "./config.js";
import { HttpTransport, RpcClient, StubTransport, type JsonRpcTransport } from "./rpc.js";
import { ExternalCommandSigner, StubSigner, type Signer } from "./signer.js";
import { Faucet } from "./faucet.js";
import { RateLimiter } from "./ratelimit.js";
import { createFaucetServer } from "./server.js";
import { addressScriptHash, parseAddress } from "./address.js";

/**
 * Refuse to start rather than start wrong.
 *
 * Every check here is a fault that the running service would otherwise express
 * as "it quietly did the wrong thing with money". The faucet already refuses a
 * mainnet RECIPIENT (`faucet.ts`, `bloch1t` prefix + the node's own
 * `validateaddress`), but nothing checked the addresses it spends FROM, and
 * nothing checked the node it spends AGAINST. Those are the two that matter:
 * a mainnet funding address plus a mainnet RPC turns this into a service that
 * hands real coins to anonymous strangers, and the `network: "testnet"` field
 * in the payment job is advisory — it binds the external signer only if the
 * signer chooses to honour it.
 */
function preflight(cfg: ReturnType<typeof loadConfig>): void {
  const fatal: string[] = [];

  if (!cfg.dryRun) {
    // LIVE with the stub signer used to be a console.warn, then it broadcast
    // the literal bytes "deadbeef…" to a real node.
    if (!cfg.signerCmd) {
      fatal.push(
        "LIVE mode requires FAUCET_SIGNER_CMD. Without it the stub signer emits " +
          "placeholder bytes and every broadcast is garbage sent to a real node.",
      );
    }
    if (!cfg.fundingAddress) {
      fatal.push("LIVE mode requires FAUCET_FUNDING_ADDRESS.");
    }
    // The funding and change addresses decide whose coins move. A mainnet one
    // here is the whole hazard, and it was accepted silently as a bare string.
    for (const [name, value] of [
      ["FAUCET_FUNDING_ADDRESS", cfg.fundingAddress],
      ["FAUCET_CHANGE_ADDRESS", cfg.changeAddress],
    ] as const) {
      if (!value) continue;
      const parsed = parseAddress(value);
      if (!parsed) {
        fatal.push(`${name}=${value} is not a valid Bloch address.`);
      } else if (parsed.network !== "testnet") {
        fatal.push(
          `${name} is a ${parsed.network} address. This service must never be ` +
            "funded from mainnet: it pays anonymous requesters on demand.",
        );
      }
    }
  }

  if (fatal.length > 0) {
    for (const f of fatal) console.error(`[bloch-faucet] FATAL: ${f}`);
    process.exit(2);
  }
}

function main(): void {
  const cfg = loadConfig();
  preflight(cfg);

  const transport: JsonRpcTransport = cfg.dryRun
    ? new StubTransport(cfg.fundingAddress ? (addressScriptHash(cfg.fundingAddress) ?? "00".repeat(32)) : "00".repeat(32))
    : new HttpTransport(cfg.rpcUrl, cfg.rpcApiKey);

  const signer: Signer =
    cfg.signerCmd && !cfg.dryRun ? new ExternalCommandSigner(cfg.signerCmd) : new StubSigner();

  const rpc = new RpcClient(transport);
  const faucet = new Faucet(cfg, rpc, signer);
  const limiter = new RateLimiter(
    cfg.perAddressWindowMs,
    cfg.perIpWindowMs,
    cfg.perIpMax,
    cfg.globalWindowMs,
    cfg.globalMaxSats,
  );
  const server = createFaucetServer(cfg, faucet, limiter);

  server.listen(cfg.port, cfg.host, () => {
    console.log(`[bloch-faucet] TESTNET-ONLY reference faucet (SCAFFOLD, unaudited).`);
    console.log(`[bloch-faucet] listening on http://${cfg.host}:${cfg.port}`);
    console.log(`[bloch-faucet] mode: ${cfg.dryRun ? "DRY-RUN (stub RPC + stub signer, no broadcast)" : "LIVE"}`);
    console.log(`[bloch-faucet] signer: ${signer.kind}; rpc: ${cfg.dryRun ? "stub" : cfg.rpcUrl}`);
    console.log(
      `[bloch-faucet] policy: ${cfg.amountSats} sat per address per ` +
        `${cfg.perAddressWindowMs / 3_600_000} h; ${cfg.perIpMax} requests per IP per ` +
        `${cfg.perIpWindowMs / 3_600_000} h; global ceiling ${cfg.globalMaxSats} sat per ` +
        `${cfg.globalWindowMs / 3_600_000} h.`,
    );
    console.log(
      `[bloch-faucet] NOTE: limiter state is in-memory — a restart clears every cooldown.`,
    );
    console.log(`[bloch-faucet] Test BLCH has NO value. BLCH is not a security.`);
  });
}

main();
