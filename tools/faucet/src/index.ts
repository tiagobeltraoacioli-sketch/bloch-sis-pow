// SPDX-License-Identifier: MIT OR Apache-2.0
// Entry point: wire config -> transport -> rpc -> signer -> faucet -> server.

import { loadConfig } from "./config.js";
import { HttpTransport, RpcClient, StubTransport, type JsonRpcTransport } from "./rpc.js";
import { ExternalCommandSigner, StubSigner, type Signer } from "./signer.js";
import { Faucet } from "./faucet.js";
import { RateLimiter } from "./ratelimit.js";
import { createFaucetServer } from "./server.js";

function main(): void {
  const cfg = loadConfig();

  const transport: JsonRpcTransport = cfg.dryRun
    ? new StubTransport(cfg.fundingAddress || "bloch1t" + "0".repeat(48))
    : new HttpTransport(cfg.rpcUrl, cfg.rpcApiKey);

  const signer: Signer =
    cfg.signerCmd && !cfg.dryRun ? new ExternalCommandSigner(cfg.signerCmd) : new StubSigner();

  const rpc = new RpcClient(transport);
  const faucet = new Faucet(cfg, rpc, signer);
  const limiter = new RateLimiter(cfg.perAddressWindowMs, cfg.perIpWindowMs, cfg.perIpMax);
  const server = createFaucetServer(cfg, faucet, limiter);

  server.listen(cfg.port, cfg.host, () => {
    console.log(`[bloch-faucet] TESTNET-ONLY reference faucet (SCAFFOLD, unaudited).`);
    console.log(`[bloch-faucet] listening on http://${cfg.host}:${cfg.port}`);
    console.log(`[bloch-faucet] mode: ${cfg.dryRun ? "DRY-RUN (stub RPC + stub signer, no broadcast)" : "LIVE"}`);
    console.log(`[bloch-faucet] signer: ${signer.kind}; rpc: ${cfg.dryRun ? "stub" : cfg.rpcUrl}`);
    if (!cfg.dryRun && !cfg.signerCmd) {
      console.warn(`[bloch-faucet] WARNING: LIVE mode without FAUCET_SIGNER_CMD — broadcasts will fail.`);
    }
    console.log(`[bloch-faucet] Test BLCH has NO value. BLCH is not a security.`);
  });
}

main();
