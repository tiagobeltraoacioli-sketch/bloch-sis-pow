// SPDX-License-Identifier: MIT OR Apache-2.0
// Entry point: wire config -> transport -> rpc -> signer -> faucet -> server.

import { loadConfig } from "./config.js";
import { HttpTransport, RpcClient, StubTransport, type JsonRpcTransport } from "./rpc.js";
import { ExternalCommandSigner, StubSigner, type Signer } from "./signer.js";
import { Faucet } from "./faucet.js";
import { RateLimiter } from "./ratelimit.js";
import { createFaucetServer } from "./server.js";

/**
 * Refuse to start rather than start wrong.
 *
 * Every check here is a fault that the running service would otherwise express
 * as "it quietly did the wrong thing with money".
 *
 * ## What replaced the address-prefix check, and why it is stronger
 *
 * This function used to require `FAUCET_FUNDING_ADDRESS` to parse as a
 * `bloch1t…` testnet address, on the theory that a mainnet-shaped string could
 * not name mainnet coins. That check has been removed, and NOT because the
 * hazard went away — it is the whole hazard: a mainnet funding source plus a
 * mainnet RPC turns this into a service that hands real coins to anonymous
 * strangers.
 *
 * It was removed because it never actually checked that. It inspected a
 * STRING, in isolation from `FAUCET_RPC_URL`; a `bloch1t…` prefix says nothing
 * whatsoever about which chain is at the other end of the socket, and on
 * Genesis-4 the funding key does not have an address form at all, so the check
 * could only ever be satisfied by a value that was already wrong.
 *
 * What is checked instead: the node is asked for its GENESIS BLOCK ID and it
 * must equal `FAUCET_EXPECT_GENESIS_BLOCK_ID`. That binds the service to one
 * specific chain — the funding hash, the RPC, and the network are now verified
 * against each other rather than each alone — and it fails closed on a
 * repointed URL, a reset testnet, and a mainnet endpoint alike.
 */
async function preflight(cfg: ReturnType<typeof loadConfig>, rpc: RpcClient): Promise<void> {
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
    if (!cfg.fundingScriptHash) {
      fatal.push(
        "LIVE mode requires FAUCET_FUNDING_SCRIPT_HASH (64 hex, from `bloch-pos spendkey`).",
      );
    }
    if (!cfg.expectGenesisBlockId) {
      fatal.push(
        "LIVE mode requires FAUCET_EXPECT_GENESIS_BLOCK_ID — the 64-hex block_id of " +
          "the testnet's genesis block, from `getblockbyslot [0]`. Without it nothing " +
          "stops this service from being pointed at mainnet by a changed URL.",
      );
    } else {
      let seen: string;
      try {
        seen = await rpc.getGenesisBlockId();
      } catch (e) {
        fatal.push(
          `could not read the genesis block from ${cfg.rpcUrl}: ` +
            `${e instanceof Error ? e.message : String(e)}. The faucet will not spend ` +
            "against a node whose identity it could not confirm.",
        );
        seen = "";
      }
      if (seen && seen !== cfg.expectGenesisBlockId) {
        fatal.push(
          `${cfg.rpcUrl} is a DIFFERENT CHAIN: its genesis block is ${seen}, and this ` +
            `faucet is configured for ${cfg.expectGenesisBlockId}. Refusing to spend. ` +
            "If the testnet was reset, update FAUCET_EXPECT_GENESIS_BLOCK_ID deliberately.",
        );
      }
    }
  }

  if (fatal.length > 0) {
    for (const f of fatal) console.error(`[bloch-faucet] FATAL: ${f}`);
    process.exit(2);
  }
}

async function main(): Promise<void> {
  const cfg = loadConfig();

  const transport: JsonRpcTransport = cfg.dryRun
    ? new StubTransport(cfg.fundingScriptHash || "00".repeat(32))
    : new HttpTransport(cfg.rpcUrl, cfg.rpcApiKey);

  const signer: Signer =
    cfg.signerCmd && !cfg.dryRun ? new ExternalCommandSigner(cfg.signerCmd) : new StubSigner();

  const rpc = new RpcClient(transport);
  // Preflight needs the RPC client, so it runs after wiring and before the
  // listener: nothing can reach `drip()` until this has passed.
  await preflight(cfg, rpc);
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

main().catch((e) => {
  console.error(`[bloch-faucet] FATAL: ${e instanceof Error ? e.message : String(e)}`);
  process.exit(2);
});
