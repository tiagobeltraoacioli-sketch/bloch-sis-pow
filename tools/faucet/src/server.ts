// SPDX-License-Identifier: MIT OR Apache-2.0
// HTTP server: serves the web form and a small JSON API over Node's stdlib http
// (no framework dependency).

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { isIP } from "node:net";
import { normalizeIp, type FaucetConfig } from "./config.js";
import type { Faucet } from "./faucet.js";
import type { RateLimiter } from "./ratelimit.js";
import { parseAddress, encodeAddress } from "./address.js";
import { renderForm } from "./web.js";

// L1M-02: X-Forwarded-For is honoured only when the TCP peer is a configured
// trusted proxy (cfg.trustedProxies), and then it is read FROM THE RIGHT: each
// trusted proxy APPENDS the address it accepted the connection from
// (nginx `$proxy_add_x_forwarded_for`), so the left-most entries are whatever
// the client typed and must never be used. Walking right-to-left and skipping
// our own proxies, the first other entry is the address our outermost trusted
// proxy actually saw. Before this fix the LEFT-most entry was used, so a client
// rotating a forged XFF value got a fresh per-IP bucket on every request.
// Missing header, all-proxy chain, or a non-IP entry → charge the TCP peer
// (one shared bucket for the proxy, fail closed).
export function clientIpFrom(
  remoteAddress: string | undefined,
  xff: string | string[] | undefined,
  trustedProxies: readonly string[],
): string {
  const peer = remoteAddress === undefined ? "unknown" : normalizeIp(remoteAddress);
  if (trustedProxies.length === 0 || !trustedProxies.includes(peer)) return peer;
  const joined = Array.isArray(xff) ? xff.join(",") : xff;
  if (typeof joined !== "string" || joined.length === 0) return peer;
  const hops = joined.split(",").map((h) => normalizeIp(h));
  for (let i = hops.length - 1; i >= 0; i--) {
    const hop = hops[i]!;
    if (trustedProxies.includes(hop)) continue;
    return isIP(hop) === 0 ? peer : hop;
  }
  return peer;
}

function clientIp(req: IncomingMessage, trustedProxies: readonly string[]): string {
  return clientIpFrom(req.socket.remoteAddress, req.headers["x-forwarded-for"], trustedProxies);
}

function json(res: ServerResponse, status: number, body: unknown): void {
  const s = JSON.stringify(body);
  res.writeHead(status, { "content-type": "application/json", "content-length": Buffer.byteLength(s) });
  res.end(s);
}

async function readBody(req: IncomingMessage, limit = 64 * 1024): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = "";
    let size = 0;
    req.on("data", (c) => {
      size += c.length;
      if (size > limit) {
        reject(new Error("body too large"));
        req.destroy();
        return;
      }
      data += c;
    });
    req.on("end", () => resolve(data));
    req.on("error", reject);
  });
}

export function createFaucetServer(cfg: FaucetConfig, faucet: Faucet, limiter: RateLimiter) {
  return createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://localhost");
    const ip = clientIp(req, cfg.trustedProxies);

    try {
      if (req.method === "GET" && url.pathname === "/") {
        const html = renderForm(cfg);
        res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
        res.end(html);
        return;
      }

      if (req.method === "GET" && url.pathname === "/api/health") {
        json(res, 200, { ok: true, service: "bloch-testnet-faucet", dryRun: cfg.dryRun });
        return;
      }

      if (req.method === "GET" && url.pathname === "/api/status") {
        json(res, 200, {
          service: "bloch-testnet-faucet",
          network: "testnet",
          dryRun: cfg.dryRun,
          amountSats: cfg.amountSats,
          feeSats: cfg.feeSats,
          perAddressWindowMs: cfg.perAddressWindowMs,
          perIpWindowMs: cfg.perIpWindowMs,
          perIpMax: cfg.perIpMax,
          rails: "SCAFFOLD/reference, unaudited, testnet-only; test BLCH has no value; BLCH is not a security.",
        });
        return;
      }

      if (req.method === "POST" && url.pathname === "/api/faucet") {
        const contentType = req.headers["content-type"]?.split(";")[0]?.trim().toLowerCase();
        if (contentType !== "application/json") {
          json(res, 415, { ok: false, error: "application/json required" });
          return;
        }
        // Browser forms cannot submit JSON. Also reject explicit cross-site
        // fetches while preserving the same-origin faucet form.
        if (req.headers["sec-fetch-site"] === "cross-site") {
          json(res, 403, { ok: false, error: "cross-site request refused" });
          return;
        }
        let address = "";
        try {
          const raw = await readBody(req);
          const parsed = raw ? (JSON.parse(raw) as { address?: string }) : {};
          address = (parsed.address ?? "").trim();
        } catch (e) {
          json(res, 400, { ok: false, error: `bad request body: ${e instanceof Error ? e.message : e}` });
          return;
        }
        if (!address) {
          json(res, 400, { ok: false, error: "missing 'address'", code: "bad_request" });
          return;
        }

        const parsedAddress = parseAddress(address);
        if (parsedAddress) address = encodeAddress(parsedAddress.hashHex, parsedAddress.network);

        // T-3 fix: reserve-then-confirm, not check-then-record. `reserve` is
        // fully synchronous (checks AND provisionally records the hit in one
        // call, before any `await` below), so no concurrent request for
        // this same address/IP can observe the pre-reservation state — that
        // is what actually closes the TOCTOU `check`+`record` had (see
        // ratelimit.ts's module comment for the full race).
        const reservedAt = Date.now();
        const decision = limiter.reserve(address, ip, reservedAt);
        if (!decision.allowed) {
          const retryS = Math.ceil((decision.retryAfterMs ?? 0) / 1000);
          res.setHeader("retry-after", String(retryS));
          json(res, 429, {
            ok: false,
            error: decision.reason ?? "rate limited",
            code: "rate_limited",
            retryAfterSeconds: retryS,
          });
          return;
        }

        // T-3 fix: `faucet.drip` itself throwing (not just returning
        // `{ ok: false }`) must ALSO release the reservation — the outer
        // catch below still reports the 500, but without this the
        // reservation would be silently stranded (this address/IP
        // permanently "in flight" until process restart).
        try {
          const result = await faucet.drip(address);
          if (result.ok) {
            // Reservation stands — the payment actually went out.
            json(res, 200, result);
          } else {
            // The drip did not pay out, so release the reservation — an
            // address must not be charged a cooldown (nor an IP a slot in
            // its window) for a request that sent no funds.
            limiter.release(address, ip, reservedAt);
            const status = result.code === "faucet_empty" || result.code === "node_error" ? 503 : 400;
            json(res, status, result);
          }
        } catch (e) {
          limiter.release(address, ip, reservedAt);
          throw e; // handled by the outer catch (500 + logged)
        }
        return;
      }

      json(res, 404, { ok: false, error: "not found" });
    } catch (e) {
      json(res, 500, { ok: false, error: `internal error: ${e instanceof Error ? e.message : e}` });
    }
  });
}
