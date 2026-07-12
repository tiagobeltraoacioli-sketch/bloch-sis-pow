// SPDX-License-Identifier: MIT OR Apache-2.0
// HTTP server: serves the web form and a small JSON API over Node's stdlib http
// (no framework dependency).

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { FaucetConfig } from "./config.js";
import type { Faucet } from "./faucet.js";
import type { RateLimiter } from "./ratelimit.js";
import { renderForm } from "./web.js";

// Only honor X-Forwarded-For when explicitly told we sit behind a trusted proxy
// (FAUCET_TRUST_PROXY=1). Otherwise a client can rotate the XFF header to forge a
// fresh source IP and bypass the per-IP rate limit — so we use the real socket
// peer by default.
const TRUST_PROXY = process.env["FAUCET_TRUST_PROXY"] === "1";

function clientIp(req: IncomingMessage): string {
  if (TRUST_PROXY) {
    const xff = req.headers["x-forwarded-for"];
    if (typeof xff === "string" && xff.length > 0) return xff.split(",")[0]!.trim();
  }
  return req.socket.remoteAddress ?? "unknown";
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
    const ip = clientIp(req);

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

        // Rate limit BEFORE doing work.
        const decision = limiter.check(address, ip);
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

        const result = await faucet.drip(address);
        if (result.ok) {
          limiter.record(address, ip);
          json(res, 200, result);
        } else {
          const status = result.code === "faucet_empty" || result.code === "node_error" ? 503 : 400;
          json(res, status, result);
        }
        return;
      }

      json(res, 404, { ok: false, error: "not found" });
    } catch (e) {
      json(res, 500, { ok: false, error: `internal error: ${e instanceof Error ? e.message : e}` });
    }
  });
}
