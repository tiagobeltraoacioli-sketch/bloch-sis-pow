import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";

// EXERCISING `/g4` LOCALLY. The finality page reads a same-origin `/g4`, which
// is a Cloudflare Pages Function (`functions/g4.js`) that asks both keyless
// archivals and reports whether they agreed. `vite dev` does not run Functions,
// so `/g4` 404s under `npm run dev`:
//
//   npm run build && npx wrangler pages dev dist   # runs the real Function
//
// Two other ways to look at the page without that:
//   - `?replay=stall|rewind|conflict` drives it from fixtures, no network at
//     all, banner-marked REPLAY throughout.
//   - the Function is a plain module and can be called directly:
//       node --input-type=module -e "const m=await import('./functions/g4.js'); \
//         console.log(await (await m.onRequestPost({request:new Request('http://x', \
//         {method:'POST',body:JSON.stringify({method:'getchaininfo'})}),env:{}})).json())"
//
// A dev middleware that ran the Function inside Vite was tried and removed:
// mounted either with or without a route prefix it hung, because Vite's own
// stack had taken the request before the handler saw it. A convenience that
// works only sometimes is worse than a documented command that always does.
//
// The client always POSTs JSON-RPC to a same-origin `/rpc`.
//  - In production, Cloudflare Pages runs `functions/rpc.js` (read-allowlist
//    passthrough) at that path.
//  - In dev there are no CF Functions, so we proxy `/rpc` straight to a local
//    Bloch node RPC (a read-only SSH tunnel, e.g. `ssh -L 16210:127.0.0.1:16210
//    ovh-bloch`). Override the target with VITE_RPC_TARGET if your tunnel uses a
//    different port.
const RPC_TARGET = process.env.VITE_RPC_TARGET || "http://127.0.0.1:16210";

/**
 * Run the `/g4` Pages Function in dev.
 *
 * Without this, the finality page can only be exercised in replay mode
 * locally: `/g4` exists solely as a Cloudflare Function, so `npm run dev`
 * would 404 it and the live path would never be looked at before deploy. The
 * Function is imported and invoked here rather than reimplemented, so the dev
 * server and production run the same corroboration logic — a second copy would
 * drift, and drift in this particular file means the page starts claiming two
 * nodes agreed when it never asked one of them.
 */
function g4Function(): Plugin {
  return {
    name: "g4-function-dev",
    configureServer(server) {
      server.middlewares.use("/g4", async (req, res) => {
        try {
          const chunks: Buffer[] = [];
          for await (const c of req) chunks.push(c as Buffer);
          const mod = await server.ssrLoadModule("/functions/g4.js");
          const request = new Request("http://local/g4", {
            method: req.method,
            headers: { "content-type": "application/json" },
            body: req.method === "POST" ? Buffer.concat(chunks) : undefined,
          });
          const out =
            req.method === "OPTIONS"
              ? await mod.onRequestOptions()
              : await mod.onRequestPost({ request, env: {} });
          res.statusCode = out.status;
          out.headers.forEach((v: string, k: string) => res.setHeader(k, v));
          res.end(Buffer.from(await out.arrayBuffer()));
        } catch (e: any) {
          res.statusCode = 500;
          res.end(JSON.stringify({ error: { message: String(e?.message ?? e) } }));
        }
      });
    },
  };
}

export default defineConfig({
  plugins: [react(), g4Function()],
  server: {
    port: 5273,
    proxy: {
      "/rpc": {
        target: RPC_TARGET,
        changeOrigin: true,
        rewrite: () => "/",
      },
    },
  },
  build: {
    target: "es2020",
    sourcemap: false,
  },
});
