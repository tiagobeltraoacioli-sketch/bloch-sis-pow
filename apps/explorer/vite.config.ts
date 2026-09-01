import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The client always POSTs JSON-RPC to a same-origin `/rpc`.
//  - In production, Cloudflare Pages runs `functions/rpc.js` (read-allowlist
//    passthrough) at that path.
//  - In dev there are no CF Functions, so we proxy `/rpc` straight to a local
//    Bloch node RPC (a read-only SSH tunnel, e.g. `ssh -L 16210:127.0.0.1:16210
//    ovh-bloch`). Override the target with VITE_RPC_TARGET if your tunnel uses a
//    different port.
const RPC_TARGET = process.env.VITE_RPC_TARGET || "http://127.0.0.1:16210";

// The Genesis-4 read upstream for `npm run dev`. An archival, never a
// validator: the node RPC has no auth or rate limiting and is served by the
// consensus thread itself.
const G4_TARGET = process.env.VITE_G4_TARGET || "http://139.180.166.5:8080";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5273,
    proxy: {
      "/rpc": {
        target: RPC_TARGET,
        changeOrigin: true,
        rewrite: () => "/",
      },
      // Genesis-4 reads. In production this path is `functions/g4.js`, which
      // fans out to the two archivals; in dev there are no CF Functions, so
      // point straight at one archival. This loses the `?node=` pinning that
      // two-node agreement needs — every pinned read lands on the same box.
      // `agree()` detects that (it compares the `x-bloch-node-index` the
      // Function stamps, which this proxy does not set) and reports "no
      // cross-check was possible" rather than a false agreement. So the
      // finality panels are honest in dev; they are just less informative.
      "/g4": {
        target: G4_TARGET,
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
