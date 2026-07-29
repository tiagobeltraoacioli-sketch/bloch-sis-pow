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
    },
  },
  build: {
    target: "es2020",
    sourcemap: false,
  },
});
