// SPDX-License-Identifier: MIT OR Apache-2.0
// The faucet's single-page web form. Self-contained HTML (no external assets),
// theme-aware, with the required honesty rails on-screen.

import type { FaucetConfig } from "./config.js";

export function renderForm(cfg: FaucetConfig): string {
  const amt = (cfg.amountSats / 1e8).toString();
  const mode = cfg.dryRun ? "DRY-RUN (no broadcast)" : "LIVE (testnet node)";
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Bloch Testnet Faucet</title>
<style>
  :root { color-scheme: light dark; --fg:#111; --bg:#fafafa; --card:#fff; --muted:#666; --accent:#3a5bd9; --warn:#8a5a00; --warnbg:#fff6e0; }
  @media (prefers-color-scheme: dark) { :root { --fg:#eee; --bg:#15161a; --card:#1e2027; --muted:#9aa; --accent:#7f9cff; --warn:#ffd77a; --warnbg:#2a2410; } }
  * { box-sizing:border-box; }
  body { font:15px/1.5 system-ui,sans-serif; color:var(--fg); background:var(--bg); margin:0; padding:2rem 1rem; }
  main { max-width:640px; margin:0 auto; }
  h1 { font-size:1.5rem; margin:0 0 .25rem; }
  .card { background:var(--card); border-radius:12px; padding:1.25rem; box-shadow:0 1px 3px rgba(0,0,0,.12); margin:1rem 0; }
  label { display:block; font-weight:600; margin-bottom:.4rem; }
  input[type=text] { width:100%; padding:.6rem .7rem; font:inherit; border:1px solid #8884; border-radius:8px; background:transparent; color:inherit; }
  button { margin-top:.9rem; padding:.6rem 1.1rem; font:inherit; font-weight:600; border:0; border-radius:8px; background:var(--accent); color:#fff; cursor:pointer; }
  button:disabled { opacity:.5; cursor:progress; }
  .muted { color:var(--muted); font-size:.9rem; }
  .rails { background:var(--warnbg); color:var(--warn); border-radius:10px; padding:.9rem 1rem; font-size:.86rem; }
  .rails ul { margin:.4rem 0 0; padding-left:1.1rem; }
  #out { margin-top:1rem; font-size:.92rem; white-space:pre-wrap; word-break:break-all; }
  code { background:#8882; padding:.1rem .3rem; border-radius:4px; }
  .badge { display:inline-block; font-size:.75rem; padding:.15rem .5rem; border-radius:999px; background:#8883; }
</style>
</head>
<body>
<main>
  <h1>Bloch Testnet Faucet <span class="badge">${mode}</span></h1>
  <p class="muted">Dispenses <strong>${amt} test BLCH</strong> to a testnet <code>bloch1t…</code> address.</p>

  <div class="rails">
    <strong>Read this. This is a SCAFFOLD / reference tool — unaudited, pre-production.</strong>
    <ul>
      <li>Testnet-only. Test BLCH has <strong>NO value</strong> — it is a faucet for a zero-security testnet.</li>
      <li>BLCH is not a security; nobody makes any value or investment claim.</li>
      <li>Bloch is ownerless and neutral; Postern Labs is one builder among many with no protocol privilege.</li>
      <li>Base mainnet-beta is experimental: relaxed PoW (k=4) is trivially forgeable and 51%-attackable.</li>
      <li>Reference tool, untested against a live network.</li>
    </ul>
  </div>

  <form class="card" id="f">
    <label for="addr">Testnet address</label>
    <input id="addr" name="address" type="text" placeholder="bloch1t…" autocomplete="off" spellcheck="false"/>
    <button id="btn" type="submit">Request ${amt} test BLCH</button>
    <div id="out"></div>
  </form>

  <p class="muted">JSON API: <code>POST /api/faucet</code> with <code>{"address":"bloch1t…"}</code>. Health: <code>GET /api/health</code>.</p>
</main>
<script>
  const f = document.getElementById('f');
  const out = document.getElementById('out');
  const btn = document.getElementById('btn');
  f.addEventListener('submit', async (e) => {
    e.preventDefault();
    const address = document.getElementById('addr').value.trim();
    out.textContent = ''; btn.disabled = true;
    try {
      const res = await fetch('/api/faucet', {
        method:'POST', headers:{'content-type':'application/json'},
        body: JSON.stringify({ address })
      });
      const j = await res.json();
      if (j.ok) {
        out.textContent = '✅ Sent ' + (j.amountSats/1e8) + ' test BLCH' +
          (j.dryRun ? ' (DRY-RUN, not broadcast)' : '') +
          '\ntxid: ' + j.txid;
      } else {
        out.textContent = '❌ ' + j.error + (j.code ? ' ['+j.code+']' : '');
      }
    } catch (err) {
      out.textContent = '❌ request failed: ' + err;
    } finally {
      btn.disabled = false;
    }
  });
</script>
</body>
</html>`;
}
