//! Self-contained web dashboard — zero external assets, hand-rolled
//! HTTP (GET only). Routes:
//!
//!   GET /           → HTML dashboard (inline CSS/JS, polls /api/stats)
//!   GET /api/stats  → JSON snapshot of the pool state
//!
//! The honesty banner is part of the page, not a footnote: this pool is
//! a reference for coordination/testing on a network whose coin is
//! worth nothing by design, solo mining is the default, and any pool
//! nearing majority hashrate is a 51%-attack vector.

use std::sync::Arc;

use log::info;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::state::PoolState;

/// RFC 9116 security.txt, served at /.well-known/security.txt so researchers
/// have a clear disclosure path (Cloudflare Security Insights flagged its
/// absence on this origin). NOTE: refresh `Expires` before it lapses; a stale
/// Expires makes the file non-compliant. Not signed here — cross-check the
/// contact out of band (an OpenPGP/minisign clear-sign is a follow-up).
const SECURITY_TXT: &str = "\
Contact: mailto:tiagobeltraoacioli@gmail.com\n\
Expires: 2027-01-11T00:00:00.000Z\n\
Preferred-Languages: en, pt-BR\n\
Policy: https://posternlabs.com/SECURITY.md\n\
Canonical: https://posternpool.com/.well-known/security.txt\n\
";

pub async fn run(pool: Arc<PoolState>) -> std::io::Result<()> {
    let listener = TcpListener::bind(&pool.cfg.dashboard).await?;
    info!("dashboard: http://{}", pool.cfg.dashboard);

    loop {
        let (mut socket, _) = listener.accept().await?;
        let pool2 = pool.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            // Slowloris guard: a client that connects and sends nothing
            // must not pin a task + fd forever (stratum has the same
            // guard via its idle timeout).
            let n = match tokio::time::timeout(
                std::time::Duration::from_secs(5),
                socket.read(&mut buf),
            ).await {
                Ok(Ok(n)) if n > 0 => n,
                _ => return,
            };
            let head = String::from_utf8_lossy(&buf[..n]);
            let path = head.split_whitespace().nth(1).unwrap_or("/");

            let (status, ctype, body) = match path {
                "/api/stats" => ("200 OK", "application/json", stats_json(&pool2).to_string()),
                "/" | "/index.html" => ("200 OK", "text/html; charset=utf-8", html_page()),
                "/.well-known/security.txt" =>
                    ("200 OK", "text/plain; charset=utf-8", SECURITY_TXT.to_string()),
                _ => ("404 Not Found", "text/plain", "not found".to_string()),
            };

            // Security headers on every response. posternpool.com is served
            // DNS-only (not behind Cloudflare's proxy), so these must live at
            // the origin — they address the Cloudflare Security Insights
            // findings (missing HSTS, missing security.txt) here. The app sits
            // behind Fly's TLS-terminating edge, so HSTS rides back over HTTPS
            // (browsers ignore it over plain HTTP). The dashboard page uses
            // inline CSS/JS and fetches /api/stats same-origin, hence the CSP.
            let resp = format!(
                "HTTP/1.1 {status}\r\n\
                 Content-Type: {ctype}\r\n\
                 Content-Length: {len}\r\n\
                 X-Content-Type-Options: nosniff\r\n\
                 X-Frame-Options: DENY\r\n\
                 Referrer-Policy: no-referrer\r\n\
                 Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n\
                 Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\n\
                 Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=(), usb=()\r\n\
                 Connection: close\r\n\r\n\
                 {body}",
                status = status, ctype = ctype, len = body.len(), body = body,
            );
            let _ = socket.write_all(resp.as_bytes()).await;
            let _ = socket.shutdown().await;
        });
    }
}

fn stats_json(pool: &Arc<PoolState>) -> Value {
    let ledger = pool.ledger.lock();
    let sessions = pool.sessions.lock();
    let job = pool.current_job();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default().as_secs();

    // Estimated split if a block were found right now (PPLNS window).
    // Sat amounts serialize as STRINGS throughout /api/stats: JS
    // numbers lose exactness past 2^53, and an honesty tool must not
    // do approximate arithmetic on debts (weight already does this).
    let contribs = ledger.window_contributions();
    let reward = job.as_ref().map(|j| j.reward_sat).unwrap_or(0);
    let est = crate::payout::split_reward(&contribs, reward, ledger.fee_bps);
    let est_map: Value = est.miners.iter()
        .map(|(a, v)| (a.clone(), json!(v.to_string())))
        .collect::<serde_json::Map<String, Value>>()
        .into();

    let miners: Vec<Value> = ledger.miners.iter().map(|(addr, st)| json!({
        "address":          addr,
        "shares":           st.shares,
        "weight":           st.weight.to_string(),
        "last_share_unix":  st.last_share_unix,
        "credited_sat":     st.credited_sat.to_string(),
        "est_next_block_sat": est_map.get(addr).cloned().unwrap_or(json!("0")),
        // Withholding visibility: expected block finds implied by this
        // miner's accepted work vs blocks actually submitted. A large
        // expected count with zero finds is statistically anomalous.
        "expected_blocks":  st.expected_blocks,
        "blocks_found":     st.blocks_found,
    })).collect();

    let blocks: Vec<Value> = ledger.blocks_found.iter().rev().take(50).map(|b| json!({
        "height":        b.height,
        "hash":          b.hash_hex,
        "reward_sat":    b.reward_sat.to_string(),
        "unix":          b.unix,
        "status":        b.status.as_str(),
        "pool_take_sat": b.pool_take_sat.to_string(),
        "paid_miners":   b.payouts.len(),
    })).collect();

    use crate::shares::BlockStatus;
    let count = |st: BlockStatus| ledger.blocks_found.iter()
        .filter(|b| b.status == st).count();

    // Honest luck + share-of-network. Network rate is derived from the
    // block target and the 30 s consensus spacing — a rough estimate,
    // labeled as such. It exists so THIS pool can see itself approach
    // the 51% line the banner warns about.
    let pool_rate = ledger.est_work_rate(600);
    let net_rate = job.as_ref()
        .map(|j| crate::shares::work_from_bits(j.bits) as f64
            / bloch_crypto::core::TARGET_BLOCK_TIME as f64)
        .unwrap_or(0.0);
    let luck_pct = if ledger.expected_blocks > 0.0 {
        json!(ledger.blocks_found.len() as f64 / ledger.expected_blocks * 100.0)
    } else {
        Value::Null
    };

    json!({
        "pool": {
            "address":      pool.cfg.pool_address,
            "fee_bps":      ledger.fee_bps,
            "share_bits":   format!("{:08x}", ledger.share_bits),
            "pplns_window": pool.cfg.pplns_window,
            "confirm_depth": pool.cfg.confirm_depth,
            "uptime_secs":  now.saturating_sub(ledger.started_unix),
            "node_rpc":     pool.upstream.url(),
            // Node health: seconds since the last successful template
            // (null = never). New miners get no work once stale.
            "template_age_secs": match pool.template_age_secs() {
                u64::MAX => Value::Null,
                age => json!(age),
            },
            "node_healthy": pool.template_fresh(),
        },
        "work": {
            "height":            job.as_ref().map(|j| j.height).unwrap_or(0),
            "block_bits":        job.as_ref().map(|j| format!("{:08x}", j.bits)).unwrap_or_default(),
            "block_reward_sat":  reward.to_string(),
            // candidates/s — one candidate = seed expansion + SIS residual
            // gate + SHAKE-256 aux hash. NOT bare hash/s; see shares.rs.
            "est_candidates_per_sec_10m": pool_rate,
        },
        "luck": {
            // expected = Σ share_weight / block_work at each share's bits.
            "expected_blocks":  ledger.expected_blocks,
            "found_blocks":     ledger.blocks_found.len(),
            "luck_pct":         luck_pct,
            "est_network_candidates_per_sec": net_rate,
            // Rough pool fraction of network hashrate (10 m pool rate
            // over target-spacing-implied network rate).
            "est_pool_share_pct": if net_rate > 0.0 {
                json!(pool_rate / net_rate * 100.0)
            } else { Value::Null },
        },
        "totals": {
            "connected_miners": sessions.len(),
            "shares_accepted":  ledger.shares_total,
            "shares_stale":     ledger.stale_total,
            "blocks_found":     ledger.blocks_found.len(),
            "blocks_pending":   count(BlockStatus::Pending),
            "blocks_confirmed": count(BlockStatus::Confirmed),
            "blocks_orphaned":  count(BlockStatus::Orphaned),
            "blocks_rejected":  ledger.blocks_rejected,
        },
        "miners": miners,
        "blocks": blocks,
    })
}

fn html_page() -> String {
    HTML.to_string()
}

const HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>&#9670; bloch-pool — reference pool</title>
<style>
  :root {
    --bg: #0c1116; --panel: #131a21; --line: #1f2a33;
    --text: #d7e1e8; --dim: #7b8a94; --teal: #2dd4bf; --warn: #f0b429;
  }
  * { box-sizing: border-box; margin: 0; }
  body { background: var(--bg); color: var(--text);
         font: 15px/1.5 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
         padding: 24px; max-width: 1080px; margin: 0 auto; }
  h1 { font-size: 20px; letter-spacing: .04em; }
  h1 .diamond { color: var(--teal); }
  h2 { font-size: 13px; text-transform: uppercase; letter-spacing: .12em;
       color: var(--dim); margin: 28px 0 10px; }
  .banner { border: 1px solid var(--warn); background: rgba(240,180,41,.07);
            border-radius: 8px; padding: 14px 16px; margin: 18px 0;
            font-size: 13.5px; }
  .banner strong { color: var(--warn); }
  .banner ul { margin: 8px 0 0 18px; }
  .banner li { margin: 3px 0; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
          gap: 10px; }
  .tile { background: var(--panel); border: 1px solid var(--line);
          border-radius: 8px; padding: 12px 14px; }
  .tile .k { font-size: 11px; color: var(--dim); text-transform: uppercase;
             letter-spacing: .1em; }
  .tile .v { font-size: 20px; margin-top: 4px; color: var(--teal); }
  .tile .v.plain { color: var(--text); }
  table { width: 100%; border-collapse: collapse; background: var(--panel);
          border: 1px solid var(--line); border-radius: 8px; overflow: hidden;
          font-size: 13px; }
  th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid var(--line); }
  th { color: var(--dim); font-weight: normal; text-transform: uppercase;
       font-size: 11px; letter-spacing: .1em; }
  tr:last-child td { border-bottom: none; }
  td.addr { max-width: 340px; overflow: hidden; text-overflow: ellipsis;
            white-space: nowrap; }
  .empty { color: var(--dim); padding: 14px; }
  .scroll { overflow-x: auto; }
  footer { margin-top: 30px; color: var(--dim); font-size: 12px; }
  a { color: var(--teal); }
</style>
</head>
<body>
<h1><span class="diamond">&#9670;</span> bloch-pool <span style="color:var(--dim)">— open-source reference pool</span></h1>

<div class="banner">
  <strong>Read this before pointing hashrate here.</strong>
  <ul>
    <li><strong>Pools centralize what should be decentralized.</strong> A pool controlling
        &gt;51% of network hashrate <em>is</em> a 51%-attack vector. The healthy outcome is
        several independent small pools plus solo miners. This software is open source
        precisely so you can run your own — please do.</li>
    <li><strong>The coin is worth nothing by design.</strong> Bloch is mainnet-beta:
        unaudited, young, 51%-attackable. This pool exists for coordination and testing,
        not profit.</li>
    <li><strong>Solo mining is the default</strong> (<code>bloch --mine</code>) and needs
        no pool. Pooling is opt-in.</li>
    <li><strong>The PoW is not lattice-hard.</strong> Bloch-SIS-PoW is SHAKE-256
        cumulative-work hashcash with a Module-SIS <em>structural gate</em>; shares are
        plain hash-difficulty shares. No lattice bit-security number attaches to it.</li>
  </ul>
</div>

<h2>Pool</h2>
<div class="grid" id="tiles"></div>

<h2>Honest luck (withholding / bad luck is visible here, not hidden)</h2>
<div class="grid" id="luck"></div>

<h2>Miners (per-address shares, credits, expected vs found blocks)</h2>
<div class="scroll"><div id="miners"></div></div>

<h2>Blocks found</h2>
<div class="scroll"><div id="blocks"></div></div>

<footer>
  PPLNS payout: block reward (subsidy + fees) minus the pool fee
  (<span id="fee">?</span>) is split pro-rata over the last-N-shares window,
  snapshotted at the moment of the find.
  Credits are <em>provisional</em> until the block is canonical at the
  configured confirmation depth; an orphaned/red block's credits are dropped,
  never booked. Credits are ledger entries (journaled to disk, replayed on
  restart); disbursement is an operator wallet action.
  On monthly vesting boundaries the coinbase additionally carries the
  consensus-mandated founder vesting tranche — chain consensus, not a pool fee.
  Reference software — unaudited, not production.
</footer>

<script>
function fmtSat(v) { return (Number(v) / 1e8).toFixed(4) + " BLOCH"; }
function fmtRate(v) {
  if (v > 1e6) return (v/1e6).toFixed(2) + " Mcand/s";
  if (v > 1e3) return (v/1e3).toFixed(2) + " kcand/s";
  return v.toFixed(1) + " cand/s";
}
function tile(k, v, plain) {
  return '<div class="tile"><div class="k">' + k + '</div><div class="v' +
         (plain ? ' plain' : '') + '">' + v + '</div></div>';
}
function table(headers, rows) {
  if (!rows.length) return '<div class="empty">none yet</div>';
  return '<table><tr>' + headers.map(h => '<th>' + h + '</th>').join('') + '</tr>' +
    rows.map(r => '<tr>' + r.map(c => '<td class="addr">' + c + '</td>').join('') + '</tr>').join('') +
    '</table>';
}
async function refresh() {
  try {
    const s = await (await fetch('/api/stats')).json();
    document.getElementById('tiles').innerHTML =
      tile('height (next block)', s.work.height) +
      tile('pool work rate (10m)', fmtRate(s.work.est_candidates_per_sec_10m)) +
      tile('connected miners', s.totals.connected_miners) +
      tile('shares accepted', s.totals.shares_accepted, true) +
      tile('blocks (conf/pend/orph)', s.totals.blocks_confirmed + ' / ' +
           s.totals.blocks_pending + ' / ' + s.totals.blocks_orphaned) +
      tile('block reward', fmtSat(s.work.block_reward_sat), true) +
      tile('pool fee', (s.pool.fee_bps / 100).toFixed(2) + ' %', true) +
      tile('share bits', s.pool.share_bits, true) +
      tile('node', s.pool.node_healthy ? 'healthy' :
           'UNREACHABLE (' + s.pool.template_age_secs + 's)', !s.pool.node_healthy);
    // Honest-luck panel: expected vs found makes both bad luck and
    // statistical block withholding visible; the share-of-network tile
    // turns into a warning as the pool approaches the 51% line.
    const luck = s.luck.luck_pct === null ? 'n/a (no work yet)'
                                          : s.luck.luck_pct.toFixed(1) + ' %';
    let share = 'n/a';
    let shareWarn = '';
    if (s.luck.est_pool_share_pct !== null) {
      const p = s.luck.est_pool_share_pct;
      share = p.toFixed(2) + ' %';
      if (p >= 40) {
        shareWarn = '<div class="banner"><strong>This pool is approaching a ' +
          'majority of network hashrate (' + share + ' est.).</strong> ' +
          'That makes it a 51%-attack vector. Move hashrate to another pool ' +
          'or solo mine — seriously.</div>';
      }
    }
    document.getElementById('luck').innerHTML =
      tile('expected blocks', s.luck.expected_blocks.toFixed(3), true) +
      tile('found blocks', s.luck.found_blocks) +
      tile('luck', luck) +
      tile('est. share of network', share) +
      tile('node-rejected submits', s.totals.blocks_rejected, true) +
      tile('confirm depth', s.pool.confirm_depth, true) +
      shareWarn;
    document.getElementById('fee').textContent = (s.pool.fee_bps / 100).toFixed(2) + '%';
    document.getElementById('miners').innerHTML = table(
      ['address', 'shares', 'credited (confirmed)', 'est. next block',
       'expected blocks', 'found'],
      s.miners.map(m => [m.address, m.shares, fmtSat(m.credited_sat),
                         fmtSat(m.est_next_block_sat),
                         m.expected_blocks.toFixed(3), m.blocks_found]));
    document.getElementById('blocks').innerHTML = table(
      ['height', 'hash', 'status', 'reward', 'miners paid', 'pool take'],
      s.blocks.map(b => [b.height, b.hash.slice(0, 20) + '…', b.status,
                         fmtSat(b.reward_sat), b.paid_miners,
                         fmtSat(b.pool_take_sat)]));
  } catch (e) { /* pool restarting; retry on next tick */ }
}
refresh();
setInterval(refresh, 3000);
</script>
</body>
</html>
"#;
