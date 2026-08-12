// SPDX-License-Identifier: AGPL-3.0-or-later
// The Bloch sphere — a Fibonacci lattice of points on a sphere, rotating
// slowly. Copied from the founder-approved preview (bloch-site.html).
// Static (single frame) under prefers-reduced-motion; redraws on theme change.
(function () {
  const c = document.getElementById('sphere');
  if (!c) return;
  const ctx = c.getContext('2d');
  const DPR = Math.min(window.devicePixelRatio || 1, 2);
  const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  function css(n) { return getComputedStyle(document.documentElement).getPropertyValue(n).trim(); }

  // A Fibonacci lattice on the sphere: an actual even point distribution, not
  // scattered dots — the structure is the subject.
  const N = 520;
  const pts = [];
  const golden = Math.PI * (3 - Math.sqrt(5));
  for (let i = 0; i < N; i++) {
    const y = 1 - (i / (N - 1)) * 2;
    const r = Math.sqrt(Math.max(0, 1 - y * y));
    const th = golden * i;
    pts.push([Math.cos(th) * r, y, Math.sin(th) * r]);
  }

  function size() {
    const w = c.clientWidth || 600;
    c.width = w * DPR; c.height = w * DPR;
  }

  let t = 0;
  function draw() {
    const W = c.width, H = c.height, R = Math.min(W, H) * 0.38;
    const cx = W / 2, cy = H / 2;
    const accent = css('--accent'), ink = css('--ink'), violet = css('--violet'), line = css('--line');
    ctx.clearRect(0, 0, W, H);

    const ca = Math.cos(t), sa = Math.sin(t);
    const tilt = -0.42, ct = Math.cos(tilt), st = Math.sin(tilt);

    // equator, drawn behind
    ctx.strokeStyle = line; ctx.lineWidth = 1 * DPR;
    ctx.beginPath();
    for (let i = 0; i <= 96; i++) {
      const a = (i / 96) * Math.PI * 2;
      let x = Math.cos(a), z = Math.sin(a), y = 0;
      const x2 = x * ca - z * sa, z2 = x * sa + z * ca;
      const y2 = y * ct - z2 * st;
      const X = cx + x2 * R, Y = cy + y2 * R;
      i ? ctx.lineTo(X, Y) : ctx.moveTo(X, Y);
    }
    ctx.closePath(); ctx.stroke();

    const proj = pts.map(([x, y, z]) => {
      const x2 = x * ca - z * sa, z2 = x * sa + z * ca;
      const y2 = y * ct - z2 * st, z3 = y * st + z2 * ct;
      return [cx + x2 * R, cy + y2 * R, z3];
    }).sort((a, b) => a[2] - b[2]);

    for (const [X, Y, Z] of proj) {
      const depth = (Z + 1) / 2;               // 0 back .. 1 front
      ctx.globalAlpha = 0.16 + depth * 0.72;
      ctx.fillStyle = depth > 0.86 ? violet : accent;
      ctx.beginPath();
      ctx.arc(X, Y, (0.9 + depth * 1.7) * DPR, 0, Math.PI * 2);
      ctx.fill();
    }
    ctx.globalAlpha = 1;

    // state vector
    const vx = 0.52, vy = 0.62, vz = 0.59;
    const x2 = vx * ca - vz * sa, z2 = vx * sa + vz * ca;
    const y2 = vy * ct - z2 * st;
    ctx.strokeStyle = ink; ctx.lineWidth = 2 * DPR; ctx.lineCap = 'round';
    ctx.beginPath(); ctx.moveTo(cx, cy); ctx.lineTo(cx + x2 * R, cy + y2 * R); ctx.stroke();
    ctx.fillStyle = accent;
    ctx.beginPath(); ctx.arc(cx + x2 * R, cy + y2 * R, 5 * DPR, 0, Math.PI * 2); ctx.fill();
  }

  function frame() { t += 0.0022; draw(); requestAnimationFrame(frame); }
  size(); draw();
  if (!reduce) frame();
  window.addEventListener('resize', () => { size(); draw(); });
  matchMedia('(prefers-color-scheme: dark)').addEventListener('change', draw);
})();
