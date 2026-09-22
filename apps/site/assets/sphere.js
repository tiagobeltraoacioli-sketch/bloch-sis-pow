// SPDX-License-Identifier: AGPL-3.0-or-later
// Interactive validator globe. Every Fibonacci-lattice point maps to one
// Genesis-4 validator and opens its detail page in the Bloch Explorer.
(function () {
  const canvas = document.getElementById('sphere');
  if (!canvas) return;

  const ctx = canvas.getContext('2d');
  const tooltip = document.getElementById('validator-sphere-tooltip');
  const status = document.getElementById('validator-sphere-status');
  const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const golden = Math.PI * (3 - Math.sqrt(5));
  const fallbackCount = 140;
  const explorerBase = 'https://blochl1.com/validators/';
  let dpr = Math.min(window.devicePixelRatio || 1, 2);
  let points = [];
  let projected = [];
  let total = fallbackCount;
  let active = null;
  let angle = 0;
  let hovered = null;
  let keyboardIndex = null;
  let pointerInside = false;

  function css(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  }

  function buildPoints(count) {
    total = count;
    points = Array.from({ length: count }, (_, index) => {
      const y = count === 1 ? 0 : 1 - (index / (count - 1)) * 2;
      const radius = Math.sqrt(Math.max(0, 1 - y * y));
      const theta = golden * index;
      return { index, x: Math.cos(theta) * radius, y, z: Math.sin(theta) * radius };
    });
    updateStatus();
    draw();
  }

  function updateStatus() {
    if (!status) return;
    status.textContent = active === null
      ? `${total} validators · select a point to inspect`
      : `${active} active · ${total} validators · select a point to inspect`;
  }

  function size() {
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    const width = canvas.clientWidth || 600;
    canvas.width = Math.round(width * dpr);
    canvas.height = Math.round(width * dpr);
  }

  function draw() {
    const width = canvas.width;
    const height = canvas.height;
    const radius = Math.min(width, height) * 0.38;
    const cx = width / 2;
    const cy = height / 2;
    const accent = css('--accent');
    const ink = css('--ink');
    const violet = css('--violet');
    const line = css('--line');
    const ca = Math.cos(angle);
    const sa = Math.sin(angle);
    const tilt = -0.42;
    const ct = Math.cos(tilt);
    const st = Math.sin(tilt);
    ctx.clearRect(0, 0, width, height);

    ctx.strokeStyle = line;
    ctx.lineWidth = dpr;
    ctx.beginPath();
    for (let i = 0; i <= 96; i += 1) {
      const a = (i / 96) * Math.PI * 2;
      const x = Math.cos(a);
      const z = Math.sin(a);
      const x2 = x * ca - z * sa;
      const z2 = x * sa + z * ca;
      const y2 = -z2 * st;
      const px = cx + x2 * radius;
      const py = cy + y2 * radius;
      if (i) ctx.lineTo(px, py); else ctx.moveTo(px, py);
    }
    ctx.closePath();
    ctx.stroke();

    projected = points.map((point) => {
      const x2 = point.x * ca - point.z * sa;
      const z2 = point.x * sa + point.z * ca;
      const y2 = point.y * ct - z2 * st;
      const z3 = point.y * st + z2 * ct;
      return { index: point.index, x: cx + x2 * radius, y: cy + y2 * radius, z: z3 };
    }).sort((a, b) => a.z - b.z);

    for (const point of projected) {
      const depth = (point.z + 1) / 2;
      const selected = point.index === hovered || point.index === keyboardIndex;
      ctx.globalAlpha = selected ? 1 : 0.22 + depth * 0.72;
      ctx.fillStyle = depth > 0.82 ? violet : accent;
      if (selected) {
        ctx.strokeStyle = ink;
        ctx.lineWidth = 1.5 * dpr;
        ctx.beginPath();
        ctx.arc(point.x, point.y, 9 * dpr, 0, Math.PI * 2);
        ctx.stroke();
      }
      ctx.beginPath();
      ctx.arc(point.x, point.y, (selected ? 4.2 : 1.25 + depth * 1.9) * dpr, 0, Math.PI * 2);
      ctx.fill();
    }
    ctx.globalAlpha = 1;

    const vx = 0.52;
    const vy = 0.62;
    const vz = 0.59;
    const x2 = vx * ca - vz * sa;
    const z2 = vx * sa + vz * ca;
    const y2 = vy * ct - z2 * st;
    ctx.strokeStyle = ink;
    ctx.lineWidth = 2 * dpr;
    ctx.lineCap = 'round';
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.lineTo(cx + x2 * radius, cy + y2 * radius);
    ctx.stroke();
    ctx.fillStyle = accent;
    ctx.beginPath();
    ctx.arc(cx + x2 * radius, cy + y2 * radius, 5 * dpr, 0, Math.PI * 2);
    ctx.fill();
  }

  function nearest(event) {
    const rect = canvas.getBoundingClientRect();
    const x = (event.clientX - rect.left) * dpr;
    const y = (event.clientY - rect.top) * dpr;
    const maxDistance = 15 * dpr;
    let match = null;
    let distance = maxDistance * maxDistance;
    for (const point of projected) {
      const dx = point.x - x;
      const dy = point.y - y;
      const next = dx * dx + dy * dy;
      if (next < distance) {
        distance = next;
        match = point;
      }
    }
    return match;
  }

  function validatorUrl(index) {
    return `${explorerBase}${index}`;
  }

  function showTooltip(point) {
    if (!tooltip || !point) return;
    const canvasRect = canvas.getBoundingClientRect();
    const parentRect = canvas.parentElement.getBoundingClientRect();
    tooltip.textContent = `Validator v${point.index} · open in explorer`;
    tooltip.style.left = `${canvasRect.left - parentRect.left + point.x / dpr}px`;
    tooltip.style.top = `${canvasRect.top - parentRect.top + point.y / dpr}px`;
    tooltip.hidden = false;
  }

  function hideTooltip() {
    if (tooltip) tooltip.hidden = true;
  }

  canvas.addEventListener('pointerenter', () => { pointerInside = true; });
  canvas.addEventListener('pointerleave', () => {
    pointerInside = false;
    hovered = null;
    hideTooltip();
    draw();
  });
  canvas.addEventListener('pointermove', (event) => {
    if (event.pointerType === 'touch') return;
    const point = nearest(event);
    hovered = point ? point.index : null;
    canvas.style.cursor = point ? 'pointer' : 'grab';
    if (point) showTooltip(point); else hideTooltip();
    draw();
  });
  canvas.addEventListener('click', (event) => {
    const point = nearest(event);
    if (point) window.location.assign(validatorUrl(point.index));
  });
  canvas.addEventListener('focus', () => {
    keyboardIndex = keyboardIndex ?? 0;
    const point = projected.find((item) => item.index === keyboardIndex);
    showTooltip(point);
    draw();
  });
  canvas.addEventListener('blur', () => {
    keyboardIndex = null;
    hideTooltip();
    draw();
  });
  canvas.addEventListener('keydown', (event) => {
    if (!['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown', 'Enter', ' '].includes(event.key)) return;
    event.preventDefault();
    if (event.key === 'Enter' || event.key === ' ') {
      window.location.assign(validatorUrl(keyboardIndex ?? 0));
      return;
    }
    const direction = event.key === 'ArrowLeft' || event.key === 'ArrowUp' ? -1 : 1;
    keyboardIndex = ((keyboardIndex ?? 0) + direction + total) % total;
    const point = projected.find((item) => item.index === keyboardIndex);
    showTooltip(point);
    draw();
  });

  function frame() {
    if (!pointerInside && keyboardIndex === null) angle += 0.0022;
    draw();
    window.requestAnimationFrame(frame);
  }

  async function syncValidatorCount() {
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 5000);
    try {
      const response = await fetch('https://blochl1.com/rpc', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'getvalidatorcount', params: [] }),
        signal: controller.signal,
      });
      const body = await response.json();
      const count = Number(body && body.result && body.result.total);
      const activeCount = Number(body && body.result && body.result.active);
      if (Number.isInteger(count) && count > 0 && count <= 4096) {
        active = Number.isInteger(activeCount) ? activeCount : null;
        buildPoints(count);
      }
    } catch {
      // The fallback is the last verified network count; the globe remains usable.
    } finally {
      window.clearTimeout(timeout);
    }
  }

  buildPoints(fallbackCount);
  size();
  draw();
  if (!reduce) frame();
  syncValidatorCount();
  window.addEventListener('resize', () => { size(); draw(); });
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', draw);
})();
