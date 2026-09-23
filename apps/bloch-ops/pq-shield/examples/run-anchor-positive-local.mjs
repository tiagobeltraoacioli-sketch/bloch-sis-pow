// Build the checked-out Rust reference service, run it on an ephemeral loopback
// port, exercise disposable PQ signatures, and always stop our service process.
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const manifest = fileURLToPath(new URL('../../../../services/pq-shield-api/Cargo.toml', import.meta.url));
const check = fileURLToPath(new URL('./anchor-positive-check.mjs', import.meta.url));
const targetDir = join(tmpdir(), 'pq-shield-anchor-service-build');

function freeLoopbackPort() {
  return new Promise((resolve, reject) => {
    const socket = createServer();
    socket.once('error', reject);
    socket.listen(0, '127.0.0.1', () => {
      const { port } = socket.address();
      socket.close(() => resolve(port));
    });
  });
}

function runCheck(url) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [check], {
      stdio: 'inherit', env: { ...process.env, PQ_SHIELD_TEST_URL: url },
    });
    child.once('error', reject);
    child.once('exit', (code, signal) => code === 0 ? resolve() : reject(
      new Error(`Anchor check exited ${code ?? signal}`)));
  });
}

const buildEnv = { ...process.env, CARGO_TARGET_DIR: targetDir };
execFileSync('cargo', ['build', '--quiet', '--manifest-path', manifest], {
  env: buildEnv, stdio: 'inherit', timeout: 300_000,
});
const port = await freeLoopbackPort();
const url = `http://127.0.0.1:${port}`;
const binary = join(targetDir, 'debug', process.platform === 'win32' ? 'pq-shield-api.exe' : 'pq-shield-api');
const service = spawn(binary, [], {
  env: { ...process.env, PQ_SHIELD_BIND: `127.0.0.1:${port}` },
  stdio: ['ignore', 'ignore', 'pipe'],
});
let serviceError = '';
service.stderr.on('data', chunk => { serviceError += chunk.toString().slice(0, 4096); });

try {
  const deadline = Date.now() + 15_000;
  let ready = false;
  while (Date.now() < deadline) {
    assert.equal(service.exitCode, null, `Local service exited early: ${serviceError}`);
    try {
      const response = await fetch(`${url}/health`, { signal: AbortSignal.timeout(1000) });
      const body = await response.json();
      if (response.ok && body.status === 'ok' && body.service === 'pq-shield-api') {
        ready = true;
        break;
      }
    } catch { /* Service is still starting. */ }
    await new Promise(resolve => setTimeout(resolve, 200));
  }
  assert.ok(ready, `Local service did not become healthy: ${serviceError}`);
  await runCheck(url);
} finally {
  if (service.exitCode === null) {
    service.kill('SIGTERM');
    await Promise.race([
      new Promise(resolve => service.once('exit', resolve)),
      new Promise(resolve => setTimeout(resolve, 2000)),
    ]);
    if (service.exitCode === null) service.kill('SIGKILL');
  }
}
