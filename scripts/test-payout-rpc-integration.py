#!/usr/bin/env python3
"""Real HTTP and child-process tests; synthetic chain state, no production RPC or keys."""
import contextlib
import http.server
import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import threading
import unittest

ROOT = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('fixtures', ROOT / 'test-verify-validator-payout.py')
f = importlib.util.module_from_spec(spec)
spec.loader.exec_module(f)
HELPER = pathlib.Path(os.environ.get('BLOCH_PAYOUT_HELPER', ROOT / 'verify-validator-payout.py')).resolve()


@contextlib.contextmanager
def server(node, mode='json'):
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            request = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            if mode == 'html':
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'<html>archival unavailable</html>')
                return
            if mode == 'redirect':
                self.send_response(307)
                self.send_header('Location', '/unexpected')
                self.end_headers()
                return
            result = node(request['method'], request['params'])
            payload = json.dumps({'jsonrpc': '2.0', 'id': request['id'], 'result': result}).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
    httpd = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield 'http://127.0.0.1:' + str(httpd.server_port) + '/'
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


class HTTPIntegration(unittest.TestCase):
    def invoke(self, a, b, output, *extra):
        env = os.environ.copy()
        # A broken ambient proxy must not affect explicitly local RPCs.
        env['http_proxy'] = env['HTTP_PROXY'] = 'http://127.0.0.1:1'
        env['no_proxy'] = env['NO_PROXY'] = ''
        return subprocess.run([sys.executable, str(HELPER), '--rpc-a', a, '--rpc-b', b,
                               '--withdrawal-txid', f.W, '--spend-txid', f.S,
                               '--destination', f.D, '--value-sat', '1000',
                               '--out', str(output), *extra],
                              env=env, capture_output=True, text=True, timeout=20)

    def test_success_records_exact_stdout_and_preserves_existing_report(self):
        first, second = f.Node(), f.Node()
        with tempfile.TemporaryDirectory() as directory, server(first) as a, server(second) as b:
            output = pathlib.Path(directory) / 'report.json'
            result = self.invoke(a, b, output)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(output.read_text(), result.stdout)
            report = json.loads(result.stdout)
            self.assertEqual(report['schema_version'], 1)
            self.assertEqual(report['approved_intent']['spend_txid'], f.S)
            self.assertEqual(report['attempts_used'], 1)
            self.assertIsNone(report['signed_transaction_inspection'])
            original = output.read_bytes()
            again = self.invoke(a, b, output)
            self.assertNotEqual(again.returncode, 0)
            self.assertEqual(again.stdout, '')
            self.assertEqual(output.read_bytes(), original)
            self.assertEqual(set(first.calls), {'getvalidatoradmission', 'getchaininfo', 'gettxstatus', 'gettxout'})

    def test_moving_head_recovers_over_real_http(self):
        first = f.Node(); first.advance = True
        with tempfile.TemporaryDirectory() as directory, server(first) as a, server(f.Node()) as b:
            result = self.invoke(a, b, pathlib.Path(directory) / 'report.json')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)['attempts_used'], 2)

    def test_pending_wrong_destination_html_and_redirect_never_create_report(self):
        for failure in ('pending', 'destination', 'html', 'redirect'):
            first = f.Node()
            if failure == 'pending': first.status[f.S] = {'status': 'pending'}
            if failure == 'destination': first.outputs[f.S]['utxo']['script_hash'] = f.W
            mode = failure if failure in ('html', 'redirect') else 'json'
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory, server(first, mode) as a, server(f.Node()) as b:
                output = pathlib.Path(directory) / 'report.json'
                result = self.invoke(a, b, output)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, '')
                self.assertIn('Not verified:', result.stderr)
                self.assertFalse(output.exists())

    def test_invalid_signed_file_stops_before_any_rpc(self):
        first, second = f.Node(), f.Node()
        with tempfile.TemporaryDirectory() as directory, server(first) as a, server(second) as b:
            output = pathlib.Path(directory) / 'report.json'
            result = self.invoke(a, b, output, '--signed-tx', str(pathlib.Path(directory) / 'missing.hex'),
                                 '--payout-bin', '/nonexistent/bloch-pos', '--validator', '71',
                                 '--input-value', '2000', '--withdrawal-script', f.W,
                                 '--base-fee', '10', '--epoch', '5000', '--max-fee', '1000')
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(first.calls + second.calls, [])
            self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
