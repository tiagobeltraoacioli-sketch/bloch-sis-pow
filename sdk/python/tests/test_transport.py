import unittest

from blochclient.client import BlochClient, _check_key_transport
from blochclient.errors import BlochTransportError


class ApiKeyTransport(unittest.TestCase):
    """L1M-18: an API key never crosses the network over plaintext http://."""

    def test_loopback_and_https_are_allowed(self):
        for url in ["https://rpc.example:16210", "http://127.0.0.1:16210", "http://127.9.9.9/",
                    "http://localhost:16210", "http://LOCALHOST:1", "http://[::1]:16210"]:
            with self.subTest(url=url):
                _check_key_transport(url, False, "m")

    def test_remote_plaintext_is_refused_unless_opted_in(self):
        for url in ["http://rpc.example:16210", "http://10.0.0.5:16210", "http://[2001:db8::1]/"]:
            with self.subTest(url=url):
                with self.assertRaises(BlochTransportError):
                    _check_key_transport(url, False, "m")
                _check_key_transport(url, True, "m")

    def test_call_refuses_before_any_network_io(self):
        client = BlochClient("http://192.0.2.1:16210", api_key="secret", timeout=0.01)
        with self.assertRaises(BlochTransportError) as ctx:
            client.call("getblockcount")
        self.assertIn("refusing to send the API key", str(ctx.exception))
        # Without a key, reads are unaffected by the check (no key to leak).
        self.assertFalse(BlochClient("http://192.0.2.1:16210").allow_insecure_http)

    def test_keyed_requests_do_not_follow_redirects(self):
        import http.server
        import threading

        seen = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                seen.append((self.path, self.headers.get("X-API-Key")))
                self.rfile.read(int(self.headers.get("Content-Length", "0")))
                if self.path == "/":
                    self.send_response(302)
                    self.send_header("Location", "/elsewhere")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                else:
                    body = b'{"jsonrpc":"2.0","result":7,"id":1}'
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

            def do_GET(self):  # noqa: N802  (urllib turns a redirected POST into a GET)
                seen.append((self.path, self.headers.get("X-API-Key")))
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            url = f"http://127.0.0.1:{server.server_port}/"
            with self.assertRaises(BlochTransportError) as ctx:
                BlochClient(url, api_key="secret").call("getblockcount")
            self.assertIn("redirect refused", str(ctx.exception))
            self.assertEqual(seen, [("/", "secret")], "the key must not be re-sent to the redirect target")
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
