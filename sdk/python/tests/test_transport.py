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


if __name__ == "__main__":
    unittest.main()
