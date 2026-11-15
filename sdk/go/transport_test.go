// SPDX-License-Identifier: MIT OR Apache-2.0

package blochclient

import "testing"

// L1M-18: an API key never goes over plaintext http:// to a non-loopback host
// unless the caller opts in explicitly.
func TestCheckKeyTransport(t *testing.T) {
	ok := []string{
		"https://rpc.example:16210",
		"http://127.0.0.1:16210",
		"http://127.5.6.7:16210",
		"http://localhost:16210",
		"http://[::1]:16210",
	}
	for _, u := range ok {
		if err := checkKeyTransport(u, false); err != nil {
			t.Errorf("%s: unexpected refusal: %v", u, err)
		}
	}
	bad := []string{"http://rpc.example:16210", "http://10.0.0.5:16210", "http://[2001:db8::1]:16210"}
	for _, u := range bad {
		if err := checkKeyTransport(u, false); err == nil {
			t.Errorf("%s: API key would cross the network in the clear", u)
		}
		if err := checkKeyTransport(u, true); err != nil {
			t.Errorf("%s: explicit opt-in refused: %v", u, err)
		}
	}
	c := New("http://rpc.example:16210")
	c.APIKey = "k"
	if err := c.Call("getblockcount", nil, nil); err == nil {
		t.Fatal("Call sent an API key over plaintext http to a remote host")
	}
}
