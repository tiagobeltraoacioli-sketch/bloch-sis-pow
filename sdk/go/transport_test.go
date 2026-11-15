// SPDX-License-Identifier: MIT OR Apache-2.0

package blochclient

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

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
	// The refusal must come from the transport check itself: a DNS or
	// connection error would also be non-nil, so match the message, and use a
	// RoundTripper that fails the test if any request leaves.
	c.HTTPClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Error("a request left with the API key")
		return nil, errors.New("blocked by test")
	})}
	err := c.Call("getblockcount", nil, nil)
	var te *TransportError
	if !errors.As(err, &te) || !strings.Contains(te.Message, "refusing to send the API key") {
		t.Fatalf("expected the plaintext-transport refusal, got %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
