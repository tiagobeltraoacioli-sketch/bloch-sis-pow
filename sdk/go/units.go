// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) Bloch community contributors
//
// Unit helpers: satoshis <-> BLCH display, plus a light address-network guess.
// The integer satoshi value is the ONLY on-chain truth (1 BLCH = 100_000_000
// satoshis); the float *_bloch fields are display-only.

package blochclient

import (
	"fmt"
	"strings"
)

const (
	// SatsPerBloch is the number of satoshis in one whole BLCH.
	SatsPerBloch = 100_000_000
	// BlochDecimals is the number of decimal places in a BLCH display value.
	BlochDecimals = 8

	MainnetPrefix = "bloch1q"
	TestnetPrefix = "bloch1t"
)

// SatsToBloch formats integer satoshis as a BLCH display string with 8 decimals.
func SatsToBloch(sats int64) string {
	neg := sats < 0
	if neg {
		sats = -sats
	}
	whole := sats / SatsPerBloch
	frac := sats % SatsPerBloch
	s := fmt.Sprintf("%d.%08d", whole, frac)
	if neg {
		return "-" + s
	}
	return s
}

// FormatBloch renders satoshis as e.g. "1.50000000 BLCH".
func FormatBloch(sats int64) string {
	return SatsToBloch(sats) + " BLCH"
}

// BlochToSats parses a human BLCH string (e.g. "1.5") into integer satoshis.
// It rejects more than 8 decimal places and non-numeric input.
func BlochToSats(bloch string) (int64, error) {
	s := strings.TrimSpace(bloch)
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	whole, frac := s, ""
	if i := strings.IndexByte(s, '.'); i >= 0 {
		whole, frac = s[:i], s[i+1:]
	}
	if len(frac) > BlochDecimals {
		return 0, fmt.Errorf("too many decimal places (max %d): %q", BlochDecimals, bloch)
	}
	frac = frac + strings.Repeat("0", BlochDecimals-len(frac))
	var w, f int64
	if whole != "" {
		if _, err := fmt.Sscanf(whole, "%d", &w); err != nil {
			return 0, fmt.Errorf("invalid BLCH amount: %q", bloch)
		}
	}
	if frac != "" {
		if _, err := fmt.Sscanf(frac, "%d", &f); err != nil {
			return 0, fmt.Errorf("invalid BLCH amount: %q", bloch)
		}
	}
	sats := w*SatsPerBloch + f
	if neg {
		sats = -sats
	}
	return sats, nil
}

// AddressNetwork is a cheap prefix guess: "mainnet", "testnet", or "". Use the
// node's validateaddress RPC for the authoritative answer.
func AddressNetwork(address string) string {
	switch {
	case strings.HasPrefix(address, MainnetPrefix):
		return "mainnet"
	case strings.HasPrefix(address, TestnetPrefix):
		return "testnet"
	default:
		return ""
	}
}
