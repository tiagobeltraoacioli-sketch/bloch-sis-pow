// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) Bloch community contributors
//
// Unit helpers: satoshis <-> BLCH display, plus a light address-network guess.
// The satoshi amount (Satoshis, uint64 / decimal string on the wire — see
// satoshis.go) is the ONLY on-chain truth (1 BLCH = 100_000_000 satoshis);
// the float *_bloch fields are display-only.

package blochclient

import (
	"fmt"
	"strconv"
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

// SatsToBloch formats a satoshi amount as a BLCH display string with 8 decimals.
func SatsToBloch(sats Satoshis) string {
	whole := uint64(sats) / SatsPerBloch
	frac := uint64(sats) % SatsPerBloch
	return fmt.Sprintf("%d.%08d", whole, frac)
}

// FormatBloch renders satoshis as e.g. "1.50000000 BLCH".
func FormatBloch(sats Satoshis) string {
	return SatsToBloch(sats) + " BLCH"
}

// BlochToSats parses a human BLCH string (e.g. "1.5") into a satoshi amount.
// It rejects negatives, more than 8 decimal places, non-numeric input, and
// anything above the total supply (MaxSats).
func BlochToSats(bloch string) (Satoshis, error) {
	s := strings.TrimSpace(bloch)
	if strings.HasPrefix(s, "-") {
		return 0, fmt.Errorf("negative BLCH amount rejected (amounts are unsigned): %q", bloch)
	}
	whole, frac := s, ""
	if i := strings.IndexByte(s, '.'); i >= 0 {
		whole, frac = s[:i], s[i+1:]
	}
	if len(frac) > BlochDecimals {
		return 0, fmt.Errorf("too many decimal places (max %d): %q", BlochDecimals, bloch)
	}
	frac = frac + strings.Repeat("0", BlochDecimals-len(frac))
	if whole == "" {
		whole = "0"
	}
	w, err := strconv.ParseUint(whole, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid BLCH amount: %q", bloch)
	}
	f, err := strconv.ParseUint(frac, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid BLCH amount: %q", bloch)
	}
	// w*SatsPerBloch + f with overflow/supply checks (MaxSats < 2^64).
	if w > (uint64(MaxSats)-f)/SatsPerBloch {
		return 0, fmt.Errorf("BLCH amount %q exceeds the total supply", bloch)
	}
	return Satoshis(w*SatsPerBloch + f), nil
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
