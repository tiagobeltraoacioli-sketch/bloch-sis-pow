// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) Bloch community contributors
// @generated (static asset) by sdk/codegen — do not edit by hand.
//
// The Satoshis wire codec: uint64 in memory, decimal string in JSON.

package blochclient

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// Satoshis is a satoshi amount (1 BLCH = 100_000_000 sat): an unsigned 64-bit
// integer in memory, a **decimal string** on the JSON wire.
//
// Why a string, not just uint64: the Genesis-4 supply cap is 100,000,000,000
// BLCH = 10^19 satoshis — 108% of int64's positive range and ~1110x
// JavaScript's exact-integer limit 2^53 (9,007,199,254,740,991). A bare JSON
// number above 2^53 is silently rounded by every IEEE-754 JSON reader, so
// widening this SDK's integer would fix Go while leaving every JS consumer of
// the same wire reading wrong balances. The amount therefore travels as a
// decimal string ("satoshis": "10000000000000000000"); uint64 is the
// in-memory consequence. See docs/specs/BLOCH-SATOSHI-ENCODING.md.
//
// Unmarshalling accepts the canonical string form and, from legacy Genesis-3
// nodes only, a bare JSON integer. The legacy form is parsed from the raw
// JSON token — never through a float64 — so this decoder loses no precision
// either way; the hazard is other readers, not this one.
type Satoshis uint64

// MaxSats is the Genesis-4 total supply in satoshis:
// 100,000,000,000 BLCH x 10^8 sat/BLCH. No valid amount can exceed it, and
// the codec rejects anything above it in both directions. It mirrors
// TOTAL_SUPPLY_SAT in crates/bloch-pos-committee/src/tokenomics_v4.rs — if
// that constant moves, regenerate the SDKs.
const MaxSats Satoshis = 10_000_000_000_000_000_000

// MarshalJSON emits the canonical decimal-string form, e.g. "12345".
func (s Satoshis) MarshalJSON() ([]byte, error) {
	if s > MaxSats {
		return nil, fmt.Errorf("satoshis %d exceeds the total supply %d", uint64(s), uint64(MaxSats))
	}
	return []byte(`"` + strconv.FormatUint(uint64(s), 10) + `"`), nil
}

// UnmarshalJSON accepts the canonical decimal string ("123") or, for legacy
// Genesis-3 nodes, a bare JSON integer (123). It rejects negatives, signs,
// non-integers, leading zeros, and anything above MaxSats. JSON null leaves
// the value untouched (standard library convention).
func (s *Satoshis) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		return nil
	}
	if len(data) > 0 && data[0] == '"' {
		var str string
		if err := json.Unmarshal(data, &str); err != nil {
			return fmt.Errorf("satoshis: %w", err)
		}
		v, err := ParseSatoshis(str)
		if err != nil {
			return err
		}
		*s = v
		return nil
	}
	// Legacy bare-number form: parse the raw token, never via float64.
	v, err := ParseSatoshis(string(data))
	if err != nil {
		return err
	}
	*s = v
	return nil
}

// ParseSatoshis parses a canonical decimal satoshi string: base-10 digits
// only, no sign, no leading zeros, at most MaxSats.
func ParseSatoshis(str string) (Satoshis, error) {
	if str == "" {
		return 0, fmt.Errorf("satoshis: empty amount")
	}
	if str[0] == '-' {
		return 0, fmt.Errorf("satoshis: negative amount %q rejected (amounts are unsigned)", str)
	}
	for i := 0; i < len(str); i++ {
		if str[i] < '0' || str[i] > '9' {
			return 0, fmt.Errorf("satoshis: %q is not a base-10 integer", str)
		}
	}
	if len(str) > 1 && str[0] == '0' {
		return 0, fmt.Errorf("satoshis: leading zeros in %q are not canonical", str)
	}
	u, err := strconv.ParseUint(str, 10, 64)
	if err != nil {
		// Digits are already validated, so the only failure left is range.
		return 0, fmt.Errorf("satoshis: %q exceeds the total supply %d", str, uint64(MaxSats))
	}
	if Satoshis(u) > MaxSats {
		return 0, fmt.Errorf("satoshis: %q exceeds the total supply %d", str, uint64(MaxSats))
	}
	return Satoshis(u), nil
}

// String returns the canonical decimal form (same digits as the wire).
func (s Satoshis) String() string {
	return strconv.FormatUint(uint64(s), 10)
}

// Uint64 returns the raw satoshi count.
func (s Satoshis) Uint64() uint64 {
	return uint64(s)
}

// Bloch formats the amount as a BLCH display string with 8 decimals.
func (s Satoshis) Bloch() string {
	return SatsToBloch(s)
}
