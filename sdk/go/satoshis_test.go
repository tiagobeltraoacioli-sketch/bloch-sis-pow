// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) Bloch community contributors
// @generated (static asset) by sdk/codegen — do not edit by hand.

package blochclient

import (
	"encoding/json"
	"testing"
)

// supplyCap is the Genesis-4 total supply, 100,000,000,000 BLCH at 8 decimals.
const supplyCapDigits = "10000000000000000000"

func TestSatoshisRoundTrip(t *testing.T) {
	cases := []struct {
		name  string
		value Satoshis
		json  string
	}{
		{"zero", 0, `"0"`},
		{"one", 1, `"1"`},
		{"one BLCH", 100_000_000, `"100000000"`},
		{"js safe limit", 9_007_199_254_740_991, `"9007199254740991"`},
		{"js safe limit + 2", 9_007_199_254_740_993, `"9007199254740993"`},
		{"largest carryover address", 1_688_654_952_300_000_000, `"1688654952300000000"`},
		{"past int64", 9_223_372_036_854_775_808, `"9223372036854775808"`},
		{"supply cap", MaxSats, `"` + supplyCapDigits + `"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			enc, err := json.Marshal(tc.value)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if string(enc) != tc.json {
				t.Fatalf("marshal = %s, want %s", enc, tc.json)
			}
			var back Satoshis
			if err := json.Unmarshal(enc, &back); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if back != tc.value {
				t.Fatalf("round-trip = %d, want %d", uint64(back), uint64(tc.value))
			}
		})
	}
}

// The supply cap must survive a struct round-trip, not just a bare scalar.
func TestSatoshisSupplyCapInStruct(t *testing.T) {
	type balance struct {
		Satoshis Satoshis `json:"satoshis"`
	}
	enc, err := json.Marshal(balance{Satoshis: MaxSats})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `{"satoshis":"` + supplyCapDigits + `"}`
	if string(enc) != want {
		t.Fatalf("marshal = %s, want %s", enc, want)
	}
	var back balance
	if err := json.Unmarshal(enc, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Satoshis != MaxSats {
		t.Fatalf("round-trip = %d, want %d", uint64(back.Satoshis), uint64(MaxSats))
	}
	// 10^19 does not fit the int64 this type used to be; prove the new type
	// carries it rather than saturating.
	if uint64(back.Satoshis) <= 9_223_372_036_854_775_807 {
		t.Fatalf("supply cap %d did not survive as a u64-range value", uint64(back.Satoshis))
	}
}

func TestSatoshisRejectsNegative(t *testing.T) {
	for _, bad := range []string{`"-1"`, `-1`, `"-10000000000000000000"`, `-9007199254740993`} {
		var s Satoshis
		if err := json.Unmarshal([]byte(bad), &s); err == nil {
			t.Fatalf("unmarshal(%s) accepted a negative amount as %d", bad, uint64(s))
		}
	}
}

func TestSatoshisRejectsAboveSupply(t *testing.T) {
	// One satoshi past the cap, and the largest u64 (which is 1.84x the cap).
	for _, bad := range []string{`"10000000000000000001"`, `"18446744073709551615"`, `"99999999999999999999"`} {
		var s Satoshis
		if err := json.Unmarshal([]byte(bad), &s); err == nil {
			t.Fatalf("unmarshal(%s) accepted %d, above the supply cap", bad, uint64(s))
		}
	}
	if _, err := json.Marshal(MaxSats + 1); err == nil {
		t.Fatal("marshal accepted an amount above the supply cap")
	}
}

func TestSatoshisRejectsMalformed(t *testing.T) {
	for _, bad := range []string{`""`, `"1.5"`, `"0x10"`, `"+1"`, `"007"`, `" 1"`, `"1 "`, `"1e19"`, `1.5`, `true`, `[]`} {
		var s Satoshis
		if err := json.Unmarshal([]byte(bad), &s); err == nil {
			t.Fatalf("unmarshal(%s) accepted a malformed amount as %d", bad, uint64(s))
		}
	}
}

// Legacy Genesis-3 nodes emit satoshis as bare JSON numbers. Accept them, and
// parse from the raw token so nothing passes through a float64.
func TestSatoshisAcceptsLegacyNumberForm(t *testing.T) {
	var s Satoshis
	if err := json.Unmarshal([]byte(`1688654952300000000`), &s); err != nil {
		t.Fatalf("legacy number form rejected: %v", err)
	}
	if uint64(s) != 1_688_654_952_300_000_000 {
		t.Fatalf("legacy parse = %d, want 1688654952300000000", uint64(s))
	}
	// A value a float64 could not hold exactly still decodes exactly, because
	// the decoder never builds a float64.
	if err := json.Unmarshal([]byte(`9007199254740993`), &s); err != nil {
		t.Fatalf("legacy number form rejected: %v", err)
	}
	if uint64(s) != 9_007_199_254_740_993 {
		t.Fatalf("legacy parse = %d, want 9007199254740993 (float64 would give ...992)", uint64(s))
	}
}

// TestSatoshisSurvivesJavaScript is the reason this type is a string on the
// wire at all.
//
// The vectors below were MEASURED, not assumed, with node v22.16.0:
//
//	node -e 'console.log(JSON.stringify(JSON.parse(`{"v":9007199254740993}`)))'
//	  -> {"v":9007199254740992}     // one satoshi lost, silently
//	node -e 'console.log(JSON.stringify(JSON.parse(`{"v":"9007199254740993"}`)))'
//	  -> {"v":"9007199254740993"}   // byte-identical
//
// JavaScript parses every JSON number into an IEEE-754 double, exact only up
// to 2^53 - 1 = 9,007,199,254,740,991. The Genesis-4 supply cap is 10^19 sat,
// about 1110x that limit, and single real balances are already ~187x past it.
// So the numeric wire form is lossy for Bloch amounts no matter how wide the
// Go integer is — which is why widening int64 to uint64 is the consequence of
// the fix and not the fix itself.
//
// This test asserts our encoder emits exactly the bytes JavaScript gives back
// unchanged, and pins the measured corruption of the numeric form.
func TestSatoshisSurvivesJavaScript(t *testing.T) {
	vectors := []struct {
		sats Satoshis
		// jsStringRoundTrip: JSON.stringify(JSON.parse(`{"v":"<digits>"}`)) in node.
		jsStringRoundTrip string
		// jsNumberRoundTrip: JSON.stringify(JSON.parse(`{"v":<digits>}`)) in node.
		jsNumberRoundTrip string
		numberIsCorrupted bool
	}{
		{
			sats:              9_007_199_254_740_991,
			jsStringRoundTrip: `{"v":"9007199254740991"}`,
			jsNumberRoundTrip: `{"v":9007199254740991}`,
			numberIsCorrupted: false, // exactly 2^53 - 1: the last exact integer
		},
		{
			sats:              9_007_199_254_740_993,
			jsStringRoundTrip: `{"v":"9007199254740993"}`,
			jsNumberRoundTrip: `{"v":9007199254740992}`,
			numberIsCorrupted: true,
		},
		{
			sats:              9_999_999_999_999_999_999,
			jsStringRoundTrip: `{"v":"9999999999999999999"}`,
			jsNumberRoundTrip: `{"v":10000000000000000000}`,
			numberIsCorrupted: true,
		},
		{
			sats:              MaxSats,
			jsStringRoundTrip: `{"v":"` + supplyCapDigits + `"}`,
			jsNumberRoundTrip: `{"v":` + supplyCapDigits + `}`,
			numberIsCorrupted: false, // 10^19 happens to be representable; 10^19-1 is not
		},
	}
	type envelope struct {
		V Satoshis `json:"v"`
	}
	for _, v := range vectors {
		enc, err := json.Marshal(envelope{V: v.sats})
		if err != nil {
			t.Fatalf("marshal %d: %v", uint64(v.sats), err)
		}
		// Byte-for-byte: what we send is what JavaScript hands back untouched.
		if string(enc) != v.jsStringRoundTrip {
			t.Fatalf("encoded %s, JavaScript round-trips %s", enc, v.jsStringRoundTrip)
		}
		// And decoding what JavaScript produced returns the exact amount.
		var back envelope
		if err := json.Unmarshal([]byte(v.jsStringRoundTrip), &back); err != nil {
			t.Fatalf("decode JS output: %v", err)
		}
		if back.V != v.sats {
			t.Fatalf("JS round-trip changed %d into %d", uint64(v.sats), uint64(back.V))
		}
		// The numeric form: pin the measured loss so nobody "simplifies" the
		// encoding back to a JSON number.
		numeric := `{"v":` + v.sats.String() + `}`
		corrupted := numeric != v.jsNumberRoundTrip
		if corrupted != v.numberIsCorrupted {
			t.Fatalf("numeric form %s vs measured JS %s: corruption = %v, expected %v",
				numeric, v.jsNumberRoundTrip, corrupted, v.numberIsCorrupted)
		}
	}
}

func TestBlochToSatsBounds(t *testing.T) {
	// The whole supply, in BLCH, parses to exactly the cap.
	got, err := BlochToSats("100000000000.00000000")
	if err != nil {
		t.Fatalf("supply cap in BLCH rejected: %v", err)
	}
	if got != MaxSats {
		t.Fatalf("BlochToSats = %d, want %d", uint64(got), uint64(MaxSats))
	}
	if SatsToBloch(MaxSats) != "100000000000.00000000" {
		t.Fatalf("SatsToBloch(cap) = %q", SatsToBloch(MaxSats))
	}
	for _, bad := range []string{"-1", "100000000001", "1.000000001", "abc"} {
		if _, err := BlochToSats(bad); err == nil {
			t.Fatalf("BlochToSats(%q) was accepted", bad)
		}
	}
}
