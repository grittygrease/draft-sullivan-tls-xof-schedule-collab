// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/sha3"
	"encoding/hex"
	"testing"
)

// Keccak-p[1600,24] is Keccak-f[1600], so the sponge run at 24 rounds
// with SHAKE's domain byte must reproduce stdlib SHAKE256 exactly. This
// validates the permutation, the round constants, the rho/pi offsets,
// the pad10*1 padding and the squeeze against an independent
// implementation, without needing external vectors.
//
// What it does not cover is the round window itself: that
// Keccak-p[1600,12] takes rounds 12..23 rather than 0..11. That comes
// from FIPS 202 Section 3.3 and is asserted separately below.
func TestKeccakSpongeAt24RoundsMatchesSHAKE256(t *testing.T) {
	lengths := []int{0, 1, 2, 135, 136, 137, 271, 272, 273, 1000}
	outputs := []int{1, 31, 32, 64, 135, 136, 137, 300}

	for _, n := range lengths {
		m := make([]byte, n)
		for i := range m {
			m[i] = byte(i * 7)
		}
		for _, l := range outputs {
			got := keccakSponge(m, domainXOF, l, 24)
			want := sha3.SumSHAKE256(m, l)
			if !bytes.Equal(got, want) {
				t.Fatalf("len(m)=%d out=%d:\n got  % x\n want % x",
					n, l, got[:min(16, l)], want[:min(16, l)])
			}
		}
	}
}

// RFC 9861, Section 5: TurboSHAKE256(M=empty, D=1F, 64).
// https://www.rfc-editor.org/rfc/rfc9861.html#section-5
// This independently published result pins the LAST twelve rounds;
// applying rounds 0..11 instead of 12..23 must fail this assertion.
func TestKeccakRoundWindow(t *testing.T) {
	want, err := hex.DecodeString(
		"367a329dafea871c7802ec67f905ae13c57695dc2c6663c61035f59a18f8e7db" +
			"11edc0e12e91ea60eb6b32df06dd7f002fbafabb6e13ec1cc20d995547600db0")
	if err != nil {
		t.Fatal(err)
	}
	got := keccakSponge(nil, domainXOF, len(want), turboRounds)
	if !bytes.Equal(got, want) {
		t.Fatalf("RFC 9861 TurboSHAKE256 round window:\n got  %x\n want %x", got, want)
	}
}

// Both profiles must run the identical schedule listing and differ only
// in the underlying permutation, so every leaf must differ between them.
func TestProfilesDifferButShareTheListing(t *testing.T) {
	th := bytes.Repeat([]byte{0x77}, SecretLen)

	run := func(p *Profile) []byte {
		e := p.Init()
		e.Absorb("psk_", []byte("psk"))
		h := e.Ratchet()
		h.Absorb("shs_", []byte("ss"))
		return h.DeriveSecret("cht", th)
	}

	a := run(SHAKE256)
	b := run(TURBOSHAKE256)
	if bytes.Equal(a, b) {
		t.Fatal("profiles produced identical output; the permutation is not being varied")
	}
	if len(a) != SecretLen || len(b) != SecretLen {
		t.Fatal("leaf length is not SecretLen")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
