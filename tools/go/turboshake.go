// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/binary"
	"math/bits"
)

// Keccak-p[1600, nr] and the TurboSHAKE256 sponge.
//
// Go's crypto/sha3 exposes no reduced-round Keccak and no TurboSHAKE, so
// the TLS13_TURBOSHAKE256 profile needs its own permutation. This is the
// only new primitive either profile of the draft requires.
//
// Keccak-p[1600, nr] applies the last nr of Keccak-f[1600]'s 24 rounds
// (FIPS 202, Section 3.3: round indices 12 + 2l - nr through 12 + 2l - 1
// with l = 6). So nr = 12 uses rounds 12..23 and nr = 24 is Keccak-f
// itself, which is what lets this code be checked against stdlib SHAKE256.

const (
	// keccakRate is the 136-octet rate shared by SHAKE256 and
	// TurboSHAKE256: 1600 bits of state less a 512-bit capacity.
	keccakRate = (1600 - 512) / 8

	// domainXOF is the RFC 9861 default domain byte, used by DF and
	// TranscriptHash, and so by MAC, which is a Derive.
	domainXOF byte = 0x1F

	turboRounds = 12
)

var keccakRC = [24]uint64{
	0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
	0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
	0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
	0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
	0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
	0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
}

var keccakRot = [24]int{
	1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
	27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
}

var keccakPi = [24]int{
	10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
	15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
}

// keccakP applies Keccak-p[1600, rounds] to a in place.
func keccakP(a *[25]uint64, rounds int) {
	for r := 24 - rounds; r < 24; r++ {
		// theta
		var c [5]uint64
		for i := 0; i < 5; i++ {
			c[i] = a[i] ^ a[i+5] ^ a[i+10] ^ a[i+15] ^ a[i+20]
		}
		for i := 0; i < 5; i++ {
			t := c[(i+4)%5] ^ bits.RotateLeft64(c[(i+1)%5], 1)
			for j := 0; j < 25; j += 5 {
				a[i+j] ^= t
			}
		}

		// rho and pi
		t := a[1]
		for i := 0; i < 24; i++ {
			j := keccakPi[i]
			t, a[j] = a[j], bits.RotateLeft64(t, keccakRot[i])
		}

		// chi
		for j := 0; j < 25; j += 5 {
			var row [5]uint64
			copy(row[:], a[j:j+5])
			for i := 0; i < 5; i++ {
				a[i+j] = row[i] ^ (^row[(i+1)%5] & row[(i+2)%5])
			}
		}

		// iota
		a[0] ^= keccakRC[r]
	}
}

// keccakSponge absorbs m and squeezes outLen octets, at the 136-octet
// rate, with the given domain-separation byte and round count. The
// padding is Keccak's pad10*1 with the domain byte leading.
func keccakSponge(m []byte, domain byte, outLen, rounds int) []byte {
	var a [25]uint64

	absorb := func(block []byte) {
		for i := 0; i < keccakRate/8; i++ {
			a[i] ^= binary.LittleEndian.Uint64(block[i*8:])
		}
		keccakP(&a, rounds)
	}

	for len(m) >= keccakRate {
		absorb(m[:keccakRate])
		m = m[keccakRate:]
	}

	last := make([]byte, keccakRate)
	copy(last, m)
	last[len(m)] = domain
	last[keccakRate-1] |= 0x80
	absorb(last)

	out := make([]byte, 0, outLen)
	for {
		var block [keccakRate]byte
		for i := 0; i < keccakRate/8; i++ {
			binary.LittleEndian.PutUint64(block[i*8:], a[i])
		}
		n := outLen - len(out)
		if n > keccakRate {
			n = keccakRate
		}
		out = append(out, block[:n]...)
		if len(out) == outLen {
			return out
		}
		keccakP(&a, rounds)
	}
}

// turboSHAKE256 is TurboSHAKE256(M, D, L) of RFC 9861: the 136-octet
// rate sponge over Keccak-p[1600,12], with the output length in octets.
func turboSHAKE256(m []byte, domain byte, l int) []byte {
	return keccakSponge(m, domain, l, turboRounds)
}

// TURBOSHAKE256 is the TLS13_TURBOSHAKE256 profile.
var TURBOSHAKE256 = &Profile{
	Name: "TLS13_TURBOSHAKE256",

	// Placeholder in Specification Required space; see Profile.TargetKDF.
	TargetKDF: 0x0100,

	// DF(S, L) = TurboSHAKE256(seq(S), 0x1F, L). L is in octets in RFC
	// 9861, so it passes through unchanged.
	df: func(seq []byte, l int) []byte {
		return turboSHAKE256(seq, domainXOF, l)
	},

	// TranscriptHash(x) = TurboSHAKE256("tls13 hash" || x, 0x1F, 64).
	th: func(x []byte) []byte {
		in := make([]byte, 0, len(transcriptHashPrefix)+len(x))
		in = append(in, transcriptHashPrefix...)
		in = append(in, x...)
		return turboSHAKE256(in, domainXOF, SecretLen)
	},
}
