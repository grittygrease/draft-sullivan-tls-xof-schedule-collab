// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import "crypto/sha3"

// transcriptHashPrefix is framed into every TranscriptHash input by both
// profiles.
const transcriptHashPrefix = "tls13 hash"

// SHAKE256 is the TLS13_SHAKE256 profile: the deck schedule instantiated
// with plain SHAKE256 over the 24-round Keccak-f[1600] permutation.
//
// This profile needs no primitive beyond crypto/sha3. DF and
// TranscriptHash are SHAKE256, and MAC is a Derive, so it is SHAKE256
// too.
var SHAKE256 = &Profile{
	Name: "TLS13_SHAKE256",

	// Placeholder in Specification Required space; see Profile.TargetKDF.
	TargetKDF: 0x0101,

	// DF(S, L) = SHAKE256(seq(S), 8 * L). Go's SHAKE API is
	// octet-oriented, so the draft's 8 * L bit conversion is implicit:
	// l octets out.
	df: func(seq []byte, l int) []byte {
		return sha3.SumSHAKE256(seq, l)
	},

	// TranscriptHash(x) = SHAKE256("tls13 hash" || x, 512), i.e. 64
	// octets.
	th: func(x []byte) []byte {
		in := make([]byte, 0, len(transcriptHashPrefix)+len(x))
		in = append(in, transcriptHashPrefix...)
		in = append(in, x...)
		return sha3.SumSHAKE256(in, SecretLen)
	},
}
