// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package tls13deck implements the key schedule of
// draft-sullivan-tls-xof-ciphers: the TLS 1.3 key schedule run on one
// Keccak permutation via a deck function, replacing HKDF.
//
// This package was written from the draft text alone.
//
// A deck is a running sequence of framed inputs. The profile's DF is the
// XOF over that sequence. Four operations drive the schedule: Init,
// Absorb, Derive and Ratchet. Derive is one DF call over the framed
// path, so every derived value is byte-exact and testable in isolation;
// nothing here needs to clone an unfinalized sponge.
package main

import "encoding/binary"

// scheduleLabel is framed by Init. The draft fixes it to the 6-octet
// ASCII string "tls13 ", with a trailing space, byte-identical to the
// RFC 9846 label prefix.
const scheduleLabel = "tls13 "

// Tags. Every tag is 4 octets, so a framed tag and the two-octet length
// of the value after it fill 8 octets, and schedule_label's frame is 8
// octets too: every key, secret and transcript hash starts on an 8-octet
// boundary.
const (
	tagSeed = "seed" // the seed of Init(seed)
	tagOut  = "out_" // the output length of a Derive
)

// Profile parameters. Both profiles of the draft use 64 octets.
const (
	// SecretLen is the length of stage and traffic secrets.
	SecretLen = 64
	// FLen is the length of Finished and PSK binder verify_data.
	FLen = 64
)

// maxFrame is the largest value frame can carry: a uint16 encodes 65535.
const maxFrame = 0xFFFF

// frame appends uint16(len(x)) || x to dst.
//
// Strings are length-prefixed only: not null-terminated, not padded.
// An empty value encodes as the two octets 0x0000 with no payload. An
// absent input omits its framed items entirely, which is not the same
// as framing an empty value.
func frame(dst, x []byte) []byte {
	if len(x) > maxFrame {
		panic("tls13deck: input exceeds the 0xFFFF frame capacity")
	}
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(x)))
	return append(dst, x...)
}

// uint16be is the two-octet big-endian encoding of n, as in the TLS
// presentation language.
func uint16be(n int) []byte {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], uint16(n))
	return b[:]
}

// A Profile is a negotiated KDF: TLS13_TURBOSHAKE256 or TLS13_SHAKE256.
// The schedule listing is identical for both; only DF, TranscriptHash
// and the MAC permutation differ.
type Profile struct {
	// Name is the schedule_profile identifier.
	Name string

	// TargetKDF is this KDF's TLS KDF Identifier in the RFC 9258
	// registry. It appears on the wire in the schedule_profile extension
	// and inside ImportedIdentity.target_kdf when an external PSK is
	// imported.
	//
	// PLACEHOLDER, DO NOT SHIP. The draft's identifiers are unassigned.
	// The values used here fall in the registry's Specification Required
	// range (0x0000-0xfeff), not its private-use range (0xff00-0xffff),
	// so IANA may assign them to an unrelated KDF. They exist only to
	// make the ipsk derivation reproducible and must be regenerated once
	// real identifiers are allocated.
	TargetKDF uint16

	// df is DF(S, L): the XOF over the framed sequence S, returning L
	// octets. L is at most 65535.
	df func(seq []byte, l int) []byte

	// th is TranscriptHash: an unkeyed 64-octet hash.
	th func(x []byte) []byte
}

// macLabel is the label of MAC. No other derivation uses it.
const macLabel = "mac"

// MAC computes every tag in the draft: the PSK binder and both Finished
// values. It is a Derive over a deck seeded with the key, under the
// label "mac", with the message as its context:
//
//	MAC(key, message, L) = Derive(Init(key), "mac", message, L)
//
// so it runs on the profile's DF like every other derivation.
func (p *Profile) MAC(key, message []byte, l int) []byte {
	return p.FromSecret(key).Expand(macLabel, message, l)
}

// TranscriptHash returns the profile's unkeyed 64-octet hash of x.
//
// TranscriptHash takes no cipher suite input in either profile, so a
// client can compute its checkpoints before the ServerHello.
func (p *Profile) TranscriptHash(x []byte) []byte { return p.th(x) }

// A Deck is a running sequence of framed inputs: one stage of the
// schedule, or a session rooted at a retained secret.
//
// The zero Deck is not valid; obtain one from Init or FromSecret.
type Deck struct {
	p   *Profile
	seq []byte
}

// Init starts a deck by framing schedule_label. Every deck is Init'd the
// same way, so every keyed sequence opens with frame(schedule_label).
func (p *Profile) Init() *Deck {
	return &Deck{p: p, seq: frame(nil, []byte(scheduleLabel))}
}

// FromSecret returns a deck seeded with a retained octet-string secret:
// an Init, then frame("seed") || frame(secret), the same way a ratchet
// seeds the next stage with its residue. Values keyed by a retained
// secret are Derived from this deck under the "ctx_" tag.
func (p *Profile) FromSecret(secret []byte) *Deck {
	d := p.Init()
	d.seed(secret)
	return d
}

// seed frames a seed under its tag: frame("seed") || frame(secret).
func (d *Deck) seed(secret []byte) {
	d.seq = frame(d.seq, []byte(tagSeed))
	d.seq = frame(d.seq, secret)
}

// Absorb feeds one tagged input into the running deck:
//
//	D = D || frame(tag) || frame(v)
//
// It is the role HKDF-Extract's mixing step plays in RFC 9846. Absorb
// produces no output.
func (d *Deck) Absorb(tag string, v []byte) {
	d.seq = frame(d.seq, []byte(tag))
	d.seq = frame(d.seq, v)
}

// context tags. The context of a Derive is a transcript checkpoint
// under "th" at a stage leaf, an expansion context under "context" for
// a retained secret, or absent.
const (
	ctagTranscript = "th__"
	ctagContext    = "ctx_"
)

// derive is the Derive operation:
//
//	out = DF(D [ || frame(ctag) || frame(context) ]
//	           || frame(label)
//	           || frame("out") || frame(uint16(L)), L)
//
// D is cloned, not consumed: the deck is left unchanged, so one deck
// yields all of a stage's leaves. A nil or empty context omits both
// framed items.
func (d *Deck) derive(label, ctag string, context []byte, l int) []byte {
	if l < 0 || l > maxFrame {
		panic("tls13deck: output length out of range")
	}
	// Clone by copying the framed path; the deck is not consumed.
	seq := make([]byte, len(d.seq), len(d.seq)+len(context)+len(label)+32)
	copy(seq, d.seq)
	if len(context) > 0 {
		seq = frame(seq, []byte(ctag))
		seq = frame(seq, context)
	}
	seq = frame(seq, []byte(label))
	seq = frame(seq, []byte(tagOut))
	seq = frame(seq, uint16be(l))
	return d.p.df(seq, l)
}

// DeriveSecret derives a stage leaf: a SecretLen-octet value bound to a
// transcript checkpoint under the "th" tag. A nil transcript is absent,
// as for binder_key, which takes no context.
//
// At a stage leaf this is exactly RFC 9846's Derive-Secret(secret,
// label, Messages), with the deck in place of the secret.
func (d *Deck) DeriveSecret(label string, transcript []byte) []byte {
	return d.derive(label, ctagTranscript, transcript, SecretLen)
}

// Expand derives a value of explicit length from this deck under the
// "ctx_" tag. A nil or empty context is omitted: the next framed item
// is the label, so both produce the same input.
//
// This is the analogue of RFC 9846's HKDF-Expand-Label.
func (d *Deck) Expand(label string, context []byte, l int) []byte {
	return d.derive(label, ctagContext, context, l)
}

// Ratchet crosses a stage boundary. The residue is a Derive under the
// label "drv", the analogue of RFC 9846's Derive-Secret(., "derived", ""),
// and the next deck is Init'd, framing schedule_label, then seeded with
// that residue. The residue never leaves the schedule.
//
// The old deck is retired: an implementation must not Absorb into or
// Derive from it afterward. Ratchet destroys the caller's deck to
// enforce that, and erases the residue once it has seeded the next deck.
func (d *Deck) Ratchet() *Deck {
	residue := d.derive("drv", ctagTranscript, nil, SecretLen)

	next := d.p.Init()
	next.seed(residue)

	erase(residue)
	d.Destroy()
	return next
}

// Destroy retires a deck, erasing its accumulated sequence. A destroyed
// deck must not be used again.
func (d *Deck) Destroy() {
	erase(d.seq)
	d.seq = nil
}

// erase zeroes b on a best-effort basis. In a garbage-collected runtime
// this cannot be guaranteed: the collector may already have copied the
// backing array.
func erase(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
