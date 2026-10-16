# Test vector generators

The Test Vectors appendix of draft-sullivan-tls-xof-schedule is
produced by two implementations, written separately, that must agree
byte for byte.
Both live in this directory, so anyone can regenerate the appendix and
check it.

`make vectors-check`, run from the repository root, first checks the Python
TurboSHAKE256 implementation against RFC 9861's vectors, quietly on success.
It then runs both generators and compares them with each other and with the
appendix, value by value. It exits non-zero on any difference or duplicate
appendix label within a profile. It needs Go 1.24 or later and Python 3.

## go/

The deck schedule as a small Go program: framing, Init, Absorb, Derive,
Ratchet, TranscriptHash, and the MAC, for both profiles. `go run .`
prints every appendix value.

* SHAKE256 comes from the Go standard library (`crypto/sha3`, Go 1.24).
* TurboSHAKE256 is not in the standard library, so `turboshake.go`
  implements Keccak-p[1600, nr] and the TurboSHAKE256 sponge directly,
  following FIPS 202 Section 3.3 and RFC 9861.
* `go test .` checks that implementation in two ways. At 24 rounds it
  must reproduce the standard library's SHAKE256. At 12 rounds,
  `TestKeccakRoundWindow` must reproduce RFC 9861, Section 5's 64-byte
  TurboSHAKE256 result for an empty message and domain byte `0x1F`.
  That known result detects using rounds 0 through 11 instead of 12 through 23.

This is the deck code from the reference implementation (a fork of the
Go TLS stack), cut down to what the appendix needs.

## pyverify/

`verify.py` is an independent re-derivation written from the draft text
alone. It shares no code with `go/` and uses its own Keccak
implementation. At 24 rounds that implementation is checked against
Python's `hashlib.shake_256` before any vector is derived.
`rfc9861_vectors.py` checks the 12-round TurboSHAKE256 against the test
vectors of RFC 9861.

## vectors_check.py

This script reads both generators' `name: hex` output and the two
per-profile vector blocks of the appendix, rejects duplicate labels within a
profile, then reports every value that differs or is missing in any of the three.

Both generators print the values in the same order and under the same
names as the appendix. A change to the schedule therefore lands in three
places in the same pull request: `go/`, `pyverify/`, and the appendix.
