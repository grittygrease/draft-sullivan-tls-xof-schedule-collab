package main

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestDeriveNFramingAndSlices(t *testing.T) {
	var input []byte
	calls := 0
	p := &Profile{df: func(s []byte, n int) []byte {
		input = append([]byte(nil), s...)
		calls++
		z := make([]byte, n)
		for i := range z {
			z[i] = byte(i)
		}
		return z
	}}
	d := p.Init()
	before := append([]byte(nil), d.seq...)
	got := d.DeriveN([]Output{{"fin", 64}, {"key", 28}}, ctagContext, nil)
	want, _ := hex.DecodeString("0006746c7331332000046f75747300020002000366696e00046f75745f0002004000036b657900046f75745f0002001c")
	if !bytes.Equal(input, want) {
		t.Fatalf("framing: %x", input)
	}
	if calls != 1 || len(got) != 2 || len(got[0]) != 64 || len(got[1]) != 28 || got[1][0] != 64 {
		t.Fatalf("wrong one-call partition: %v", got)
	}
	if !bytes.Equal(before, d.seq) {
		t.Fatal("parent changed")
	}
	d.DeriveN([]Output{{"fin", 64}, {"key", 28}}, ctagContext, []byte{})
	if !bytes.Equal(input, want) {
		t.Fatal("empty context must be omitted")
	}
}

func TestDeriveNBinding(t *testing.T) {
	for _, p := range []*Profile{SHAKE256, TURBOSHAKE256} {
		d := p.FromSecret(bytes.Repeat([]byte{42}, 64))
		base := d.DeriveN([]Output{{"fin", 64}, {"key", 28}}, ctagContext, nil)
		for _, desc := range [][]Output{
			{{"key", 28}, {"fin", 64}},
			{{"fin", 63}, {"key", 29}},
			{{"upd", 64}, {"key", 28}},
		} {
			other := d.DeriveN(desc, ctagContext, nil)
			if bytes.Equal(base[0][:16], other[0][:16]) {
				t.Fatal("descriptor change not bound")
			}
		}
		ctx := d.DeriveN([]Output{{"fin", 64}, {"key", 28}}, ctagContext, []byte{1})
		if bytes.Equal(base[0], ctx[0]) {
			t.Fatal("context not bound")
		}
		if bytes.Equal(base[0], d.Expand("fin", nil, 64)) {
			t.Fatal("single/multi domain collision")
		}
	}
}

func TestDeriveNRejects(t *testing.T) {
	for _, desc := range [][]Output{
		nil, {{"fin", 64}}, {{"fin", 64}, {"fin", 28}},
		{{"fin", 0}, {"key", 28}}, {{"fin", -1}, {"key", 28}},
		{{"fin", 65536}, {"key", 28}}, {{"fin", 65535}, {"key", 1}},
		{{"fin", 64}, {"iv_", 12}}, {{"fin", 64}, {"bad", 12}},
		make([]Output, 65536),
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("accepted invalid descriptors: %v", desc)
				}
			}()
			SHAKE256.Init().DeriveN(desc, ctagContext, nil)
		}()
	}
	defer func() {
		if recover() == nil {
			t.Fatal("accepted outs Absorb tag")
		}
	}()
	SHAKE256.Init().Absorb("outs", nil)
}

func TestDeriveNMaximumTotal(t *testing.T) {
	for _, p := range []*Profile{SHAKE256, TURBOSHAKE256} {
		out := p.Init().DeriveN([]Output{{"fin", 65534}, {"key", 1}}, ctagContext, nil)
		if len(out[0]) != 65534 || len(out[1]) != 1 {
			t.Fatal("maximum total did not preserve partition")
		}
	}
}

func TestRecordBundleAlignmentAndStorage(t *testing.T) {
	for _, nk := range []int{16, 32} {
		for _, label := range []string{"fin", "upd"} {
			d := SHAKE256.FromSecret(bytes.Repeat([]byte{1}, SecretLen))
			out := d.DeriveN([]Output{{label, SecretLen}, {"key", nk + 12}}, ctagContext, nil)
			if SecretLen%8 != 0 || (SecretLen+nk)%8 != 0 {
				t.Fatal("secret, key_block, or IV is not aligned")
			}
			original := out[1][0]
			extended := append(out[0], 0)
			if out[1][0] != original || extended[64] != 0 {
				t.Fatal("output slices share appendable storage")
			}
		}
	}
}

func TestEmptyContextCanonicalization(t *testing.T) {
	for _, p := range []*Profile{SHAKE256, TURBOSHAKE256} {
		d := p.FromSecret(bytes.Repeat([]byte{7}, SecretLen))
		absent := d.Expand("fin", nil, SecretLen)
		empty := d.Expand("fin", []byte{}, SecretLen)
		if !bytes.Equal(absent, empty) {
			t.Fatal("empty Derive context must equal omitted context")
		}
		d.Absorb("ctx_", []byte{})
		if bytes.Equal(absent, d.Expand("fin", nil, SecretLen)) {
			t.Fatal("explicitly absorbed empty field must remain distinct")
		}
	}
}
