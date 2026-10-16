package main

import (
	"bytes"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

func TestExpandEmptyContextIsOmitted(t *testing.T) {
	for _, p := range []*Profile{SHAKE256, TURBOSHAKE256} {
		t.Run(p.Name, func(t *testing.T) {
			d := p.FromSecret(bytes.Repeat([]byte{0x42}, SecretLen))
			missing := d.Expand("rsp", nil, SecretLen)
			empty := d.Expand("rsp", []byte{}, SecretLen)
			if !bytes.Equal(empty, missing) {
				t.Fatalf("empty context differs from missing:\n got %x\nwant %x", empty, missing)
			}
			if bytes.Equal(d.Expand("rsp", []byte{0}, SecretLen), missing) {
				t.Fatal("nonempty context was omitted")
			}
		})
	}
}

func TestServerFinishedUsesPreFinishedCheckpoint(t *testing.T) {
	for _, p := range []*Profile{SHAKE256, TURBOSHAKE256} {
		t.Run(p.Name, func(t *testing.T) {
			output, err := os.CreateTemp(t.TempDir(), "vectors")
			if err != nil {
				t.Fatal(err)
			}
			defer output.Close()
			stdout := os.Stdout
			func() {
				os.Stdout = output
				defer func() { os.Stdout = stdout }()
				emitVectors(p)
			}()
			data, err := os.ReadFile(output.Name())
			if err != nil {
				t.Fatal(err)
			}
			values := make(map[string][]byte)
			for _, line := range strings.Split(string(data), "\n") {
				name, value, ok := strings.Cut(line, ":")
				if ok {
					decoded, err := hex.DecodeString(strings.TrimSpace(value))
					if err != nil {
						t.Fatal(err)
					}
					values[name] = decoded
				}
			}
			checkpoint := p.TranscriptHash([]byte("ClientHello..before server Finished"))
			want := p.MAC(values["finished_key (server)"], checkpoint, FLen)
			if !bytes.Equal(values["server verify_data"], want) {
				t.Error("server Finished does not use the pre-Finished checkpoint")
			}
			if !bytes.Equal(values["TH_PRE_SF"], checkpoint) {
				t.Error("missing or incorrect TH_PRE_SF vector")
			}
		})
	}
}
