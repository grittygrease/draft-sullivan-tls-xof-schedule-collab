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

func TestExportedAuthenticatorUsesEncodedMessages(t *testing.T) {
	draft, err := os.ReadFile("../../draft-sullivan-tls-xof-schedule.md")
	if err != nil {
		t.Fatal(err)
	}
	_, fixture, ok := strings.Cut(string(draft), "EA test certificate (DER):\n")
	if !ok {
		t.Fatal("missing certificate fixture in draft")
	}
	fixture, _, _ = strings.Cut(fixture, "~~~~")
	der, err := hex.DecodeString(strings.Join(strings.Fields(fixture), ""))
	if err != nil || len(der) != 204 {
		t.Fatalf("invalid draft certificate: length %d, error %v", len(der), err)
	}
	// Independently assemble the documented wire fields for the expected
	// transcripts, including both handshake headers and CertificateEntry.
	cert := append([]byte{11, 0, 0, 214, 1, 0xa5, 0, 0, 209, 0, 0, 204}, der...)
	cert = append(cert, 0, 0)
	cv := append([]byte{15, 0, 0, 68, 8, 7, 0, 64}, make([]byte, 64)...)
	for _, p := range []*Profile{SHAKE256, TURBOSHAKE256} {
		t.Run(p.Name, func(t *testing.T) {
			output, err := os.CreateTemp(t.TempDir(), "ea-vectors")
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
					values[name], err = hex.DecodeString(strings.TrimSpace(value))
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			transcript := append(values["Handshake Context"], cert...)
			if !bytes.Equal(values["TranscriptHash(HC || Certificate)"], p.TranscriptHash(transcript)) {
				t.Error("authenticator hash does not cover the encoded Certificate")
			}
			want := p.MAC(values["Finished MAC Key"], p.TranscriptHash(append(transcript, cv...)), FLen)
			if !bytes.Equal(values["Finished"], want) {
				t.Error("authenticator Finished does not cover both encoded messages")
			}
		})
	}
}
