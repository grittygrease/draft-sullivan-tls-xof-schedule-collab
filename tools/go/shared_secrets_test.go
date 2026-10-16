package main

import (
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

func TestPSKOnlyAndHybridVectors(t *testing.T) {
	want := map[string]map[string]string{
		"TLS13_SHAKE256": {
			"c_hs_traffic (PSK-only)": "e0ab811e34a7026586f6514a8d44877c5b849e707bc4e627bdf7c086c6a85646ed6081654a02acde603a5296011ad5bc46738e0e84f661ddc298bc544435fb40",
			"s_hs_traffic (PSK-only)": "d929a47d730a8a55f71c0a27539850705f3a5e61bff48f6bb18a169752282c8a43a36bb6dbd554d438afbd5f3bf18c13a09c3432709ab6012ff16d7269e0ce73",
			"c_ap_traffic (PSK-only)": "43f2b9c7574c16870c00698693a64ca19345e2b7133392349a17c54f8ba38adb6cfa6a82badc71d432e267fea4ff6ff73ec7d88b5fadffaf6891b9258f09954c",
			"c_hs_traffic (hybrid)":   "2bab27300224fa295fa4902de9ce7629667de0da042aceffe72705df148c5c1da68034c847bb188dc9f64a5ee78c1b82a2511ce3f9c40cf92173e3d08f9b83d1",
			"s_hs_traffic (hybrid)":   "39fc698e23a46015524eebfcec1e8887975c7b2c189909139ef45e54bd9e5fd911f11f822cdaaa6f9a2156ebb00c116723cf5d68ea958dbd5f04b17c113a79e1",
			"c_ap_traffic (hybrid)":   "7ed2add97208d6a43e4f86b9f3ef4693489c89fdb292b6902b4c77c8836843754d49dcc41797a6855e2e6a59b173a6456410b4646dd436f37b9882fc52b15a74",
		},
		"TLS13_TURBOSHAKE256": {
			"c_hs_traffic (PSK-only)": "992d293e453d6196ad8f3b48bfc892e2d4a318a913d840385aa3294a57c146ade1b4422614d22217018c7070928f0ae784f324cc8300dc2121fd24a1ae584067",
			"s_hs_traffic (PSK-only)": "017771ca9ceffd0dec2afa9438bb78c9f67472344d4340926a59083f09414edc1962edd8ec267756e08613a5bc87b3b75caff6c4be33a5e976ec4ff274e8c49b",
			"c_ap_traffic (PSK-only)": "f3e043c8dcf9a40474c02415f63b4e9954c1bd20d33f2bf715b92a2fcefc38f5a4f24b7f516aa19a008000665f27fdef7f9cf707f14c1db60b803238857dd386",
			"c_hs_traffic (hybrid)":   "65a7e7990bbb12d12a4f8a8e37242925b1197c6fd92662ec61bee3dd86b229bd2c73e935d6b3af8c59730fc222b443ab7332c542b76f935df1824f14fa2dcd73",
			"s_hs_traffic (hybrid)":   "165cb3cdddd65eafa2d7177fa96e9c22eb956d48985f95d7b0b9bf41b973bcd9a56d6e7c0c0c7ab6f369e3e6e5dfdb99d4d11d564434233aa5f3ffdca930f72a",
			"c_ap_traffic (hybrid)":   "6f704ca7b0295a1db58ddee2f78731bd9003a0281baa454eb6a3a105e9d7be12bb5c54e71909cbcdc86443d8814cf0b067f2efb180236e74c0735496d69c7406",
		},
	}
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
			got := make(map[string]string)
			for _, line := range strings.Split(string(data), "\n") {
				name, value, ok := strings.Cut(line, ":")
				if ok {
					got[name] = strings.TrimSpace(value)
				}
			}
			for name, value := range want[p.Name] {
				if got[name] != value {
					t.Errorf("%s: got %s, want %s", name, got[name], value)
				}
			}
			a := p.TranscriptHash([]byte("hybrid component 1"))
			b := p.TranscriptHash([]byte("hybrid component 2"))
			// These schedules must differ from omission and ordered absorbs.
			for _, test := range []struct {
				name, fixture string
				components    [][]byte
			}{
				{"empty", "PSK-only", [][]byte{nil}},
				{"concatenated", "hybrid", [][]byte{append(append([]byte{}, a...), b...)}},
				{"reversed", "hybrid", [][]byte{b, a}},
			} {
				t.Run(test.name, func(t *testing.T) {
					e := p.Init()
					e.Absorb("psk_", p.TranscriptHash([]byte("psk")))
					h := e.Ratchet()
					for _, component := range test.components {
						h.Absorb("shs_", component)
					}
					thSH := p.TranscriptHash([]byte("ClientHello..ServerHello"))
					different := map[string][]byte{
						"c_hs_traffic": h.DeriveSecret("cht", thSH),
						"s_hs_traffic": h.DeriveSecret("sht", thSH),
					}
					app := h.Ratchet()
					different["c_ap_traffic"] = app.DeriveSecret("cat",
						p.TranscriptHash([]byte("ClientHello..server Finished")))
					app.Destroy()
					for name, value := range different {
						if got[name+" ("+test.fixture+")"] == hex.EncodeToString(value) {
							t.Errorf("%s: %s matched %s", name, test.fixture, test.name)
						}
					}
				})
			}
		})
	}
}
