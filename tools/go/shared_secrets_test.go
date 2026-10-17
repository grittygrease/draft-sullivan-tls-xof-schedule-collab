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
			"c_hs_traffic (PSK-only)": "8002d2845fb5f1b98da952a729e2d1a455802417e6b8b49385c418cd148fb127fd4dd559b94e308586b0090bb74c2b9163e36f740a1cf53383c6949c91724950",
			"s_hs_traffic (PSK-only)": "577e01db7d08e1d8356df00beb13f51795864eb02e213c9a58acab3a3bb6592359df8a8cd0b3cff1e8c140943f4106db60547853d79791a57a348f3f088e4e56",
			"c_ap_traffic (PSK-only)": "35af7a37f2f35c50428c35486dd8776c1fcb0cb834f77ce8e690b5250754380faa40ac0e491b2741ffa2b4b7c2fd132a0a2ea56b1b48bda90b9eb4aa2ed813cc",
			"c_hs_traffic (hybrid)":   "4e725e4687624689defb14a5786f2fc4e76309c28adaa7a5fc266cb1064ab53d207c7610d43912147b58e619427870be0c5610f42bdd6b1416fa291a330f76af",
			"s_hs_traffic (hybrid)":   "ecd094adf9c38c21fca2ede44fd1abf9f0a806dcf556373d54a58ace6cde91c84ac56e31fa9a2fd1ab1c9f9195935a58134d127d60a0127222f6a439a865b6e7",
			"c_ap_traffic (hybrid)":   "9eb5243783dfd08e82d91a5aca6c843a8c6467d852d269d668cbf9fc774438fd08560544ba42f5d8935fb0cacb450a189d62f556a0cf25c7752082c56a745171",
		},
		"TLS13_TURBOSHAKE256": {
			"c_hs_traffic (PSK-only)": "6580a4de683ec8c089dac82552e74aa074d89ba694108a6fb2d8bcde0a8f1bb5042080fd9295ba0e6f0e5840c76f391441b09fdc446fc4ece571b95737ea0144",
			"s_hs_traffic (PSK-only)": "bcc778a1f97fb32f4c0668ce707bad0eaa989a81ad502dc75095c2364db5ce192aab04dc21ec3948d3c76bc9357fe1e17b03ee6db2b6421bbbde1da812ae7760",
			"c_ap_traffic (PSK-only)": "77463327a3609cfe97ee9c7523c8b071341450fba775a70a7b40bc1a947f064dadd30d198dd1d8bd7f53d29a3b5bd994d44bd065b51e728dcf1a7be5acd66c7d",
			"c_hs_traffic (hybrid)":   "2b199e54700a4992cc8df58b138564777fa58cfdb09a3cf6f474f78e81ac90e365a64b68ed75e9818dfe48b43b7b76a0b2ee7e2a596b6027ef960dddddcc63b8",
			"s_hs_traffic (hybrid)":   "ac1e433ba3fd73cb6054ddb95bc43e68a6f98346f5ed157033a38dfa07530c9f7f5163876821a5d73599f13ea12a74a1c53bb3800f845b7eae61eed000d7f237",
			"c_ap_traffic (hybrid)":   "2c3d56389ed9582a11b61d36ffeee3f78feb25fcd576fa66166314bb465534d4e0beb9c1685e60cab2084b7db9ab0f77d30ec48a8aa8d6efa90af6250157a2b8",
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
					binder := e.DeriveN([]Output{{"rbk", SecretLen}, {"drv", SecretLen}}, ctagTranscript, nil)
					h := p.FromSecret(binder[1])
					for _, component := range test.components {
						h.Absorb("shs_", component)
					}
					thSH := p.TranscriptHash([]byte("ClientHello..ServerHello"))
					hs := h.DeriveN([]Output{{"cht", SecretLen}, {"sht", SecretLen}}, ctagTranscript, thSH)
					different := map[string][]byte{
						"c_hs_traffic": hs[0],
						"s_hs_traffic": hs[1],
					}
					app := h.Ratchet()
					application := app.DeriveN([]Output{{"cat", SecretLen}, {"sat", SecretLen}, {"exs", SecretLen}},
						ctagTranscript, p.TranscriptHash([]byte("ClientHello..server Finished")))
					different["c_ap_traffic"] = application[0]
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
