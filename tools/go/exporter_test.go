package main

import (
	"os"
	"strings"
	"testing"
)

// Pin explicit-frame results for both exporter stages and the raw external
// PSK binder, using the appendix fixtures in both profiles.
func TestTwoStageExporterAndExternalBinderVectors(t *testing.T) {
	want := map[string]map[string]string{
		"TLS13_SHAKE256": {
			"exporter_label_secret":          "d4b6b6351c8c08da5843bfb0e39c4ad2b2686ff71d8baa1f05c0e9d3fa06825cbab3553a3e9d0dd7a71d3c712678b6f6f06d57e37180217d97e26bc7943072a5",
			"TLS-Exporter (32 octets)":       "a9c3287164d223f7b88d8ddd805a7159f082146cbe44ed5987bd5195f6d34293",
			"early_exporter_label_secret":    "cc8b50a689ea0e42f9e580877c58701c9ba03b98ad5e783c8bf4b3d84ecaf17584eb76cd06f61cfc66ea7f669ee60b337da2c6b1cb4e555851887f501c00b9d2",
			"early exporter (32 octets)":     "213a0a9a2b99554845a69ef666fd1a9d2fc640819360af5a3958d82f1df79d00",
			"binder_key (ebk)":               "d86efa2938c7867973463e6885c5c5db55b9162ff5b3cf1080c92392387916cbb29b4bb5a1ba6821c71a72908220abaa82ce910e750411ac4dc74f6250a38d83",
			"finished_key (external binder)": "5d4d86dbcf32afaa81c518cc453565303379a4c2b1719477a1bbbec67673fedefa7c609ad40b0eac4c87f7a5b476eef33fd31bc5bc87477df67336205e15773c",
			"external binder verify_data":    "d62b772fd7784240711c49b856e82a2b442fdfe4f4865c416b0b32f72dfca84f7832f9a214af2f34bc21948dfdc44192edcbf4571ec7f82093c80ab027c84236",
		},
		"TLS13_TURBOSHAKE256": {
			"exporter_label_secret":          "a6aefd256a6bc0fd6adbff6c882f20aa5a84e2be73e50ff3f340149ee5a89bb5f9c104a1319076860dcb193d51098d670f606e92c61a299b1b81089cba3105ef",
			"TLS-Exporter (32 octets)":       "ed7f44dde38ef5fe6441560aed075c78dfe079a2a37a2af988f35a2ef2f0da2d",
			"early_exporter_label_secret":    "1c3807bfd182fbc9d63f2e9d272c1c06b5ed593c4d5cc43befdad754e6d7c528814e81c1a41be9a0b1c1d527ed29681792c7b4cb750430b2b0592ee76f1abddc",
			"early exporter (32 octets)":     "844ea5d8b5ff06f5ec6c0b916019b73c2cc25aa50e78c31cb7764519510f6490",
			"binder_key (ebk)":               "43bc3e3fbce124364f99b5e78ba81f29a3d61575b776cc99a33cbac7adfdc745d201aaa567856dd4da89d7f260899c5dfafe1ec3e1e0bd5c066b94e2b66940f4",
			"finished_key (external binder)": "fd2e6599c6c60a42f2e9a2d72e59aa21bae1a9cd7b657d5eaf4dae81f73c6e103d5ba7be11152ce8635f8e8d79a430472d2ee8e89ed96a7264da0d3ffbc0d668",
			"external binder verify_data":    "6285bd415678e51f90e868a489d40142b0baa93a8dd63a566e5849882b26ba5a4ef3fb8062c16e883c758d062757ea353f75b2c465b36e4f607a83850dcf5d10",
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
		})
	}
}
