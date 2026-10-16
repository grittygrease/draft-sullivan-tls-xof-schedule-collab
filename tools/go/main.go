// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"fmt"
)

// main emits the Test Vectors appendix values for both profiles, in the
// "name: hex" form tools/vectors_check.py compares. Every stated input is
// either a short ASCII string or TranscriptHash of one, so the whole set
// is reproducible from the draft text alone.
//
// Run: go run . (from tools/go)
func main() {
	for _, p := range []*Profile{SHAKE256, TURBOSHAKE256} {
		fmt.Printf("\n================ %s ================\n", p.Name)
		emitVectors(p)
	}
}

func emitVectors(p *Profile) {
	out := func(name string, v []byte) {
		fmt.Printf("%-34s %s\n", name+":", hex.EncodeToString(v))
	}
	section := func(s string) { fmt.Printf("\n# %s\n", s) }

	// ---- stated inputs -------------------------------------------------
	th := func(s string) []byte { return p.TranscriptHash([]byte(s)) }

	psk := th("psk")
	ss := th("asymmetric shared secret")
	epsk := th("epsk")

	thCH0 := th("truncated ClientHello")
	thCH := th("ClientHello")
	thSH := th("ClientHello..ServerHello")
	thPreSF := th("ClientHello..before server Finished")
	thSF := th("ClientHello..server Finished")
	thCF := th("ClientHello..client Finished")

	// ClientHelloInner.random: the 32 octets 0x00..0x1f.
	inner := make([]byte, 32)
	for i := range inner {
		inner[i] = byte(i)
	}

	section("TranscriptHash of the stated inputs (also TranscriptHash vectors)")
	out("TranscriptHash(\"psk\")", psk)
	out("TranscriptHash(\"asymmetric ...\")", ss)
	out("TranscriptHash(\"epsk\")", epsk)
	out("TH_CH0", thCH0)
	out("TH_CH", thCH)
	out("TH_SH", thSH)
	out("TH_PRE_SF", thPreSF)
	out("TH_SF", thSF)
	out("TH_CF", thCF)

	// ---- early stage ---------------------------------------------------
	section("Early stage")
	e := p.Init()
	out("Init() sequence", e.seq)
	n := len(e.seq)
	e.Absorb("psk_", psk)
	out("Absorb(E,\"psk_\",PSK) contributed", e.seq[n:])

	cETraffic := e.DeriveSecret("cet", thCH)
	earlyExporterSecret := e.DeriveSecret("ees", thCH)
	binderKey := e.DeriveSecret("rbk", nil) // no context
	out("c_e_traffic", cETraffic)
	out("early_exporter_secret", earlyExporterSecret)
	out("binder_key (rbk)", binderKey)

	// The absent-PSK variant, whose absorbed bytes the draft pins.
	e0 := p.Init()
	m := len(e0.seq)
	e0.Absorb("psk_", []byte(""))
	out("Absorb(E,\"psk_\",\"\") contributed", e0.seq[m:])

	// ---- PSK binder ----------------------------------------------------
	section("PSK binder")
	binderFK := p.FromSecret(binderKey).Expand("fin", nil, SecretLen)
	binderVD := p.MAC(binderFK, thCH0, FLen)
	out("finished_key (binder)", binderFK)
	out("binder verify_data", binderVD)

	section("External PSK binder")
	externalBinderKey := e.DeriveSecret("ebk", nil)
	externalBinderFK := p.FromSecret(externalBinderKey).Expand("fin", nil, SecretLen)
	externalBinderVD := p.MAC(externalBinderFK, thCH0, FLen)
	out("binder_key (ebk)", externalBinderKey)
	out("finished_key (external binder)", externalBinderFK)
	out("external binder verify_data", externalBinderVD)

	// ---- handshake stage -----------------------------------------------
	section("Handshake stage")
	refE := p.Init()
	refE.Absorb("psk_", psk)
	residueEH := refE.derive("drv", ctagTranscript, nil, SecretLen)
	out("residue E->H", residueEH)

	h := e.Ratchet()
	h.Absorb("shs_", ss)
	cHsTraffic := h.DeriveSecret("cht", thSH)
	sHsTraffic := h.DeriveSecret("sht", thSH)
	out("c_hs_traffic", cHsTraffic)
	out("s_hs_traffic", sHsTraffic)

	// ---- Finished ------------------------------------------------------
	section("Finished")
	finFK := p.FromSecret(sHsTraffic).Expand("fin", nil, SecretLen)
	finVD := p.MAC(finFK, thPreSF, FLen)
	out("finished_key (server)", finFK)
	out("server verify_data", finVD)

	// ---- application stage ---------------------------------------------
	section("Application stage")
	refH := p.Init()
	refH.seed(residueEH)
	refH.Absorb("shs_", ss)
	residueHT := refH.derive("drv", ctagTranscript, nil, SecretLen)
	out("residue H->T", residueHT)

	tt := h.Ratchet()
	cApTraffic := tt.DeriveSecret("cat", thSF)
	sApTraffic := tt.DeriveSecret("sat", thSF)
	exporterSecret := tt.DeriveSecret("exs", thSF)
	resumptionSecret := tt.DeriveSecret("rss", thCF)
	out("c_ap_traffic", cApTraffic)
	out("s_ap_traffic", sApTraffic)
	out("exporter_secret", exporterSecret)
	out("resumption_secret", resumptionSecret)

	// ---- retained-secret derivations ------------------------------------
	section("Record keys (Nk=16, Nn=12 of TLS_AES_128_GCM)")
	keyBlock := p.FromSecret(cApTraffic).Expand("key", nil, 16+12)
	out("key_block", keyBlock)
	out("write_key = key_block[0..16]", keyBlock[:16])
	out("write_iv  = key_block[16..28]", keyBlock[16:])

	section("Key update")
	upd := p.FromSecret(cApTraffic).Expand("upd", nil, SecretLen)
	out("app_traffic_secret_1", upd)

	section("Resumption")
	rpsk := p.FromSecret(resumptionSecret).Expand("rsp", []byte("nonce"), SecretLen)
	// An empty context is omitted rather than framed, so an empty
	// ticket_nonce and an absent one are the same input.
	rpskEmpty := p.FromSecret(resumptionSecret).Expand("rsp", nil, SecretLen)
	out("resumption_psk (nonce)", rpsk)
	out("resumption_psk (empty nonce)", rpskEmpty)

	section("Exporters")
	exporterLabelSecret := p.FromSecret(exporterSecret).Expand("exl",
		[]byte("test label"), SecretLen)
	exporter := p.FromSecret(exporterLabelSecret).Expand("exp",
		p.TranscriptHash([]byte("test context")), 32)
	earlyExporterLabelSecret := p.FromSecret(earlyExporterSecret).Expand("exl",
		[]byte("test label"), SecretLen)
	earlyExporter := p.FromSecret(earlyExporterLabelSecret).Expand("exp",
		p.TranscriptHash([]byte("test context")), 32)
	out("exporter_label_secret", exporterLabelSecret)
	out("TLS-Exporter (32 octets)", exporter)
	out("early_exporter_label_secret", earlyExporterLabelSecret)
	out("early exporter (32 octets)", earlyExporter)

	section("PSK import")
	// RFC 9258 ImportedIdentity, in the TLS presentation language:
	//   opaque external_identity<1..2^16-1>;
	//   opaque context<0..2^16-1>;
	//   uint16 target_protocol;   0x0304 = TLS 1.3
	//   uint16 target_kdf;        placeholder, see Profile.TargetKDF
	be16 := func(n int) []byte { return []byte{byte(n >> 8), byte(n)} }
	ext := []byte("external psk identity")
	ii := append(be16(len(ext)), ext...)
	ii = append(ii, be16(0)...)      // empty context
	ii = append(ii, be16(0x0304)...) // target_protocol
	ii = append(ii, be16(int(p.TargetKDF))...)
	out("ImportedIdentity", ii)
	ipsk := p.FromSecret(epsk).Expand("ipk", p.TranscriptHash(ii), SecretLen)
	out("ipsk (ipk)", ipsk)

	section("Imported PSK binder")
	importedE := p.Init()
	importedE.Absorb("psk_", ipsk)
	importedBinderKey := importedE.DeriveSecret("ibk", nil)
	importedBinderFK := p.FromSecret(importedBinderKey).Expand("fin", nil, SecretLen)
	importedBinderVD := p.MAC(importedBinderFK, thCH0, FLen)
	out("binder_key (ibk)", importedBinderKey)
	out("finished_key (imported binder)", importedBinderFK)
	out("imported binder verify_data", importedBinderVD)

	section("ECH acceptance confirmations")
	d := p.FromSecret(inner)
	accept := d.Expand("eca",
		p.TranscriptHash([]byte("ech_conf_messages")), 8)
	hrr := d.Expand("hca",
		p.TranscriptHash([]byte("hrr_ech_conf_messages")), 8)
	out("accept_confirmation", accept)
	out("hrr_accept_confirmation", hrr)

	// Each fixture starts a fresh schedule with the same PSK/checkpoints.
	for _, fixture := range []struct {
		name       string
		components [][]byte
	}{
		{"PSK-only", nil},
		{"hybrid", [][]byte{th("hybrid component 1"), th("hybrid component 2")}},
	} {
		section(fixture.name)
		e := p.Init()
		e.Absorb("psk_", psk)
		h := e.Ratchet()
		for _, component := range fixture.components {
			h.Absorb("shs_", component)
		}
		out("c_hs_traffic ("+fixture.name+")", h.DeriveSecret("cht", thSH))
		out("s_hs_traffic ("+fixture.name+")", h.DeriveSecret("sht", thSH))
		t := h.Ratchet()
		out("c_ap_traffic ("+fixture.name+")", t.DeriveSecret("cat", thSF))
		t.Destroy()
	}
}
