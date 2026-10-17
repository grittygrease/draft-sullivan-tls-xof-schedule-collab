// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"fmt"
)

// main emits the Test Vectors appendix values for both profiles, in the
// "name: hex" form tools/vectors_check.py compares. The stated inputs,
// including the Exported Authenticator handshake messages, are all
// reproducible from the draft text alone.
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

	early := e.DeriveN([]Output{{"cet", SecretLen}, {"ees", SecretLen}}, ctagTranscript, thCH)
	cETraffic, earlyExporterSecret := early[0], early[1]
	binder := e.DeriveN([]Output{{"rbk", SecretLen}, {"drv", SecretLen}}, ctagTranscript, nil)
	binderKey, residueEH := binder[0], binder[1]
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
	externalBundle := e.DeriveN([]Output{{"ebk", SecretLen}, {"drv", SecretLen}}, ctagTranscript, nil)
	externalBinderKey := externalBundle[0]
	externalBinderFK := p.FromSecret(externalBinderKey).Expand("fin", nil, SecretLen)
	externalBinderVD := p.MAC(externalBinderFK, thCH0, FLen)
	out("binder_key (ebk)", externalBinderKey)
	out("finished_key (external binder)", externalBinderFK)
	out("external binder verify_data", externalBinderVD)

	// ---- handshake stage -----------------------------------------------
	section("Handshake stage")
	out("residue E->H", residueEH)
	h := p.FromSecret(residueEH)
	e.Destroy()
	h.Absorb("shs_", ss)
	hs := h.DeriveN([]Output{{"cht", SecretLen}, {"sht", SecretLen}}, ctagTranscript, thSH)
	cHsTraffic, sHsTraffic := hs[0], hs[1]
	out("c_hs_traffic", cHsTraffic)
	out("s_hs_traffic", sHsTraffic)

	// ---- Finished ------------------------------------------------------
	section("Finished")
	clientHS := p.FromSecret(cHsTraffic).DeriveN([]Output{{"fin", SecretLen}, {"key", 28}}, ctagContext, nil)
	serverHS := p.FromSecret(sHsTraffic).DeriveN([]Output{{"fin", SecretLen}, {"key", 28}}, ctagContext, nil)
	finFK := serverHS[0]
	finVD := p.MAC(finFK, thPreSF, FLen)
	out("finished_key (server)", finFK)
	out("server verify_data", finVD)
	out("finished_key (client)", clientHS[0])
	out("client verify_data", p.MAC(clientHS[0], thSF, FLen))
	out("key_block (client handshake)", clientHS[1])
	out("key_block (server handshake)", serverHS[1])

	// ---- application stage ---------------------------------------------
	section("Application stage")
	refH := p.Init()
	refH.seed(residueEH)
	refH.Absorb("shs_", ss)
	residueHT := refH.derive("drv", ctagTranscript, nil, SecretLen)
	out("residue H->T", residueHT)

	tt := h.Ratchet()
	app := tt.DeriveN([]Output{{"cat", SecretLen}, {"sat", SecretLen}, {"exs", SecretLen}}, ctagTranscript, thSF)
	cApTraffic, sApTraffic, exporterSecret := app[0], app[1], app[2]
	resumptionSecret := tt.DeriveSecret("rss", thCF)
	out("c_ap_traffic", cApTraffic)
	out("s_ap_traffic", sApTraffic)
	out("exporter_secret", exporterSecret)
	out("resumption_secret", resumptionSecret)

	// ---- retained-secret derivations ------------------------------------
	section("Record keys (Nk=16, Nn=12 of TLS_AES_128_GCM)")
	clientApp := p.FromSecret(cApTraffic).DeriveN([]Output{{"upd", SecretLen}, {"key", 28}}, ctagContext, nil)
	serverApp := p.FromSecret(sApTraffic).DeriveN([]Output{{"upd", SecretLen}, {"key", 28}}, ctagContext, nil)
	keyBlock := clientApp[1]
	out("key_block", keyBlock)
	out("write_key = key_block[0..16]", keyBlock[:16])
	out("write_iv  = key_block[16..28]", keyBlock[16:])
	out("key_block (server application)", serverApp[1])
	out("key_block (early)", p.FromSecret(cETraffic).Expand("key", nil, 28))

	section("Key update")
	upd := clientApp[0]
	out("app_traffic_secret_1", upd)
	out("server_app_traffic_secret_1", serverApp[0])
	clientNext := p.FromSecret(upd).DeriveN([]Output{{"upd", SecretLen}, {"key", 28}}, ctagContext, nil)
	serverNext := p.FromSecret(serverApp[0]).DeriveN([]Output{{"upd", SecretLen}, {"key", 28}}, ctagContext, nil)
	out("key_block (client generation 1)", clientNext[1])
	out("key_block (server generation 1)", serverNext[1])
	out("app_traffic_secret_2 (lookahead)", clientNext[0])
	out("server_app_traffic_secret_2 (lookahead)", serverNext[0])

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
	ipsk := p.FromSecret(epsk).Expand("ipk",
		p.TranscriptHash(ii), SecretLen)
	out("ipsk (ipk)", ipsk)

	section("ECH acceptance confirmations")
	d := p.FromSecret(inner)
	accept := d.Expand("eca",
		p.TranscriptHash([]byte("ech_conf_messages")), 8)
	hrr := d.Expand("hca",
		p.TranscriptHash([]byte("hrr_ech_conf_messages")), 8)
	out("accept_confirmation", accept)
	out("hrr_accept_confirmation", hrr)

	// ---- DTLS 1.3 ------------------------------------------------------
	section("DTLS 1.3 (schedule_label \"dtls13\")")
	de := p.InitDTLS()
	out("Init() sequence (DTLS)", de.seq)
	de.Absorb("psk_", psk)
	db := de.DeriveN([]Output{{"rbk", SecretLen}, {"drv", SecretLen}}, ctagTranscript, nil)
	dh := p.FromSecretDTLS(db[1])
	de.Destroy()
	dh.Absorb("shs_", ss)
	dHS := dh.DeriveN([]Output{{"cht", SecretLen}, {"sht", SecretLen}}, ctagTranscript, thSH)
	dCHs := dHS[0]
	out("c_hs_traffic (DTLS)", dCHs)
	dt := dh.Ratchet()
	dApp := dt.DeriveN([]Output{{"cat", SecretLen}, {"sat", SecretLen}, {"exs", SecretLen}}, ctagTranscript, thSF)
	dCAp := dApp[0]
	out("c_ap_traffic (DTLS)", dCAp)
	dRecord := p.FromSecretDTLS(dCAp).DeriveN([]Output{{"upd", SecretLen}, {"key", 28}}, ctagContext, nil)
	dKB := dRecord[1]
	out("key_block (DTLS)", dKB)
	out("sn_key (DTLS, Nk=16)", p.FromSecretDTLS(dCAp).Expand("snk", nil, 16))
	out("sn_key (DTLS handshake, Nk=16)", p.FromSecretDTLS(dCHs).Expand("snk", nil, 16))

	section("Imported PSK and no-PSK variants")
	importedEarly := p.Init()
	importedEarly.Absorb("psk_", ipsk)
	importedBundle := importedEarly.DeriveN([]Output{{"ibk", SecretLen}, {"drv", SecretLen}}, ctagTranscript, nil)
	out("binder_key (ibk)", importedBundle[0])
	importedFK := p.FromSecret(importedBundle[0]).Expand("fin", nil, SecretLen)
	out("finished_key (imported binder)", importedFK)
	out("imported binder verify_data", p.MAC(importedFK, thCH0, FLen))
	out("residue E->H (imported)", importedBundle[1])
	importedH := p.FromSecret(importedBundle[1])
	importedH.Absorb("shs_", ss)
	importedHS := importedH.DeriveN([]Output{{"cht", SecretLen}, {"sht", SecretLen}}, ctagTranscript, thSH)
	out("c_hs_traffic (imported)", importedHS[0])
	out("s_hs_traffic (imported)", importedHS[1])
	noPSKResidue := e0.DeriveSecret("drv", nil)
	out("residue E->H (no PSK)", noPSKResidue)
	noPSKH := e0.Ratchet()
	noPSKH.Absorb("shs_", ss)
	noPSKHS := noPSKH.DeriveN([]Output{{"cht", SecretLen}, {"sht", SecretLen}}, ctagTranscript, thSH)
	out("c_hs_traffic (no PSK)", noPSKHS[0])
	out("s_hs_traffic (no PSK)", noPSKHS[1])

	// ---- Exported Authenticator ----------------------------------------
	// RFC 9261 under a KDF of the draft: 64-octet exporter values,
	// TranscriptHash as the authenticator hash, MAC in place of HMAC.
	section("Exported Authenticator (server)")
	tlsExporter := func(label, context string, length int) []byte {
		labelSecret := p.FromSecret(exporterSecret).Expand("exl",
			[]byte(label), SecretLen)
		return p.FromSecret(labelSecret).Expand("exp",
			p.TranscriptHash([]byte(context)), length)
	}
	hc := tlsExporter("EXPORTER-server authenticator handshake context", "", SecretLen)
	fk := tlsExporter("EXPORTER-server authenticator finished key", "", SecretLen)
	out("Handshake Context", hc)
	out("Finished MAC Key", fk)
	cat := func(parts ...[]byte) []byte {
		var b []byte
		for _, x := range parts {
			b = append(b, x...)
		}
		return b
	}
	// The appendix's self-signed Ed25519 X.509v3 test certificate, CN=test.
	// This DER input is specified in the draft; TLS framing is built here.
	certDER, err := hex.DecodeString(
		"3081c9307da003020102020101300506032b6570300f310d300b06035504030c" +
			"0474657374301e170d3236303130313030303030305a170d3336303130313030" +
			"303030305a300f310d300b06035504030c0474657374302a300506032b657003" +
			"210003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc86641255" +
			"31b8300506032b657003410023c815b130eac1285714a01f2b99ffb720c5b234" +
			"06ff492bbf9a4852f6e6c99f000959f0a2886763e10679390eee02d4e48d6f38" +
			"2729357fc52bde69e6430f07")
	if err != nil {
		panic(err)
	}
	be24 := func(n int) []byte { return []byte{byte(n >> 16), byte(n >> 8), byte(n)} }
	// CertificateEntry: cert_data<1..2^24-1> = 0000cc || 204 DER octets,
	// extensions<0..2^16-1> = 0000; total 209 (0xd1) octets.
	entry := cat(be24(len(certDER)), certDER, be16(0))
	// Certificate: msg_type 11, length 214 (0000d6),
	// context<0..255> = 01a5, certificate_list = 0000d1 || entry.
	// RFC 9261 permits a context in unsolicited server authenticators;
	// this one-octet context is fixed solely for the test vector.
	certBody := cat([]byte{1, 0xa5}, be24(len(entry)), entry)
	cert := cat([]byte{11}, be24(len(certBody)), certBody)
	// CertificateVerify: msg_type 15, length 68 (000044),
	// algorithm = 0807 (ed25519), signature<0..65535> = 0040 || 64 zeros.
	// The signature is a fixed test value, not a real signature over the
	// content. These vectors do not verify signatures.
	signature := make([]byte, 64)
	cvBody := cat(be16(0x0807), be16(len(signature)), signature)
	certVerify := cat([]byte{15}, be24(len(cvBody)), cvBody)
	out("TranscriptHash(HC || Certificate)",
		p.TranscriptHash(cat(hc, cert)))
	out("Finished", p.MAC(fk,
		p.TranscriptHash(cat(hc, cert, certVerify)), FLen))
	// Empty authenticator (RFC 9261 Section 6): no CertificateVerify, and
	// a Certificate message with no CertificateEntries, serialized and
	// hashed but not sent. The authenticator request is the ASCII
	// stand-in "CertificateRequest"; the Certificate is the real
	// serialization with an empty certificate_request_context:
	// msg_type 11, length 4, context<0..255> = 00, certificate_list = 000000.
	emptyCert := []byte{0x0b, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00}
	out("Finished (empty authenticator)",
		p.MAC(fk, p.TranscriptHash(cat(hc, []byte("CertificateRequest"), emptyCert)), FLen))

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
		binder := e.DeriveN([]Output{{"rbk", SecretLen}, {"drv", SecretLen}}, ctagTranscript, nil)
		h := p.FromSecret(binder[1])
		for _, component := range fixture.components {
			h.Absorb("shs_", component)
		}
		hs := h.DeriveN([]Output{{"cht", SecretLen}, {"sht", SecretLen}}, ctagTranscript, thSH)
		out("c_hs_traffic ("+fixture.name+")", hs[0])
		out("s_hs_traffic ("+fixture.name+")", hs[1])
		t := h.Ratchet()
		app := t.DeriveN([]Output{{"cat", SecretLen}, {"sat", SecretLen}, {"exs", SecretLen}}, ctagTranscript, thSF)
		out("c_ap_traffic ("+fixture.name+")", app[0])
		t.Destroy()
	}
}
