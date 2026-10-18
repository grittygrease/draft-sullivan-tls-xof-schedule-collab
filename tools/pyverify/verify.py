#!/usr/bin/env python3
"""Independent re-derivation of draft-sullivan-tls-xof-schedule vectors.

Written from the draft text alone, sharing no code with the Go
generator in tools/go. It exists to satisfy the draft's own
standard for test vectors: a second implementation, written from the
document, that reproduces every value byte for byte. A disagreement is a
defect in the text, in one of the implementations, or in the vectors.

Structure is deliberately unlike the Go: plain functions over byte
strings, no deck object. SHAKE256 comes from CPython's hashlib, which is
an implementation independent of Go's. The Keccak permutation here is
written from FIPS 202 and is checked against hashlib at 24 rounds before
any vector is derived.

Output format matches the Go generator exactly, so the two can be
diffed mechanically.
"""

import hashlib
import itertools

# ---------------------------------------------------------------- Keccak

RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
ROT = [1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
       27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44]
PI = [10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
      15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1]

MASK = (1 << 64) - 1
RATE = (1600 - 512) // 8          # 136 octets, both profiles


def _rotl(x, n):
    return ((x << n) | (x >> (64 - n))) & MASK


def keccak_p(a, rounds):
    """Keccak-p[1600, rounds]: the last `rounds` of Keccak-f's 24."""
    for r in range(24 - rounds, 24):
        c = [a[i] ^ a[i + 5] ^ a[i + 10] ^ a[i + 15] ^ a[i + 20] for i in range(5)]
        for i in range(5):
            t = c[(i + 4) % 5] ^ _rotl(c[(i + 1) % 5], 1)
            for j in range(0, 25, 5):
                a[i + j] ^= t
        t = a[1]
        for i in range(24):
            j = PI[i]
            t, a[j] = a[j], _rotl(t, ROT[i])
        for j in range(0, 25, 5):
            row = a[j:j + 5]
            for i in range(5):
                a[i + j] = row[i] ^ ((~row[(i + 1) % 5] & MASK) & row[(i + 2) % 5])
        a[0] ^= RC[r]
    return a


def sponge(m, domain, outlen, rounds):
    """Rate-136 sponge with pad10*1 and a leading domain byte."""
    a = [0] * 25

    def absorb(block):
        for i in range(RATE // 8):
            a[i] ^= int.from_bytes(block[i * 8:(i + 1) * 8], "little")
        keccak_p(a, rounds)

    while len(m) >= RATE:
        absorb(m[:RATE])
        m = m[RATE:]
    last = bytearray(RATE)
    last[:len(m)] = m
    last[len(m)] = domain
    last[RATE - 1] |= 0x80
    absorb(bytes(last))

    out = b""
    while True:
        block = b"".join(a[i].to_bytes(8, "little") for i in range(RATE // 8))
        out += block[:outlen - len(out)]
        if len(out) >= outlen:
            return out[:outlen]
        keccak_p(a, rounds)


def _selftest():
    """At 24 rounds this sponge is SHAKE256; check against hashlib."""
    for n in (0, 1, 135, 136, 137, 272, 1000):
        m = bytes((i * 7) & 0xFF for i in range(n))
        for l in (1, 32, 64, 136, 300):
            mine = sponge(m, 0x1F, l, 24)
            ref = hashlib.shake_256(m).digest(l)
            assert mine == ref, f"keccak selftest failed n={n} l={l}"


# ------------------------------------------------------------- Encoding

SCHEDULE_LABEL = b"tls13 "
DTLS_SCHEDULE_LABEL = b"dtls13"       # RFC 9147, Section 5.9
SECRET_LEN = 64
FLEN = 64


def frame(x):
    assert len(x) <= 0xFFFF
    return len(x).to_bytes(2, "big") + x


def u16(n):
    return n.to_bytes(2, "big")


# ------------------------------------------------------------- Profiles

class Profile:
    def __init__(self, name, rounds, use_hashlib):
        self.name = name
        self.rounds = rounds
        self.use_hashlib = use_hashlib

    def df(self, seq, l):
        if self.use_hashlib:                      # SHAKE256(seq, 8*l)
            return hashlib.shake_256(seq).digest(l)
        return sponge(seq, 0x1F, l, self.rounds)  # TurboSHAKE256(seq, 0x1F, l)

    def th(self, x):
        return self.df(b"tls13 hash" + x, SECRET_LEN)

    def mac(self, key, message, l):
        # MAC(key, message, L) = Derive(Init(key), "mac", message, L)
        return expand(self, key, b"mac", message, l)


SHAKE256 = Profile("TLS13_SHAKE256", 24, True)
TURBOSHAKE256 = Profile("TLS13_TURBOSHAKE256", 12, False)


# ------------------------------------------------------- Deck operations

def init(sl=SCHEDULE_LABEL):
    return frame(sl)


def seeded(seed, sl=SCHEDULE_LABEL):
    # Init(seed): the seed is framed under the 4-octet tag "seed"
    return init(sl) + frame(b"seed") + frame(seed)


def absorb(d, tag, v):
    if tag not in (b"psk_", b"shs_", b"th__", b"ctx_"):
        raise ValueError("invalid Absorb tag")
    return d + frame(tag) + frame(v)


def derive(p, d, label, ctag=None, context=None, l=SECRET_LEN):
    seq = d
    if context:
        seq += frame(ctag) + frame(context)
    seq += frame(label) + frame(b"out_") + frame(u16(l))
    return p.df(seq, l)


def derive_secret(p, d, label, transcript):
    return derive(p, d, label, b"th__", transcript, SECRET_LEN)


REGISTERED_LABELS = set(b"ebk ibk rbk drv cet ees cht sht cat sat exs rss fin "
                        b"mac key upd rsp exl exp ipk eca hca snk".split())


def derive_n(p, d, descriptors, ctag=b"ctx_", context=None):
    """Encode a fixed ordered list, squeeze once, then split at sums."""
    specs = tuple(descriptors)
    if not 2 <= len(specs) <= 65535:
        raise ValueError("descriptor count must fit uint16 and exceed one")
    labels, sizes = zip(*specs)
    if len(set(labels)) != len(labels) or not set(labels) <= REGISTERED_LABELS:
        raise ValueError("labels must be distinct registered labels")
    if any(not 1 <= n <= 65535 for n in sizes) or sum(sizes) > 65535:
        raise ValueError("invalid individual or total output length")
    prefix = d
    if context:
        if ctag not in (b"ctx_", b"th__"):
            raise ValueError("invalid context tag")
        prefix += frame(ctag) + frame(context)
    terminal = frame(b"outs") + frame(u16(len(specs)))
    terminal += b"".join(frame(label) + frame(b"out_") + frame(u16(n))
                         for label, n in specs)
    stream = p.df(prefix + terminal, sum(sizes))
    bounds = [0, *itertools.accumulate(sizes)]
    return tuple(stream[a:b] for a, b in zip(bounds, bounds[1:]))


def expand(p, secret, label, context, l, sl=SCHEDULE_LABEL):
    return derive(p, seeded(secret, sl), label, b"ctx_", context, l)


def ratchet(p, d, sl=SCHEDULE_LABEL):
    residue = derive(p, d, b"drv", b"th__", None, SECRET_LEN)
    return seeded(residue, sl), residue


# ---------------------------------------------------------------- Output

def emit(p):
    def out(name, v):
        print(f"{name + ':':<34} {v.hex()}")

    def section(s):
        print(f"\n# {s}")

    th = p.th

    psk = th(b"psk")
    ss = th(b"asymmetric shared secret")
    epsk = th(b"epsk")
    th_ch0 = th(b"truncated ClientHello")
    th_ch = th(b"ClientHello")
    th_sh = th(b"ClientHello..ServerHello")
    th_pre_sf = th(b"ClientHello..before server Finished")
    th_sf = th(b"ClientHello..server Finished")
    th_cf = th(b"ClientHello..client Finished")
    inner = bytes(range(32))

    section("TranscriptHash of the stated inputs (also TranscriptHash vectors)")
    out('TranscriptHash("psk")', psk)
    out('TranscriptHash("asymmetric ...")', ss)
    out('TranscriptHash("epsk")', epsk)
    out("TH_CH0", th_ch0)
    out("TH_CH", th_ch)
    out("TH_SH", th_sh)
    out("TH_PRE_SF", th_pre_sf)
    out("TH_SF", th_sf)
    out("TH_CF", th_cf)

    section("Early stage")
    e = init()
    out("Init() sequence", e)
    n = len(e)
    e = absorb(e, b"psk_", psk)
    out('Absorb(E,"psk_",PSK) contributed', e[n:])

    c_e, early_exporter_secret = derive_n(p, e, [(b"cet", 64), (b"ees", 64)], b"th__", th_ch)
    binder_key, residue_eh = derive_n(p, e, [(b"rbk", 64), (b"drv", 64)])
    out("c_e_traffic", c_e)
    out("early_exporter_secret", early_exporter_secret)
    out("binder_key (rbk)", binder_key)

    e0 = init()
    m = len(e0)
    e0 = absorb(e0, b"psk_", b"")
    out('Absorb(E,"psk_","") contributed', e0[m:])

    section("PSK binder")
    bfk = expand(p, binder_key, b"fin", None, SECRET_LEN)
    out("finished_key (binder)", bfk)
    out("binder verify_data", p.mac(bfk, th_ch0, FLEN))

    section("External PSK binder")
    external_binder_key, _ = derive_n(
        p, e, [(b"ebk", SECRET_LEN), (b"drv", SECRET_LEN)])
    external_finished_key = expand(p, external_binder_key, b"fin",
                                   None, SECRET_LEN)
    out("binder_key (ebk)", external_binder_key)
    out("finished_key (external binder)", external_finished_key)
    out("external binder verify_data",
        p.mac(external_finished_key, th_ch0, FLEN))

    section("Handshake stage")
    h = absorb(seeded(residue_eh), b"shs_", ss)
    out("residue E->H", residue_eh)
    c_hs, s_hs = derive_n(p, h, [(b"cht", 64), (b"sht", 64)], b"th__", th_sh)
    out("c_hs_traffic", c_hs)
    out("s_hs_traffic", s_hs)

    section("Finished")
    handshake = {role: derive_n(p, seeded(secret), [(b"fin", 64), (b"key", 28)])
                 for role, secret in (("client", c_hs), ("server", s_hs))}
    out("finished_key (server)", handshake["server"][0])
    out("server verify_data", p.mac(handshake["server"][0], th_pre_sf, FLEN))
    out("finished_key (client)", handshake["client"][0])
    out("client verify_data", p.mac(handshake["client"][0], th_sf, FLEN))
    for role in handshake:
        out(f"key_block ({role} handshake)", handshake[role][1])

    section("Application stage")
    t, residue_ht = ratchet(p, h)
    out("residue H->T", residue_ht)
    c_ap, s_ap, exporter_secret = derive_n(
        p, t, [(b"cat", 64), (b"sat", 64), (b"exs", 64)], b"th__", th_sf)
    resumption_secret = derive_secret(p, t, b"rss", th_cf)
    out("c_ap_traffic", c_ap)
    out("s_ap_traffic", s_ap)
    out("exporter_secret", exporter_secret)
    out("resumption_secret", resumption_secret)

    section("Record keys (Nk=16, Nn=12 of TLS_AES_128_GCM)")
    application = {role: derive_n(p, seeded(secret), [(b"upd", 64), (b"key", 28)])
                   for role, secret in (("client", c_ap), ("server", s_ap))}
    kb = application["client"][1]
    out("key_block", kb)
    out("write_key = key_block[0..16]", kb[:16])
    out("write_iv  = key_block[16..28]", kb[16:])
    out("key_block (server application)", application["server"][1])
    out("key_block (early)", expand(p, c_e, b"key", None, 28))

    section("Key update")
    out("app_traffic_secret_1", application["client"][0])
    out("server_app_traffic_secret_1", application["server"][0])
    generation_one = {role: derive_n(p, seeded(pair[0]), [(b"upd", 64), (b"key", 28)])
                      for role, pair in application.items()}
    for role, pair in generation_one.items():
        out(f"key_block ({role} generation 1)", pair[1])
    out("app_traffic_secret_2 (lookahead)", generation_one["client"][0])
    out("server_app_traffic_secret_2 (lookahead)", generation_one["server"][0])

    section("Resumption")
    out("resumption_psk (nonce)",
        expand(p, resumption_secret, b"rsp", b"nonce", SECRET_LEN))
    out("resumption_psk (empty nonce)",
        expand(p, resumption_secret, b"rsp", None, SECRET_LEN))

    section("Exporters")
    exporter_label_secret = expand(p, exporter_secret, b"exl",
                                   b"test label", SECRET_LEN)
    early_exporter_label_secret = expand(p, early_exporter_secret, b"exl",
                                         b"test label", SECRET_LEN)
    out("exporter_label_secret", exporter_label_secret)
    out("TLS-Exporter (32 octets)",
        expand(p, exporter_label_secret, b"exp", th(b"test context"), 32))
    out("early_exporter_label_secret", early_exporter_label_secret)
    out("early exporter (32 octets)",
        expand(p, early_exporter_label_secret, b"exp", th(b"test context"), 32))

    section("PSK import")
    # RFC 9258 ImportedIdentity, TLS presentation language:
    #   opaque external_identity<1..2^16-1>;
    #   opaque context<0..2^16-1>;
    #   uint16 target_protocol;   0x0304 = TLS 1.3
    #   uint16 target_kdf;        PLACEHOLDER in Specification Required
    #                             space; must not be shipped.
    target_kdf = {"TLS13_SHAKE256": 0x0101,
                  "TLS13_TURBOSHAKE256": 0x0100}[p.name]
    ext = b"external psk identity"
    ii = (len(ext).to_bytes(2, "big") + ext
          + (0).to_bytes(2, "big")
          + (0x0304).to_bytes(2, "big")
          + target_kdf.to_bytes(2, "big"))
    out("ImportedIdentity", ii)
    ipsk = expand(p, epsk, b"ipk", th(ii), SECRET_LEN)
    out("ipsk (ipk)", ipsk)

    section("ECH acceptance confirmations")
    out("accept_confirmation",
        expand(p, inner, b"eca", th(b"ech_conf_messages"), 8))
    out("hrr_accept_confirmation",
        expand(p, inner, b"hca",
               th(b"hrr_ech_conf_messages"), 8))

    section('DTLS 1.3 (schedule_label "dtls13")')
    D = DTLS_SCHEDULE_LABEL
    de = init(D)
    out("Init() sequence (DTLS)", de)
    de = absorb(de, b"psk_", psk)
    _, d_early_residue = derive_n(p, de, [(b"rbk", 64), (b"drv", 64)])
    dh = absorb(seeded(d_early_residue, D), b"shs_", ss)
    d_c_hs, _ = derive_n(p, dh, [(b"cht", 64), (b"sht", 64)], b"th__", th_sh)
    out("c_hs_traffic (DTLS)", d_c_hs)
    dt, _ = ratchet(p, dh, D)
    d_c_ap, _, _ = derive_n(p, dt, [(b"cat", 64), (b"sat", 64), (b"exs", 64)], b"th__", th_sf)
    out("c_ap_traffic (DTLS)", d_c_ap)
    _, dtls_key_block = derive_n(p, seeded(d_c_ap, D), [(b"upd", 64), (b"key", 28)])
    out("key_block (DTLS)", dtls_key_block)
    out("sn_key (DTLS, Nk=16)", expand(p, d_c_ap, b"snk", None, 16, D))
    out("sn_key (DTLS handshake, Nk=16)", expand(p, d_c_hs, b"snk", None, 16, D))

    for name, components in [
            ("PSK-only", []),
            ("hybrid", [th(b"hybrid component 1"), th(b"hybrid component 2")])]:
        section(name)
        early = absorb(init(), b"psk_", psk)
        _, residue = derive_n(p, early, [(b"rbk", 64), (b"drv", 64)])
        handshake = seeded(residue)
        for component in components:
            handshake = absorb(handshake, b"shs_", component)
        c_hs, s_hs = derive_n(
            p, handshake, [(b"cht", 64), (b"sht", 64)], b"th__", th_sh)
        out(f"c_hs_traffic ({name})", c_hs)
        out(f"s_hs_traffic ({name})", s_hs)
        application, _ = ratchet(p, handshake)
        c_ap, _, _ = derive_n(
            p, application, [(b"cat", 64), (b"sat", 64), (b"exs", 64)],
            b"th__", th_sf)
        out(f"c_ap_traffic ({name})", c_ap)

    section("Imported PSK and no-PSK variants")
    imported_binder, imported_residue = derive_n(
        p, absorb(init(), b"psk_", ipsk), [(b"ibk", 64), (b"drv", 64)])
    out("binder_key (ibk)", imported_binder)
    imported_fk = expand(p, imported_binder, b"fin", None, SECRET_LEN)
    out("finished_key (imported binder)", imported_fk)
    out("imported binder verify_data", p.mac(imported_fk, th_ch0, FLEN))
    out("residue E->H (imported)", imported_residue)
    imported_h = absorb(seeded(imported_residue), b"shs_", ss)
    imported_secrets = derive_n(
        p, imported_h, [(b"cht", 64), (b"sht", 64)], b"th__", th_sh)
    for role, value in zip(("c", "s"), imported_secrets):
        out(f"{role}_hs_traffic (imported)", value)
    absent_h, absent_residue = ratchet(p, e0)
    out("residue E->H (no PSK)", absent_residue)
    absent_secrets = derive_n(
        p, absorb(absent_h, b"shs_", ss), [(b"cht", 64), (b"sht", 64)], b"th__", th_sh)
    for role, value in zip(("c", "s"), absent_secrets):
        out(f"{role}_hs_traffic (no PSK)", value)

    section("Exported Authenticator (server)")
    # RFC 9261 under a KDF of this document: exporter values of 64 octets,
    # TranscriptHash as the authenticator hash, MAC in place of HMAC.
    # The draft supplies this DER certificate; TLS lengths are derived here.
    cert_data = bytes.fromhex(
        "3081c9307da003020102020101300506032b6570300f310d300b06035504030c"
        "0474657374301e170d3236303130313030303030305a170d3336303130313030"
        "303030305a300f310d300b06035504030c0474657374302a300506032b657003"
        "210003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc86641255"
        "31b8300506032b657003410023c815b130eac1285714a01f2b99ffb720c5b234"
        "06ff492bbf9a4852f6e6c99f000959f0a2886763e10679390eee02d4e48d6f38"
        "2729357fc52bde69e6430f07")
    cert_context = b"\xa5"
    # CertificateEntry (209 octets): 0000cc (DER length 204), DER, 0000
    # (empty extensions). Certificate body (214 octets): 01a5 (context),
    # 0000d1 (certificate_list length 209), CertificateEntry.
    cert_entry = len(cert_data).to_bytes(3, "big") + cert_data + frame(b"")
    cert_body = (len(cert_context).to_bytes(1, "big") + cert_context
                 + len(cert_entry).to_bytes(3, "big") + cert_entry)
    # Handshake header 0b0000d6: Certificate type 11, body length 214.
    certificate = b"\x0b" + len(cert_body).to_bytes(3, "big") + cert_body
    # Fixed test signature, not a real signature over the content: these
    # vectors cover transcript hashing and Finished, not signature verification.
    # CertificateVerify body (68 octets): 0807 (ed25519), 0040 (signature
    # length 64), 64 zero octets. Header 0f000044: type 15, body length 68.
    cv_body = u16(0x0807) + frame(bytes(64))
    certificate_verify = b"\x0f" + len(cv_body).to_bytes(3, "big") + cv_body
    def tls_exporter(label, context, length):
        label_secret = expand(p, exporter_secret, b"exl", label, SECRET_LEN)
        return expand(p, label_secret, b"exp", th(context), length)
    hc = tls_exporter(
        b"EXPORTER-server authenticator handshake context", b"", SECRET_LEN)
    fk = tls_exporter(
        b"EXPORTER-server authenticator finished key", b"", SECRET_LEN)
    out("Handshake Context", hc)
    out("Finished MAC Key", fk)
    out("TranscriptHash(HC || Certificate)", th(hc + certificate))
    out("Finished", p.mac(fk, th(hc + certificate + certificate_verify), FLEN))
    # Empty authenticator (RFC 9261 Section 6): no CertificateVerify, and
    # a Certificate message with no CertificateEntries, serialized and
    # hashed but not sent. The authenticator request is the ASCII stand-in
    # "CertificateRequest"; the Certificate is the real serialization with
    # an empty certificate_request_context:
    #   msg_type 11, length 4, context<0..255> = 00, certificate_list = 000000
    empty_cert = bytes.fromhex("0b00000400000000")
    out("Finished (empty authenticator)",
        p.mac(fk, th(hc + b"CertificateRequest" + empty_cert), FLEN))


if __name__ == "__main__":
    _selftest()
    for prof in (SHAKE256, TURBOSHAKE256):
        print(f"\n================ {prof.name} ================")
        emit(prof)
