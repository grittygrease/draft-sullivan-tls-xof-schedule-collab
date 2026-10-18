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

def init():
    return frame(SCHEDULE_LABEL)


def seeded(seed):
    # Init(seed): the seed is framed under the 4-octet tag "seed"
    return init() + frame(b"seed") + frame(seed)


def absorb(d, tag, v):
    return d + frame(tag) + frame(v)


def derive(p, d, label, ctag=None, context=None, l=SECRET_LEN):
    seq = d
    if context:
        seq += frame(ctag) + frame(context)
    seq += frame(label) + frame(b"out_") + frame(u16(l))
    return p.df(seq, l)


def derive_secret(p, d, label, transcript):
    return derive(p, d, label, b"th__", transcript, SECRET_LEN)


def expand(p, secret, label, context, l):
    return derive(p, seeded(secret), label, b"ctx_", context, l)


def ratchet(p, d):
    residue = derive(p, d, b"drv", b"th__", None, SECRET_LEN)
    return seeded(residue), residue


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

    c_e = derive_secret(p, e, b"cet", th_ch)
    early_exporter_secret = derive_secret(p, e, b"ees", th_ch)
    binder_key = derive(p, e, b"rbk")
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
    external_binder_key = derive(p, e, b"ebk")
    external_finished_key = expand(p, external_binder_key, b"fin",
                                   None, SECRET_LEN)
    out("binder_key (ebk)", external_binder_key)
    out("finished_key (external binder)", external_finished_key)
    out("external binder verify_data",
        p.mac(external_finished_key, th_ch0, FLEN))

    section("Handshake stage")
    h, residue_eh = ratchet(p, e)
    out("residue E->H", residue_eh)
    h = absorb(h, b"shs_", ss)
    c_hs = derive_secret(p, h, b"cht", th_sh)
    s_hs = derive_secret(p, h, b"sht", th_sh)
    out("c_hs_traffic", c_hs)
    out("s_hs_traffic", s_hs)

    section("Finished")
    ffk = expand(p, s_hs, b"fin", None, SECRET_LEN)
    out("finished_key (server)", ffk)
    out("server verify_data", p.mac(ffk, th_pre_sf, FLEN))

    section("Application stage")
    t, residue_ht = ratchet(p, h)
    out("residue H->T", residue_ht)
    c_ap = derive_secret(p, t, b"cat", th_sf)
    s_ap = derive_secret(p, t, b"sat", th_sf)
    exporter_secret = derive_secret(p, t, b"exs", th_sf)
    resumption_secret = derive_secret(p, t, b"rss", th_cf)
    out("c_ap_traffic", c_ap)
    out("s_ap_traffic", s_ap)
    out("exporter_secret", exporter_secret)
    out("resumption_secret", resumption_secret)

    section("Record keys (Nk=16, Nn=12 of TLS_AES_128_GCM)")
    kb = expand(p, c_ap, b"key", None, 16 + 12)
    out("key_block", kb)
    out("write_key = key_block[0..16]", kb[:16])
    out("write_iv  = key_block[16..28]", kb[16:])

    section("Key update")
    out("app_traffic_secret_1", expand(p, c_ap, b"upd", None, SECRET_LEN))

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

    section("Imported PSK binder")
    imported_early = absorb(init(), b"psk_", ipsk)
    imported_binder_key = derive(p, imported_early, b"ibk")
    imported_finished_key = expand(p, imported_binder_key, b"fin",
                                   None, SECRET_LEN)
    out("binder_key (ibk)", imported_binder_key)
    out("finished_key (imported binder)", imported_finished_key)
    out("imported binder verify_data",
        p.mac(imported_finished_key, th_ch0, FLEN))

    section("ECH acceptance confirmations")
    out("accept_confirmation",
        expand(p, inner, b"eca", th(b"ech_conf_messages"), 8))
    out("hrr_accept_confirmation",
        expand(p, inner, b"hca",
               th(b"hrr_ech_conf_messages"), 8))

    for name, components in [
            ("PSK-only", []),
            ("hybrid", [th(b"hybrid component 1"), th(b"hybrid component 2")])]:
        section(name)
        early = absorb(init(), b"psk_", psk)
        handshake, _ = ratchet(p, early)
        for component in components:
            handshake = absorb(handshake, b"shs_", component)
        out(f"c_hs_traffic ({name})",
            derive_secret(p, handshake, b"cht", th_sh))
        out(f"s_hs_traffic ({name})",
            derive_secret(p, handshake, b"sht", th_sh))
        application, _ = ratchet(p, handshake)
        out(f"c_ap_traffic ({name})",
            derive_secret(p, application, b"cat", th_sf))


if __name__ == "__main__":
    _selftest()
    for prof in (SHAKE256, TURBOSHAKE256):
        print(f"\n================ {prof.name} ================")
        emit(prof)
