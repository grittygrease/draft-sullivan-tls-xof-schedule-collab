#!/usr/bin/env python3
"""Pin the TurboSHAKE256 implementation against RFC 9861's own vectors.

The 24-round SHAKE256 self-test does not exercise the 12-round window.
These independent vectors detect using rounds 0..11 instead of 12..23.
Quiet on success; mismatches print the expected and actual bytes.
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from verify import sponge

def ptn(n):
    """RFC 9861: repeat 00 01 02 .. F9 FA, truncated to n bytes."""
    pat = bytes(range(0xFB))
    return (pat * (n // len(pat) + 1))[:n]

def ts256(m, d, outlen):
    return sponge(m, d, outlen, 12)

H = lambda s: bytes.fromhex(s.replace(" ", "").replace("\n", ""))

CASES = [
    ("M=empty, D=1F, 64", b"", 0x1F, 64,
     "367A329DAFEA871C7802EC67F905AE13C57695DC2C6663C61035F59A18F8E7DB"
     "11EDC0E12E91EA60EB6B32DF06DD7F002FBAFABB6E13EC1CC20D995547600DB0"),
    ("M=ptn(17^0)=1, D=1F, 64", ptn(1), 0x1F, 64,
     "3E1712F928F8EAF1054632B2AA0A246ED8B0C378728F60BC970410155C28820E"
     "90CC90D8A3006AA2372C5C5EA176B0682BF22BAE7467AC94F74D43D39B0482E2"),
    ("M=ptn(17^1)=17, D=1F, 64", ptn(17), 0x1F, 64,
     "B3BAB0300E6A191FBE61379398359235787 94EA54843F5011090FA2F3780A9E5"
     .replace(" ", "") +
     "CB22C59D78B40A0FBFF9E672C0FBE0970BD2C845091C6044D687054DA5D8E9C7"),
    ("M=ptn(17^2)=289, D=1F, 64", ptn(289), 0x1F, 64,
     "66B810DB8E90780424C0847372FDC95710882FDE31C6DF75BEB9D4CD9305CFCA"
     "E35E7B83E8B7E6EB4B78605880116316FE2C078A09B94AD7B8213C0A738B65C0"),
    ("M=ptn(17^3)=4913, D=1F, 64", ptn(4913), 0x1F, 64,
     "C74EBC919A5B3B0DD1228185BA02D29EF442D69D3D4276A93EFE0BF9A16A7DC0"
     "CD4EABADAB8CD7A5EDD96695F5D360ABE09E2C6511A3EC397DA3B76B9E1674FB"),
    ("M=FFFFFF, D=01, 64", H("FFFFFF"), 0x01, 64,
     "D21C6FBBF587FA2282F29AEA620175FB0257413AF78A0B1B2A87419CE031D933"
     "AE7A4D383327A8A17641A34F8A1D1003AD7DA6B72DBA84BB62FEF28F62F12424"),
    ("M=FF, D=06, 64", H("FF"), 0x06, 64,
     "738D7B4E37D18B7F22AD1B5313E357E3DD7D07056A26A303C433FA3533455280"
     "F4F5A7D4F700EFB437FE6D281405E07BE32A0A972E22E63ADC1B090DAEFE004B"),
    ("M=FF, D=30, 64", H("FF"), 0x30, 64,
     "F3FE12873D34BCBB2E608779D6B70E7F86BEC7E90BF113CBD4FDD0C4E2F4625E"
     "148DD7EE1A52776CF77F240514D9CCFC3B5DDAB8EE255E39EE389072962C111A"),
]

bad = 0
for name, m, d, l, want in CASES:
    got = ts256(m, d, l)
    ok = got == H(want)
    if not ok:
        bad += 1
        print("%-28s MISMATCH" % name)
        print("   want %s" % H(want).hex())
        print("   got  %s" % got.hex())

# The long-output case: 10032 bytes, compare the LAST 32.
got = ts256(b"", 0x1F, 10032)[-32:]
want = H("ABEFA11630C6612692497426 85EC082F207265DCCF2F43534E9C61BA0C9D1D75")
ok = got == want
if not ok:
    bad += 1
    print("M=empty, D=1F, last 32 of 10032 MISMATCH")
    print("   want %s" % want.hex())
    print("   got  %s" % got.hex())

if bad:
    print("FAILED %d" % bad)
sys.exit(1 if bad else 0)
