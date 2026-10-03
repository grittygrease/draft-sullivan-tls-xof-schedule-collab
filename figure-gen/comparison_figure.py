#!/usr/bin/env python3
"""
Generate the RFC-9846-vs-deck comparison figure (aasvg) from a data model.

Two-column mirror: RFC 9846 Section 7.1 on the left, the deck schedule on the
right. Its point is that the two run node for node, so every parallel -- each
named leaf secret, each stage box, each stage-boundary op -- must sit on the
SAME row on both sides. Hand-aligned ASCII cannot guarantee that (the Ratchet(H)
connector drifted once). Here both columns are placed from one model at a shared
row cursor, so alignment holds by construction.

    python3 comparison_figure.py            # emit the aasvg block

Layout: left spine at LSP, right spine at RSP; boxes centered on their spine;
op labels and leaf branches to the right of each spine so the spine is never
overwritten. Two rows per leaf (label, then "= secret") to stay inside the page.
"""

LSP = 9            # left spine column
RSP = 42           # right spine column
BW  = 17           # inner box width

STAGES = [
    dict(acc="E", rfc_secret="Early Secret", salt="0", ikm="PSK",
         deck_init=['E = Init()', 'Absorb(E, "psk", PSK)'],
         leaves=[("c e traffic", "c_e_traffic", "TH_CH"),
                 ("e exp master", "e_exp_master", "TH_CH"),
                 ("ext binder", "binder_key", None)]),
    dict(acc="H", rfc_secret="Handshake Secret", salt="derived", ikm="(EC)DHE",
         deck_init=['H = Init(residue)', 'Absorb(H, "dh", DHE)'],
         leaves=[("c hs traffic", "c_hs_traffic", "TH_SH"),
                 ("s hs traffic", "s_hs_traffic", "TH_SH")]),
    dict(acc="T", rfc_secret="Main Secret", salt="derived", ikm="0",
         deck_init=['T = Init(residue)'],
         leaves=[("c ap traffic", "c_ap_traffic", "TH_SF"),
                 ("s ap traffic", "s_ap_traffic", "TH_SF"),
                 ("exp master", "exp_master", "TH_SF"),
                 ("res master", "res_master", "TH_CF")]),
]

class Canvas:
    def __init__(self): self.g = {}
    def put(self, r, c, s):
        for i, ch in enumerate(s):
            self.g[(r, c + i)] = ch
    def ch(self, r, c, s): self.g[(r, c)] = s
    def vline(self, r0, r1, c):
        for r in range(r0, r1 + 1):
            self.g.setdefault((r, c), "|")
    def render(self):
        if not self.g: return ""
        maxr = max(r for r, _ in self.g); maxc = max(c for _, c in self.g)
        return "\n".join("".join(self.g.get((r, c), " ")
                                 for c in range(maxc + 1)).rstrip()
                         for r in range(maxr + 1))

def box(cv, r, spine, text, double=False):
    h = "=" if double else "-"
    c = spine - (BW + 2)//2
    cv.put(r,   c, "+" + h*BW + "+")
    cv.put(r+1, c, "|" + text.center(BW) + "|")
    cv.put(r+2, c, "+" + h*BW + "+")

def build():
    cv = Canvas()
    cv.put(0, 1, "RFC 9846, Section 7.1")
    cv.put(1, 1, "=" * 21)
    cv.put(0, RSP - 8, "This document, the deck schedule")
    cv.put(1, RSP - 8, "=" * 32)
    r = 3
    for si, st in enumerate(STAGES):
        last = si == len(STAGES) - 1
        # stage input: RFC extract line (left), deck init/absorb (right)
        cv.put(r, 1, f'HKDF-Extract({st["salt"]}, {st["ikm"]})')
        for i, line in enumerate(st["deck_init"]):
            cv.put(r + i, RSP - 8, line)
        r = max(r, r + len(st["deck_init"]) - 1) + 1
        cv.ch(r, LSP, "|"); cv.ch(r, RSP, "|"); r += 1
        cv.ch(r, LSP, "v"); cv.ch(r, RSP, "v"); r += 1
        # stage boxes, same rows: RFC octet secret vs deck accumulator state
        box(cv, r, LSP, st["rfc_secret"]); box(cv, r, RSP, st["acc"] + " accumulator", double=True)
        r += 3
        body0 = r
        # op header, right of each spine
        cv.put(r, LSP + 2, "Derive-Secret(., Lbl, TH)")
        cv.put(r, RSP + 2, f'Derive({st["acc"]}, Lbl, TH)')
        r += 1
        # leaves: label row + value row, both sides on the same rows
        for (label, secret, th) in st["leaves"]:
            tag = f'  {th}' if th else '  (no context)'
            cv.put(r, LSP, f'+-> "{label}"{tag}')
            cv.put(r, RSP, f'+-> "{label}"')
            r += 1
            cv.put(r, LSP + 4, f'= {secret}')
            cv.put(r, RSP + 4, f'= {secret}')
            r += 1
        if not last:
            # stage boundary, same row. The ratchet EMITS the residue (its
            # internal squeeze output = Derive(acc,"derived"), the RFC "derived"
            # analogue, a testable checkpoint); it does not lead into it. The
            # emitted residue then seeds the next deck (Init(residue)).
            cv.put(r, LSP + 2, 'Derive-Secret(., "derived")')
            cv.put(r, RSP + 2, f'Ratchet({st["acc"]}) emits residue')
            cv.vline(body0, r, LSP); cv.vline(body0, r, RSP)
            r += 1
            cv.ch(r, LSP, "v"); cv.ch(r, RSP, "v"); r += 1
        else:
            # last stage: T's leaves are the final outputs, no boundary op
            cv.vline(body0, r - 1, LSP); cv.vline(body0, r - 1, RSP)
    return cv.render()

if __name__ == "__main__":
    fig = build()
    print(fig)
    print("\n[width]", max((len(l) for l in fig.splitlines()), default=0), "cols")
