---
title: XOF-based key schedules for TLS 1.3
abbrev: XOF-based key schedules for TLS 1.3
docname: draft-sullivan-tls-xof-schedule-latest
category: std
updates: 9258
ipr: trust200902
area: Security
workgroup: TLS
keyword:
  - TLS 1.3
  - key schedule
  - KDF
  - XOF
  - deck function
  - duplex
  - sponge
  - cSHAKE
  - KMAC
  - cipher suites

author:
  - fullname: Nick Sullivan
    organization: Cryptography Consulting LLC
    email: nicholas.sullivan+ietf@gmail.com
  - fullname: Markku-Juhani O. Saarinen
    organization: Tampere University, Finland
    email: markku-juhani.saarinen@tuni.fi

normative:
  RFC9846:
  RFC9847:
  RFC9258:
  RFC9849:
  RFC9861:
  FIPS202:
    target: https://csrc.nist.gov/pubs/fips/202/final
    title: "SHA-3 Standard: Permutation-Based Hash and\
      \ Extendable-Output Functions"
    author:
      - org: National Institute of Standards and Technology
    date: 2015-08
    seriesinfo:
      FIPS: "202"
      DOI: 10.6028/NIST.FIPS.202

informative:
  RFC9257:
  I-D.ietf-tls-hybrid-design:
  SP800-185:
    target: https://csrc.nist.gov/pubs/sp/800/185/final
    title: "SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash, and\
      \ ParallelHash"
    author:
      - org: National Institute of Standards and Technology
    date: 2016-12
    seriesinfo:
      NIST: "SP 800-185"
      DOI: 10.6028/NIST.SP.800-185
  RFC9001:
  RFC9147:
  RFC9261:
  SP800-133:
    target: https://csrc.nist.gov/pubs/sp/800/133/r2/final
    title: "Recommendation for Cryptographic Key Generation"
    author:
      - org: National Institute of Standards and Technology
    date: 2020-06
    seriesinfo:
      NIST: "SP 800-133r2"
      DOI: 10.6028/NIST.SP.800-133r2
  SP800-108:
    target: https://csrc.nist.gov/pubs/sp/800/108/r1/upd1/final
    title: "Recommendation for Key Derivation Using Pseudorandom\
      \ Functions"
    author:
      - org: National Institute of Standards and Technology
    date: 2024-08
    seriesinfo:
      NIST: "SP 800-108r1"
      DOI: 10.6028/NIST.SP.800-108r1-upd1
  SP800-56C:
    target: https://csrc.nist.gov/pubs/sp/800/56/c/r2/final
    title: "Recommendation for Key-Derivation Methods in\
      \ Key-Establishment Schemes"
    author:
      - org: National Institute of Standards and Technology
    date: 2020-08
    seriesinfo:
      NIST: "SP 800-56Cr2"
      DOI: 10.6028/NIST.SP.800-56Cr2
  BDPV08:
    target: https://keccak.team/files/SpongeIndifferentiability.pdf
    title: "On the Indifferentiability of the Sponge Construction"
    author:
      - ins: G. Bertoni
      - ins: J. Daemen
      - ins: M. Peeters
      - ins: G. Van Assche
    date: 2008
    seriesinfo:
      "EUROCRYPT": "2008, LNCS 4965, pp. 181-197"
      DOI: 10.1007/978-3-540-78967-3_11
  XOODYAK:
    target: https://keccak.team/xoodyak.html
    title: "Xoodyak, a Lightweight Cryptographic Scheme"
    author:
      - ins: J. Daemen
      - ins: S. Hoffert
      - ins: M. Peeters
      - ins: G. Van Assche
      - ins: R. Van Keer
    date: 2020
    seriesinfo:
      "IACR Transactions on Symmetric Cryptology": "2020(S1)"
      DOI: 10.46586/tosc.v2020.iS1.60-87
  STROBE:
    target: https://eprint.iacr.org/2017/003
    title: "The STROBE Protocol Framework"
    author:
      - ins: M. Hamburg
    date: 2017
  DISCO:
    target: https://eprint.iacr.org/2019/180
    title: "Disco: Modern Session Encryption"
    author:
      - ins: D. Wong
    date: 2019
  TLS13KS:
    target: https://eprint.iacr.org/2021/467
    title: "Key-Schedule Security for the TLS 1.3 Standard"
    author:
      - ins: C. Brzuska
      - ins: A. Delignat-Lavaud
      - ins: C. Egger
      - ins: C. Fournet
      - ins: K. Kohbrok
      - ins: M. Kohlweiss
    date: 2022
    seriesinfo:
      "ASIACRYPT": "2022"
  MRH:
    target: https://doi.org/10.1007/978-3-540-24638-1_2
    title: "Indifferentiability, Impossibility Results on Reductions,
      and Applications to the Random Oracle Methodology"
    author:
      - ins: U. Maurer
      - ins: R. Renner
      - ins: C. Holenstein
    date: 2004
    seriesinfo:
      "TCC": "2004, LNCS 2951, pp. 21-39"
      DOI: 10.1007/978-3-540-24638-1_2
  RSS:
    target: https://doi.org/10.1007/978-3-642-20465-4_27
    title: "Careful with Composition: Limitations of the
      Indifferentiability Framework"
    author:
      - ins: T. Ristenpart
      - ins: H. Shacham
      - ins: T. Shrimpton
    date: 2011
    seriesinfo:
      "EUROCRYPT": "2011, LNCS 6632, pp. 487-506"
      DOI: 10.1007/978-3-642-20465-4_27
  KEYEDSPONGE:
    target: https://doi.org/10.1007/978-3-662-48116-5_18
    title: "Security of Keyed Sponge Constructions Using a Modular
      Proof Approach"
    author:
      - ins: E. Andreeva
      - ins: J. Daemen
      - ins: B. Mennink
      - ins: G. Van Assche
    date: 2015
    seriesinfo:
      "FSE": "2015"
      DOI: 10.1007/978-3-662-48116-5_18
  FSKD:
    target: https://doi.org/10.1007/978-3-319-70697-9_21
    title: "Full-State Keyed Duplex With Built-In Multi-User Support"
    author:
      - ins: J. Daemen
      - ins: B. Mennink
      - ins: G. Van Assche
    date: 2017
    seriesinfo:
      "ASIACRYPT": "2017"
      DOI: 10.1007/978-3-319-70697-9_21
  BINDEL:
    target: https://eprint.iacr.org/2018/903
    title: "Hybrid Key Encapsulation Mechanisms and Authenticated Key
      Exchange"
    author:
      - ins: N. Bindel
      - ins: J. Brendel
      - ins: M. Fischlin
      - ins: B. Goncalves
      - ins: D. Stebila
    date: 2019
    seriesinfo:
      "PQCrypto": "2019, LNCS 11505, pp. 206-226"
      DOI: 10.1007/978-3-030-25510-7_12
---

--- abstract

TLS 1.3 runs its entire key schedule on HKDF over SHA-2.  This document
defines an extension that replaces that schedule with one built on an
extendable-output function (XOF):  the negotiated KDF governs every
derivation, the Finished and binder MACs, and the transcript hash, so no
SHA-2 remains in the key schedule.  The cipher suites, AEAD algorithms,
state machine, and record layer are unchanged, and a connection without
the extension uses HKDF as today.  Two KDFs are defined, SHAKE256 and
the reduced-round TurboSHAKE256.  This document updates RFC 9258.

--- middle

# Introduction

In TLS 1.3 {{RFC9846}}, every cipher suite runs its key schedule on HKDF
over the suite's hash.  This document defines an extension by which a
connection negotiates a key-derivation function of its own:  an
XOF-based KDF whose key schedule runs on a single Keccak permutation and
replaces HKDF across every derivation, the Finished and binder MACs, and
the transcript hash.  The permutation is the one a deployment already
carries when it uses SHA-3, ML-KEM, or ML-DSA.  When no KDF is
negotiated, the cipher suite's hash names HKDF and TLS 1.3's own
schedule runs, exactly as today.  Instantiating HKDF with a SHA-3 hash
would remove SHA-2 without changing how the schedule works.  This
document changes the schedule itself, not the hash.

TLS 1.3 already negotiates groups, KEMs, signature schemes, PSKs, and
AEAD algorithms.  This document extends that agility to the key schedule
itself.  A TLS 1.3 cipher suite identifies an AEAD algorithm and the
hash used with HKDF.  This document leaves the suite alone and
negotiates the KDF beside it:

~~~~
connection = cipher suite (TLS 1.3) + KDF (this document)
~~~~

A KDF ({{schedule-profiles}}) defines every key-schedule computation the
connection uses:  the transcript hash, the secret and key derivations,
the Finished and PSK binder MACs, and the Encrypted Client Hello
acceptance computations.  It is negotiated in the schedule_profile
extension of {{cipher-suites}}, independently of the cipher suite.  A
connection that negotiates no KDF is a TLS 1.3 connection:  absence is
the default, and TLS 1.3's own schedule needs no identifier of its own.

Both profiles express the schedule as one deck function:  an
extendable-output function that absorbs the schedule's inputs as
length-framed strings and squeezes each derived value from the
accumulated sequence.  It is defined once for both profiles in
{{deck-schedule}}, and each selects a different permutation for it:
TLS13_TURBOSHAKE256 ({{turboshake-profile}}) uses the 12-round
TurboSHAKE256 {{RFC9861}}, and TLS13_SHAKE256 ({{shake-profile}}) uses
the 24-round SHAKE256 {{FIPS202}}.  Finished and PSK binder values use
one MAC ({{mac-op}}).  The Encrypted Client Hello acceptance value is a
Derive ({{ech-generic}}).

## Design Goals

A KDF turns the whole derivation surface of a connection into one named,
testable object.  Every value comes from one permutation, every
derivation is injectively framed ({{deck-interface}}), and every one has
a byte-exact test vector ({{test-vectors}}).  Neither KDF uses SHA-2,
HMAC, or HKDF in any role, and the correspondence with TLS 1.3 can be
audited shape by shape ({{shapes}}).

The alternative is to keep TLS 1.3's HKDF schedule and give it a SHA-3
hash.  That inherits TLS 1.3's analysis directly, and {{fips-schedule}}
records a variant close to it.

The deck costs fewer permutation calls than that alternative.  HKDF is
built on HMAC, which runs every derivation as two nested hash calls,
overhead that exists only to key a hash not built for keying.  A keyed
sponge needs no such wrapper:  it produces each value in one squeeze,
with no separate extract step between stages.

Over the representative handshake of {{comparison}}, the deck costs 39
Keccak permutation calls against 156 for a hash-only HKDF-SHA3-256 over
the same permutation ({{permutation-count}}).  That factor follows from
HKDF's definition over HMAC, which runs every operation as two nested
hash calls, so no HKDF instantiation removes it.

## Scope

This document does not define a new version of TLS, and defines no
cipher suites.  It adds one extension and changes nothing else:  the
state machine, the record layer, and every wire structure other than
that extension are TLS 1.3's, and the cipher suites, the AEAD
algorithms and their per-record nonce construction are TLS 1.3's.

A KDF governs only the key schedule.  Negotiating one does not by itself
make a connection free of SHA-2:  certificate-based authentication is
negotiated separately and commonly relies on SHA-2.  A deployment that
requires a fully SHA-2-free connection must additionally restrict itself
to SHA-2-free signature schemes and certificate chains, or use PSK-only
authentication ({{security-considerations}}).  Note also that the cipher
suite continues to name a hash, which under a KDF of this document
governs nothing in the key schedule ({{profile-governs}}).

## Deck Functions {#deck-functions}

A key schedule is a derivation tree, and a deck function
({{related-constructions}}) expresses one directly:  absorb a stage's
inputs into a running accumulator, derive a leaf from a clone at each
branch, and ratchet the accumulator itself into the next stage.  One XOF
does the work HKDF splits between Extract, at the stage boundaries, and
Expand-Label, at the leaves.

The construction takes no key:  a secret is an ordinary framed input,
and the security rests on the XOF's own bound, not on a keyed-primitive
assumption ({{cryptographic-analysis}}).  The operations named here,
Init, Absorb, Derive, and Ratchet, are defined normatively in
{{deck-schedule}}.

# Conventions and Definitions {#conventions}

{::boilerplate bcp14}

This document uses the following terms.

KDF:
: The key-derivation function of a connection, named by a TLS KDF
  Identifier and negotiated in the schedule_profile extension
  ({{cipher-suites}}).  It defines every key-schedule computation of
  the connection ({{schedule-profiles}}) and determines the key
  schedule:  a TLS13_TURBOSHAKE256 or TLS13_SHAKE256 identifier implies
  this document's deck schedule ({{deck-schedule}}), and absence of the
  extension implies TLS 1.3's HKDF schedule over the cipher suite's
  hash.

selected_cipher_suite:
: The cipher suite selected in the ServerHello message, as a 16-bit
  integer.  uint16(selected_cipher_suite) yields its two-octet TLS 1.3
  encoding.

recorded cipher suite:
: For a resumption PSK, the cipher suite of the ticket.  An imported PSK
  records no cipher suite:  it is bound to a KDF, not a suite
  ({{psk-importer}}).

trunk (stage trunk):
: The running deck accumulator for a schedule stage (E, H, or T),
  which absorbs the stage's inputs, is cloned for each of the
  stage's leaf outputs, and is ratcheted at the stage boundary to
  an internal residue that seeds the next stage's trunk.

DHE:
: The asymmetric shared secret, computed as in
  {{Section 7.4 of RFC9846}}.

Nk, Nn:
: The AEAD key and nonce lengths of the selected cipher suite, in
  octets.

FLen:
: The length of Finished and PSK binder verify_data: 64 octets in
  both profiles of this document.

uint16(n):
: The two-octet big-endian encoding of n, as in the TLS presentation
  language.

||:
: Octet-string concatenation.

x\[a..b\]:
: Octets a through b-1 of the octet string x, indexed from zero.

frame(x):
: uint16(len(x)) \|\| x, where len(x) is the octet length of x.
: Strings are length-prefixed only:  they are not null-terminated or
  otherwise padded after x.  Both profiles of this document build every
  derivation input from framed items, so inputs are injectively encoded.
: A uint16 encodes 65535, so frame(x) carries any x of 0xFFFF octets or
  fewer, and longer inputs do not occur:  variable-length public values
  are reduced by the transcript hash or explicitly bounded before
  framing, and the one variable-length secret input, an external PSK, is
  bounded by {{psk-importer}}.

An empty value contributes frame("") wherever it is framed, encoding as
the two octets 0x0000 with no payload octets.  An absent input omits its
framed items entirely.  Omitting an input is not the same as framing an
empty value.

## Transcript Hash {#transcript-hash}

The transcript hash is an unkeyed 64-octet hash defined by the
negotiated KDF ({{turboshake-profile}}, {{shake-profile}}).
TranscriptHash is computed over the handshake transcript as in
{{Section 4.1 of RFC9846}}:  message type and length fields are
included, and record-layer framing is excluded.  TranscriptHash accepts
any octet string.  The TLS 1.3 rules define only how the handshake
transcript is serialized before hashing, and the same function is
applied to non-transcript inputs such as exporter labels and imported
PSK identities.  For a HelloRetryRequest, the synthetic-message
construction in {{Section 4.1 of RFC9846}} is retained, substituting
TranscriptHash for Hash.

In both profiles of this document, TranscriptHash takes no cipher suite
input, so a client can compute its checkpoints before the ServerHello.
The selected suite enters the transcript at the ServerHello, separating
later outputs as in TLS 1.3.  The schedule_profile extension enters the
transcript at the ClientHello, so TH_CH0, TH_CH, and TH_SH bind the
offered KDFs.

This document uses the following checkpoint values:

TH_CH0:
: TranscriptHash of the partial ClientHello transcript in
  {{Section 4.3.11.2 of RFC9846}}:  the handshake messages through the
  ClientHello, with the ClientHello truncated after the
  PreSharedKeyExtension.identities field and the binders list excluded.
  After a HelloRetryRequest, this partial transcript includes the first
  ClientHello and the HelloRetryRequest via the synthetic-message
  construction of {{transcript-hash}}, exactly as in TLS 1.3.

TH_CH:
: TranscriptHash(ClientHello).

TH_SH:
: TranscriptHash(ClientHello up to and including ServerHello).

TH_SF:
: TranscriptHash(ClientHello up to and including the server
  Finished message).

TH_CF:
: TranscriptHash(ClientHello up to and including the client
  Finished message).

For a Finished MAC computed by either peer, the covered transcript
is taken up to but not including the Finished message being
computed, consistent with {{Section 4.5.3 of RFC9846}}.

# Key-Derivation Functions {#schedule-profiles}

A KDF is a set of algorithms and encodings negotiated in the
schedule_profile extension ({{cipher-suites}}), independently of the
cipher suite.  A KDF specifies:

- the XOF over which its deck schedule and MAC are instantiated
  ({{deck-schedule}});
- SecretLen, the length of stage and traffic secrets;
- FLen, the length of Finished and binder verify_data;
- TranscriptHash(messages), the unkeyed transcript hash of
  {{transcript-hash}};
- the derivation of initial and stage secrets from PSK and
  key-exchange inputs (an extract operation, a stage accumulator,
  or an equivalent construction);
- the derivation of every handshake, application, exporter, and
  resumption secret;
- the Finished MAC and PSK binder computations;
- record key and IV derivation;
- traffic-secret update;
- exporter derivation;
- resumption PSK derivation;
- the Encrypted Client Hello acceptance computations; and
- the domain-separation and input-framing rules its derivations
  use.

The suite continues to select the AEAD, as in
{{Section 4.2 of RFC9846}}.  Future specifications may define additional
KDFs by registering a TLS KDF Identifier ({{iana-considerations}}) whose
definition covers every computation listed above.

Every derivation of a KDF MUST bind at least the following into the
input of the underlying primitive:  a protocol identifier (the KDFs of
this document frame schedule_label, {{deck-schedule}}), the derivation
label, the output length (a KDF MAY instead fix the length of an
internal stage secret as a constant, provided the operation that
produces it is domain-separated from every variable-length operation),
the transcript checkpoint or other public context where applicable, and
the secret input or the stage that carries it.  All variable-length
items MUST be length-framed.  No two distinct derivation paths will
produce identical encoded inputs to the underlying primitive unless they
intentionally derive the same value.

Both profiles of this document bind the output length as uint16, so no
output longer than 65535 octets is derivable.  The one derivation whose
length is caller-chosen is the exporter:  an implementation MUST reject
a TLS-Exporter request for more than 65535 octets rather than reduce the
requested length modulo 65536, which would let two different requested
lengths bind the same encoded value.  Every other output length in this
document is a profile constant or Nk + Nn, all far below the bound, so
the exporter is the only derivation where this rejection can occur.

# KDF Selection and PSK Compatibility {#governing-profile}

The negotiated KDF governs the whole key schedule of a connection, the
role SHA-256 or SHA-384 plays in {{Section 7.1 of RFC9846}}.  Its XOF
runs every derivation of the schedule ({{deck-schedule}}).

A PSK binder is computed before the server selects a cipher suite, and
verified under the KDF the PSK is bound to.  As in
{{Section 4.3.11 of RFC9846}}, a server MUST verify the binder of any
PSK it selects.  The binder is keyed by a secret derived under that KDF
({{finished-and-binder-mac}}), so a PSK established under one KDF cannot
key another and pass verification.

A server MUST NOT select a PSK unless the KDF of the connection it forms
is compatible with the KDF associated with the PSK.  Two KDFs are
compatible only if they are the same TLS KDF Identifier.  This document
defines no broader compatibility.  This rule is the analogue of RFC
9846, Section 4.3.11, which requires a resumption to share the PSK's
hash:  under this document the KDF is the hash ({{profile-governs}}).

Otherwise a 1-RTT resumption follows TLS 1.3.  The selected cipher
suite need not equal the PSK's recorded cipher suite.  A resumption MAY
change the AEAD as long as the KDFs are compatible.  The selected suite
appears in the ServerHello and therefore in the transcript, which
separates every handshake and application output as in TLS 1.3
({{downgrade-resistance}}).

After a HelloRetryRequest, an updated binder remains under the PSK's
KDF.  A client SHOULD omit from its updated ClientHello any PSK whose
KDF is incompatible with the KDF implied by the HelloRetryRequest, and
MUST recompute binders as required by {{Section 4.3.11.2 of RFC9846}}.

For 0-RTT, the server MUST require the selected cipher suite to equal
the PSK's recorded cipher suite ({{zero-rtt}}).  This is TLS 1.3's own
0-RTT rule.

A PSK that is offered but not selected leaves no trace in the schedule.
If the server does not select the client's PSK, both peers compute the
connection's schedule as a handshake without a PSK:  the client discards
any PSK-keyed schedule state it built for the binder or for early data,
along with its outputs, and begins the schedule again with the empty
PSK, applying the destruction rules of its KDF.

Implementations MUST associate every PSK and session ticket with the
KDF, and the cipher suite, under which it was established:  the KDF to
select a compatible PSK and compute its binder, the cipher suite for the
0-RTT equality check and the Nk and Nn of any early-data keys.

# Keyed Derivations {#derived-outputs}

Every derivation in this document that is keyed by a retained
octet-string secret, rather than by a live stage of a profile's
schedule, is a deck session rooted at that secret ({{deck-schedule}}),
specified once for both profiles in {{expand-op}} since the deck is
identical up to its permutation.  MAC computes the Finished and PSK
binder tags.  {{mac-op}} defines it once as a byte layout over the
profile's permutation, and each profile fixes that permutation
({{turboshake-mac}}, {{shake-mac}}).  Stage schedules themselves remain
profile-specific ({{turboshake-profile}}, {{shake-profile}}).

## Deriving from a Retained Secret {#expand-op}

A value keyed by a retained octet-string secret is a Derive
({{deck-interface}}) whose deck is seeded with that secret rather than
run as a live stage trunk.  The seed is the secret itself: Init(secret),
the same way a ratchet seeds the next stage with its residue.  Derive
then adds the label, the context under the "context" tag if any, and
the "out" length:

~~~~
D     = Init(secret)                # Init frames schedule_label
value = Derive(D, label, [context], [L])
~~~~

label is an ASCII label, context is an octet string, and L is the output
length in octets.  Every item is length-framed by the deck
({{domain-separation}}), so distinct derivations map to distinct deck
inputs.  When context is empty it is omitted rather than framed as an
empty value.  The frame of the following "out" tag delimits the absence,
so an omitted context and an empty one never yield the same input.  L
never exceeds 65535 octets ({{schedule-profiles}}).  Such a Derive is
the analogue of TLS 1.3's HKDF-Expand-Label and carries its labels
where TLS 1.3 has a counterpart.

The following retained-secret derivations are instances of this shape,
each fixing the base secret, label, context, and output length.
The exporter ({{exporters-generic}}) is a further instance whose context
is a composite of two transcript hashes, and the ECH acceptance
confirmations ({{ech-generic}}) are instances whose context is a single
one.  Every derivation of this shape carries its context under the
"context" tag, including one whose context is itself a transcript hash.

| Output | Base secret | Label | Context | Length |
|--------|-------------|-------|---------|--------|
| record keys ({{record-keys-generic}}) | a traffic secret | "key" | none | Nk + Nn |
| next traffic secret ({{key-update-generic}}) | current traffic secret | "traffic upd" | none | SecretLen |
| resumption_psk | res_master | "resumption" | ticket_nonce | SecretLen |
| ipsk ({{import-derivation}}) | epsk | "derived psk" | see below | SecretLen |

The ipsk row's context is TranscriptHash(ImportedIdentity), the
transcript-hash reduction of ImportedIdentity defined in
{{import-derivation}}.

## MAC {#mac-op}

MAC(key, message, L) computes every tag in this document:  the PSK
binder and both Finished values.  Both profiles use it.

MAC builds the octet string mac_input from a key, a positional tuple X,
and a fixed customization string S, then applies the profile's
permutation to mac_input as a sponge, with a 136-octet rate, a 512-bit
capacity, and domain-separation byte 0x04 appended in the manner of
TurboSHAKE {{RFC9861}}, squeezing 8 * L bits:

~~~~
K = key
X = frame(schedule_label) || frame(message)
S = "TLS 1.3 MAC"
mac_input = bytepad(encode_string("KMAC") || encode_string(S), 136)
            || bytepad(encode_string(K), 136)
            || X || right_encode(8 * L)
~~~~

The four length encoders are byte-oriented.  For a non-negative integer
n, let b be the number of octets in its minimal big-endian form, taking
b to be 1 when n is 0.

left_encode(n):
: the single octet b followed by n as b octets.

right_encode(n):
: n as b octets followed by the single octet b.

encode_string(s):
: for an octet string s of len(s) octets, left_encode(8 * len(s))
  followed by s.

bytepad(s, w):
: left_encode(w) followed by s, then zero octets until the length is a
  multiple of w.

The input X is positional.  Unlike the deck's Absorb and Derive inputs,
which pair each value with a frame(tag), the MAC fields carry no
per-item tags.  Their fixed order and length-framing parse them
unambiguously, and S is the same in every invocation of either profile.

The two profiles fix the permutation ({{turboshake-mac}},
{{shake-mac}}), and each profile's section names the construction its
permutation makes of this layout.  MAC is defined by the layout above,
not by reference to KMAC.

Because right_encode(8 * L) binds the output length into mac_input
before the permutation runs, different output lengths yield distinct MAC
inputs.  MAC is the analogue of TLS 1.3's HMAC-based Finished and binder
MACs.  It carries no label:  distinct invocations yield distinct values
because the key and the message differ.  Both Finished values are
computed the same way, each over a different key and a different message
({{finished-and-binder-mac}}).
L never exceeds 65535 octets ({{schedule-profiles}}).

## Record Keys {#record-keys-generic}

Record keys are the "key" derivation of {{expand-op}}: a traffic secret
derived in one call to key_block, so a retained traffic secret suffices
to re-derive its keys, as in TLS 1.3.  For early-data keys, derived
before the ServerHello, Nk and Nn are those of the offered PSK's
recorded cipher suite.  For every other traffic secret they are those of
selected_cipher_suite.

key_block is that derivation:  the traffic secret as the seed, the
label "key", no context, and output length Nk + Nn.

~~~~
# no context, so the third argument is the output length
key_block = Derive(Init(traffic_secret), "key", Nk + Nn)
write_key = key_block[0..Nk]
write_iv  = key_block[Nk..Nk+Nn]
~~~~

The split is unambiguous:  Nk and Nn are fixed by the suite, and their
sum is bound into the derivation as the output length.  The traffic
secret is already specific to one direction and one stage, so no
direction or epoch input is needed.  The per-record nonce construction,
record format, and AEAD additional data are unchanged from TLS 1.3.

## Key Update {#key-update-generic}

A key update derives the next traffic-secret generation,
app_traffic_secret_{N+1}, from the current one by the "traffic upd"
derivation of {{expand-op}}, with record keys re-derived from the new
secret as above.  An implementation MUST NOT derive generation N+1 from
anything other than generation N, in particular not from a retained
stage accumulator or a counter:  that rule determines the derived value
and so is an interoperability requirement.  Each generation is also an
erasure boundary, and the previous secret, its keys, and any schedule
state derived from them are destroyed once the new generation is
installed ({{erasure-boundaries}}).

## Finished and PSK Binder MACs {#finished-and-binder-mac}

Finished and PSK binder verify_data are computed under a dedicated MAC
key, derived from a stage or traffic secret ({{expand-op}}), rather
than by MACing that secret directly.  This matches
{{Section 4.5.3 of RFC9846}}:  finished_key and binder_key take the
roles of TLS 1.3's identically named intermediates, and MAC takes the
role of TLS 1.3's HMAC.

~~~~
finished_key = Derive(Init(base_key), "finished")
verify_data  = MAC(finished_key, th, FLen)
~~~~

For a Finished message, base_key is the base key that message takes in
the authentication-input table of {{Section 4.5 of RFC9846}}:  the
sender's handshake traffic secret for a Finished sent during the
handshake, and the sender's current application traffic secret for a
post-handshake authentication Finished.  The label is "finished", and
th covers the transcript up to but not including the Finished message
being computed.  For a PSK binder, the dedicated key is
derived in two steps, as TLS 1.3 derives binder_key in Section 7.1 and
then finished_key from it in Section 4.3.11.2, via Section 4.5.3:

~~~~
binder_key   = Derive(E, ext_or_res_label)
finished_key = Derive(Init(binder_key), "finished")
verify_data  = MAC(finished_key, TH_CH0, FLen)
~~~~

E is the live early trunk of the schedule keyed by that PSK, before its
ratchet ({{key-schedule}}).  binder_key is a Derive directly on E, a
third early leaf alongside c_e_traffic and e_exp_master, so the early
trunk is the analogue of TLS 1.3's Early Secret from which Section 7.1
derives binder_key.  ext_or_res_label is "ext binder" for an external
PSK and "res binder" for a resumption PSK.

finished_key is derived under "finished" for both a Finished and a
binder, and the two are already separated one step up by their base
secret, a handshake traffic secret against binder_key.  Both
finished_key and binder_key are 64 octets, the length of every stage and
traffic secret in both profiles (SecretLen, {{turboshake-profile}},
{{shake-profile}}), matching TLS 1.3's use of Hash.length for the same
intermediates.  Binder verification follows {{governing-profile}}.

{{comparison}} counts every finished_key and binder_key derivation of a
representative full handshake against the corresponding TLS 1.3
HKDF-Expand-Label calls.

finished_key and binder_key are dedicated MAC keys, and a Finished MAC
key shares its base key, the sender's handshake traffic secret, with
that sender's record keys ({{record-keys-generic}}).  Their separation
from the record keys follows from domain separation
({{domain-separation}}).  Sharing the base secret reproduces TLS 1.3's
structure and its exposure exactly ({{cryptographic-analysis}});  this
document establishes no separate joint-security argument for that
sharing ({{open-analysis}}).

Binders are computed before the ServerHello.  This is possible in both
profiles because the early trunk binds no cipher suite:  the client
clones the early trunk to obtain binder_key at ClientHello time, in
either profile ({{deck-schedule}}).

## Exporters {#exporters-generic}

Exporters are keyed by the retained exporter master secret:

~~~~
TLS-Exporter(label, context, length):
    # the context argument is itself a framed pair
    return Derive(Init(exp_master), "exporter",
                  frame(TranscriptHash(label))
                  || frame(TranscriptHash(context)), length)
~~~~

The early exporter is the same construction keyed by e_exp_master.
Hashing the label and the context bounds their lengths, so the composite
context is a fixed-width pair and a long context cannot displace the
label.  An implementation MUST reject a TLS-Exporter request for more
than 65535 octets ({{schedule-profiles}}).

## ECH Acceptance Confirmations {#ech-generic}

For the KDFs of this document, the ECH acceptance signals of {{RFC9849}}
are:

~~~~
D = Init(ClientHelloInner.random)

accept_confirmation =
    Derive(D, "ech accept confirmation",
           TranscriptHash(ech_conf_messages), 8)

hrr_accept_confirmation =
    Derive(D, "hrr ech accept confirmation",
           TranscriptHash(hrr_ech_conf_messages), 8)
~~~~

replacing the HKDF-Extract and HKDF-Expand-Label computations of
{{RFC9849}}, with ech_conf_messages and hrr_ech_conf_messages the
handshake message ranges that document identifies for each
confirmation, per {{Section 4.1 of RFC9846}}.
TranscriptHash(ech_conf_messages) is RFC 9849's transcript_ech_conf, the
same single transcript-hash operation, applied once.

Keying the confirmation on ClientHelloInner.random alone matches
{{RFC9849}}, whose confirmation key is HKDF-Extract(0,
ClientHelloInner.random), with no handshake secret mixed in.  This
document seeds a deck with that same value and takes one Derive, in
place of RFC 9849's extract-then-expand, so the acceptance signal
keeps its RFC 9849 properties.  Only a server that decrypted the
inner ClientHello, and so learned ClientHelloInner.random, can
compute the confirmation, and no network attacker can forge it.
Because the confirmation transcript covers the ServerHello, it
binds its handshake and does not transplant to another.

## PSK Import Derivation {#import-derivation}

An external PSK is imported per target KDF ({{psk-importer}}).  For
every KDF of this document, ipsk is the "derived psk" derivation of
{{expand-op}}, keyed by epsk with TranscriptHash(ImportedIdentity) as
context, with target_kdf as the KDF.  This follows the shape of the RFC
9258 derivation, with the entire serialized ImportedIdentity reduced by
the transcript hash as the context.  ipsk is an explicit octet string by
design:  it crosses a system boundary into the PSK store.  epsk is
absorbed as the secret of a deck derivation ({{expand-op}}) in both
profiles, so a low-entropy or attacker-influenced epsk never keys either
profile's underlying permutation directly.

# Negotiating a KDF {#cipher-suites}

This document defines no cipher suites.  A connection uses the cipher
suites of TLS 1.3, and negotiates its KDF separately, in a new
extension.

Coupling the two would make the offered set the product of the AEAD
choices and the schedule choices, and would oblige a client that wants
one schedule with two AEADs to carry a code point for each combination.
The schedule and the AEAD are independent choices, and this document
negotiates them independently.

The value negotiated is a TLS KDF Identifier, the registry {{RFC9258}}
already created for naming a key schedule independently of a cipher
suite.  A KDF of this document registers there
({{iana-considerations}}).

~~~~
struct {
    uint16 profiles<2..2^16-2>;   /* TLS KDF Identifiers */
} ScheduleProfileList;
~~~~

The extension_data of a schedule_profile extension
({{iana-considerations}}) is a ScheduleProfileList in a ClientHello, in
preference order, and a single uint16 in a ServerHello or a
HelloRetryRequest.

Absence is the default, and the default is TLS 1.3:  a connection whose
ClientHello omits the extension, or whose server does not echo it, runs
the key schedule in {{Section 7.1 of RFC9846}}, HKDF over the negotiated
cipher suite's hash.  That is HKDF_SHA256 or HKDF_SHA384 as the suite's
hash determines, so TLS 1.3's own schedule needs no value of its own
here and an endpoint of this document interoperates with TLS 1.3
unchanged.  A client that requires an alternative schedule signals it by
offering only KDFs of this document ({{downgrade-resistance}}).  Because
absence is the sole signal for the TLS 1.3 schedule, a
ScheduleProfileList MUST NOT include HKDF_SHA256 or HKDF_SHA384, the
other values of the RFC 9258 registry.  A server that receives either
MUST treat it as if that KDF were not offered, and MUST NOT select it.

The KDFs of this document are TLS13_TURBOSHAKE256
({{turboshake-profile}}) and TLS13_SHAKE256 ({{shake-profile}}).

A server MUST NOT select a KDF the client did not offer.  A server that
selects a KDF of this document MUST send the extension in its
ServerHello, so the selection is covered by the transcript
({{downgrade-resistance}}).

A server that sends a HelloRetryRequest and selects a KDF of this
document MUST carry the selected KDF as a schedule_profile extension in
the HelloRetryRequest.  That selection pins the KDF for the rest of the
handshake and is the KDF implied by the HelloRetryRequest
({{governing-profile}}).  The client computes its second ClientHello
and every later checkpoint under that KDF, and the HelloRetryRequest is
covered by the transcript.

## What the KDF Governs {#profile-governs}

A KDF defines every key-schedule computation of the connection,
including the transcript hash ({{schedule-profiles}}).  When a KDF of
this document is negotiated, the hash named by the cipher suite governs
nothing in the key schedule:  the transcript hash is the KDF's, and the
derivations and MACs are the KDF's.

The cipher suite's name still carries that hash.  A connection on
TLS_AES_128_GCM_SHA256 with TLS13_TURBOSHAKE256 selected takes
AES-128-GCM, its Nk and Nn, and its per-record nonce construction from
the suite, and takes SHA-256 from nowhere:  no part of the key
schedule uses it.  A connection that negotiates no KDF is unaffected:
the suite's hash governs its schedule exactly as TLS 1.3 specifies.

# The Deck Schedule {#deck-schedule}

Both KDFs of this document express the key schedule as a deck function
({{deck-functions}}).

The schedule's normative interface is defined here, in terms of the
profile's XOF and nothing else:  Init and Absorb build a framed input
sequence, Derive reads one to produce a keyed output, and Ratchet
crosses a stage boundary.  A derived value is one XOF call over the
sequence that produced it.  The security this rests on is the XOF's own
({{cryptographic-analysis}}), not a contract inherited from an
abstraction.  {{turboshake-profile}} and {{shake-profile}} each give a
short instantiation naming the profile's XOF, permutation, and
domain-separation constants.

This document uses the following terms.

schedule_label:
: The fixed 6-octet ASCII string "tls13 " (with a trailing space),
  framed at Init ({{deck-interface}}) into every derivation of both
  profiles.  It marks the TLS 1.3 deck schedule and is identical for
  both profiles, which are separated by their XOF, not by this label.
  It is byte-identical to the "tls13 " label prefix in
  {{Section 7.1 of RFC9846}}.  Its byte-level separation from other uses
  of the same XOF, including the transcript hash, is covered in
  {{domain-separation}}.

deck function:
: An extendable-output function evaluated over a sequence of framed
  input strings, with the output length bound into the sequence before
  any output is produced ({{deck-interface}}).  The construction beneath
  it is an XOF and takes no key parameter, its secrets being ordinary
  framed inputs.  Related work on keyed functions over a forked state is
  discussed in {{related-constructions}}.

stage:
: One of the three phases of the schedule:  early (keyed by the PSK),
  handshake (adds the key-exchange secrets), and application.  Stages
  are separated by ratchets ({{deck-interface}}).  A key update is a
  derivation of the retained traffic secret ({{key-update-generic}}),
  not a ratchet.

ratchet:
: Crossing a stage boundary with the Ratchet operation of
  {{deck-interface}}:  the residue is Derive(D, "derived"), and the next
  deck is Init'd, framing schedule_label, then seeded with that residue,
  after which the completed deck is destroyed ({{erasure-boundaries}}).

The presentation is stateful, but the construction is not.  Every
derived value equals one invocation of a profile's deck function over
the framed derivation path from its stage's initialization to that
value, with no extract-then-expand structure.  The three stages of
{{key-schedule}} are protocol phases separated by ratchets, not KDF
steps:  shared trunks absorb each input once, the handshake holds only
two intermediate secrets, and the one-way truncations fall at the
stage boundaries where TLS must erase prior state.

## The Deck Schedule Interface {#deck-interface}

A deck is a running sequence of framed inputs.  The profile's DF(S, L)
is the XOF over that sequence ({{turboshake-instantiation}},
{{shake-instantiation}}).  It returns L octets, and L is at most 65535.
The schedule runs one deck per stage, driven by four operations.

### Operations

~~~~
Init([seed])         D = frame(schedule_label) [ || frame(seed) ]

Absorb(D, tag, v)    D = D || frame(tag) || frame(v)

Derive(D, label,     out = DF(D [ || frame(ctag) || frame(context) ]
       [context], [L])         || frame(label)
                               || frame("out") || frame(uint16(L)), L)
                     # D is cloned, not consumed
                     # ctag names context, as tag names v in Absorb
                     # omitted L is SecretLen

Ratchet(D)           residue = Derive(D, "derived")
                     return Init(residue)
                     # residue = Derive-Secret(., "derived", "");
                     # the next deck is Init, seeded with the residue
~~~~

Init starts a deck by framing schedule_label.  Every deck is Init'd, so
every keyed sequence opens with frame(schedule_label), TLS 1.3's
"tls13 " prefix ({{domain-separation}}).  A ratchet residue or a
retained secret is passed to Init as the seed ({{key-schedule}},
{{expand-op}}).
Absorb feeds one tagged input into the running deck.  That is the same
role HKDF-Extract's mixing step plays in TLS 1.3.

Derive is the keyed-output operation.  It clones the running deck,
absorbs that leaf's context, then adds the leaf label.  The context is a
transcript checkpoint under ctag "th" at a stage leaf, an expansion
context under ctag "context" for a retained secret, or none.  The
context precedes the label here, the reverse of TLS 1.3's HkdfLabel
order.  The framing is injective either way, so the order does not bear
on security, and placing the context first lets sibling leaves that
share it branch after one absorption.

The clone leaves the deck unchanged, so one deck yields all of a stage's
leaves.  Derive fills exactly HKDF-Expand-Label's role.  At a stage leaf
it stands in for TLS 1.3's Derive-Secret(secret, label, Messages), with
the deck in place of the secret.  A value keyed by a retained secret is
a Derive over a deck seeded with that secret ({{expand-op}}).  A Derive
that omits L, including every leaf of the key schedule
({{key-schedule}}) and the Ratchet residue, outputs SecretLen octets.  A
Derive that fixes its own length passes L explicitly (record keys,
exporters, the ECH confirmation).

Ratchet crosses a stage boundary.  Its residue is a Derive under the
label "derived", which is this schedule's analogue of TLS 1.3's
Derive-Secret(., "derived", "") between stages.  The next deck is Init'd
like any other, framing schedule_label, then seeded with that residue,
so "derived" names the residue, not the new deck.  The residue is
internal and never leaves the schedule.  Any stage input, such as the
asymmetric shared secret, is a later Absorb into the new deck, not part
of the ratchet.

The old deck is retired, and an implementation MUST NOT Absorb into or
Derive from it afterward.  Because the residue is a squeeze, a later
compromise recovers the retired state only by guessing it, which its
min-entropy bounds ({{erasure-boundaries}}).  This is not the in-place
Ratchet() of Cyclist or STROBE ({{XOODYAK}}, {{STROBE}}), which returns
nothing.

A Derive is one DF call over its framed path, and a ratchet residue is
one such Derive.  It is therefore byte-exact and testable alone.

## Derivation Shapes {#shapes}

Every TLS 1.3 derivation replaced by this document is an instance of
one of six shapes.

| Shape | TLS 1.3 site | Realization |
|---|---|---|
| Root absorb | the Early Secret extract | Init + Absorb |
| Accumulate | the Handshake Secret extract IKM (per component) | Absorb |
| Ratchet | Derive-Secret(., "derived", "") at a boundary | Ratchet |
| Derive from a deck | traffic and exporter secrets; PSK binder keys | Derive |
| Derive from a secret | record keys; exporters; key update; resumption; PSK import ({{RFC9258}}) | Derive |
| Keyed check | Finished; PSK binders | MAC |
{: #shape-table title="Derivation Shapes and Their Realizations"}

Shapes 1 through 3 act on the trunk of a stage.  Shapes 4 and 5 are the
same operation, Derive, over a live trunk or over a seeded deck rooted
at a retained secret ({{expand-op}}).  Shape 6 is a self-contained keyed
call.  Record keys are derived from their traffic secret by a separate
call, as in TLS 1.3, so a retained traffic secret suffices to re-derive
its keys.  Deriving them within the call that produces the traffic
secret would save a few invocations but break that re-derivability, so
the schedule keeps the separate call.

## Key Schedule {#key-schedule}

The schedule has three stages separated by two ratchets.  A key-update
generation is a derivation of the retained traffic secret
({{key-update-generic}}), not a further ratchet.  Stage trunks and stage
secrets bind no cipher suite value, matching the TLS 1.3 extracts they
replace, and no leaf derivation binds one either:  a client offering
several cipher suites under one KDF computes one schedule, and only the
record-key derivations depend on the suite, through the Nk + Nn they
output ({{record-keys-generic}}).  Every derivation frames
schedule_label at Init ({{deck-interface}}).  The negotiated KDF is
bound by the XOF, not by this label.  This listing is identical for both
profiles.  Only each profile's DF and MAC instantiations differ
({{turboshake-profile}}, {{shake-profile}}).

~~~~
E = Init()
Absorb(E, "psk", PSK)              # "" when no PSK is offered

# early-stage leaves, each a clone of the early deck E
c_e_traffic  = Derive(E, "c e traffic", TH_CH)   # 0-RTT
e_exp_master = Derive(E, "e exp master", TH_CH)   # 0-RTT
binder_key   = Derive(E, ext_or_res_label)        # no context

H = Ratchet(E)                     # residue = Derive(E, "derived")
                                   # then H = Init(residue)
Absorb(H, "dh", DHE)               # once per key-exchange component

c_hs_traffic = Derive(H, "c hs traffic", TH_SH)
s_hs_traffic = Derive(H, "s hs traffic", TH_SH)

T = Ratchet(H)                     # residue = Derive(H, "derived")
                                   # then T = Init(residue)

c_ap_traffic = Derive(T, "c ap traffic", TH_SF)
s_ap_traffic = Derive(T, "s ap traffic", TH_SF)
exp_master   = Derive(T, "exp master", TH_SF)
res_master   = Derive(T, "res master", TH_CF)
# T destroyed
~~~~

When the negotiated group is a hybrid or other multi-component key
exchange, DHE is not one secret.  Each component shared secret is
absorbed by its own Absorb(H, "dh", component), in the order that group
defines them, and the components are never concatenated first.  Both
peers MUST absorb in that order, so they build the same handshake-stage
input sequence.

### Absent and Empty Inputs {#absent-empty}

A handshake without a PSK still executes Absorb(E, "psk", "").  That
call contributes the following bytes:

~~~~
frame("psk") || frame("") = 0x0003 || "psk" || 0x0000
~~~~

This is unambiguous because a PSK of this document is never zero-length
(an imported or resumption PSK is 64 octets, {{psk-importer}}).  In that
case the early stage carries no leaves and its deck holds only known
constants, as TLS 1.3's Early Secret is the extract of two known
constants.  The stage exists for uniformity across handshake modes, and
the schedule's security does not rest on its secrecy when no PSK is
present.  A PSK-only handshake omits Absorb(H, "dh", ...) entirely:  the
tag "dh" does not appear in the sequence.

### Stage Secrets {#stage-secrets}

The three stage decks E, H, and T are this schedule's analogue of TLS
1.3's Early, Handshake, and Main Secret.  They are states, not values.
A leaf clones the running deck rather than reading an extracted octet
string, so no named early or main secret is materialized.

Each stage boundary is a Ratchet ({{deck-interface}}) whose residue is
Derive(D, "derived"), and whose next deck is Init'd, framing
schedule_label, and seeded with that residue.  That residue is the
analogue of TLS 1.3's unnamed "derived" salt.  It never leaves the
schedule.  It seeds the next deck once and is then discarded
({{erasure-boundaries}}).

The values that do leave, the traffic and exporter secrets, are
separated by their framed paths ({{domain-separation}}):  sibling leaves
within a stage differ by label, and every leaf also binds its transcript
checkpoint.  Early data is separated in addition by the 0-RTT equality
check ({{governing-profile}}).  Every stage binds its transcript at the
leaves, so the decks themselves bind none.  The derivation graph maps
the TLS 1.3 graph node for node, adding none ({{derivation-graph}}).

# The TLS13_TURBOSHAKE256 Profile {#turboshake-profile}

The TLS13_TURBOSHAKE256 profile instantiates the deck schedule of
{{deck-schedule}} with TurboSHAKE256 {{RFC9861}}, built on the 12-round
Keccak-p\[1600,12\] permutation of {{FIPS202}}.

The profile parameters are:

SecretLen:
: 64 octets, the length of every stage and traffic secret.

FLen:
: 64 octets.

## Instantiation {#turboshake-instantiation}

The deck function is:

~~~~
DF(S, L) = TurboSHAKE256(seq(S), 0x1F, L)
~~~~

where seq(S) is the concatenation of every framed item of S in order.
TurboSHAKE256's output length is in octets per {{RFC9861}}, so L is
passed unchanged, unlike the SHAKE256 profile, whose bit-oriented length
needs an 8 * L conversion ({{shake-instantiation}}).

The transcript hash of {{transcript-hash}} is instantiated with the same
function:  TranscriptHash(x) = TurboSHAKE256("tls13 hash" || x, 0x1F,
64).  The domain-separation byte for the deck and the transcript hash is
fixed to 0x1F, the RFC 9861 default, so an API without the D parameter
implements both unchanged.  The MAC ({{mac-op}}) requires D = 0x04, so
the TurboSHAKE interface this profile uses has to expose the domain
byte.

TurboSHAKE256 uses the Keccak-p\[1600,12\] permutation as a sponge:
input is absorbed into a 1600-bit state in rate-sized blocks of 136
octets, with the permutation applied after each block, and output is
read from the same state.  The capacity is the 512-bit portion of the
state that input and output never touch.  It is what the erasure
argument of {{erasure-boundaries}} relies on, and the 64-octet secret,
transcript-hash, and Finished and binder MAC lengths are set to match
it.

### Required API Surface

The required API surface is incremental absorption, cloning of an
unfinalized state, and one-shot squeeze with the output length
known up front.  Cloning before any output is incremental input to
two separate invocations, which Section 2.1 of {{RFC9861}} permits.
No absorb-after-squeeze occurs anywhere in this document, so no
access below the TurboSHAKE interface is required.  The clone
discipline is the same one TLS stacks already apply to SHA-2
transcript-hash checkpoints.

## MAC {#turboshake-mac}

This profile's MAC is the construction of {{mac-op}} over this profile's
Keccak-p\[1600,12\] permutation:  the sponge is TurboSHAKE256(mac_input,
0x04, L), which this document names TurboKMAC256.  TurboKMAC256 is not a
NIST-defined instance of KMAC ({{cryptographic-analysis}}).

# The TLS13_SHAKE256 Profile {#shake-profile}

The TLS13_SHAKE256 profile instantiates the deck schedule of
{{deck-schedule}} with plain SHAKE256 {{FIPS202}}, built on the 24-round
Keccak-f\[1600\] permutation, in place of TurboSHAKE256's
Keccak-p\[1600,12\].  This profile mirrors the TLS13_TURBOSHAKE256
profile's framing exactly:  domain separation comes from the same
framed-prefix mechanism the TurboSHAKE profile uses, an absorbed
frame(schedule_label) at Init ({{deck-interface}}), not from cSHAKE's
function-name and customization-string inputs.  The two profiles' decks
therefore differ only in the underlying permutation, so derivation
({{expand-op}}) and the MAC construction ({{mac-op}}) are shared by both
profiles.

The profile parameters, SecretLen and FLen, are 64 octets as in
{{turboshake-profile}}.

## Instantiation {#shake-instantiation}

The deck function is:

~~~~
DF(S, L) = SHAKE256(seq(S), 8 * L)
~~~~

where seq(S) is the concatenation of every framed item of S in order,
SHAKE256(X, L) is the function of {{FIPS202}} with X the main input and
L the output length in bits, and 8 * L converts this document's
octet-oriented L to the bit-oriented L argument of SHAKE256.

SHAKE256 takes no function-name or customization-string input.  This
profile's domain separation comes from seq(S) beginning with
frame(schedule_label), as {{shake-profile}} describes
({{deck-interface}}).

The transcript hash of {{transcript-hash}} is instantiated with the
same function: TranscriptHash(x) = SHAKE256("tls13 hash" || x, 512).

SHAKE256 uses the Keccak-f\[1600\] permutation as a sponge with the same
136-octet rate and 512-bit capacity as TurboSHAKE256
({{turboshake-instantiation}}).  The capacity is what the erasure
argument of {{erasure-boundaries}} relies on, and the 64-octet secret,
transcript-hash, and Finished and binder MAC lengths match it in both
profiles.

### Required API Surface

The required API surface is that of {{turboshake-instantiation}}:  no
absorb-after-squeeze occurs, so no access below the SHAKE256 interface
is required.

## MAC {#shake-mac}

This profile's MAC is the construction of {{mac-op}} over this profile's
Keccak-f\[1600\] permutation:  that permutation is the one cSHAKE256 and
KMAC256 are built on, and the layout and 0x04 domain byte are the ones
cSHAKE and KMAC use, so the result is byte-for-byte NIST KMAC256
{{SP800-185}} by construction.

# PSK Importer {#psk-importer}

TLS 1.3 permits external PSKs {{RFC9846}}, and {{RFC9258}} imports an
external PSK into a target KDF, producing a PSK bound to its target.
This document uses that mechanism unchanged.

A KDF of this document is a TLS KDF Identifier
({{iana-considerations}}), so an external PSK imported for use with one
is imported under RFC 9258's own ImportedIdentity, with target_kdf
naming the KDF.  No variant structure is needed, and none is defined.

The earlier coupling is what made a variant structure seem necessary.
RFC 9258 binds an imported PSK to a KDF and not to a cipher suite,
deliberately, so that a PSK cannot be reused across key schedules.  A
design in which the cipher suite selects the schedule has no KDF to
name, and has to bind the suite instead.  Negotiating the schedule in
its own extension removes the problem rather than working around it:
the thing RFC 9258 wants to bind is once again a value the protocol
negotiates.

The import derivation is the generic derivation of
{{import-derivation}}, keyed by epsk under target_kdf.  An endpoint MUST
NOT use the raw external PSK epsk directly as a TLS PSK under a KDF of
this document, and MUST NOT import an epsk longer than 0xFFFF octets, so
every framed value fits a single frame.  A client that imports one
external PSK for use under more than one KDF MUST produce a separate
ImportedIdentity, and hence a separate ipsk, per target_kdf, exactly as
RFC 9258 requires.

# Zero-RTT and Early Data {#zero-rtt}

Early data remains PSK-only and remains replayable under the TLS 1.3
anti-replay model.  This document changes neither.  A client MAY send
early data only if the first offered PSK's recorded cipher suite is
among the cipher suites it offers and the remembered ALPN and early-data
policy match the ticket.  A server MUST reject early data unless the
selected cipher suite equals the offered PSK's recorded cipher suite,
the selected ALPN equals the ticket's, and all TLS 1.3 anti-replay
checks pass.  The suite-equality check, not the binder, prevents
redirecting early data to a different AEAD.

# Alerts {#alerts}

This section lists the alerts an implementation of this document
sends, in addition to those already defined by TLS 1.3:

- illegal_parameter: a raw external PSK offered for use under a KDF
  of this document without import ({{psk-importer}}); or an
  ImportedIdentity whose target_kdf does not equal the selected KDF.

- decrypt_error: a Finished or PSK binder MAC that fails
  verification, as in TLS 1.3.

- handshake_failure:  no KDF of this document is mutually supported
  when one is required.

# Companion Mechanisms {#companion-mechanisms}

Several deployed mechanisms invoke HKDF-Expand-Label directly.  This
document defines the Encrypted Client Hello confirmation for its KDFs
({{ech-generic}}), because ECH is pervasive in the deployments most
likely to exercise these schedules.  The remaining mechanisms are out of
scope until a companion document defines their analogues.

## Out of Scope

- DTLS 1.3 {{RFC9147}} derives a record sequence-number encryption key
  (Section 4.2.3) and separates its schedule with the "dtls13" label
  prefix (Section 5.9).  DTLS-Only is N in {{iana-considerations}}.
- QUIC {{RFC9001}} derives its Initial secrets and its "quic key", "quic
  iv", "quic hp", and "quic ku" values with HKDF-Expand-Label.
- Exported Authenticators {{RFC9261}} derive their own Finished keys
  with HKDF-Expand-Label.

An endpoint negotiating a KDF of this document MUST NOT use these
mechanisms with that connection unless a specification defines their
derivations for that KDF.

# IANA Considerations {#iana-considerations}

This document requests no cipher suite code points.  It uses those of
TLS 1.3 ({{cipher-suites}}).

## The schedule_profile Extension

IANA is requested to register one entry in the TLS ExtensionType Values
registry per the procedures of {{RFC9847}}.

| Value | Extension Name | TLS 1.3 | DTLS-Only | Recommended | Reference |
|---|---|---|---|---|---|
| TBD | schedule_profile | CH, SH, HRR | N | N | This document |
{: #iana-ext-table title="Requested TLS ExtensionType Registration"}

It is permitted in the ClientHello, the ServerHello, and the
HelloRetryRequest.  DTLS-Only is N because schedule_profile is a TLS
extension and DTLS record-layer derivations are out of scope
({{companion-mechanisms}}).  Recommended is N pending working group
consensus.

## TLS KDF Identifiers

IANA is requested to register two entries in the TLS KDF Identifiers
registry created by {{RFC9258}}, per its Specification Required policy.
No new registry is created:  that registry already names a key schedule
independently of a cipher suite, which is what this document negotiates.

| Value | Description | Reference |
|---|---|---|
| TBD | TLS13_TURBOSHAKE256 | This document |
| TBD | TLS13_SHAKE256 | This document |
{: #iana-profile-table title="Requested TLS KDF Identifier Registrations"}

A KDF registered here defines every key-schedule computation it governs:
its transcript hash, its secret and key derivations, its Finished and
PSK binder MACs, and its Encrypted Client Hello acceptance computations
({{schedule-profiles}}).  A registration that leaves any of those to the
cipher suite, as HKDF_SHA256 leaves its hash, has to say so:  a KDF
silent on a computation is under-specified, not inheriting.

## Update to RFC 9258

{{RFC9258}} anticipates this document:  "Future specifications that
change the way the KDF is negotiated will need to update this
specification to make clear how target KDFs are determined for the
import process."  This document changes how the KDF is negotiated, and
determines target KDFs as follows.

The target_kdf of an ImportedIdentity is the TLS KDF Identifier the
importing client will negotiate in the schedule_profile extension
({{cipher-suites}}).  For a connection that negotiates no KDF, the
target_kdf is HKDF_SHA256 or HKDF_SHA384 as the target cipher suite's
hash determines, exactly as before this document.  Nothing else in
{{RFC9258}} changes.

The schedule_profile extension carries the negotiated TLS KDF Identifier
value on the wire, and the transcript hash covers it
({{cipher-suites}}), so no final message-level trace for a KDF of this
document can exist before its value is assigned.  Schedule-level vectors
do not wait on that assignment, since every derivation of
{{key-schedule}} takes its transcript checkpoint as an argument, and a
checkpoint stated as a literal value pins the output with no code point
anywhere in the input.  The one exception is ipsk
({{import-derivation}}), whose context is TranscriptHash of an
ImportedIdentity that carries target_kdf.  Early allocation under RFC
7120 should be considered once the document is adopted.
{{test-vectors}} carries no message-level trace yet.

# Security Considerations {#security-considerations}

This section follows RFC 3552.  It states what the schedules protect,
the assumptions they rest on, the properties common to every KDF of this
document, and the analysis specific to each.

## KDF Separation {#profile-separation}

Within a KDF, distinct derivation paths produce distinct injectively
framed inputs to its XOF:  labels, output lengths, and context fields
are bound into each output, so no two derivation paths collide
({{domain-separation}}).

Between the two KDFs of this document, separation is by XOF, not by that
shared label.  TLS13_TURBOSHAKE256 and TLS13_SHAKE256 frame the same
schedule_label, so their inputs can coincide.  They run different
permutations, the 12-round Keccak-p\[1600,12\] and the 24-round
Keccak-f\[1600\], though the first is the last 12 rounds of the second
({{FIPS202}}, Sections 3.3 and 3.4).  Most secret inputs are bound to a
single KDF ({{psk-profile-binding}}, {{governing-profile}}), so a
coincidence of framed inputs across the two cannot expose either's
secret.  An
external PSK imported for use under both is the exception:
{{psk-importer}} requires a separate ipsk per target_kdf, but the epsk
beneath them is one secret, absorbed under both permutations.  A
deployment that negotiates TLS13_SHAKE256 to avoid the reduced-round
premise ({{turboshake-sec}}) does not gain that separation for such a
PSK.

Handshake and application outputs under different cipher suites of one
KDF are separated by the transcript as in TLS 1.3, and early data by the
0-RTT equality check ({{downgrade-resistance}}).  {{domain-separation}}
gives the byte-level argument, which holds for both KDFs because they
share the framing and differ only in permutation.

## PSK-to-KDF Binding {#psk-profile-binding}

A PSK is associated with the KDF under which it was established, and its
binder is computed and verified under that KDF:  the binder is keyed by
a secret derived through that KDF's XOF ({{finished-and-binder-mac}},
{{deck-interface}}).  A PSK established under one KDF therefore cannot
key the early stage of another and still produce a binder that verifies,
because the two KDFs run different permutations.  The server rejects the
mismatch on binder verification ({{governing-profile}}).

Resumption locks on the hash, and under a KDF of this document the
KDF is the hash ({{profile-governs}}).  TLS 1.3 lets a resumption
change the cipher suite but not the hash, because the hash drives the
KDF.  This document lets a resumption change the AEAD but not the
KDF, for the same reason.  The binder and the KDF-compatibility rule
hold the KDF fixed across a resumption ({{governing-profile}}), and
the AEAD may change on a 1-RTT resumption exactly as TLS 1.3
permits.

The binder does not lock the AEAD.  On a 1-RTT resumption the selected
suite is confirmed by the transcript, exactly as in TLS 1.3.  Early
data is different, because its keys are derived and used before the
transcript can confirm the server's selection: there the 0-RTT equality
check, not the binder, keeps early data on the AEAD the client used
({{zero-rtt}}).

## Downgrade Resistance {#downgrade-resistance}

The selected cipher suite appears in the ServerHello and therefore in
the transcript from TH_SH onward, which every handshake and application
output binds ({{key-schedule}}).  Every handshake and application
output is thereby separated by the selected suite, exactly as in TLS
1.3:  a peer that assumed a different suite would hold a different
transcript, and its Finished MAC would fail.  Intermediate secrets are
suite-independent, and no output binds the suite directly.  The
transcript carries it.  Early data is the one output derived before the
ServerHello enters the transcript, and there the 0-RTT equality check
separates the suite ({{zero-rtt}}).

The negotiated KDF is separated two ways.  First, its XOF produces
every derivation, so a peer that assumed a different KDF would derive
different keys and its Finished MAC would fail ({{deck-schedule}}).
Second, a server that selects a KDF of this document echoes the
schedule_profile extension in its ServerHello, which the transcript
covers ({{cipher-suites}}).  For early data, the KDF is the one the
offered PSK is bound to, whose binder is an early-stage output under
that KDF ({{governing-profile}}, {{psk-profile-binding}}).

Downgrade to the TLS 1.3 schedule is a separate case, because that
schedule is signalled by the absence of the extension rather than by a
value ({{cipher-suites}}).  An attacker cannot produce it:  TLS 1.3's
transcript covers the ClientHello as the client sent it and as the
server received it, so stripping the extension in flight makes the two
transcripts differ and the Finished MACs fail.  What remains is a server
that does not implement the extension and declines by saying nothing.
That is a capability mismatch rather than a downgrade, and it is visible
to the client, which sees no schedule_profile in the ServerHello.  What
a client does about it is the client's policy, as for any extension it
requires and a server ignores.

The two KDFs of this document differ only in the underlying permutation
and share the composed security argument ({{cryptographic-analysis}},
{{per-profile-considerations}}).  A deployment that offers both accepts
whichever the server echoes, and the echo is covered by the transcript
({{cipher-suites}}).

## PSK Entropy {#psk-entropy}

As in TLS 1.3, binder unforgeability against an attacker who can
guess an external PSK requires the PSK to have adequate entropy,
since such an attacker can recompute the binder offline.  External
PSKs SHOULD be drawn with at least 512 bits of entropy, matching the
512-bit capacity and 256-bit target security level of both profiles
({{cryptographic-analysis}}).  That exceeds the 128-bit floor
{{RFC9257}} recommends for external PSKs.

## Authentication Is Out of Scope

A KDF of this document governs only the key schedule.  A fully
SHA-2-free connection also requires SHA-2-free authentication:
certificate-based authentication is negotiated separately, through the
signature_algorithms and signature_algorithms_cert extensions, and
commonly relies on SHA-2.  A deployment that must avoid SHA-2 entirely
MUST restrict those extensions accordingly, or use PSK-only
authentication.  Ed25519 uses SHA-512 internally, so avoiding SHA-2
also means excluding it in favor of a SHA-2-free signature such as
Ed448, ML-DSA, or an SLH-DSA-SHAKE variant.

## Retained TLS 1.3 Properties

The 0-RTT replay properties of TLS 1.3 are unchanged.  Early data is
governed by {{zero-rtt}}, which does not depend on the KDF.  The
key-erasure discipline TLS 1.3 relies on for forward secrecy is
retained, realized by each profile's destruction rules
({{erasure-boundaries}}).  The forward-secrecy property that discipline
supports rests on the ratchet's one-wayness, analyzed in
{{cryptographic-analysis}} and, for the cross-stage chaining, booked
open in {{open-analysis}}.

Hybrid key exchange is not a TLS 1.3 property.  TLS 1.3 defines none.
This schedule absorbs each asymmetric-secret component under its own
framed tag, never concatenating them ({{key-schedule}}), following
{{I-D.ietf-tls-hybrid-design}}.  Because each component is a distinct
framed input, one high-entropy component keeps the derivation
unpredictable even if another is adversarial.  That combiner robustness
rests on the injective framing and the random-oracle argument
({{domain-separation}}, {{cryptographic-analysis}}, {{BINDEL}}), not on
TLS 1.3.

## Cryptographic Analysis {#cryptographic-analysis}

Every derivation is one call to the profile's XOF over an injectively
framed byte string, so the bound that governs it is the sponge's own
({{BDPV08}}).  The TLS 1.3 key schedule has a proof over its derivation
graph ({{TLS13KS}}).

### Threat Model and Goals

The adversary model and key-schedule goals are those of {{TLS13KS}}:  an
active network adversary controls message delivery.  It may learn
selected stage secrets under compromise predicates.  It seeks to
distinguish unseen traffic keys, forge Finished or binder values, break
forward secrecy across ratchet boundaries, or downgrade the negotiated
cipher suite.  Authentication of peer identity remains outside the
cipher suite, as in TLS 1.3.  The schedule must provide
indistinguishability of record keys and exporter outputs under the
chosen AEAD, integrity of the handshake transcript through Finished and
binder verification, forward secrecy from handshake compromise to
application traffic once the asymmetric shared secret is used, and the
TLS 1.3 0-RTT replay model when early data is accepted.

### Primitive Assumptions

DF is the profile's XOF over a framed byte string, its permutation
modeled as random ({{FIPS202}}).  A sponge over such a permutation is
indifferentiable from a random oracle up to 2^(c/2) of its calls
({{BDPV08}}, Theorem 2 and Section 5), which is 2^256 at the 512-bit
capacity both profiles use.  That is a mode result in the
ideal-permutation model, independent of the round count.  What differs
between the profiles is the strength of that premise:  the 24-round
permutation of TLS13_SHAKE256 carries the default assurance of the full
Keccak permutation, and the 12-round permutation of TLS13_TURBOSHAKE256
rests on the reduced-round cryptanalysis of {{RFC9861}}, Section 7,
which this document books open ({{turboshake-sec}},
{{open-analysis}}).

The analysis then reasons in that random-oracle model.  The step from
sponge to oracle is the indifferentiability composition of {{MRH}},
which is sound for single-stage games and not in general for multi-stage
ones ({{RSS}}).  {{TLS13KS}} states its result against a single
adversary making oracle queries, which this document argues is
single-stage in that sense but does not prove ({{open-analysis}}).  The
bound is indifferent to the structure of the input:  it asks only that
distinct queries be distinct strings.

The framing supplies exactly that.  Every derivation is a single call
DF(S, L) where seq(S) is injectively framed ({{domain-separation}}), so
distinct derivations query the oracle at distinct points.  An adversary
that never queries it on a string carrying the secret cannot
distinguish those outputs from independent uniform strings.  Against a
secret of 512 bits of entropy it reaches such a string with probability
at most q / 2^512 in q queries ({{psk-entropy}} covers a weaker external
PSK).  Each profile's Instantiation section fixes the XOF, its
domain-separation parameter, and the output lengths
({{turboshake-instantiation}}, {{shake-instantiation}}).

Injective framing is therefore the whole of what this schedule must
supply for the sponge's indifferentiability bound to apply to each
derivation.  It is not the whole of the handshake-level argument.  The
single-stage classification, the cross-stage chaining (including its
salted Diffie-Hellman step), and the reduced-round assumption remain
open ({{open-analysis}}).

### Derivation Graph {#derivation-graph}

Each derived octet string is one leaf of a derivation tree ({{shapes}}).
The stage trunks E, H, and T and the ratchet residues map to TLS 1.3's
Early/Handshake/Main Secrets and its unnamed "derived" salt as
{{stage-secrets}} sets out.  binder_key is a Derive on the live early
trunk, one of its leaves, and finished_key is a derivation of a retained
secret ({{expand-op}});  each keys exactly one MAC invocation and no
other output ({{finished-and-binder-mac}}).  The comparison of
{{comparison}} matches every TLS 1.3 site to a leaf here, none missing,
so the map is one-to-one on derived values, node for node with no
derivation added.  It is structural and does not carry the TLS 1.3
proof.

This document defines each leaf by its framed path, one deck invocation
from its stage's Init to that leaf.  The analysis follows that path,
where each leaf is a single random-oracle query
({{cryptographic-analysis}}).  An implementation carries the trunk and
clones it at each branch ({{permutation-count}}).  Because the clone
reproduces that framed path byte for byte, it is output-identical to
computing each leaf's path independently, and adds no assumption beyond
the per-leaf discrete-query analysis.  Whether that analysis covers the
forked schedule as a whole is booked open ({{open-analysis}}).

### What Is Not Yet Established {#open-analysis}

This document changes the key schedule of a protocol whose key schedule
has been analyzed, and does not yet have an equivalent analysis of its
own.  The following are open.

The single-stage classification.  {{MRH}}'s composition is sound only
for single-stage games ({{RSS}}).  This document argues the game it
relies on qualifies, and so that the random-oracle substitution carries
to this schedule, but does not prove it ({{cryptographic-analysis}}).

The chaining.  {{TLS13KS}} is proved over discrete extract-and-expand
nodes, not over an accumulator carried across each stage and cloned at
its leaves.  That analysis is owed.

The reduced round count.  Keccak-p\[1600,12\] is not proven, by
{{RFC9861}} or by this document ({{turboshake-sec}}).  TLS13_SHAKE256
exists for deployments unwilling to assume it.

The MAC.  TurboKMAC256 is not covered by NIST's KMAC analysis, which is
scoped to the full-round permutation ({{turboshake-sec}}).
Establishing its EUF-CMA security is work this document leaves open.  A
deployment unwilling to wait for it can negotiate TLS13_SHAKE256, whose
MAC is NIST KMAC256 and carries no such obligation.

## Erasure Boundaries {#erasure-boundaries}

### Why a Stage Boundary Is a Ratchet

A sponge accumulator is built on a permutation, and permutations are
invertible.  An accumulator reached from an earlier one by absorption
alone therefore carries its whole past.  The blocks absorbed in
between are public, so anyone holding the later state recovers the
earlier one.  This is a property of any sponge realization of the
interface of {{deck-interface}}, not of the instantiations chosen
here, and it is why a stage boundary cannot be an absorb.  A design
that carried a raw accumulator across one would let a post-handshake
state compromise re-derive handshake traffic secrets.

A Ratchet breaks the chain because its squeeze returns a function of the
state, not the state itself.  In the random-oracle model ({{MRH}}), that
squeeze is one-way against a state the adversary cannot guess:
recovering the state means querying the oracle on it, which takes
probability q / 2^m in q queries when the state holds m bits of
min-entropy.  A boundary that mixes the asymmetric shared secret has
high m.  The early-to-handshake boundary carries only the PSK, so
its one-wayness is the PSK's min-entropy ({{psk-entropy}}):  a
low-entropy external PSK earns no forward secrecy there from the Ratchet
alone.  A PSK-only handshake absorbs no asymmetric shared secret at all
({{absent-empty}}), so every one of its boundaries carries that same
min-entropy.  That conditional one-wayness is what every erasure
boundary rests on.

Accordingly a Ratchet sits at each stage boundary where TLS requires
erasure or compromise isolation:  the early-to-handshake transition and
the handshake-to-application transition ({{key-schedule}}).  A Ratchet's
residue is Derive(D, "derived"), an unnamed value that seeds the next
deck ({{deck-interface}}) rather than leaving the schedule.  The trunk
is then erased, so what survives the boundary is an octet string and not
a state.

That the trunk is erased is the State Handling expectation below, not an
automatic consequence of the squeeze.  The one-wayness argument of this
section is conditional on it.  At a stage boundary the predecessor is a
state, so one-wayness is what defeats sponge invertibility.

A key-update generation shares that one-way property but is not a
Ratchet:  it is a derivation of a retained traffic secret
({{key-update-generic}}), whose predecessor is already an octet string,
so there is no state to break.

### State Handling

A ratchet's forward secrecy is only as good as the erasure behind it,
and erasure is local:  no peer observes it, and no interoperability test
detects its absence.  The rules below are therefore expectations, not
interoperability requirements, and an implementation SHOULD follow them
as its platform allows.

An accumulator of a stage should not outlive that stage's ratchet,
should not be retained as a successor across a ratchet, and should not
be serialized, exported, or compared.  Squeezed octet-string secrets
deserve the same discipline as their TLS 1.3 counterparts.
Handshake-stage traffic secrets and record keys should be destroyed
when their TLS 1.3 analogues would be, and each stage secret once the
next stage has absorbed it.

Every cloned accumulator is a 200-octet copy of secret state, and a
clone exists for the span of a Derive.  Keeping that window short, and
zeroizing each clone when it is dropped, limits what a compromise
recovers.  Compromise of a live accumulator yields that stage's
underived leaves, as compromise of a stage secret does in TLS 1.3.
Because a live sponge state is invertible, it also yields the inputs
absorbed into it, including any asymmetric shared secret:  a further
reason an accumulator must not outlive its stage.

On platforms that cannot guarantee erasure these rules are best effort
({{implementation-considerations}}).

## Domain Separation {#domain-separation}

The invariant the analysis relies on is that distinct derivation paths
yield distinct byte strings as deck-function inputs.  It follows from
two facts, and this document owes both.

First, a framed sequence decodes to exactly one list of items.  frame(x)
is uint16(len(x)) || x with no padding ({{conventions}}), so a reader
takes two octets, reads that many, and repeats:  the item boundaries are
recoverable from the bytes, and two sequences with different item lists
differ as strings.

Second, distinct paths give different item lists.  Every deck opens with
frame(schedule_label), then its rooting item ({{deck-interface}},
{{expand-op}}):  the PSK for the early stage, the early residue for the
handshake stage, the handshake residue for the application stage, and
the retained secret for a derivation ({{key-schedule}}).  A residue or a
retained secret is framed at Init with no tag, and the early stage's
"psk" tag is the same in every handshake, so two decks of the same shape
are told apart by that value and not by their structure.  What separates
them structurally is the label:  a path over a live stage trunk and a
path over a seeded deck draw from disjoint label vocabularies
({{key-schedule}}, {{derived-outputs}}).  Within either, every later
item is a framed tag drawn from this document's fixed vocabulary
followed by its framed value, in an order the schedule fixes, so two
paths of the same kind and the same length that agree tag for tag can
differ only in a value.  Two paths that differ at all therefore differ
at some item, and by the first fact their sequences differ.

A label does not separate a MAC from a derivation.  The domain byte
does:  0x04 for the MAC against the deck's native byte, so a MAC and a
deck derivation are never inputs to the same function
({{finished-and-binder-mac}}).  Absent inputs are distinguished from
empty inputs by the framed tag stream ({{conventions}}).  Unkeyed
transcript hashing is separated at the byte level.  A TranscriptHash
input begins with the raw octets of "tls13 hash".  Every keyed sequence
begins with frame(schedule_label), because every deck is Init'd that
way ({{deck-interface}}):

~~~~
"tls13 hash"           = 0x74 0x6c ...

frame(schedule_label)  = uint16(6) || "tls13 "
                       = 0x00 0x06 || "tls13 "
~~~~

The TranscriptHash input's leading octet is 0x74.  Every keyed
sequence's leading octet is 0x00.  These cannot coincide, so the
first octet alone separates a keyed sequence from the transcript
hash.

## Related Constructions {#related-constructions}

This schedule has the shape of a keyed function over a forked state,
but keys its XOF with an ordinary framed secret rather than a key
parameter ({{deck-interface}}).  Relating it to the analyses of keyed
sponges and forked-state constructions is future work
({{open-analysis}}).  For keyed sponges the gap is a specific one.
Proving Derive a pseudorandom function would discharge the
pseudorandomness assumptions {{TLS13KS}} makes of its extract and expand
functions and of the MAC deriving its binder values, though not its
collision-resistance or salted Diffie-Hellman assumptions.  No
keyed-sponge result reaches this construction as specified.  The
outer-keyed sponge is Sponge(K || m), the key first, with the analysis
limited to keys occupying whole rate blocks ({{KEYEDSPONGE}}), where
this schedule frames schedule_label ahead of a framed secret that does
not fill a rate block.  The inner-keyed sponge keys the capacity
({{KEYEDSPONGE}}), and the full-state keyed duplex keys its initial
state ({{FSKD}}), where this schedule keys nothing at initialization and
absorbs its secret through the rate.  That prefix is not incidental:  it
is what gives a keyed sequence its leading 0x00 ({{domain-separation}}).
Closing this needs a keyed-sponge result that tolerates a public prefix
and a secret that does not fill a block, or a schedule that fits an
existing one.
The closest deployed analogue is Disco {{DISCO}},
a handshake schedule over a forked sponge, though its thin formal
analysis makes it precedent, not assurance.

## Per-Profile Considerations {#per-profile-considerations}

The schedule-wide analysis both profiles share is in
{{cryptographic-analysis}}, {{erasure-boundaries}},
{{domain-separation}}, and {{related-constructions}}.  The two profiles
are structurally identical and differ only in the permutation
({{deck-schedule}}); this section states what is specific to each.

### TLS13_TURBOSHAKE256 {#turboshake-sec}

TLS13_TURBOSHAKE256 targets 256-bit security, which {{RFC9861}}, Table 4
claims for TurboSHAKE256 and its 512-bit capacity ({{RFC9861}}, Section
2.2) supports.  The capacity sets that level, not the length of any
secret.

Everything at that level rests on the 12-round permutation, whose
assurance {{RFC9861}}, Section 7 places on the cryptanalysis of
reduced-round Keccak rather than on proof.  That is the assumption this
profile adds, and neither {{RFC9861}} nor this document proves it.

Capacity, framing, and the derivation graph match the TLS13_SHAKE256
profile ({{per-profile-considerations}}), which reaches the same target
over the full 24-round Keccak-f\[1600\] permutation.  A deployment that
prefers that larger round margin can negotiate TLS13_SHAKE256, the
conservative choice ({{shake-profile}}).

TurboKMAC256 is introduced by this document:  it is the KMAC layout over
a permutation of fewer rounds than the Keccak-f\[1600\]-based cSHAKE256
of KMAC256, so NIST's KMAC security analysis does not cover it, and this
document does not claim it is a NIST-validated instance of KMAC256.

### TLS13_SHAKE256 {#shake-sec}

TLS13_SHAKE256 uses SHAKE256's Keccak-f\[1600\] in place of
TurboSHAKE256's Keccak-p\[1600,12\] ({{shake-instantiation}}), so it
carries no reduced-round assumption.  It does not use raw keyed SHAKE256
for any keyed operation:  derivation is a deck-native
absorb-then-squeeze session over a framed protocol identifier
({{expand-op}}), and MAC is the construction of {{mac-op}}, whose key
block, function name, and customization string provide the keyed-mode
domain separation that bare SHAKE256 lacks ({{shake-mac}}).

## Out of Scope

QUIC, DTLS 1.3, and Exported Authenticators remain out of scope for both
profiles ({{companion-mechanisms}}):  an endpoint negotiating a KDF of
this document MUST NOT use those mechanisms with that connection unless
a specification defines their derivations for that KDF.

--- back

# Comparison with TLS 1.3 {#comparison}

This appendix is non-normative.  It compares the TLS 1.3 schedule with
the deck schedule of {{deck-schedule}}.  Both profiles share this
schedule and differ only in the underlying permutation, so the
comparison applies equally to TLS13_TURBOSHAKE256 and TLS13_SHAKE256,
and the figure labels the deck side generically.  With finished_key and
binder_key as dedicated MAC keys ({{finished-and-binder-mac}}), the two
schedules are close structurally, not only in the values they produce:
both carry the same named intermediates, binder_key and finished_key,
into the same MAC step, and both produce the same six traffic and main
secrets from the same three trunk inputs.

~~~ aasvg
 RFC 9846, Section 7.1            This document, the deck schedule
 =====================            ================================

 HKDF-Extract(0, PSK)             E = Init()
                                  Absorb(E, "psk", PSK)
         |                                |
         v                                v
+-----------------+              +=================+
|   Early Secret  |              |  E accumulator  |
+-----------------+              +=================+
         | Derive-Secret(., Lbl, TH)      | Derive(E, Lbl, TH)
         +-> "c e traffic"  TH_CH         +-> "c e traffic"
         |   = c_e_traffic                |   = c_e_traffic
         +-> "e exp master"  TH_CH        +-> "e exp master"
         |   = e_exp_master               |   = e_exp_master
         +-> "ext binder"  (no context)   +-> "ext binder"
         |   = binder_key                 |   = binder_key
         | Derive-Secret(., "derived")    | Ratchet(E) emits residue
         v                                v
 HKDF-Extract(derived, (EC)DHE)   H = Init(residue)
                                  Absorb(H, "dh", DHE)
         |                                |
         v                                v
+-----------------+              +=================+
| Handshake Secret|              |  H accumulator  |
+-----------------+              +=================+
         | Derive-Secret(., Lbl, TH)      | Derive(H, Lbl, TH)
         +-> "c hs traffic"  TH_SH        +-> "c hs traffic"
         |   = c_hs_traffic               |   = c_hs_traffic
         +-> "s hs traffic"  TH_SH        +-> "s hs traffic"
         |   = s_hs_traffic               |   = s_hs_traffic
         | Derive-Secret(., "derived")    | Ratchet(H) emits residue
         v                                v
 HKDF-Extract(derived, 0)         T = Init(residue)
         |                                |
         v                                v
+-----------------+              +=================+
|   Main Secret   |              |  T accumulator  |
+-----------------+              +=================+
         | Derive-Secret(., Lbl, TH)      | Derive(T, Lbl, TH)
         +-> "c ap traffic"  TH_SF        +-> "c ap traffic"
         |   = c_ap_traffic               |   = c_ap_traffic
         +-> "s ap traffic"  TH_SF        +-> "s ap traffic"
         |   = s_ap_traffic               |   = s_ap_traffic
         +-> "exp master"  TH_SF          +-> "exp master"
         |   = exp_master                 |   = exp_master
         +-> "res master"  TH_CF          +-> "res master"
         |   = res_master                 |   = res_master
~~~
{: #comparison-figure title="RFC 9846 7.1 and the Deck Schedule"}

The left column writes (EC)DHE, the name used before {{RFC9846}}
renamed that input the asymmetric shared secret, which is the term this
document uses elsewhere.  The figure's fixed column width does not admit
the longer name.

The residue is a well-defined, byte-exact value, the analogue of TLS
1.3's Derive-Secret(., "derived", ""), and therefore a useful checkpoint
for tracing and test vectors.

Both schedules root binder_key at the same Early Secret analogue:  TLS
1.3 derives it from Early Secret, and this document derives it (a
Derive) from the early trunk E, which is that analogue, as a third early
leaf beside c_e_traffic and e_exp_master ({{finished-and-binder-mac}}).
Both then derive finished_key from binder_key or from a traffic secret
by the same "finished" label, feeding the same MAC step:  HMAC on the
left, MAC on the right.

The schedules diverge in topology, not in which named secrets exist:
TLS 1.3 threads every stage transition through a discrete HKDF-Extract,
salted by a Derive-Secret("derived") call, where the deck schedule
absorbs each stage's inputs into one running state and crosses the
boundary with a single Ratchet.  The Finished and binder MACs, record
keys, exporters, resumption PSK, key updates, and PSK import each
replace their TLS 1.3 counterparts one for one, and {{shapes}} gives the
per-shape rules.

## Invocation Count {#invocation-count}

The figure of {{comparison-figure}} shows structural closeness.  This
table quantifies it.  Both profiles share the deck schedule and thus
the same invocation count, given once for both.

The handshake counted is one full 1-RTT handshake that offers and
selects a PSK, uses the asymmetric shared secret, accepts 0-RTT early
data, issues one NewSessionTicket, performs one KeyUpdate in each
direction, and serves one TLS-Exporter request:  the maximal common case
both {{Section 7.1 of RFC9846}} and {{key-schedule}} cover completely.
Counts are per endpoint.

A deck invocation is one Derive, MAC, or Ratchet call, matching the
One-Shot Equivalence of {{deck-interface}}.  A TLS 1.3 invocation is
one HKDF-Extract, HKDF-Expand-Label, or HMAC call.  Absorb builds an
input sequence rather than invoking the primitive and is not
separately counted, matching how {{shapes}} already accounts for deck
operations.  Transcript-hash computations are excluded from both
columns:  both schedules compute the same checkpoints over the same
messages.

| Derived value | Deck (this document) | TLS 1.3 |
|---|---|---|
| Early Secret analogue | 0 | 1 (HKDF-Extract) |
| binder_key | 1 (Derive) | 1 (Derive-Secret) |
| finished_key (binder) | 1 (Derive) | 1 (Expand-Label) |
| PSK binder verify_data | 1 (MAC) | 1 (HMAC) |
| client_early_traffic_secret | 1 (Derive) | 1 (Derive-Secret) |
| early_exporter_secret | 1 (Derive) | 1 (Derive-Secret) |
| early traffic key + iv | 1 (Derive) | 2 (Expand-Label) |
| "derived" salt (to Handshake Secret) | 1 (Ratchet) | 1 (Derive-Secret) |
| Handshake Secret (absorbed, not ratcheted) | 0 | 1 (HKDF-Extract) |
| client_handshake_traffic_secret | 1 (Derive) | 1 (Derive-Secret) |
| server_handshake_traffic_secret | 1 (Derive) | 1 (Derive-Secret) |
| client hs traffic key + iv | 1 (Derive) | 2 (Expand-Label) |
| server hs traffic key + iv | 1 (Derive) | 2 (Expand-Label) |
| finished_key (server Finished) | 1 (Derive) | 1 (Expand-Label) |
| server Finished verify_data | 1 (MAC) | 1 (HMAC) |
| finished_key (client Finished) | 1 (Derive) | 1 (Expand-Label) |
| client Finished verify_data | 1 (MAC) | 1 (HMAC) |
| "derived" salt (to Main Secret) | 1 (Ratchet) | 1 (Derive-Secret) |
| Main Secret analogue | 0 | 1 (HKDF-Extract) |
| client_application_traffic_secret_0 | 1 (Derive) | 1 (Derive-Secret) |
| server_application_traffic_secret_0 | 1 (Derive) | 1 (Derive-Secret) |
| exporter_secret | 1 (Derive) | 1 (Derive-Secret) |
| resumption_secret | 1 (Derive) | 1 (Derive-Secret) |
| client ap traffic key + iv (gen 0) | 1 (Derive) | 2 (Expand-Label) |
| server ap traffic key + iv (gen 0) | 1 (Derive) | 2 (Expand-Label) |
| client_application_traffic_secret_1 | 1 (Derive) | 1 (Expand-Label) |
| client ap traffic key + iv (gen 1) | 1 (Derive) | 2 (Expand-Label) |
| server_application_traffic_secret_1 | 1 (Derive) | 1 (Expand-Label) |
| server ap traffic key + iv (gen 1) | 1 (Derive) | 2 (Expand-Label) |
| resumption PSK (NewSessionTicket) | 1 (Derive) | 1 (Expand-Label) |
| TLS-Exporter output (one request) | 1 (Derive) | 2 (Derive-Secret + Expand-Label) |
| Total | 28 | 39 |
{: #invocation-count-table title="Invocation Count for One Full Handshake"}

Of the deck total, 3 invocations are MAC (the PSK binder and both
Finished values) and 25 are Derive or Ratchet.  Of the TLS 1.3 total, 3
invocations are HMAC and 36 are HKDF-Extract or HKDF-Expand-Label.  The
schedule crosses two ratchets ({{key-schedule}}), so the handshake stage
is entered by absorbing into a new trunk rather than by a third ratchet:
the TLS 1.3 extract it replaces has no deck counterpart, as {{shapes}}
states.

The deck is lower at the operation level in every row where TLS 1.3
needs two Expand-Label calls against this document's single Derive that
outputs Nk + Nn octets and splits the result ({{record-keys-generic}}),
and in the three rows where TLS 1.3 forms a stage secret with an
HKDF-Extract that this document reaches by absorbing or seeding a trunk.
Each ratchet, by contrast, matches its Derive-Secret("derived") call one
for one.

The operation count is not the cost, because a single invocation costs
more than one permutation call whenever its framed input exceeds the
rate.  The composed security argument of {{cryptographic-analysis}} does
not rest on either count.

## Permutation Count {#permutation-count}

An invocation is not a permutation call.  Both profiles absorb in
rate-sized blocks, 136 octets in either instantiation
({{turboshake-instantiation}}, {{shake-instantiation}}), so an
invocation whose framed input exceeds the rate costs more than one call.
{{permutation-method}} gives the per-operation counting rule.

Over the handshake of {{invocation-count}}, counted by that rule and
excluding the transcript hash as that table does, with a 64-octet PSK, a
32-octet shared secret, and a 64-octet transcript hash:

| Schedule | Permutation calls |
|---|---|
| Either profile of this document | 39 |
| TLS 1.3 with KMAC primitives | 117 |
| HKDF-SHA3-256 over the same permutation | 156 |
{: #permutation-count-table title="Permutation Calls for One Full Handshake"}

The count is set by input lengths, not by which primitive produced
them.  The shared secret is the only key-exchange value the deck
absorbs.  A key share, a KEM ciphertext, and the handshake messages
never reach it, since each leaf binds its stage's transcript only
through its fixed-length hash ({{implementation-considerations}}).  A
pure-ML-KEM handshake, and an ML-KEM hybrid whose components are each
absorbed separately ({{key-schedule}}), cost the same as x25519 at these
lengths.

Both profiles reach the same count:  they share the schedule and frame
the same fixed schedule_label at Init ({{deck-interface}}), so every
sequence opens with the same 8-octet frame.

A keyed sponge does not carry HMAC's two nested hashes per operation or
KMAC's per-call re-keying.  The step from 117 to 39 is structural, not a
further gain from Keccak:  both schedules run the same permutation, and
the deck spends less only because it carries one state instead of
re-keying a primitive at every call.

# Permutation-Counting Method {#permutation-method}

This appendix is non-normative.  It gives the per-operation rule behind
the permutation counts of {{permutation-count}}.

The framing is not small next to the rate:  frame(schedule_label) is 8
octets and a framed 64-octet secret or transcript hash is 66, so a leaf
binding both a key and a transcript checkpoint spans two blocks.

For an input of n octets producing L octets, a sponge over the profile's
permutation applies floor(n / 136) + 1 permutations while absorbing,
since the padding rule always appends at least one octet, and
ceil(L / 136) - 1 more while squeezing, since the first output block is
read from the state the absorption left.

Sibling leaves that bind one transcript checkpoint, a stage's traffic
secrets, share its absorption.  Because the context precedes the label
({{deck-interface}}), the running deck is cloned after the checkpoint
is absorbed, so the checkpoint enters the permutation once for the
stage and not once per leaf.

HKDF-SHA3-256 over the same handshake spends 156 permutation calls,
four for each of its 39 invocations.  Each HKDF-Extract, and each
HKDF-Expand-Label of at most 32 octets, is one HMAC-SHA3-256, and one
HMAC-SHA3-256 is four permutation calls:  two for the inner hash of
(K XOR ipad) || m and two for the outer hash of (K XOR opad) || digest,
each filling one 136-octet block and padding into a second.  That
two-nested-hashes-per-operation factor follows from HKDF's definition
over HMAC, so no HKDF instantiation removes it.

Replacing HMAC with KMAC narrows the gap but does not close it.  The
NIST primitives of {{fips-schedule}}, KMAC for extraction, expansion,
and the MAC, spend 117 permutation calls, three for each of the same 39
invocations.  KMAC runs one cSHAKE where HMAC nests two hashes, but each
call still absorbs a bytepad-framed customization block and a
bytepad-framed key block before its message, so it saves one of HMAC's
four permutations and not two.  That is a quarter below HKDF-SHA3 and
three times this document, which frames each key inline and carries the
running state a fresh KMAC call rebuilds.

# Implementation Considerations {#implementation-considerations}

This appendix is non-normative.

Both profiles need the same three capabilities of an XOF:  incremental
absorption, cloning of a state that has not produced output, and a
squeeze of a length known before the squeeze begins.  Each profile's
concrete parameters are in {{turboshake-instantiation}} and
{{shake-instantiation}}.

Each handshake and application leaf absorbs its transcript checkpoint,
TH_SH, TH_SF, or TH_CF, as its Derive context ({{key-schedule}}), the
same point at which the corresponding TLS 1.3 Derive-Secret call
consumes Messages.  A stack ported from TLS 1.3 therefore need not
compute any transcript checkpoint it does not already compute.

A client that offers PSKs associated with different KDFs computes each
binder under its own PSK's KDF, and therefore maintains transcript-hash
state per KDF for the partial ClientHello transcript.  TranscriptHash is
itself defined by the KDF ({{turboshake-instantiation}},
{{shake-instantiation}}), so the checkpoints of {{transcript-hash}}
differ per offered KDF.  A client offering more than one either buffers
the handshake messages until the KDF is known or carries checkpoint
state per offered KDF, discarding the state of those not selected once
the KDF is pinned, at the ServerHello or at a HelloRetryRequest.  This
is the one place where offering more than one KDF costs an
implementation more than a single schedule:  the schedule binds no
cipher suite ({{key-schedule}}), so it is shared across every suite
offered, and only the record-key output lengths depend on the suite
({{record-keys-generic}}).

A binder and a Finished derive their MAC key from different base
secrets, binder_key against a handshake traffic secret, though both
derive it under "finished" ({{finished-and-binder-mac}}).  An
implementation that feeds a binder's MAC key from the Finished path's
base secret produces a wrong binder that no Finished-path test vector
detects.

In garbage-collected runtimes, zeroization is inherently best effort:
the runtime may have copied or moved key material, and erasing every
copy is not achievable from the language.  The erasure rules of
{{erasure-boundaries}} are written to be met on such platforms by
ceasing use, dropping references, and zeroizing the buffers the
implementation controls, as implementations already do for TLS 1.3 key
material.

# Test Vectors {#test-vectors}

This appendix is non-normative.

The vectors below are tentative.  They were produced by a reference
implementation and reproduced byte for byte by a second implementation
written from this document alone, in another language and sharing no
code with the first, but written by the same author.  They are therefore
not yet the independent evidence this appendix calls for, and they may
change.  Each profile's permutation is pinned against published vectors,
TurboSHAKE256 against those of {{RFC9861}} and SHAKE256 against those
of {{FIPS202}}.  What rests on a single reading of this document is
the schedule itself:  the framing, the field order, and the context
tags.  That is the part most likely to move.

Every secret and checkpoint is TranscriptHash of a short ASCII string,
so the inputs are reproducible from this document and the same values
serve as TranscriptHash vectors:

~~~~
PSK     = TranscriptHash("psk")
DHE     = TranscriptHash("asymmetric shared secret")
epsk    = TranscriptHash("epsk")
TH_CH0  = TranscriptHash("truncated ClientHello")
TH_CH   = TranscriptHash("ClientHello")
TH_SH   = TranscriptHash("ClientHello..ServerHello")
TH_SF   = TranscriptHash("ClientHello..server Finished")
TH_CF   = TranscriptHash("ClientHello..client Finished")
~~~~

ClientHelloInner.random is the 32 octets 0x00 through 0x1f.  Record keys
use Nk = 16 and Nn = 12.  The exporters use label "test label" and
context "test context" with a 32-octet output.  The two resumption
values use ticket_nonce "nonce" and an empty ticket_nonce, which is
omitted rather than framed ({{expand-op}}).  The ImportedIdentity has
external_identity "external psk identity", an empty context, and
target_protocol 0x0304.

Its target_kdf carries a placeholder TLS KDF Identifier, 0x0100 for
TLS13_TURBOSHAKE256 and 0x0101 for TLS13_SHAKE256.  These are a
convention of this appendix and not a request:  {{iana-considerations}}
asks for two registrations without naming values, and the registry
assigns that range under Specification Required, so other values may be
assigned.  If they are, the ipsk vectors must be regenerated.  Every
other value here is independent of the assignment, because each
derivation takes its transcript checkpoint as an argument.

## TLS13_SHAKE256 Vectors

~~~~
# TranscriptHash of the stated inputs (also TranscriptHash vectors)
TranscriptHash("psk"):
  66eccc8045416ec22d1379ac2298aa749cb0bb86db4fca5578365a7c75bd244a
  3044aa9ba8ae404b2da7860a2e85af8998ec43aab11c2a117256e29d966eddd7
TranscriptHash("asymmetric ..."):
  72ef6a9ea47b1d38179210bda501fc29433b568b7247faec3c5de03c7ff500aa
  2e5276beb174cbec19e35148f9dcc4953e542c71aa0090effebb46fca99035ec
TranscriptHash("epsk"):
  861eebba4babfad7f02ca29cb787b1ef048e23540fc395941306e7958d406f20
  36be826abc7c912faaa8ea571dbf9c2f8128f739d803c5b22dd2cd1d6a9f6f49
TH_CH0:
  0e0254dce0001d20e9ccf45f038e0e4369bd5f0ca4cfbb01a3a5dc2cdb1c2761
  f999edb7213590745ebbf209134a2746795f9f0fd7bd5ea993797af6c9de97de
TH_CH:
  92dc319d6999c7606c589f50f53834bca7dc871f67bbc5bdc0abe70f4f708c7a
  7b93ae22c5544bfc18a7bdcfe54e1ac18c1f64335c0a4ec078aa9255cdc08500
TH_SH:
  df71253c5be0dacc544f06b8124ed65474bf4be5be8d63bab10018a5dfbbed6c
  bb0371f2a1649157053b23c7d25eadd1bc400fc05ba8510549d2930a374ca54a
TH_SF:
  63fc9f9ca068104fa93d078e5fdaff21307d9f2e3b48751dd3239d362c8c467a
  41a6d37c11d58da2a22c263f52609f54a57c6470e6ccd02e6bce36cd4de2adaf
TH_CF:
  1a9c3bfbbf4d6e6f00efe79b6096f91f576eedbd7237275e204120bccf608d41
  ce09d75493cbee316335d0783ce9d67b5a2692f87cddd6c8c0264a51a1b55c3a

# Early stage
Init() sequence:
  0006746c73313320
Absorb(E,"psk",PSK) contributed:
  000370736b004066eccc8045416ec22d1379ac2298aa749cb0bb86db4fca5578
  365a7c75bd244a3044aa9ba8ae404b2da7860a2e85af8998ec43aab11c2a1172
  56e29d966eddd7
c_e_traffic:
  8dc314eeb21286fbbf04003d6278ea72fe0b13fe33ea5007aff15f0e4a41d759
  e915c5002d2f5453c372b42ddd4bbce4151b6783cff709c1e9dea4526555e262
e_exp_master:
  deb93e40618718411940505fee4f7c269cf6a43c472b6c975f04b8650dc7597c
  5b4cedbd9f4a7f65280c2b4a0bc5ffdb020dd33c8ae18872267d8eee8e32f91c
binder_key (res binder):
  df739c3daffcf27d839bb50f4a5ceb320949b48c150efff26eb41b152c96ebf6
  c8ebe92c567b627bbcbf879699e560615ca9e77a4d6b12db03ca0b20a03e12a6
Absorb(E,"psk","") contributed:
  000370736b0000

# PSK binder
finished_key (binder):
  a464ab156a0e7d96613123a32df837b5602d9b13d60f4abdd02783a765278f56
  3b6893fd4ce4f1f00bd0be0a2cec8c22c4bcb35d86b93b52dfd95dad5b68f520
binder verify_data:
  216930054442f25ec1e319c3167328d9999125b993a740d02fd788e70c2dfe80
  aa9d2af76cbddb861c9109b8f1b5fb957cd33dbdd52900e80adfb99a569a4e9f

# Handshake stage
residue E->H:
  55321ee114b95625d9c8103f88e32643ee4a1d078ece6466a9cd090be610547e
  1058452cd6a87eeb50f33d298b7101ec93e6bb864f0c59ddad138ce2b05cdd8f
c_hs_traffic:
  8919262f4bf1e009be8a2db7bea5fd69d53122ac3a30b53055baa4b8fbce103b
  2595d7224424b209bf973f57c6ba025eda9bfd4251360b08ba6f1086933fb813
s_hs_traffic:
  b8f14d8627a58c305c312d373f10ab6d8afbb5db7df4647e55b4417abe4c742a
  8375494391555e06462758315e1c6180a20a11067cda2f9d8efa865ed8d628f0

# Finished
finished_key (server):
  6193189f09f3d8ea91e8359152fed882614e29a2c1e9f144da6dea191be96a0c
  5ee48cd6a7da4d1a148d964281aedc555747f97891c6b064c58010bed37539e7
server verify_data:
  5b880210c58a90c4630af11561a5cc47937800441d698ebf3087f6b4acc134ed
  146e5e27d222540a1d4cbc7dd6b70acea06a36e289dcf7dec2e49876f2c759a1

# Application stage
residue H->T:
  ce284cacaa34498dde8b98c62ff7dcba8404a58801109a05540d57593140b29c
  349d0964d9a07211a23fad1019d8bfc86f9f125604705bc83322378901668d6e
c_ap_traffic:
  4c0616b42d11ec3fa6d8269f9117a67d2f2dae89f649879771515540c57d6524
  79460868a8dd5129c6c72ffe770e7d7a2bbec428074f6cfd0172c46280699b37
s_ap_traffic:
  ab1b41c63566f88f27f4cfe27ea4ccfb571d6a70777e7c5dbc082dc33b0a44a7
  04e2bbbf9126f2b501e325c070e6e8e56cf6bb54a33495298f47dafad755e862
exp_master:
  8dca7254b7fd66f9f55fa2603e125e4475ae0596d15398f3402d1fc96387c0e2
  5310718a071b4f4cc4e3e62d7409f7c5ec68396ec1923fa70184e064ada15e85
res_master:
  f3074f8f48a8df60be7a81f1d81da85cfd227aa64e3ffcd29410186aa0602669
  61e405e61fad9a79ecf7501d8759563f62e16e7e4afb143777fb64b50569ca60

# Record keys (Nk=16, Nn=12 of TLS_AES_128_GCM)
key_block:
  1abdab692ea5277cb7c518a4bf074674fe83f8de919be76e348d308c
write_key = key_block[0..16]:
  1abdab692ea5277cb7c518a4bf074674
write_iv  = key_block[16..28]:
  fe83f8de919be76e348d308c

# Key update
app_traffic_secret_1:
  b9b387bb48ed7250afb536185437b7d13de8ecf535b1f94bef48b435cf6ae8ed
  b0a9ef61af372a6ce289a6bcf2f6398314fa7bdd6f9952501da956fbe481b860

# Resumption
resumption_psk (nonce):
  e946d2b2bd97c664e37963a0d552a5aa884b5ef2e08a94c34d2fa95b9137b823
  82f75c137bdae2c4063044b6c102e3b42feac3458577a77c80026747f7e63033
resumption_psk (empty nonce):
  250b68c2d2a19dc8ec2e9510dfa279b5e5c13be9f6c110e37db01eec617048e6
  e875986aece53ad2ea62e4489a31857222394bfbd3964d637df91614f7a8a78f

# Exporters
TLS-Exporter (32 octets):
  9577a6257c074295eef984f5938ffe10a874213a0656c24bfa64726986906686
early exporter (32 octets):
  7e39f663acea3827736eb496a412a77e255156b9f8a113920b93aec9123d565c

# PSK import
ImportedIdentity:
  001565787465726e616c2070736b206964656e74697479000003040101
ipsk (derived psk):
  dd0536afa369d9437a398ae510b475a9081cac1f012ff501f49cf7d113f906ba
  d9601569986b22d88043e75907911a9c7345771012d0f9cba962670b0a929a1b

# ECH acceptance confirmations
accept_confirmation:
  c5450cace00affb1
hrr_accept_confirmation:
  69e7dc04a9f22121
~~~~

## TLS13_TURBOSHAKE256 Vectors

~~~~
# TranscriptHash of the stated inputs (also TranscriptHash vectors)
TranscriptHash("psk"):
  68ced33b52672668e960da11aa8a214f786ec8bba642feb48120b4c413de5992
  50e219a151e0a33412fd20d408ff40e62484dbfebb9d513916d0ead5c3d6defe
TranscriptHash("asymmetric ..."):
  8903e4a30203a04f848773bd22e64268a9370acee1c87c935a552b8507dc47cd
  95f15119ffeb5c3bc62a6f00a85d6e931b3c7c9bcb682bfd5c4b6500b4b6d21a
TranscriptHash("epsk"):
  9333fa09a9fb23511218694c6b44a83c3feaa1d7a644b3f745b4a198f6dadbd0
  20b71a4286dbee2062369fc2580435ed1ec28c9a99a6e3398a469b50fb2f2bc1
TH_CH0:
  8ce8a28c96e1601c1aa8fcc4dcbe37ae1da39584a3d99b361923816b27acab85
  aafa2fb99e9eec536e6d1d7a8326cf64e4fcff54094be16fae7f1f1e4862727d
TH_CH:
  4d04ddcadef309d940351efa0f8850bdb46bd500b81e38080a9ac7a15db5418a
  b552c899797daa2eb2ee3fc9c841bb5186243053b5240a6887bc1d505ac43ff7
TH_SH:
  f7dd7e7ae81ce9c3e4a2b5b06ee80b7eb1134042cf26403135a0f79f478b5c25
  673e7d9bc81fc5fa8eb8ebb62e55d65decd3ca80c3162e50b418951d15076f36
TH_SF:
  a3e0515a234d20f5a35d4afe1f034327c45b0ac71275c2cddf8379fb9383d89a
  82da608a7cd51a0c1ae5104772e80f814403dbb5ce6d365b958d00533af1a494
TH_CF:
  91779f45864417e2b1bc9799ca052341ae8e8879bae468c89b30e4de83d79c89
  a486e8665aa763bc86b0802bd58b7868e30773fcde2aa5eff6cf17533e418515

# Early stage
Init() sequence:
  0006746c73313320
Absorb(E,"psk",PSK) contributed:
  000370736b004068ced33b52672668e960da11aa8a214f786ec8bba642feb481
  20b4c413de599250e219a151e0a33412fd20d408ff40e62484dbfebb9d513916
  d0ead5c3d6defe
c_e_traffic:
  d67d72815a03f3133a92a9c2b7e803ab0c189ce9556b449ef55f5334a308f492
  be65ae2df723ecb7aca3a4308211192701a3d77627e47033e3bca542e246318f
e_exp_master:
  66fc225aba92994e95b59de340415b7d480c3e22f908662fdaa94cd14f8cc9ec
  005f8d8e3c81c410810d8c120d3abc69ab15c1e3515071d2473e76190e778749
binder_key (res binder):
  f786e8aa41a3f5b6371109956e537a1934339f96925f64a986d766c3ddc71ef8
  5d9e2fe02afd46f32131c7d7dfdfda9488ca64e6d3d78cf2f93c2f6d7b981ac7
Absorb(E,"psk","") contributed:
  000370736b0000

# PSK binder
finished_key (binder):
  2c83c8720e56a0ad4281b3149a41ecf34f880c23d43464dbca6718e49041a7a8
  1fcfdc608d8a48d559f8eaf108e3137ed5029c8e88e8831776d858ea37f3be43
binder verify_data:
  13589a03331d4dc6670d515e2b910c451fb53dff10a7c865ea5ec17afeae603e
  a2aad2ed3ac93bacc72cafdfcc1cbd96327487aebaab3ad146ffcdf86be06203

# Handshake stage
residue E->H:
  e072e5f19d821f866ee30a1573b515a1bb5ef48d5799c07c426a98cd46d2ede6
  a429c36eb7fd0ffa4bd24b441bcb7c331b50fbe92e5230e659dd87c7928ea56e
c_hs_traffic:
  d7b576daf46934ea25e5221a8e7734950c33980fbcd3e5e63d5b5bfa11c19249
  d06fb884cee245530d442572621b0b67ab77c81a7bacbddc58ae33a4debf4364
s_hs_traffic:
  e8dd5e9929ad2b6f1d0d89ba8ae26fb4d98a766f8a008dbe2515f5d5d3b898cf
  670796f6f2ed107c43ab1a211a37735028d67cbcd7d3d3ce501db77f6dcbcb50

# Finished
finished_key (server):
  0571d5e83ffef92f9044389b959f5f1130f6f0503638e8f366e27fe79fbe520d
  73f3f6f62ae0c134320f1dd9432df6c756f83bf35f58943c7ee3c1863ffd20f7
server verify_data:
  8efcca010fd741cde182f922e38ea2bfe95173d2d7c33b7505dc3a27ffd6d7aa
  774f156bdb38c156baec08159e0cc1a662243767eb0f730480971cec6d32b1c0

# Application stage
residue H->T:
  85eb68510203f3f89c4fb152aa825c9760ee08b78cd2597ab1f9654a2b625f31
  50ce5aa92a79fb58a7329777791e5ab186aa1c48eb4215a8bea5298ca6e5bf84
c_ap_traffic:
  f8aa74249ab3b4987dfdcaa1dbf5e902bbdbfcd028368695f068f75ccf771536
  268320456a89ea53f1c16d5eb650b2ebffe678cc1ab37a0efe0a00b43e8fbaf7
s_ap_traffic:
  0b2ecd818c025b55da1e283d7249e53753c8943864d0437acd34609d5b20e9a4
  bf9c7596594e32bbe2a39b5b087d79d7bc55d269e60d0c76a27a87427e99f20b
exp_master:
  d3ba3d208ba2969bed14d8a2c283de9191db0a94616eb5650993b2e2069f4e27
  142839bf2e1764a0f884136d4e495e5d8597d1c92e089dc3ab250314caec9cbe
res_master:
  248ac8baac7821842b09ed219caa68cc4052ef091b7cd1aa7dcb15d9fc74c3cd
  0d08ec2bd01b8750f50946b0b9208e14136cdd3ce15b34085cff2f0a2ec54ec0

# Record keys (Nk=16, Nn=12 of TLS_AES_128_GCM)
key_block:
  b1bce022917899cbf534dc767178dbd321081b50ca6f0536542cde70
write_key = key_block[0..16]:
  b1bce022917899cbf534dc767178dbd3
write_iv  = key_block[16..28]:
  21081b50ca6f0536542cde70

# Key update
app_traffic_secret_1:
  e8880ec46b4d9604ca954b9e37d701e4cbab9d9fa065148a7a66b312defbecea
  dc5d9eb76294e67ceab2ec25930c4442fce6ee9de075c6acfa7bf3e743f00f8b

# Resumption
resumption_psk (nonce):
  8ff5bb6a0d899a0fcf853f987d38ff118dfcef39898c78ac3c26c82c79fc8a20
  4a16ff80ea24ba0f56289b74961231eb1daaa98ec805e710f9e07bdbc9238d12
resumption_psk (empty nonce):
  03c3bd9082229b48616402a298ba4ed0dc428474daad95a7600a347e6e1bc7c1
  d3caf3bd097c034081c64ed4a3b55b69b10594d2b28ef25f64e5a3e33ae5910a

# Exporters
TLS-Exporter (32 octets):
  089d086244fdf269cb5761e666feb97bb02dde4d7616fea8937e4cda36f99c02
early exporter (32 octets):
  d40ac0409da2f2f22e90a9906c0fac1d77a8230ec60c787e34694812a8d2197c

# PSK import
ImportedIdentity:
  001565787465726e616c2070736b206964656e74697479000003040100
ipsk (derived psk):
  816b1a76acf9c1112971aee8b84d1e06bfbe169ee74f4ee3cf60cd37df3d5f1d
  248c35dc42b4ddc5b123fc69730482454fce97aea42ff2735acc2cc7988368e5

# ECH acceptance confirmations
accept_confirmation:
  1d3220c2df122d69
hrr_accept_confirmation:
  c7a9dada2343008a
~~~~

A message-level full-handshake trace in the style of RFC 8448 has not
been extracted, though a reference implementation wires TLS13_SHAKE256
into a TLS stack.

# The NIST Shapes of the TLS 1.3 Key Schedule (Informative) {#fips-schedule}

This appendix is non-normative.  The deck schedule of {{deck-schedule}}
is built by taking each computation TLS 1.3 derives from HKDF and
giving it a deck operation instead ({{shapes}}).  This appendix sets
that against the other target: for each site of the TLS 1.3 key
schedule, what this document does there, and the NIST Recommendation
that governs a site of that shape.

| RFC 9846, Section 7.1 site | This document | NIST for a site of that shape |
|---|---|---|
| the PSK input | unchanged | {{SP800-133}}, Section 6.2.2 |
| the asymmetric shared secret input | unchanged | {{SP800-133}}, Section 6.2.1 |
| HKDF-Extract, forming each stage secret | Absorb, and Ratchet at each boundary | {{SP800-56C}}, Section 5.1 |
| Derive-Secret and HKDF-Expand-Label, at every leaf | Derive | {{SP800-108}}, Section 4.4 |
| Transcript-Hash | DF, unkeyed | {{FIPS202}} |
| the Finished and PSK binder MACs | KMAC256, or TurboKMAC256 | {{SP800-185}} |
{: #nist-shape-table title="TLS 1.3 Key-Schedule Sites, This Document, and the NIST Recommendation for Each Shape"}

The MAC is the only row where this document uses an approved
construction in its approved role.  On TLS13_SHAKE256 it is
byte-for-byte NIST KMAC256 ({{shake-mac}}), which is a MAC where
{{SP800-185}} specifies a MAC.  Every other row replaces the HKDF site
with a deck operation, and that is the design rather than an omission:
the deck is not an approved key-derivation function under any current
Special Publication, no CAVP or CMVP testing covers it, and
TLS13_TURBOSHAKE256 rests on reduced-round functions NIST has not
approved at all.  A deployment that requires approved components cannot
use either KDF of this document.

The natural question is then what an approved schedule would use, and
the answer is not simply KMAC everywhere. {{SP800-108}}, Section 4.4
adds a KDF using KMAC and needs no iteration, "When using KMAC, there is
no need for an iterated PRF execution", so the expansion row is
available: it also requires the output length before the call, "KMAC128
or KMAC256 shall be used" rather than a KMACXOF variant, which the
deck's Derive already satisfies for that same reason
({{deck-interface}}).  The extraction row is not available.

{{SP800-56C}}, Section 5.1 admits two auxiliary MAC algorithms and no
others, "either an implementation of HMAC ... or an implementation of
AES-CMAC", and then ties the rows together, "the PRF used by the KDF in
key expansion is determined by the MAC algorithm that is used for
randomness extraction", which rules out an HMAC extract with a KMAC
expand as well.  Table 4 permits HMAC-SHA3-256, so the one conformant
SHA-3-family schedule today is HMAC-SHA3 in both rows: TLS 1.3 with a
SHA-3 hash, which changes the hash and not the schedule.

That row is not closed, though. {{SP800-56C}}, Section 8.3: "At this
time, KMAC has not been specified for use in the implementation of a
two-step key-derivation procedure.  This restriction may be reconsidered
once a KMAC-based KDF has been approved for use as a PRF-based KDF in a
revision of \[SP 800-108\]." That revision exists: {{SP800-108}} is
Revision 1, and its own account of what changed reads "In Revision 1, a
KDF using KMAC is added in Section 4.4".  The condition NIST named has
been met and the reconsideration has not yet happened.  Section 4.1 of
{{SP800-56C}} meanwhile already approves KMAC as the auxiliary function
of a one-step KDF, "H(x) = KMAC#(salt, x, H_outputBits, S)", keyed by a
salt, so KMAC keyed by a salt is an approved derivation primitive today
and it is the two-step composition that is pending.

Whichever way that resolves, the KMAC schedule is not free:  every KMAC
call reabsorbs a bytepad-framed key block that the deck's running state
carries instead.
