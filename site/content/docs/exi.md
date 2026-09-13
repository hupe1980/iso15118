+++
title = "The EXI profile"
description = "ISO 15118 pins every EXI coding option out of band. This is the exact profile the iso15118 crate implements, why strict=false changes every message, and how the codec is bounded."
weight = 40
+++

EXI — Efficient XML Interchange, in its schema-informed mode — is the hardest and
most safety-critical part of ISO 15118. It is also a large specification with many
switches, and ISO 15118 pins all of them **out of band**: no EXI options document
is transmitted, so every coding option is knowledge that implementations either
share or silently disagree about.

Getting a single one wrong produces a stream that looks plausible and decodes to
nonsense, so the exact profile is worth stating.

## The profile

| Option | Value |
|---|---|
| Grammars | Schema-informed, from the V2G XSDs |
| Alignment | `bit-packed` |
| Compression | Off |
| Fidelity | **Default — `strict` is _false_** |
| Options document | Absent; the header is the single byte `0x80` |
| `preserve.*`, `selfContained` | All off |
| `valueMaxLength`, `valuePartitionCapacity` | Unbounded |
| Enumeration order | Schema document order, *not* lexicographic |
| Global element order | By local name, then namespace, across the whole schema **set** including imports |

## The row implementations get wrong

`strict = false` is the one. Non-strict grammars carry extra productions for
content the schema does not declare. Those productions live at the **second**
event-code level and cost no bits of their own — but their mere existence widens
every first-level event code.

**A grammar state with one declared production needs one bit under non-strict
rules and zero under strict ones.** Every element in every message is shifted.

This crate does not assert that profile, it demonstrates it: the golden-vector
tests walk real ISO 15118-20 frames captured from an independent C++
implementation, event by event, re-encode them byte for byte, and include a
negative test showing that strict-mode widths *cannot* decode the same bytes.

## Design

### Build-time generation

A workspace-internal generator reads the official XSDs and emits typed Rust
structs whose `Encode`/`Decode` walk derived event-code arithmetic. The output is
committed, so the codec is readable without running the generator — but the
generator remains the source of truth. See [Code generation](@/docs/codegen.md).

### No state tables

A content model's whole grammar is five short integer slices that a shared
interpreter drives. The equivalent unrolled DFA for one `maxOccurs="2048"`
particle is 2049 states, and ISO 15118-20 has several; here each costs one `u32`.
This is what makes the generated code fit on an ECU.

### Owned decode, bounded before allocation

In bit-packed EXI a string is a run of bit-shifted Unicode code points and a
`hexBinary` is a run of bit-shifted bytes. Nothing is contiguous in the input
unless it happens to land byte-aligned, so borrowing is impossible and decoded
values are owned — which is why `alloc` is a requirement of this crate rather
than a feature of it.

What the decoder does guarantee is that **every length is checked against its
schema facet _and_ against the bytes actually remaining before a buffer is
reserved.** A forged length field cannot make the decoder reserve memory the
stream could never fill.

### Bounded everything, in both directions

Maximum element depth, maximum array cardinality, and **both** length facets,
straight from the schemas. `#![forbid(unsafe_code)]` crate-wide.

The second half of that is the part a codec loses first and misses longest.
XML Schema has three length facets — `minLength`, `maxLength` and `length` — and
the third is not the second. `genChallengeType` is `length = 16`: a fifteen-byte
value is not a short nonce, it is not a nonce. Carrying only the maximum is how a
decoder comes to accept a truncated ECDH public key, re-encode it, and produce a
message every conforming peer rejects.

So `exi::Lengths` carries a minimum as well as a maximum, `Lengths::exact` is its
own constructor, and every string and binary value is checked against both on the
way in *and* on the way out:

```rust
use iso15118::exi::Lengths;

assert!(Lengths::exact(16).admits(16));
assert!(!Lengths::exact(16).admits(15));   // not a short challenge — not one
assert!(Lengths::max(800).admits(0));      // a certificate may be absent-ish
assert!(!Lengths::new(7, 37).admits(6));   // an EVSEID has a floor
```

Six V2G types have an exact length, and they are exactly the ones where a
truncated value would be a security problem rather than a formatting one: both
generations' `GenChallenge`, ISO 15118-20's `SessionID`, the ECDH public key, and
the three encrypted-contract-private-key envelopes. Two more have a floor —
`eMAID` and `EVSEID`.

<div class="note">
<span class="note-title">Why the third form is not the second</span>
ISO 15118-2 permits a short <code>SessionID</code> (<code>maxLength = 8</code>);
ISO 15118-20 does not (<code>length = 8</code>). A codec carrying only the
maximum accepts a four-byte one and re-encodes a message no -20 peer will take —
which is the shape of every example in this crate that is a compiled doctest, and
why they are.
</div>

### The second level is a rejection, not a fallback

Non-strict grammars widen every event code to leave room for undeclared content,
and that room is reachable. A state below its particle's `minOccurs` — ISO
15118-20 WPT really has `minOccurs="2"` — has one declared production and one
spare code. Reading the spare as "the next item" or as `EE` would let a peer drop
a mandatory repetition and still decode. It is `UnknownEventCode`.

### Fragment mode

Both the document grammar and the fragment grammar are implemented, because Plug
& Charge signs fragments. They differ from their very first event code: a fragment
is indexed by every element qname the schema *declares* (281 in ISO 15118-20
`CommonMessages`) and a document only by its global elements (54). See
[Plug & Charge](@/docs/plug-and-charge.md).

## The value string table

Every string *value* may be written into a two-level table — a partition local to
its element or attribute, and one global to the document — so that a later
occurrence can be a short reference instead of the characters again.

**This codec decodes both forms and writes only one.** `ValueCoding::Literal` is
the default: every value written out in full. A reference is what `exificient`
produces and what Canonical EXI requires — *"a string value MUST be represented
using a compact identifier if possible"* — and it is also what no deployed
implementation can read. `libcbv2g`, the codec [EVerest](https://everest.energy)
ships, has no value table: its decoder subtracts the literal's length offset of
two and returns `EXI_ERROR__STRINGVALUES_NOT_SUPPORTED` for anything shorter. A
message carrying a reference is not larger for that peer, it is undecodable.

```rust
use iso15118::exi::{ExiDocument, ValueCoding};
# use iso15118::app_protocol::SupportedAppProtocolReq;
# use iso15118::Protocol;
# let msg = SupportedAppProtocolReq::advertising([Protocol::Iso20, Protocol::Iso2]);
let interoperable = msg.to_vec()?;                          // every value in full
let canonical = msg.to_vec_with(ValueCoding::Referenced)?;  // what exificient writes
# Ok::<_, iso15118::exi::ExiError>(())
```

Signature verification accepts either, since a peer may have canonicalised
properly — see [Plug & Charge](@/docs/plug-and-charge.md).

The table arithmetic is exact either way, and the rule that catches people is
that **EXI populates a partition only when a value is coded literally**: a value
found in the *global* partition is not added to the local one. All 121 message
types are checked byte for byte against `exificient` in `Referenced` mode.

### Keep string values ASCII

`libcbv2g` reads and writes one **octet** per character and rejects anything
above 127. EXI specifies a character as a Unicode code point, which is what this
crate writes — so for ASCII the two agree exactly and above it they do not agree
at all. `"Ladesäule"` as a `ServiceName` is valid ISO 15118 and undecodable to
EVerest. This crate does not refuse it: the schema permits it, and silently
transliterating your data would be the worse failure.

## Using the codec directly

`exi` is a usable schema-informed EXI implementation in its own right, and the
generated message codecs are written against just two types:

```rust
use iso15118::exi::{Decoder, Encoder, ExiDocument, Header};
use iso15118::app_protocol::SupportedAppProtocolReq;
use iso15118::Protocol;

let req = SupportedAppProtocolReq::advertising([Protocol::Iso20, Protocol::Iso2]);
let bytes = req.to_vec()?;
assert_eq!(bytes[0], 0x80, "the ISO 15118 EXI header is a single byte");
assert_eq!(SupportedAppProtocolReq::from_bytes(&bytes)?, req);
# Ok::<_, iso15118::exi::ExiError>(())
```

`app_protocol` is the crate's reference implementation of a hand-written
schema-informed grammar; the generated code for the larger schemas follows
exactly its shape, with the event-code widths derived rather than written out.

## Is it right?

Round-tripping an encoder through its own decoder proves they agree with each
other and nothing more. Every grammar and every message in this crate is diffed
against the EXI reference implementation, as documents *and* as fragments — see
[Verification](@/docs/verification.md) for what that covers and what it found.
