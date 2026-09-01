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
<span class="note-title">What it caught on the first run</span>
This crate's own README had been showing readers an ISO 15118-20
<code>SessionStopReq</code> with a four-byte <code>SessionID</code> since it was
written. ISO 15118-2 permits a short one (<code>maxLength = 8</code>);
ISO 15118-20 does not (<code>length = 8</code>). The example is a compiled
doctest, and it stopped compiling the moment the facet was enforced.
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

Every string *value* an EXI stream carries is offered to a two-level table first:
a partition local to the element or attribute it belongs to, and a partition
global to the whole document. A repeat costs a couple of bits instead of its
characters, which is why a certificate chain sent twice in one session is nearly
free the second time.

Getting this wrong is not a size regression, it is a wire incompatibility: reader
and writer must add entries in exactly the same order or every subsequent index
desynchronises. The subtle rule is that **EXI populates a partition only when a
value is coded literally.** A value found in the *global* partition is not added
to the local one — and doing otherwise desynchronises as soon as one string
appears under two element names, which is most real messages.

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
