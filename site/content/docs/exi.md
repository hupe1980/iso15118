+++
title = "The EXI profile"
description = "ISO 15118 pins every EXI coding option out of band. The exact profile the iso15118 crate implements, why strict=false changes every message, the value string table, and how the codec is bounded."
weight = 40
+++

ISO 15118 transmits no EXI options document, so every coding option is shared
knowledge. Getting one wrong produces a plausible stream that decodes to nonsense.

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
| Enumeration order | Schema document order, not lexicographic |
| Global element order | By local name, then namespace, across the whole schema set including imports |

**`strict = false` is the row implementations get wrong.** Non-strict grammars add
second-level productions for undeclared content; they cost no bits themselves but
widen every first-level event code — a state with one declared production needs
one bit, not zero. Golden-vector tests re-encode real ISO 15118-20 frames from an
independent C++ implementation byte for byte, and a negative test shows
strict-mode widths cannot decode them.

## Design

- **Generated, then committed.** A workspace-internal generator emits typed structs
  and their `ExiDocument` implementations; see [Code generation](@/docs/codegen.md).
- **No state tables.** A content model is five short integer slices driven by a
  shared interpreter; a `maxOccurs="2048"` particle costs one `u32`, not 2049
  states.
- **Owned decode, bounded before allocation.** Bit-packed strings are not
  byte-aligned, so decoded values are owned and `alloc` is required. Every length
  is checked against its schema facet and the bytes remaining before a buffer is
  reserved.
- **The second level is a rejection.** A spare event code below a particle's
  `minOccurs` is `UnknownEventCode`, not "the next item" — a peer cannot drop a
  mandatory repetition.
- **Documents and fragments.** Plug & Charge signs fragments, which are indexed over
  every declared element (281 in ISO 15118-20 `CommonMessages`), documents over
  global elements only (54).

### Bounded everything, in both directions

Maximum depth, array cardinality, and all three length facets — `minLength`,
`maxLength` and `length` — on the way in and the way out:

```rust
use iso15118::exi::Lengths;

assert!(Lengths::exact(16).admits(16));
assert!(!Lengths::exact(16).admits(15));   // not a short challenge — not one
assert!(Lengths::max(800).admits(0));      // a certificate may be absent-ish
assert!(!Lengths::new(7, 37).admits(6));   // an EVSEID has a floor
```

Six V2G types have an exact length — both `GenChallenge`s, ISO 15118-20's
`SessionID`, the ECDH public key, the three encrypted contract-key envelopes — and
`eMAID` and `EVSEID` have a floor. ISO 15118-2 allows a short `SessionID`;
ISO 15118-20 does not.

## The value string table

A repeated string value may be written as a short reference into a local or global
partition. **This codec decodes both forms and writes literals.**
`ValueCoding::Literal` is the default, because `libcbv2g` — the codec
[EVerest](https://everest.energy) ships — has no value table and returns
`EXI_ERROR__STRINGVALUES_NOT_SUPPORTED` for a reference. `Referenced` is what
`exificient` writes and Canonical EXI requires.

```rust
use iso15118::exi::{ExiDocument, ValueCoding};
# use iso15118::app_protocol::SupportedAppProtocolReq;
# use iso15118::Protocol;
# let msg = SupportedAppProtocolReq::advertising([Protocol::Iso20, Protocol::Iso2]);
let interoperable = msg.to_vec()?;                          // every value in full
let canonical = msg.to_vec_with(ValueCoding::Referenced)?;  // what exificient writes
# Ok::<_, iso15118::exi::ExiError>(())
```

A partition is populated only when a value is coded literally, and a value found
in the global partition is not added to the local one. All 166 message types match
`exificient` byte for byte in `Referenced` mode. Signature verification accepts
either form — see [Plug & Charge](@/docs/plug-and-charge.md).

**Keep string values ASCII.** `libcbv2g` reads one octet per character and rejects
anything above 127; EXI writes Unicode code points. `"Ladesäule"` is valid
ISO 15118 and undecodable to EVerest. This crate does not alter your data.

## Using the codec directly

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

`app_protocol` is a hand-written schema-informed grammar; the generated code
follows its shape with derived widths. How it is checked:
[Verification](@/docs/verification.md).
