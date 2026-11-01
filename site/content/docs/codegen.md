+++
title = "Code generation"
description = "How iso15118 turns the official ISO 15118 XSD schemas into Rust: derived EXI grammars, reduced content models, and a generator that refuses to guess."
weight = 110
+++

A workspace-internal generator reads the official XSDs, derives the EXI grammars,
reduces each content model to the arithmetic the codecs need, checks the reduction
against the grammar, and emits Rust. A mismatch fails the run.

## The output is committed

`src/generated/` is in the repository — module indexes included — so building
never needs the schemas. The generator is the source of truth:

```sh
scripts/generate.sh && git diff --exit-code src/generated
```

## Getting the schemas

ISO publishes the XSDs freely under its own terms, so they are not redistributed:
`scripts/fetch-schemas.sh` downloads them into a gitignored directory, checks each
against a pinned SHA-256 (`scripts/schemas.sha256`), and prints where.

```sh
scripts/fetch-schemas.sh     # reproducible download; prints <schemas>
scripts/generate.sh          # regenerate src/generated/
```

The specification texts are paid documents; nothing in the build needs them.

## What the generator emits

For each schema set:

- typed structs with an `ExiDocument` implementation and inherent
  `encode_body`/`decode_body` methods;
- `minimal()` — the smallest value a type permits;
- `refusal(code)` — the response refusing a request, built on `minimal()`, so it
  always encodes;
- `requests()` — every request of the set at its minimum, so tests cover all of
  them without a hand-kept list.

No state tables: a content model is five short integer slices — productions per
item, event-code widths, the width after a repeat, occurrence bounds — driven by a
shared interpreter. One `maxOccurs="2048"` particle, seven at 1024 and sixteen
`unbounded` (all in the imported XMLDSig schema) each cost one `u32`.

## When it cannot express something

Some XSD constructs have no faithful Rust representation, and the generator's
contract is that it says so rather than dropping them quietly:

```sh
cargo run -p iso15118-codegen -- <schemas>/iso15118-2/V2G_CI_MsgDef.xsd --why
```

lists every declaration it could not express and why; such input is refused at
decode, never silently skipped.

## Enumerations and response codes

- Enumeration indices follow schema document order, so a discriminant is its EXI
  index.
- `is_ok`, `is_warning` and `is_failure` on every response code come from the
  schemas' `OK_`/`WARNING_`/`FAILED_` prefixes.

## Is the derivation right?

Every derived grammar is diffed against `exificient`, and every generated message
round-tripped against bytes it produced, as documents and as fragments — see
[Verification](@/docs/verification.md).
