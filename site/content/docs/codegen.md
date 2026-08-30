+++
title = "Code generation"
description = "How iso15118 turns the official ISO 15118 XSD schemas into Rust: derived EXI grammars, reduced content models, and a generator that refuses to guess."
weight = 110
+++

The ISO 15118-2 and -20 message sets are not written by hand. A
workspace-internal generator reads the official XSDs, derives the EXI grammars,
reduces each content model to the arithmetic the codecs need, checks that
reduction against the derived grammar, and emits Rust.

**A mismatch at any step fails the build rather than producing a plausible codec.**

## The output is committed

`src/generated/` is in the repository, so:

- a reader can see the codec without running the generator;
- **building or using the crate never needs the schemas** — only regenerating does;
- and the check that the two have not drifted is one command.

```sh
scripts/generate.sh && git diff --exit-code src/generated
```

The generator is still the source of truth. Editing the generated files is not a
fix; it is a divergence that the command above will catch.

## Getting the schemas

The XSDs for ISO 15118-2 and -20 are published freely by ISO. They are *licensed*,
though, so they are not redistributed here — `specs/` is gitignored except for its
README.

```sh
scripts/fetch-schemas.sh     # reproducible download into specs/
scripts/generate.sh          # regenerate src/generated/
```

The spec **texts** (the PDFs) are paid documents, and so are the DIN SPEC 70121
schemas. Nothing in the build depends on having either.

## What the generator emits

For each schema set: typed Rust structs, and `Encode`/`Decode` implementations
that walk derived event-code arithmetic.

Notably it does **not** emit state tables. A content model's whole grammar becomes
five short integer slices — productions before each item, the event-code width at
each position, the width after a repeat, and the occurrence bounds — which a
shared interpreter drives. The equivalent unrolled DFA for one `maxOccurs="2048"`
particle is 2049 states, and ISO 15118-20 has several; here each costs one `u32`.

That is what makes the generated code fit on a microcontroller, and it is why the
crate can afford to ship all five schema sets behind feature flags.

## When it cannot express something

Some XSD constructs have no faithful Rust representation, and the generator's
contract is that it says so rather than dropping them quietly:

```sh
cargo run -p iso15118-codegen -- specs/iso15118-2/V2G_CI_MsgDef.xsd --why
```

reports every declaration it could not express and the reason. A type that is
reported is a type whose decoder refuses the input, not one that silently decodes
to something incomplete.

## Enumerations and response codes

Two details that would otherwise be forty-odd hand-maintained constants per
generation:

- **Enumeration indices follow schema document order**, not lexicographic order.
  The generator derives them, so an enum's discriminant *is* its EXI index.
- **Response-code classification is derived from the schemas' own naming.** The
  `OK_`, `WARNING_` and `FAILED_` prefixes give every code an `is_ok`, `is_warning`
  and `is_failure`, which is what lets the session layer act on "a failure ended
  this session" without either generation's code list being maintained by hand.

## Is the derivation right?

That is the whole question, and it is why the generator is checked against an
independent implementation rather than against itself. Every grammar it derives is
diffed against `exificient`, and every message it generates is round-tripped
against bytes that same implementation produced — as documents and as fragments.

See [Verification](@/docs/verification.md), including the list of defects that
check found and that no round-trip test could have.
