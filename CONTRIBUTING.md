# Contributing

Issues and pull requests are welcome.

## The one rule that is not negotiable

**A change to any wire format needs a golden vector or a spec citation.**

"It round-trips with itself" is not evidence that it matches what a charger will
send — it is evidence that the encoder and the decoder were changed together. The
whole point of this crate's verification strategy is that a third implementation
agrees, so a change to the EXI layer, to a generated codec, or to the grammar
derivation has to be checked against one.

In practice that means one of:

- `scripts/verify-grammars.sh` and `scripts/verify-messages.sh` still pass;
- a new golden vector captured from another implementation;
- a citation to the requirement in ISO 15118 or in EXI 1.0 — checked against the
  text, not written from memory. A citation nobody can check is worth less than
  none, and `scripts/verify-citations.sh` checks the half a machine can: that
  every `[V2G2-nnn]` in the repository names a requirement ISO 15118-2 actually
  defines. ISO 15118-2:2014(E) is readable in full from a US FHWA rulemaking
  docket, so "I could not check it" is not available for that part.

## Before opening a pull request

```sh
cargo fmt --all
cargo clippy --workspace --all-targets --all-features
cargo clippy --all-targets --no-default-features
cargo test --workspace --all-features
cargo test --no-default-features
```

If you touched anything the wire format depends on, also:

```sh
scripts/fetch-schemas.sh                                    # once
scripts/generate.sh && git diff --exit-code src/generated   # codegen has not drifted
scripts/verify-grammars.sh
scripts/verify-messages.sh
```

Those three need a JDK and the ISO schemas. The schemas are licensed and are not
in the repository; `scripts/fetch-schemas.sh` downloads them reproducibly.

If you added or changed a `[V2G2-nnn]` citation:

```sh
scripts/verify-citations.sh    # needs pdftotext and network access
```

It fetches ISO 15118-2's own text and fails on any citation that names no
requirement.

If you touched `pnc::pki`:

```sh
scripts/make-test-pki.sh        # needs openssl; rewrites tests/fixtures/pki
scripts/make-test-envelope.sh   # needs openssl; rewrites the envelope fixture
```

Only necessary when the *shape* of a fixture changes. The validity windows are
absolute dates rather than `-days N`, so the chains do not rot and a test that
passes today passes in 2049. Neither the PDF nor the extracted text is ever written into the
repository — the copyright notice on every page is explicit — so the script keeps
them in a scratch directory.

If you touched a decoder, give the fuzzer a few minutes:

```sh
cargo +nightly fuzz run <target> fuzz/corpus/<target> fuzz/seeds/<target> -- -max_total_time=60
```

The fuzz crate is not in the workspace, so `cargo check` will not tell you a
target has stopped compiling against an API change. `cd fuzz && cargo check
--all-targets` will.

`tests/concepts.rs` will look like it tests nothing: it guards the maintainers'
internal architecture notes, which live in a gitignored `concepts/` directory and
are not part of this repository as you receive it. It **skips** when that
directory is absent, which is what CI and every contributor see. It is committed
rather than kept alongside the notes so that an API rename cannot quietly stop it
compiling.

Anything a user would notice — an API change, a fixed defect, a new rule — gets an
entry in `CHANGELOG.md` under the unreleased heading.

## Generated code

`src/generated/` is committed but is **not** edited by hand. The generator in
`codegen/` is the source of truth, and `scripts/generate.sh` followed by
`git diff --exit-code src/generated` is the check that the two have not drifted.
A change there belongs in the generator.

## Style

- `#![forbid(unsafe_code)]` is crate-wide and stays that way.
- Every spec constant cites the requirement it comes from. Where ISO 15118-2 and
  -20 differ, both values are given rather than one being made to stand for both.
- Where a value is a judgement rather than a citation — because the standard is a
  paid document this project does not have — say so in the doc comment. An
  invented citation is worse than an honest gap.
- Comments explain *why*, not *what*. The protocol is full of decisions that look
  arbitrary until you know which field failure they prevent; those are the ones
  worth writing down — briefly. A paragraph that does not change what a reader
  does is one to cut.
- Documentation describes what the crate is now, never how it got there. Findings,
  fixes and "what a later pass found" belong in `CHANGELOG.md`.

## The documentation site

`site/` is a [Zola](https://www.getzola.org/) site published to GitHub Pages.

```sh
zola --root site serve     # http://127.0.0.1:1111
zola --root site check     # every internal and external link
```

CI builds and link-checks it on every pull request that touches `site/`, and
deploys from `main`.

## Adding a message set

The generator reads XSDs and emits Rust; adding a schema set is a matter of
pointing it at one and wiring up a feature flag. What it will not do is guess:
anything it cannot express faithfully is reported rather than dropped.

```sh
cargo run -p iso15118-codegen -- specs/iso15118-2/V2G_CI_MsgDef.xsd --why
```

DIN SPEC 70121 is the obvious candidate and is deliberately not implemented: its
schemas are behind a paywall, and hand-transcribing them would produce a codec
with no reference to check against — precisely the failure mode this project
exists to avoid.

## Licence

By contributing you agree that your work is dual-licensed under MIT and
Apache-2.0, as the rest of the crate is.
