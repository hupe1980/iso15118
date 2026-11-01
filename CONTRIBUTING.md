# Contributing

Issues and pull requests are welcome.

## The one rule

**A change to any wire format needs a golden vector or a spec citation.**
"It round-trips with itself" only shows that the encoder and decoder changed
together. A change to the EXI layer, a generated codec or the grammar derivation
is checked against a third implementation:

- `scripts/verify-grammars.sh` and `scripts/verify-messages.sh` still pass;
- a golden vector captured from another implementation; or
- a citation to ISO 15118 or EXI 1.0, checked against the text.
  `scripts/verify-citations.sh` confirms every `[V2G2-nnn]` names a requirement
  ISO 15118-2:2014 defines (the text is public on a US FHWA docket).

## Before opening a pull request

```sh
cargo fmt --all
cargo clippy --workspace --all-targets --all-features
cargo clippy --all-targets --no-default-features
cargo test --workspace --all-features
cargo test --no-default-features
```

If the wire format is involved (needs a JDK):

```sh
scripts/fetch-schemas.sh                                    # once
scripts/generate.sh && git diff --exit-code src/generated   # codegen has not drifted
scripts/verify-grammars.sh
scripts/verify-messages.sh
scripts/verify-captures.sh                                  # needs tshark
```

The ISO schemas are licensed and not in the repository; `fetch-schemas.sh`
downloads them and every script checks them against `scripts/schemas.sha256`. A
mismatch means ISO serves different bytes at the same URL: re-pinning is a
reviewed change, and the `src/generated` diff it causes is the review. The
capture corpus is GPL-2.0 and is fetched into a gitignored directory.

If you added or changed a `[V2G2-nnn]` citation:

```sh
scripts/verify-citations.sh    # needs pdftotext and network access
```

The PDF and its extracted text stay in a scratch directory; they are never
written into the repository.

If you touched `pnc::pki` fixtures:

```sh
scripts/make-test-pki.sh        # needs openssl; rewrites tests/fixtures/pki
scripts/make-test-envelope.sh   # needs openssl; rewrites the envelope fixture
```

Validity windows are absolute dates, so the chains do not expire.

If you touched a decoder, fuzz it for a few minutes. Put the corpus first: new
inputs are written to the first directory, and `fuzz/seeds/` is the curated set.

```sh
cargo +nightly fuzz run <target> fuzz/corpus/<target> fuzz/seeds/<target> -- -max_total_time=60
cd fuzz && cargo check --all-targets    # the fuzz crate is not in the workspace
```

User-visible changes get an entry in `CHANGELOG.md`.

## Tests that guard the docs

- `tests/claims.rs` checks the counts the README and the site state; the three
  `verify-*` scripts check the totals they measure the same way.
- `tests/concepts.rs` guards maintainers' notes kept in gitignored directories
  and skips without them, except one check that always runs: nothing published
  may cite those directories.

`scripts/requirement-coverage.sh` lists, per `[V2G2-nnn]`, whether a test names
it, the code implements it, or only prose cites it.

## Generated code

`src/generated/` is committed and never edited by hand; `scripts/generate.sh`
writes all of it. A change belongs in `codegen/`. To see what the generator
cannot express:

```sh
cargo run -p iso15118-codegen -- concepts/reference/iso15118-2/V2G_CI_MsgDef.xsd --why
```

A message set is added from its published XSDs and differed against
`exificient`, never hand-transcribed.

## Style

- `#![forbid(unsafe_code)]` stays.
- Every spec constant cites its requirement; where -2 and -20 differ, both
  values are given. A value that is a judgement says so.
- Comments explain *why*, briefly.
- Documentation describes the crate as it is. History belongs in `CHANGELOG.md`.

## The documentation site

`site/` is a [Zola](https://www.getzola.org/) site published to GitHub Pages.

```sh
zola --root site serve     # http://127.0.0.1:1111
zola --root site check     # every internal and external link
```

## Releases

Each release carries a CycloneDX SBOM and a build-provenance attestation for the
published `.crate`:

```sh
gh attestation verify iso15118-X.Y.Z.crate --repo hupe1980/iso15118
```

## Licence

By contributing you agree that your work is dual-licensed under MIT and
Apache-2.0, as the rest of the crate is.
