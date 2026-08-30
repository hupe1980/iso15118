//! Round-trips every message type against the EXI reference implementation,
//! as an EXI **document** and again as an EXI **fragment**.
//!
//! `scripts/verify-messages.sh` generates a schema-valid XML instance for each
//! global element of each schema set, encodes it with `exificient` both ways,
//! and points `ISO15118_VECTORS` at the results. This test decodes each of
//! those with the generated codec and re-encodes it; the bytes must match
//! exactly.
//!
//! The fragment half matters because that is the form ISO 15118 signs. A
//! fragment is indexed by every element qname the schema set *declares*, local
//! declarations included — a longer table than the global-element list a
//! document is indexed by — so the same message encodes differently from its
//! very first event code. No amount of self-consistency reveals a mistake
//! there; only another implementation does.
//!
//! Where `tests/golden.rs` proves the grammar arithmetic on a few captured
//! messages, and `tests/iso2_messages.rs` proves the generated structs on those
//! same messages, this covers **every** message type and every field the
//! sampler can populate.
//!
//! Without `ISO15118_VECTORS` the test reports that it was skipped, so a normal
//! `cargo test` on a machine with no JDK and no schemas stays green.

#![cfg(all(feature = "iso2", feature = "iso20"))]

use std::path::{Path, PathBuf};

use iso15118::exi::{ExiDocument, ExiResult};

/// Decodes one schema set's bytes and re-encodes them.
type Reencode = fn(&[u8]) -> ExiResult<Vec<u8>>;

fn reencode<D: ExiDocument>(bytes: &[u8]) -> ExiResult<Vec<u8>> {
    D::from_bytes(bytes)?.to_vec()
}

/// The same, through the fragment grammar rather than the document grammar.
macro_rules! sets {
    ($doc:ident, $frag:ident) => {
        fn $doc() -> Vec<(&'static str, Reencode)> {
            vec![
                ("iso2", reencode::<iso15118::iso2::Document> as Reencode),
                ("iso20_messages", reencode::<iso15118::iso20::messages::Document>),
                ("iso20_ac", reencode::<iso15118::iso20::ac::Document>),
                ("iso20_dc", reencode::<iso15118::iso20::dc::Document>),
                ("iso20_wpt", reencode::<iso15118::iso20::wpt::Document>),
                ("iso20_acdp", reencode::<iso15118::iso20::acdp::Document>),
            ]
        }

        fn $frag() -> Vec<(&'static str, Reencode)> {
            macro_rules! f {
                ($t:ty) => {
                    (|b: &[u8]| <$t>::from_fragment(b)?.to_fragment()) as Reencode
                };
            }
            vec![
                ("iso2", f!(iso15118::iso2::Document)),
                ("iso20_messages", f!(iso15118::iso20::messages::Document)),
                ("iso20_ac", f!(iso15118::iso20::ac::Document)),
                ("iso20_dc", f!(iso15118::iso20::dc::Document)),
                ("iso20_wpt", f!(iso15118::iso20::wpt::Document)),
                ("iso20_acdp", f!(iso15118::iso20::acdp::Document)),
            ]
        }
    };
}

sets!(document_sets, fragment_sets);

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

#[test]
fn every_message_round_trips_against_the_reference() {
    check("documents", ".vectors", document_sets());
}

#[test]
fn every_message_round_trips_as_a_fragment_against_the_reference() {
    check("fragments", ".fragments", fragment_sets());
}

fn check(what: &str, suffix: &str, sets: Vec<(&'static str, Reencode)>) {
    let Some(dir) = std::env::var_os("ISO15118_VECTORS").map(PathBuf::from) else {
        eprintln!("skipping: set ISO15118_VECTORS, or run scripts/verify-messages.sh");
        return;
    };

    let mut checked = 0usize;
    let mut failures: Vec<String> = Vec::new();
    let mut missing: Vec<String> = Vec::new();

    for (set, reencode) in sets {
        let path: &Path = &dir.join(format!("{set}{suffix}"));
        let Ok(text) = std::fs::read_to_string(path) else {
            missing.push(set.to_owned());
            continue;
        };
        for line in text.lines() {
            let Some((name, encoded)) = line.split_once(' ') else { continue };
            let expected = unhex(encoded);
            checked += 1;
            match reencode(&expected) {
                Ok(actual) if actual == expected => {}
                Ok(actual) => failures.push(format!(
                    "{set}/{name}: re-encoded differently\n     reference {}\n     ours      {}",
                    hex(&expected),
                    hex(&actual)
                )),
                Err(e) => {
                    failures.push(format!("{set}/{name}: {e}\n     bytes {}", hex(&expected)));
                }
            }
        }
    }

    if !missing.is_empty() {
        eprintln!("no vectors for: {}", missing.join(", "));
    }
    assert!(checked > 0, "ISO15118_VECTORS was set but held no vectors");

    if failures.is_empty() {
        eprintln!("all {checked} {what} round-trip against the reference");
    } else {
        for f in &failures {
            eprintln!("  FAIL {f}");
        }
        panic!("{} of {checked} {what} disagree with the reference", failures.len());
    }
}
