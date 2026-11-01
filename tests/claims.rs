//! The counts the README and the documentation site state, measured.
//!
//! A number in published prose is a claim, and the cheapest one to leave wrong:
//! the code grows, the sentence does not, and nothing fails. This register pairs
//! each stated count with the thing it counts, and fails naming the file and the
//! line when they disagree — or when the sentence that carried the number has
//! gone, so a deleted claim also deletes its entry here.
//!
//! Only what can be measured from a clean checkout is here: no network, no JDK,
//! no licensed schemas. The grammar and message totals belong to the scripts
//! that measure them against `exificient`; the capture totals to the replay.

#![cfg(all(feature = "iso2", feature = "iso20"))]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// A number written as digits or as a word, up to ninety-nine.
fn number(word: &str) -> Option<usize> {
    const UNITS: [&str; 20] = [
        "zero",
        "one",
        "two",
        "three",
        "four",
        "five",
        "six",
        "seven",
        "eight",
        "nine",
        "ten",
        "eleven",
        "twelve",
        "thirteen",
        "fourteen",
        "fifteen",
        "sixteen",
        "seventeen",
        "eighteen",
        "nineteen",
    ];
    const TENS: [&str; 10] =
        ["", "", "twenty", "thirty", "forty", "fifty", "sixty", "seventy", "eighty", "ninety"];
    let word = word.trim().to_ascii_lowercase();
    if let Ok(n) = word.parse() {
        return Some(n);
    }
    let unit = |w: &str| UNITS.iter().position(|u| *u == w);
    if let Some(n) = unit(&word) {
        return Some(n);
    }
    let (tens, rest) = word.split_once('-').map_or((word.as_str(), None), |(t, r)| (t, Some(r)));
    let ten = TENS.iter().position(|t| !t.is_empty() && *t == tens)?;
    let extra = match rest {
        Some(rest) => unit(rest).filter(|n| (1..10).contains(n))?,
        None => 0,
    };
    Some(ten * 10 + extra)
}

/// One stated count: in `file`, the phrase `before` + a number + `after`.
struct Claim {
    file: &'static str,
    before: &'static str,
    after: &'static str,
}

/// Every occurrence of the claim in its file, as `(line, stated number)`.
fn stated(claim: &Claim) -> Vec<(usize, Option<usize>)> {
    let text = fs::read_to_string(root().join(claim.file)).expect("read published file");
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let mut from = 0;
        while let Some(at) = line[from..].find(claim.before) {
            let start = from + at + claim.before.len();
            let rest = &line[start..];
            if let Some(end) = rest.find(claim.after) {
                out.push((i + 1, number(&rest[..end])));
            }
            from = start;
        }
    }
    out
}

fn check(claims: &[Claim], measured: usize, what: &str) {
    let mut wrong = Vec::new();
    for claim in claims {
        let found = stated(claim);
        if found.is_empty() {
            wrong.push(format!(
                "{}: no \"{}<n>{}\" any more — update this register with the prose",
                claim.file, claim.before, claim.after
            ));
        }
        for (line, n) in found {
            if n != Some(measured) {
                wrong
                    .push(format!("{}:{line}: says {n:?} {what}, measured {measured}", claim.file));
            }
        }
    }
    assert!(wrong.is_empty(), "stated counts that disagree with the code:\n{}", wrong.join("\n"));
}

#[test]
fn the_fuzz_target_count() {
    let measured = fs::read_dir(root().join("fuzz/fuzz_targets"))
        .expect("read fuzz targets")
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "rs"))
        .count();
    check(
        &[
            Claim {
                file: "README.md",
                before: "`#![forbid(unsafe_code)]` and ",
                after: " fuzz targets",
            },
            Claim {
                file: "site/content/docs/verification.md",
                before: "layouts pinned, ",
                after: " fuzz targets",
            },
            Claim {
                file: "site/content/docs/verification.md",
                before: "| **Fuzzing** | ",
                after: " `cargo-fuzz` targets",
            },
            // The landing page's figure.
            Claim { file: "site/config.toml", before: "fuzz_targets = \"", after: "\"" },
        ],
        measured,
        "fuzz targets",
    );
}

#[test]
fn the_feature_flag_count() {
    // A Windows checkout has CRLF line endings; the table is found by its lines.
    let manifest = fs::read_to_string(root().join("Cargo.toml"))
        .expect("read Cargo.toml")
        .replace("\r\n", "\n");
    let features = manifest
        .split("\n[features]\n")
        .nth(1)
        .expect("a [features] table")
        .split("\n[")
        .next()
        .expect("its body");
    let measured = features
        .lines()
        .filter_map(|l| l.split_once(" = ").map(|(name, _)| name.trim()))
        .filter(|name| !name.starts_with('#') && *name != "default")
        .count();
    check(
        &[Claim {
            file: "site/content/docs/features.md",
            before: "There are ",
            after: " flags besides",
        }],
        measured,
        "feature flags",
    );
}

#[test]
fn every_request_with_a_refusal() {
    use iso15118::iso20::{ac, ac_der_iec, ac_der_sae, acdp, dc, messages, wpt};
    let measured = iso15118::iso2::BodyChoice::requests().len()
        + messages::Document::requests().len()
        + ac::Document::requests().len()
        + dc::Document::requests().len()
        + wpt::Document::requests().len()
        + acdp::Document::requests().len()
        + ac_der_iec::Document::requests().len()
        + ac_der_sae::Document::requests().len();
    check(
        &[Claim { file: "README.md", before: "All ", after: " requests across" }],
        measured,
        "requests",
    );
}

/// The same pattern `scripts/verify-citations.sh` greps, over the same tree.
#[test]
fn the_cited_requirement_count() {
    fn walk(path: &Path, out: &mut Vec<PathBuf>) {
        if path.is_dir() {
            for entry in fs::read_dir(path).expect("read dir").flatten() {
                walk(&entry.path(), out);
            }
        } else {
            out.push(path.to_path_buf());
        }
    }
    let mut files = Vec::new();
    for dir in ["src", "tests", "examples", "codegen/src", "site/content", "README.md"] {
        walk(&root().join(dir), &mut files);
    }
    let mut cited = BTreeSet::new();
    for file in files {
        let Ok(text) = fs::read_to_string(&file) else { continue };
        let mut rest = text.as_str();
        while let Some(at) = rest.find("V2G2-") {
            rest = &rest[at + 5..];
            let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
            if !digits.is_empty() {
                cited.insert(digits);
            }
        }
    }
    check(
        &[
            Claim { file: "README.md", before: "the ", after: " requirement numbers cited here" },
            Claim {
                file: "site/content/docs/verification.md",
                before: "itself — **",
                after: "** cited",
            },
            Claim {
                file: "site/content/docs/verification.md",
                before: "defines  (",
                after: " of 852)",
            },
        ],
        cited.len(),
        "cited requirements",
    );
}
