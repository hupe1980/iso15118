//! The internal architecture notes, checked for the mistakes prose cannot make
//! loudly.
//!
//! `concepts/` is gitignored — it is internal, not published — so this test
//! **skips when the directory is absent**, which is what CI and every consumer
//! of the crate see. It runs on the machine that has the notes, which is the
//! only machine that can break them.
//!
//! What it checks is the class of error that reads perfectly and is wrong:
//!
//! * `D` and `R` numbers are **stable identifiers** cited from the other
//!   documents and from code comments, so a citation to one that does not exist
//!   is a dangling reference nothing else would catch;
//! * the entries are numbered contiguously from 1, because a gap means an entry
//!   was deleted and the identifiers after it silently changed meaning;
//! * the counts the prose states — "twenty-seven things", "Six rules" — agree
//!   with the number of entries, because a list that grows and a sentence that
//!   does not is the cheapest wrong thing to write;
//! * every relative link between the documents resolves;
//! * every open roadmap item names exactly one feature specification under
//!   `specs/`, and every specification there is named by exactly one item;
//! * nothing published cites `concepts/`, `specs/` or `.specify/` — a reader of
//!   the crate, the site or the README cannot open any of them. This one needs
//!   no notes to run, so it is the one check here CI does see.
//!
//! Each of those has already been wrong here at least once. The sibling `emob`
//! workspace added the same guard after the same failure, which is the strongest
//! argument for it: two independent codebases, one mistake.

#![cfg(feature = "std")]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

fn concepts() -> Option<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("concepts");
    dir.is_dir().then_some(dir)
}

/// Every `*.md` in `concepts/`, as `(file name, text)`.
fn pages(dir: &Path) -> Vec<(String, String)> {
    let mut out: Vec<_> = fs::read_dir(dir)
        .expect("read concepts/")
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "md"))
        .map(|p| {
            let name = p.file_name().expect("file name").to_string_lossy().into_owned();
            (name, fs::read_to_string(&p).expect("read concepts page"))
        })
        .collect();
    out.sort();
    assert!(!out.is_empty(), "concepts/ exists but holds no documents");
    out
}

/// The identifiers *defined* in a register, as `**D12 —` at the start of a line.
fn defined(text: &str, letter: char) -> BTreeSet<u32> {
    text.lines()
        .filter_map(|line| {
            let rest = line.strip_prefix("**")?.strip_prefix(letter)?;
            let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
            // ` —` rather than any separator: `**D1 is` would be prose.
            rest[digits.len()..].starts_with(" —").then(|| digits.parse().ok())?
        })
        .collect()
}

/// The identifiers *cited* anywhere, as a bare `D12` word.
fn cited(pages: &[(String, String)], letter: char) -> BTreeSet<u32> {
    let mut out = BTreeSet::new();
    for (_, text) in pages {
        for word in text.split(|c: char| !c.is_ascii_alphanumeric()) {
            let Some(digits) = word.strip_prefix(letter) else { continue };
            if !digits.is_empty()
                && digits.chars().all(|c| c.is_ascii_digit())
                && let Ok(n) = digits.parse()
            {
                out.insert(n);
            }
        }
    }
    out
}

/// Registers are contiguous from 1, and nothing cites an identifier that is not
/// there.
#[test]
fn every_identifier_resolves_and_the_numbering_has_no_holes() {
    let Some(dir) = concepts() else { return };
    let pages = pages(&dir);

    for (letter, register) in [('D', "DECISIONS.md"), ('R', "RISKS.md")] {
        let text = &pages
            .iter()
            .find(|(name, _)| name == register)
            .unwrap_or_else(|| panic!("concepts/{register} is missing"))
            .1;
        let defined = defined(text, letter);
        assert!(!defined.is_empty(), "{register} defines no {letter} entries");

        let expected: BTreeSet<u32> =
            (1..=*defined.iter().next_back().expect("a highest")).collect();
        assert_eq!(
            defined, expected,
            "{register}: the {letter} numbering has a hole. They are stable identifiers cited \
             from code comments, so a gap means an entry was deleted and every citation after \
             it now means something else"
        );

        let dangling: Vec<_> = cited(&pages, letter).difference(&defined).copied().collect();
        assert!(
            dangling.is_empty(),
            "{register}: {letter} identifiers cited but never defined: {dangling:?}"
        );
    }
}

/// A count stated in prose is a claim, and it is the cheapest one to get wrong.
///
/// Three of these were wrong in one pass here — a feature count, a standards
/// part number, a CI job that already existed — so the ones that *can* be
/// checked mechanically are.
#[test]
fn the_counts_the_prose_states_are_the_counts_there_are() {
    /// A written-out number, up to ninety-nine.
    ///
    /// Built rather than tabulated, and that is the point: the table this
    /// replaces stopped at forty, so the *guard* failed the day the register it
    /// guards reached forty-one. A check that breaks when the thing it checks
    /// grows is worse than no check, because it fails in a way that looks like
    /// the document being wrong.
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
        let unit = |w: &str| UNITS.iter().position(|u| *u == w);
        if let Some(n) = unit(&word) {
            return Some(n);
        }
        let (tens, rest) = match word.split_once('-') {
            Some((tens, rest)) => (tens, Some(rest.to_owned())),
            None => (word.as_str(), None),
        };
        let ten = TENS.iter().position(|t| !t.is_empty() && *t == tens)?;
        let extra = match rest {
            Some(rest) => unit(&rest).filter(|n| (1..10).contains(n))?,
            None => 0,
        };
        Some(ten * 10 + extra)
    }

    let Some(dir) = concepts() else { return };
    let pages = pages(&dir);
    let page = |name: &str| &pages.iter().find(|(n, _)| n == name).expect("page").1;

    // "Twenty-seven things the implementation settled ..."
    let decisions = page("DECISIONS.md");
    let stated = decisions
        .lines()
        .find_map(|l| l.split_once(" things the implementation settled").map(|(n, _)| n))
        .and_then(number)
        .expect("DECISIONS.md states how many entries it has, in words");
    assert_eq!(
        stated,
        defined(decisions, 'D').len(),
        "DECISIONS.md says {stated} entries and has a different number of them"
    );

    // "## Six rules this design keeps re-learning" over `1.` .. `n.`
    let readme = page("README.md");
    let stated = readme
        .lines()
        .find_map(|l| l.strip_prefix("## ")?.split_once(" rules this design").map(|(n, _)| n))
        .and_then(number)
        .expect("README.md heads its rule list with a count, in words");
    let listed = readme
        .lines()
        .filter(|l| {
            l.split_once(". **").is_some_and(|(n, _)| n.chars().all(|c| c.is_ascii_digit()))
        })
        .count();
    assert_eq!(stated, listed, "README.md says {stated} rules and lists {listed}");
}

/// A relative link to a sibling document that does not exist renders as a link
/// and goes nowhere.
#[test]
fn every_link_between_the_documents_resolves() {
    let Some(dir) = concepts() else { return };
    let mut broken = Vec::new();
    for (name, text) in pages(&dir) {
        for target in text.split("](").skip(1).filter_map(|rest| rest.split(')').next()) {
            // Only same-directory documents; `../emob/...` and URLs are not this
            // repository's to guarantee. Every filename here is written by hand
            // in this repository, so the extension really is case-sensitive.
            let is_markdown = Path::new(target).extension().is_some_and(|e| e == "md");
            if !is_markdown || target.contains('/') {
                continue;
            }
            if !dir.join(target).exists() {
                broken.push(format!("{name} -> {target}"));
            }
        }
    }
    assert!(broken.is_empty(), "dangling links between concepts documents: {broken:?}");
}

/// The roadmap is the spec of specs: an open item is a `` ### `#anchor` ``
/// heading naming one folder on a `**Specified as:**` line, and a folder under
/// `specs/` that no item names is work nobody has scheduled.
#[test]
fn every_roadmap_item_names_its_specification() {
    let Some(dir) = concepts() else { return };
    let specs = Path::new(env!("CARGO_MANIFEST_DIR")).join("specs");
    if !specs.is_dir() {
        return;
    }
    let roadmap = fs::read_to_string(dir.join("ROADMAP.md")).expect("read ROADMAP.md");

    let items = roadmap.lines().filter(|l| l.starts_with("### `#")).count();
    let named: Vec<&str> = roadmap
        .lines()
        .filter_map(|l| l.strip_prefix("**Specified as:** `")?.split('`').next())
        .collect();
    assert_eq!(
        items,
        named.len(),
        "ROADMAP.md: {items} items but {} **Specified as:** lines",
        named.len()
    );

    let unique: BTreeSet<&str> = named.iter().copied().collect();
    assert_eq!(unique.len(), named.len(), "ROADMAP.md names a specification twice: {named:?}");

    let missing: Vec<_> =
        unique.iter().filter(|s| !specs.join(s).join("spec.md").is_file()).collect();
    assert!(missing.is_empty(), "ROADMAP.md names specifications that do not exist: {missing:?}");

    // Folders are `NNN-slug`; `archive/` holds the shipped, superseded and refused.
    let orphans: Vec<_> = fs::read_dir(&specs)
        .expect("read specs/")
        .flatten()
        .filter(|e| e.path().is_dir())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|name| name.as_bytes().first().is_some_and(u8::is_ascii_digit))
        .filter(|name| !unique.contains(name.as_str()))
        .collect();
    assert!(orphans.is_empty(), "specs/ holds specifications no roadmap item names: {orphans:?}");
}

/// The published tree stands on its own. A path into the internal notes, the
/// specifications or the Spec Kit machinery renders as a reference and leads
/// nowhere for every reader who is not a maintainer.
#[test]
fn nothing_published_cites_the_internal_tree() {
    fn walk(path: &Path, out: &mut Vec<PathBuf>) {
        if path.is_dir() {
            for entry in fs::read_dir(path).expect("read dir").flatten() {
                walk(&entry.path(), out);
            }
        } else if path.extension().is_some_and(|e| e == "rs" || e == "md") {
            out.push(path.to_path_buf());
        }
    }

    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    for published in ["src", "examples", "tests", "site/content", "README.md"] {
        walk(&root.join(published), &mut files);
    }
    // This file is the guard, and has to name what it guards.
    files.retain(|f| !f.ends_with("tests/concepts.rs"));

    let mut leaks = Vec::new();
    for file in &files {
        let text = fs::read_to_string(file).expect("read published file");
        for (n, line) in text.lines().enumerate() {
            let cites = ["concepts/", "specs/", ".specify/"].iter().any(|internal| {
                line.match_indices(internal).any(|(at, _)| {
                    // `concepts/` as a path, not the tail of `some-concepts/`.
                    !line[..at]
                        .chars()
                        .next_back()
                        .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
                })
            });
            if cites {
                let file = file.strip_prefix(root).unwrap_or(file).display();
                leaks.push(format!("{file}:{}", n + 1));
            }
        }
    }
    assert!(leaks.is_empty(), "published files cite a path their reader does not have: {leaks:?}");
}
