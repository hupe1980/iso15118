//! The documentation site's code samples, checked against the code they claim
//! to come from.
//!
//! A site sample is not compiled by anything — Zola renders markdown, and a
//! snippet that drifted from the crate would keep rendering perfectly. The
//! failure mode is a reader copying something that has not built in months.
//!
//! So a fenced Rust block in `site/content/` may carry a
//! `<!-- pinned-to: <path> -->` comment on the line above it, and this test
//! insists every line of that block appears verbatim somewhere in that file.
//! Pinning is opt-in: a block that illustrates a shape rather than reproducing
//! real code carries no comment and is not checked.

#![cfg(feature = "std")]

use std::fs;
use std::path::{Path, PathBuf};

/// A source line with any doc-comment prefix removed.
///
/// The most useful pin targets are the module documentation of `secc` and
/// `evcc` — those samples are doctests, so pinning to them means the site shows
/// code the compiler has already agreed with.
fn strip_doc_prefix(line: &str) -> &str {
    let line = line.trim();
    line.strip_prefix("//!").or_else(|| line.strip_prefix("///")).unwrap_or(line).trim()
}

/// Repository root, from this test's own location.
fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

/// Every `(source file, pinned-to target, code)` triple in the site content.
fn pinned_blocks() -> Vec<(PathBuf, PathBuf, String)> {
    let content = root().join("site/content");
    let mut out = Vec::new();
    let mut stack = vec![content];

    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().is_none_or(|e| e != "md") {
                continue;
            }
            let text = fs::read_to_string(&path).expect("read site page");
            let mut lines = text.lines().peekable();
            while let Some(line) = lines.next() {
                let Some(target) = line
                    .trim()
                    .strip_prefix("<!-- pinned-to:")
                    .and_then(|rest| rest.strip_suffix("-->"))
                else {
                    continue;
                };
                // The fence has to be the very next line, so a stray comment
                // cannot silently pin nothing.
                let fence = lines.next().unwrap_or_default();
                assert!(
                    fence.starts_with("```"),
                    "{}: `pinned-to` must sit directly above a fenced block, found {fence:?}",
                    path.display()
                );
                let code: String = lines
                    .by_ref()
                    .take_while(|l| !l.starts_with("```"))
                    .collect::<Vec<_>>()
                    .join("\n");
                out.push((path.clone(), root().join(target.trim()), code));
            }
        }
    }
    out
}

/// Every pinned line has to exist, verbatim, in the file it names.
///
/// Line by line rather than as one block: the site elides the surrounding
/// function and its error handling, so the sample is a subsequence of the real
/// code rather than a contiguous copy of it. What matters is that no line is
/// something the crate no longer says.
#[test]
fn site_samples_match_the_code_they_are_pinned_to() {
    // The site is not part of the published crate — a consumer wants the
    // library, not a Zola tree — so `cargo test` on a vendored copy finds no
    // `site/` at all. That is not a failure; there is simply nothing here to
    // check. It is only a failure when the directory *is* present and has
    // stopped yielding pinned blocks, which means the site moved and this test
    // has quietly become vacuous.
    let content = root().join("site/content");
    if !content.is_dir() {
        eprintln!("site/ is not in this tree (it is excluded from the package); nothing to check");
        return;
    }

    let blocks = pinned_blocks();
    assert!(!blocks.is_empty(), "site/content is here but has no pinned blocks — has it moved?");

    for (page, target, code) in blocks {
        let source = fs::read_to_string(&target)
            .unwrap_or_else(|e| panic!("{}: pinned to {}: {e}", page.display(), target.display()));

        for line in code.lines() {
            let needle = line.trim();
            if needle.is_empty() || needle == "}" || needle == "{" {
                continue;
            }
            assert!(
                source.lines().any(|l| strip_doc_prefix(l) == needle),
                "{} is pinned to {}, which no longer contains:\n    {needle}",
                page.display(),
                target.display(),
            );
        }
    }
}
