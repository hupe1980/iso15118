//! `pnc::pki`'s RFC 5280 core against `x509-limbo` — a path-validation suite
//! somebody else wrote, run by `rustls-webpki`, Go, `pyca/cryptography`, Botan and
//! `GnuTLS`.
//!
//! `tests/pki.rs` checks the core against certificates OpenSSL minted, but the
//! people who wrote the code chose those chains, so they test what the authors
//! thought of. This runs every limbo case the V2G profile can take — every
//! certificate on P-256 or P-521 — with `Profile::Unchecked`: full path
//! validation, the leaf's naming and key usage left to the caller, as limbo's
//! own host-name and EKU expectations are.
//!
//! Every case either reaches limbo's verdict or is listed in
//! `tests/x509_limbo/divergences.tsv` with a reason class. The test fails on a
//! disagreement nobody listed, and on a listed case that now agrees — a list
//! that can only grow would stop saying anything.
//!
//! The suite is fetched at a pinned commit, never committed:
//!
//! ```sh
//! scripts/fetch-x509-limbo.sh /tmp/limbo
//! ISO15118_X509_LIMBO=/tmp/limbo/limbo.json \
//!     cargo test --release --all-features --test x509_limbo -- --nocapture
//! ```
//!
//! Without `ISO15118_X509_LIMBO` it skips by name.

#![cfg(all(feature = "pnc-rustcrypto", feature = "std"))]

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use iso15118::pnc::pki::{
    self, CertError, Certificate, ChainError, Evidence, MAX_PATH_LEN, Policy, Profile, TrustAnchor,
    TrustAnchors,
};
use iso15118::pnc::rustcrypto::Backend;
use serde_json::Value;

/// Why a case is allowed to disagree with limbo.
const CLASSES: &[&str] = &[
    // The V2G path limit: three certificates, the anchor not counted [V2G2-009].
    "path-length",
    // A CRL decides the verdict and this crate reads it differently. Every
    // `crl::*` case is fed to `validate` as `Evidence::crls`, so a row here is a
    // real disagreement about RFC 5280 §5 — and there are none today.
    "revocation",
    // Peer name, SAN, EKU or key usage of the leaf: `Profile::Unchecked` leaves
    // them to the caller, exactly as its documentation says.
    "caller",
    // A deliberate V2G-profile rule refuses what web PKI accepts, or the other
    // way round.
    "profile",
    // This crate is wrong. Fixed before release or recorded on the roadmap.
    "defect",
];

#[test]
fn every_in_profile_case_reaches_limbo_verdict_or_is_listed() {
    let Some(path) = std::env::var_os("ISO15118_X509_LIMBO").map(PathBuf::from) else {
        eprintln!("skipping: ISO15118_X509_LIMBO is not set — run scripts/fetch-x509-limbo.sh");
        return;
    };
    let suite: Value = serde_json::from_slice(
        &std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display())),
    )
    .expect("limbo.json is JSON");
    assert_eq!(suite["version"], 1, "the harness reads limbo's format version 1");
    let listed = divergences();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after 1970")
        .as_secs()
        .try_into()
        .expect("seconds fit an i64");

    let mut agree = 0usize;
    let mut out_of_profile = 0usize;
    let mut diverged: BTreeMap<&str, usize> = BTreeMap::new();
    let mut unlisted = Vec::new();
    let mut stale = Vec::new();
    let mut seen = BTreeSet::new();

    for case in suite["testcases"].as_array().expect("testcases") {
        let id = case["id"].as_str().expect("id");
        seen.insert(id.to_owned());

        let trusted: Vec<Vec<u8>> = pems(&case["trusted_certs"]);
        let pool: Vec<Vec<u8>> = pems(&case["untrusted_intermediates"]);
        // Limbo hands CRLs over beside the chain; they are revocation evidence
        // exactly as a station's back end would hand them in.
        let crls: Vec<Vec<u8>> =
            if case["crls"].is_null() { Vec::new() } else { pems(&case["crls"]) };
        let peer = pem(case["peer_certificate"].as_str().expect("peer_certificate"));

        if [&peer].into_iter().chain(&trusted).chain(&pool).any(|der| out_of_v2g_profile(der)) {
            out_of_profile += 1;
            continue;
        }

        let at = case["validation_time"].as_str().map_or(now, rfc3339);
        let (accepted, why) = verdict(&peer, &pool, &trusted, &crls, at);
        let expected = match case["expected_result"].as_str() {
            Some("SUCCESS") => true,
            Some("FAILURE") => false,
            other => panic!("{id}: expected_result {other:?}"),
        };

        match (accepted == expected, listed.get(id)) {
            (true, None) => agree += 1,
            (true, Some(_)) => stale.push(id.to_owned()),
            (false, Some(class)) => *diverged.entry(class.as_str()).or_default() += 1,
            (false, None) => unlisted.push(format!(
                "{id}\texpected {}, got {}{}",
                if expected { "SUCCESS" } else { "FAILURE" },
                if accepted { "SUCCESS" } else { "FAILURE" },
                why.map(|e| format!(" ({e})")).unwrap_or_default(),
            )),
        }
    }

    let unknown: Vec<_> = listed.keys().filter(|id| !seen.contains(*id)).collect();
    let total: usize = suite["testcases"].as_array().map_or(0, Vec::len);
    eprintln!(
        "x509-limbo: {total} cases — {agree} agree, {} listed divergences {diverged:?}, \
         {out_of_profile} out of profile",
        diverged.values().sum::<usize>()
    );

    assert!(unknown.is_empty(), "divergences.tsv lists cases limbo does not have: {unknown:?}");
    assert!(
        stale.is_empty(),
        "listed as divergences, but they now agree — remove them: {stale:#?}"
    );
    assert!(
        unlisted.is_empty(),
        "{} disagreements nobody listed:\n{}",
        unlisted.len(),
        unlisted.join("\n")
    );
}

/// Whether `pnc::pki` accepts the peer certificate, trying every name-linked
/// chain the pool allows within [`MAX_PATH_LEN`].
///
/// `validate` takes an ordered chain, leaf first; limbo hands over an unordered
/// pool that may hold decoys. A link `validate` would accept has the next
/// certificate's subject equal to this one's issuer, so only those orders are
/// tried — every one of them, so this is path building by enumeration. It lives
/// here rather than in the crate: on the wire, both generations send the chain
/// in order.
fn verdict(
    peer: &[u8],
    pool: &[Vec<u8>],
    trusted: &[Vec<u8>],
    crls: &[Vec<u8>],
    now: i64,
) -> (bool, Option<ChainError>) {
    let crls: Vec<&[u8]> = crls.iter().map(Vec::as_slice).collect();
    let evidence = Evidence::crls(&crls);
    let anchors: Vec<TrustAnchor<'_>> =
        trusted.iter().map(|der| TrustAnchor::public(der, "limbo")).collect();
    let anchors = TrustAnchors::new(&anchors);
    let parsed: Vec<Option<Certificate<'_>>> =
        pool.iter().map(|der| Certificate::parse(der).ok()).collect();

    let mut chains: Vec<Vec<usize>> = vec![Vec::new()];
    let mut frontier = chains.clone();
    for _ in 1..MAX_PATH_LEN {
        let mut next = Vec::new();
        for chain in &frontier {
            let last = match chain.last() {
                Some(&i) => parsed[i].as_ref(),
                None => None,
            };
            let issuer = match (chain.last(), last) {
                (None, _) => match Certificate::parse(peer) {
                    Ok(cert) => cert.issuer.encoded,
                    Err(_) => break,
                },
                (Some(_), Some(cert)) => cert.issuer.encoded,
                (Some(_), None) => continue,
            };
            for (i, cert) in parsed.iter().enumerate() {
                if chain.contains(&i) {
                    continue;
                }
                if cert.as_ref().is_some_and(|c| c.subject.encoded == issuer) {
                    let mut longer = chain.clone();
                    longer.push(i);
                    next.push(longer);
                }
            }
        }
        chains.extend(next.iter().cloned());
        frontier = next;
    }

    let mut last_error = None;
    for chain in &chains {
        let ders: Vec<&[u8]> =
            std::iter::once(peer).chain(chain.iter().map(|&i| pool[i].as_slice())).collect();
        match pki::validate(
            &ders,
            &anchors,
            Policy::iso2(Profile::Unchecked),
            &evidence,
            now,
            &Backend,
        ) {
            Ok(_) => return (true, None),
            Err(e) => last_error = Some(e),
        }
    }
    (false, last_error)
}

/// A certificate on a curve or algorithm the V2G profile does not have at all
/// (RSA, P-384, Ed25519, ML-DSA) — a case about it says nothing about this
/// crate's path validation.
fn out_of_v2g_profile(der: &[u8]) -> bool {
    matches!(
        Certificate::parse(der),
        Err(CertError::UnsupportedCurve | CertError::UnsupportedSignatureAlgorithm)
    )
}

/// `tests/x509_limbo/divergences.tsv`: `id<TAB>class<TAB>reason`, `#` comments.
fn divergences() -> BTreeMap<String, String> {
    let file = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/x509_limbo/divergences.tsv");
    let text = std::fs::read_to_string(file).unwrap_or_else(|e| panic!("{file}: {e}"));
    let mut out = BTreeMap::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.splitn(3, '\t');
        let (Some(id), Some(class), Some(reason)) = (fields.next(), fields.next(), fields.next())
        else {
            panic!("divergences.tsv:{}: want id<TAB>class<TAB>reason", n + 1);
        };
        assert!(CLASSES.contains(&class), "divergences.tsv:{}: class {class:?}", n + 1);
        assert!(!reason.trim().is_empty(), "divergences.tsv:{}: {id} has no reason", n + 1);
        assert!(
            out.insert(id.to_owned(), class.to_owned()).is_none(),
            "divergences.tsv:{}: {id} listed twice",
            n + 1
        );
    }
    out
}

fn pems(list: &Value) -> Vec<Vec<u8>> {
    list.as_array()
        .expect("a list of PEM certificates")
        .iter()
        .map(|v| pem(v.as_str().expect("PEM")))
        .collect()
}

/// The DER inside one PEM block.
fn pem(text: &str) -> Vec<u8> {
    let body: String = text
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .flat_map(str::chars)
        .filter(|c| !c.is_whitespace())
        .collect();
    base64(&body)
}

fn base64(text: &str) -> Vec<u8> {
    let value = |c: u8| -> u32 {
        match c {
            b'A'..=b'Z' => u32::from(c - b'A'),
            b'a'..=b'z' => u32::from(c - b'a') + 26,
            b'0'..=b'9' => u32::from(c - b'0') + 52,
            b'+' => 62,
            b'/' => 63,
            _ => panic!("not base64: {:?}", c as char),
        }
    };
    let bytes = text.trim_end_matches('=').as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut acc = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            acc |= value(c) << (18 - 6 * i);
        }
        let n = chunk.len() * 6 / 8;
        out.extend_from_slice(&acc.to_be_bytes()[1..=n]);
    }
    out
}

/// `YYYY-MM-DDTHH:MM:SS[.fff]` with `Z` or a `±HH:MM` offset, as limbo writes
/// it. A fraction is floored: `validate` takes whole seconds, as an X.509
/// `Time` carries them.
fn rfc3339(text: &str) -> i64 {
    let field = |range: std::ops::Range<usize>| -> i64 {
        text.get(range).and_then(|t| t.parse().ok()).unwrap_or_else(|| panic!("time {text:?}"))
    };
    let (year, month, day) = (field(0..4), field(5..7), field(8..10));
    let (hour, minute, second) = (field(11..13), field(14..16), field(17..19));
    let bytes = text.as_bytes();
    let mut zone = 19;
    if bytes.get(zone) == Some(&b'.') {
        zone += 1;
        while bytes.get(zone).is_some_and(u8::is_ascii_digit) {
            zone += 1;
        }
    }
    let offset = match bytes.get(zone) {
        Some(b'Z') | None => 0,
        Some(sign @ (b'+' | b'-')) => {
            let east = field(zone + 1..zone + 3) * 3600 + field(zone + 4..zone + 6) * 60;
            if *sign == b'+' { east } else { -east }
        }
        Some(_) => panic!("time {text:?}"),
    };
    // Days from civil (Howard Hinnant's algorithm).
    let shifted = if month <= 2 { year - 1 } else { year };
    let era = shifted.div_euclid(400);
    let year_of_era = shifted - era * 400;
    let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    days * 86_400 + hour * 3600 + minute * 60 + second - offset
}

#[test]
fn the_time_parser_agrees_with_known_instants() {
    assert_eq!(rfc3339("1970-01-01T00:00:00Z"), 0);
    assert_eq!(rfc3339("2030-01-01T00:00:00+00:00"), 1_893_456_000);
    assert_eq!(rfc3339("2024-01-01T01:00:00+01:00"), 1_704_067_200);
    assert_eq!(rfc3339("2024-01-01T00:00:00.999+00:00"), 1_704_067_200);
}

#[test]
fn the_base64_decoder_agrees_with_known_vectors() {
    assert_eq!(base64("TWFu"), b"Man");
    assert_eq!(base64("TWE="), b"Ma");
    assert_eq!(base64("TQ=="), b"M");
}
