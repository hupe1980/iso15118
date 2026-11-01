//! A chain from a published V2G test pool: Hubject's openPlugnCharge archive.
//!
//! Every other chain `pnc::pki` is tested against was minted by OpenSSL from
//! this repository's own script. These were issued by Hubject, under its real
//! V2G Root — a certificate authority nobody here runs — and the archive is
//! public, with no registration:
//! <https://github.com/OpenChargingCloud/openPlugnCharge/archive/refs/heads/master.zip>.
//!
//! The archive is not committed. Extract it and point `ISO15118_PKI_POOL` at
//! the `openPlugnCharge-master` directory:
//!
//! ```text
//! unzip -q master.zip -d /tmp/pool
//! ISO15118_PKI_POOL=/tmp/pool/openPlugnCharge-master cargo test --all-features --test pki_pool
//! ```
//!
//! Without the variable every test here **skips by name**. With it set and a
//! file missing, the test fails: a mistyped path is not a skip.
//!
//! What this establishes is narrower than it sounds, and the narrowness is the
//! point: the pool publishes an end-entity certificate for **one** of the three
//! Annex F profiles — the OEM provisioning certificate. Its CPO and MO Sub-CAs
//! carry no leaf, so the SECC and contract profiles stay on OpenSSL's fixtures
//! (`tests/pki.rs`).

#![cfg(all(feature = "pnc-rustcrypto", feature = "std"))]

use std::path::PathBuf;

use iso15118::pnc::pki::{self, ChainError, Policy, Profile, TrustAnchor, TrustAnchors};
use iso15118::pnc::rustcrypto::Backend;

/// Inside every certificate's window: the leaves run 2018-11-05 → 2022-11-05,
/// the OEM Sub-CAs to 2022-12-18, the root to 2057.
const IN_2020: i64 = 1_577_836_800; // 2020-01-01T00:00:00Z
/// After the leaves expired, before the root does.
const IN_2023: i64 = 1_672_531_200; // 2023-01-01T00:00:00Z

/// The archive's directory, or `None` (and a named skip) when it is not set.
fn pool(test: &str) -> Option<PathBuf> {
    let Some(dir) = std::env::var_os("ISO15118_PKI_POOL") else {
        eprintln!(
            "skipping {test}: set ISO15118_PKI_POOL to the extracted openPlugnCharge-master directory"
        );
        return None;
    };
    Some(PathBuf::from(dir).join("Certificates"))
}

/// One PEM certificate as DER.
fn pem(path: &std::path::Path) -> Vec<u8> {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("ISO15118_PKI_POOL is set, but {}: {e}", path.display()));
    let body: String = text
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN CERTIFICATE-----"))
        .skip(1)
        .take_while(|l| !l.starts_with("-----END"))
        .collect();
    base64(body.trim()).unwrap_or_else(|| panic!("{}: not base64", path.display()))
}

/// RFC 4648 base64, padding allowed. Twenty lines here beats a dependency the
/// crate itself does not need: the crate reads DER and nothing else.
fn base64(text: &str) -> Option<Vec<u8>> {
    let value = |c: u8| match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    };
    let bytes: Vec<u8> = text.bytes().filter(|c| !c.is_ascii_whitespace()).collect();
    let data = bytes.strip_suffix(b"==").or_else(|| bytes.strip_suffix(b"=")).unwrap_or(&bytes);
    let mut out = Vec::with_capacity(data.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &c in data {
        acc = (acc << 6) | u32::from(value(c)?);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xFF) as u8);
        }
    }
    Some(out)
}

struct Pool {
    root: Vec<u8>,
    sub1: Vec<u8>,
    sub2: Vec<u8>,
    leaves: Vec<(String, Vec<u8>)>,
}

fn load(dir: &std::path::Path) -> Pool {
    let oem = dir.join("OEM certificates");
    let leaves = (1..=10)
        .map(|n| {
            let name = format!("hubjectopenpnc{n:04}");
            let der = pem(&oem.join("OEM Provisioning Certificates").join(format!("{name}.pem")));
            (name, der)
        })
        .collect();
    Pool {
        root: pem(&dir.join("V2G Root Certificate").join("V2G Root.pem")),
        sub1: pem(&oem.join("OEM Sub CA 1.pem")),
        sub2: pem(&oem.join("OEM Sub CA 2.pem")),
        leaves,
    }
}

/// All ten OEM provisioning leaves validate to Hubject's V2G Root, under the
/// profile Table F.5 gives them — and, since the real chain happens to meet
/// ISO 15118-20 Amd 1's nesting rule and size bound too, under -20's rules as
/// well.
#[test]
fn every_published_provisioning_leaf_validates_to_the_real_v2g_root() {
    let Some(dir) = pool("every_published_provisioning_leaf_validates_to_the_real_v2g_root") else {
        return;
    };
    let pool = load(&dir);
    let anchors = [TrustAnchor::new(&pool.root, "Hubject openPlugnCharge V2G Root")];
    let anchors = TrustAnchors::new(&anchors);

    for (name, leaf) in &pool.leaves {
        let chain: [&[u8]; 3] = [leaf, &pool.sub2, &pool.sub1];
        for policy in [
            Policy::iso2(Profile::OemProvisioningCertificate),
            Policy::iso20(Profile::OemProvisioningCertificate),
        ] {
            let path = pki::validate(&chain, &anchors, policy, IN_2020, &Backend)
                .unwrap_or_else(|e| panic!("{name} under {policy:?}: {e}"));
            // [V2G2-933]: the provisioning certificate's Common Name is its CertID.
            assert_eq!(path.subject_common_name(), Some(name.as_str()));
            assert_eq!(path.anchor_source, "Hubject openPlugnCharge V2G Root");
        }
    }
    assert_eq!(pool.leaves.len(), 10);
}

/// The same chains are refused when they should be — so the positive test above
/// cannot be passing because nothing is checked.
#[test]
fn the_published_chain_is_refused_when_it_should_be() {
    let Some(dir) = pool("the_published_chain_is_refused_when_it_should_be") else { return };
    let pool = load(&dir);
    let anchors = [TrustAnchor::new(&pool.root, "Hubject")];
    let anchors = TrustAnchors::new(&anchors);
    let policy = Policy::iso2(Profile::OemProvisioningCertificate);
    let (_, leaf) = &pool.leaves[0];

    // After the leaves expired.
    let chain: [&[u8]; 3] = [leaf, &pool.sub2, &pool.sub1];
    assert_eq!(
        pki::validate(&chain, &anchors, policy, IN_2023, &Backend),
        Err(ChainError::Expired { index: 0 }),
    );

    // One flipped bit in the leaf's signature.
    let mut flipped = leaf.clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 0x01;
    let chain: [&[u8]; 3] = [&flipped, &pool.sub2, &pool.sub1];
    let result = pki::validate(&chain, &anchors, policy, IN_2020, &Backend);
    assert!(
        matches!(result, Err(ChainError::BadSignature { .. } | ChainError::Certificate { .. })),
        "{result:?}"
    );

    // A Sub-CA missing from the middle.
    let chain: [&[u8]; 2] = [leaf, &pool.sub1];
    assert_eq!(
        pki::validate(&chain, &anchors, policy, IN_2020, &Backend),
        Err(ChainError::NoTrustAnchor),
    );

    // Held under the wrong profile: an OEM provisioning certificate is not an
    // SECC certificate, whose Domain Component is a validity condition.
    let chain: [&[u8]; 3] = [leaf, &pool.sub2, &pool.sub1];
    assert!(
        pki::validate(&chain, &anchors, Policy::iso2(Profile::SeccCertificate), IN_2020, &Backend)
            .is_err()
    );
}
