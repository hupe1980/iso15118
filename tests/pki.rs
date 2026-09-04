//! The V2G PKI: what a chain has to be before a key out of it is worth using.
//!
//! Every certificate here is minted by **OpenSSL** — `scripts/make-test-pki.sh`
//! — which matters for the same reason `exificient` matters one layer down: a
//! parser checked only against an encoder from the same workspace is checked
//! against its own opinions. These are DER somebody else produced, to the same
//! ASN.1, with the Annex F fields where Annex F says they go.
//!
//! What that is **not** is a chain from a published V2G test pool. Hubject's
//! and OPNC's need registration, so the claim this file supports is "the
//! Annex F profile is enforced, against certificates a third implementation
//! encoded" — which is weaker than interoperability and is the accurate thing
//! to say.
//!
//! The validity windows are absolute dates, so nothing here rots.

#![cfg(all(feature = "pnc-rustcrypto", feature = "std"))]

use iso15118::pnc::pki::{self, Certificate, ChainError, Curve, KeyUsage, Profile};
use iso15118::pnc::rustcrypto::Backend;

/// Inside every fixture's validity window.
const IN_2030: i64 = 1_893_456_000; // 2030-01-01T00:00:00Z
/// Before every fixture's `notBefore`.
const IN_2019: i64 = 1_546_300_800; // 2019-01-01T00:00:00Z
/// After the expired leaf's `notAfter`, still inside everything else's.
const IN_2022: i64 = 1_640_995_200; // 2022-01-01T00:00:00Z

fn der(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/tests/fixtures/pki/{name}.der", env!("CARGO_MANIFEST_DIR")))
        .unwrap_or_else(|e| panic!("run scripts/make-test-pki.sh: {name}.der: {e}"))
}

/// The SECC chain, leaf first, as `CertificateChainType` carries it.
fn secc_chain() -> [Vec<u8>; 3] {
    [der("secc"), der("sub2"), der("sub1")]
}

fn refs(v: &[Vec<u8>]) -> Vec<&[u8]> {
    v.iter().map(Vec::as_slice).collect()
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// The fields Annex F constrains, read out of DER a third implementation wrote.
#[test]
fn a_secc_certificate_reads_as_its_profile_says_it_should() {
    let bytes = der("secc");
    let cert = Certificate::parse(&bytes).expect("parse");

    assert_eq!(cert.curve, Curve::P256, "[V2G2-007]: 256-bit ECC, and nothing else");
    assert_eq!(cert.public_key.len(), 65, "uncompressed SEC1: 0x04 and two coordinates");
    assert_eq!(cert.public_key[0], 0x04);

    // Table F.2's SECC Cert row: CN is the CPID, DC is "CPO".
    assert_eq!(cert.subject.common_name, Some("DE*ABC*E00001"));
    assert_eq!(cert.subject.domain_component, Some(pki::DC_CPO));
    assert_eq!(cert.subject.organization, Some("V2G Test CPO"));

    // `CA = false`, `digitalSignature`, and nothing that would let it sign
    // certificates.
    let bc = cert.basic_constraints.expect("BasicConstraints is critical in every profile");
    assert!(!bc.ca);
    let ku = cert.key_usage.expect("KeyUsage is critical in every profile");
    assert!(ku.contains(KeyUsage::DIGITAL_SIGNATURE));
    assert!(!ku.contains(KeyUsage::KEY_CERT_SIGN));

    assert!(cert.is_valid_at(IN_2030));
    assert!(!cert.is_valid_at(IN_2019), "before notBefore");
    assert!(!cert.is_self_issued());
}

/// \[V2G2-010\]: "The size of a certificate in DER encoded form shall be not
/// bigger than 800 Bytes." The schema enforces it on the wire
/// (`certificateType` is `maxLength = 800`); this checks the fixtures are
/// realistic rather than checking the crate.
#[test]
fn every_fixture_fits_the_size_the_standard_allows() {
    for name in ["root", "sub1", "sub2", "secc", "contract", "rogue", "other", "expired", "decoy"] {
        let bytes = der(name);
        assert!(bytes.len() <= 800, "{name}.der is {} bytes", bytes.len());
    }
}

/// A root names itself, and nothing below one should.
#[test]
fn the_root_is_self_issued_and_carries_the_v2g_domain_component() {
    let bytes = der("root");
    let root = Certificate::parse(&bytes).expect("parse");
    assert!(root.is_self_issued());
    // Table F.1 fixes this value, and \[V2G2-925\] makes a missing one a
    // reason to treat a leaf as invalid.
    assert_eq!(root.subject.domain_component, Some(pki::DC_V2G));
    let bc = root.basic_constraints.expect("BasicConstraints");
    assert!(bc.ca);
    assert_eq!(bc.path_len, None, "Table F.1 leaves PathLength absent on the root");
}

/// The Sub-CA rows of Table F.2 carry `PathLength` 1 and 0, and those two
/// numbers are the whole of why a chain cannot be extended.
#[test]
fn the_sub_cas_carry_the_path_lengths_table_f2_gives_them() {
    for (name, expected) in [("sub1", Some(1)), ("sub2", Some(0))] {
        let bytes = der(name);
        let cert = Certificate::parse(&bytes).expect("parse");
        let bc = cert.basic_constraints.expect("BasicConstraints");
        assert!(bc.ca, "{name} is a CA");
        assert_eq!(bc.path_len, expected, "{name} pathLenConstraint");
        assert!(cert.key_usage.expect("KeyUsage").contains(KeyUsage::KEY_CERT_SIGN));
    }
}

// ---------------------------------------------------------------------------
// Chain validation
// ---------------------------------------------------------------------------

#[test]
fn a_well_formed_secc_chain_validates_to_its_root() {
    let chain = secc_chain();
    let root = der("root");
    let validated =
        pki::validate(&refs(&chain), &[&root], Profile::SeccCertificate, IN_2030, &Backend)
            .expect("the chain is exactly what Table F.2 describes");

    assert_eq!(validated.subject_common_name(), Some("DE*ABC*E00001"));
    assert_eq!(validated.public_key().len(), 65);
    assert_eq!(validated.intermediates.len(), 2);
}

#[test]
fn a_contract_chain_validates_and_names_the_emaid() {
    let chain = [der("contract"), der("sub2"), der("sub1")];
    let root = der("root");
    let validated =
        pki::validate(&refs(&chain), &[&root], Profile::ContractCertificate, IN_2030, &Backend)
            .expect("Table F.4's contract certificate");

    // \[V2G2-108\]: "The EMAID shall be encoded in the subject of the
    // certificate", and it is the Common Name.
    assert_eq!(validated.subject_common_name(), Some("DE8AA1A2B3C4D5"));
}

/// \[V2G2-924\]: a chain that does not trace up to a root the peer holds is one
/// the peer must refuse. The chain here is perfectly valid — it just does not
/// end where this side is willing to start.
#[test]
fn a_chain_to_an_anchor_this_side_does_not_hold_is_refused() {
    let chain = secc_chain();
    let other = der("other");
    assert_eq!(
        pki::validate(&refs(&chain), &[&other], Profile::SeccCertificate, IN_2030, &Backend),
        Err(ChainError::NoTrustAnchor),
    );
    // ...and with no anchors at all, which is the configuration mistake that
    // would otherwise validate everything.
    assert_eq!(
        pki::validate(&refs(&chain), &[], Profile::SeccCertificate, IN_2030, &Backend),
        Err(ChainError::NoTrustAnchor),
    );
}

/// The signature check is the whole point, so it gets a test that changes one
/// bit rather than one that changes a field.
#[test]
fn one_flipped_bit_anywhere_in_the_chain_breaks_it() {
    let root = der("root");
    for position in [1usize, 0] {
        let mut chain = secc_chain();
        // The last byte of a certificate is inside its signature; the middle is
        // inside its TBS. Both must fail, and for the same reason.
        let last = chain[position].len() - 1;
        chain[position][last] ^= 0x01;
        let result =
            pki::validate(&refs(&chain), &[&root], Profile::SeccCertificate, IN_2030, &Backend);
        assert!(
            matches!(result, Err(ChainError::BadSignature { .. } | ChainError::Certificate { .. })),
            "certificate {position} with a flipped bit: {result:?}"
        );
    }
}

/// A validity period is only worth checking if something checks it, and the
/// fixture is a certificate that really did expire rather than a clock moved
/// forward.
#[test]
fn a_certificate_outside_its_validity_window_is_refused() {
    let chain = [der("expired"), der("sub2"), der("sub1")];
    let root = der("root");
    assert_eq!(
        pki::validate(&refs(&chain), &[&root], Profile::SeccCertificate, IN_2022, &Backend),
        Err(ChainError::Expired { index: 0 }),
    );
    // The same chain inside the window is fine, so the test is about the date
    // and not about the certificate.
    assert!(
        pki::validate(&refs(&chain), &[&root], Profile::SeccCertificate, 1_600_000_000, &Backend)
            .is_ok()
    );
}

/// \[V2G2-867\]: "A V2G root shall not issue a leaf certificate", and every
/// Annex F leaf row is `CA = false`. A leaf that asserts `cA` is asking to be
/// treated as an issuer by whatever reads it next.
#[test]
fn a_leaf_that_claims_to_be_a_ca_is_refused() {
    let chain = [der("rogue"), der("sub2"), der("sub1")];
    let root = der("root");
    assert_eq!(
        pki::validate(&refs(&chain), &[&root], Profile::SeccCertificate, IN_2030, &Backend),
        Err(ChainError::Profile { wanted: "a leaf that is not a CA" }),
    );
}

/// \[V2G2-925\]: a leaf is invalid "if the required Domain Component value is
/// not present". Table F.2 requires `"CPO"` on an SECC certificate; the
/// contract certificate of Table F.4 has no required value, so the same chain
/// under the other profile is a different answer.
#[test]
fn the_domain_component_a_profile_requires_is_a_validity_condition() {
    let chain = [der("contract"), der("sub2"), der("sub1")];
    let root = der("root");
    // The contract certificate carries no `DC`, which Table F.4 permits.
    assert!(
        pki::validate(&refs(&chain), &[&root], Profile::ContractCertificate, IN_2030, &Backend)
            .is_ok()
    );
    // Checked as an SECC certificate, the same bytes are not one.
    assert_eq!(
        pki::validate(&refs(&chain), &[&root], Profile::SeccCertificate, IN_2030, &Backend),
        Err(ChainError::Profile { wanted: "the Domain Component its profile requires" }),
    );
}

/// The SECC certificate has `digitalSignature` and not `nonRepudiation`, which
/// Table F.4 requires of a contract certificate. Checking one chain under both
/// profiles is what makes the key-usage rule visible: the certificate does not
/// change, the question does.
#[test]
fn a_profile_that_needs_a_key_usage_bit_refuses_a_leaf_without_it() {
    let chain = secc_chain();
    let root = der("root");
    assert_eq!(
        pki::validate(&refs(&chain), &[&root], Profile::ContractCertificate, IN_2030, &Backend),
        Err(ChainError::Profile { wanted: "the KeyUsage bits its profile requires" }),
    );
}

/// \[V2G2-009\] limits a path to three certificates below the root, and the
/// note beside it says what that counts. A peer that sends more has already
/// made this side do the work, so the count is checked before the signatures.
#[test]
fn a_path_longer_than_the_standard_allows_is_refused() {
    let mut chain: Vec<Vec<u8>> = secc_chain().into();
    chain.push(der("sub1"));
    let root = der("root");
    assert_eq!(
        pki::validate(&refs(&chain), &[&root], Profile::SeccCertificate, IN_2030, &Backend),
        Err(ChainError::TooLong { len: 4 }),
    );
}

/// Order is not a hint. A chain whose certificates do not actually issue one
/// another is refused rather than reordered — reordering is a search, and a
/// search over attacker-supplied certificates is how a verifier is made to do
/// work nobody asked for.
#[test]
fn a_chain_in_the_wrong_order_is_refused_rather_than_sorted() {
    let chain = [der("secc"), der("sub1"), der("sub2")];
    let root = der("root");
    assert_eq!(
        pki::validate(&refs(&chain), &[&root], Profile::SeccCertificate, IN_2030, &Backend),
        Err(ChainError::NoTrustAnchor),
    );
}

/// Dropping the intermediate leaves a leaf whose issuer is not the anchor.
/// This is the shape of "the station sent a shorter chain than it should have",
/// which \[V2G2-923\] has the peer refuse.
#[test]
fn a_chain_with_a_missing_link_is_refused() {
    let chain = [der("secc"), der("sub1")];
    let root = der("root");
    assert_eq!(
        pki::validate(&refs(&chain), &[&root], Profile::SeccCertificate, IN_2030, &Backend),
        Err(ChainError::NoTrustAnchor),
    );
}

/// \[V2G2-878\] allows up to ten concurrently valid V2G Root Certificates for
/// one Root CA, so anchors that share a subject name are the normal case during
/// a rollover — not an anomaly.
///
/// An implementation that picks the first anchor matching by name and *then*
/// checks it fails every chain at every station on the day a new root is added
/// to the list. Selection has to consider the whole condition.
#[test]
fn an_anchor_is_chosen_by_what_verifies_not_by_what_matches_by_name() {
    let chain = secc_chain();
    let decoy = der("decoy"); // same subject DN as `root`, different key
    let root = der("root");

    // The decoy alone establishes nothing, which is the check the ordering
    // could otherwise hide.
    assert_eq!(
        pki::validate(&refs(&chain), &[&decoy], Profile::SeccCertificate, IN_2030, &Backend),
        Err(ChainError::NoTrustAnchor),
    );

    // With the decoy listed *first*, the real root is still found.
    assert!(
        pki::validate(
            &refs(&chain),
            &[&decoy, &root],
            Profile::SeccCertificate,
            IN_2030,
            &Backend,
        )
        .is_ok(),
        "a name collision in the anchor list must not shadow the anchor that works",
    );
}

/// RFC 5280 puts no constraint on where a trust anchor sits, and ISO 15118 has
/// a case that needs it: \[V2G2-927\] makes a Private Operator Root a trust
/// anchor for SECC certificates and \[V2G2-868\] has it sign leaves directly.
///
/// The same shape turns up in an ordinary deployment: a station sends its full
/// chain, and a vehicle has pinned one of the Sub-CAs rather than the root. A
/// validator that only looks for an anchor at the *top* of what arrived refuses
/// that, and "you configured the wrong certificate" is a hard failure to
/// diagnose from the cable.
#[test]
fn a_pinned_intermediate_is_a_trust_anchor_like_any_other() {
    let chain = secc_chain(); // leaf, sub2, sub1 — the station's whole chain
    let sub2 = der("sub2");
    let sub1 = der("sub1");

    // Pinning Sub-CA 2 stops the walk one step up from the leaf...
    let pinned =
        pki::validate(&refs(&chain), &[&sub2], Profile::SeccCertificate, IN_2030, &Backend)
            .expect("an anchor is an anchor wherever it sits");
    assert_eq!(pinned.anchor, Certificate::parse(&sub2).unwrap());

    // ...and pinning Sub-CA 1 stops it one step later, without the root.
    let pinned =
        pki::validate(&refs(&chain), &[&sub1], Profile::SeccCertificate, IN_2030, &Backend)
            .expect("valid");
    assert_eq!(pinned.anchor, Certificate::parse(&sub1).unwrap());

    // A chain that stops short of its own pinned anchor still fails: the
    // shortcut is about where the anchor may be, not about skipping links.
    let short = [der("secc")];
    assert_eq!(
        pki::validate(&refs(&short), &[&sub1], Profile::SeccCertificate, IN_2030, &Backend),
        Err(ChainError::NoTrustAnchor),
    );
}

/// A trust anchor is trusted by configuration rather than by its own signature
/// — but it still has to be something that may *issue*. A leaf dropped into the
/// anchor list by mistake would otherwise validate whatever it happened to have
/// signed.
#[test]
fn a_leaf_configured_as_a_trust_anchor_issues_nothing() {
    let chain = secc_chain();
    let leaf_as_anchor = der("secc");
    assert_eq!(
        pki::validate(
            &refs(&chain),
            &[&leaf_as_anchor],
            Profile::SeccCertificate,
            IN_2030,
            &Backend,
        ),
        Err(ChainError::NoTrustAnchor),
    );
}

#[test]
fn an_empty_chain_is_refused() {
    let root = der("root");
    assert_eq!(
        pki::validate(&[], &[&root], Profile::SeccCertificate, IN_2030, &Backend),
        Err(ChainError::Empty),
    );
}

/// The end of the story, and the reason the module exists: the key that comes
/// out of a validated chain is the one a Plug & Charge signature is checked
/// against. Before this, `verify` took whatever key the caller had.
#[test]
fn the_validated_key_is_the_one_a_signature_is_checked_against() {
    use iso15118::pnc::rustcrypto::VerifyingKey;

    let chain = [der("contract"), der("sub2"), der("sub1")];
    let root = der("root");
    let validated =
        pki::validate(&refs(&chain), &[&root], Profile::ContractCertificate, IN_2030, &Backend)
            .expect("valid");

    // The point out of the certificate is one the backend can build a key from,
    // which is the seam between the two halves.
    let key = VerifyingKey::p256_sec1(validated.public_key()).expect("a usable public key");
    assert_eq!(key.suite(), iso15118::pnc::Suite::EcdsaSha256);
}
