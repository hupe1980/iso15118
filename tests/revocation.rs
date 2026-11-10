//! Revocation status, as both generations make it part of path validation.
//!
//! Every OCSP response and CRL here is minted by **OpenSSL** acting as
//! responder and CA (`scripts/make-test-pki.sh revocation`), so each verdict is
//! about bytes a third implementation built from RFC 6960 and RFC 5280.
//!
//! `openssl ocsp` stamps `thisUpdate` with the time it runs, so the responses
//! carry no fixed date; `minted-at` records that instant and every test derives
//! its "now" from it. Certificates and CRLs carry absolute dates.
//!
//! Each test is named for the rule it enforces, and cites it.

#![cfg(all(feature = "pnc-rustcrypto", feature = "std", feature = "iso2", feature = "iso20"))]

use iso15118::pnc::pki::{
    self, ChainError, Environment, Evidence, EvidenceError, HashAlgorithm, Hasher, Policy, Profile,
    Reason, Source, Standing, TrustAnchor, TrustAnchors, Unknown, Validated, VerifyWith,
};
use iso15118::pnc::rustcrypto::Backend;
use iso15118::pnc::{PncError, Suite};

const HOUR: i64 = 3_600;
const DAY: i64 = 86_400;

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/fixtures/pki/revocation/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path)
        .unwrap_or_else(|e| panic!("run scripts/make-test-pki.sh revocation: {path}: {e}"))
}

fn der(name: &str) -> Vec<u8> {
    fixture(&format!("{name}.der"))
}

/// An hour after the OCSP responses were minted: inside every response's
/// window, and inside every certificate's and CRL's.
fn now() -> i64 {
    let text = String::from_utf8(fixture("minted-at")).expect("minted-at is text");
    text.trim().parse::<i64>().expect("minted-at is Unix seconds") + HOUR
}

fn refs(v: &[Vec<u8>]) -> Vec<&[u8]> {
    v.iter().map(Vec::as_slice).collect()
}

/// Validates `chain` against one anchor in `environment`, with `ocsp` and
/// `crls` as evidence, at `at`.
fn check_at(
    chain: &[&str],
    anchor: &str,
    environment: Environment,
    policy: Policy,
    ocsp: &[&str],
    crls: &[&str],
    at: i64,
) -> Result<Vec<Standing>, ChainError> {
    let chain: Vec<Vec<u8>> = chain.iter().map(|n| der(n)).collect();
    let anchor = der(anchor);
    let ocsp: Vec<Vec<u8>> = ocsp.iter().map(|n| der(n)).collect();
    let crls: Vec<Vec<u8>> = crls.iter().map(|n| der(n)).collect();
    run(&refs(&chain), &anchor, environment, policy, &refs(&ocsp), &refs(&crls), at, &Backend)
        .map(|v| v.standing)
}

#[allow(clippy::too_many_arguments)]
fn run<'a>(
    chain: &[&'a [u8]],
    anchor: &'a [u8],
    environment: Environment,
    policy: Policy,
    ocsp: &[&[u8]],
    crls: &[&[u8]],
    at: i64,
    backend: &(impl VerifyWith + Hasher),
) -> Result<Validated<'a>, ChainError> {
    let anchors = [match environment {
        Environment::Public => TrustAnchor::public(anchor, "test"),
        Environment::Private => TrustAnchor::private(anchor, "test"),
    }];
    pki::validate(
        chain,
        &TrustAnchors::new(&anchors),
        policy,
        &Evidence::new(ocsp, crls),
        at,
        backend,
    )
}

fn check(
    chain: &[&str],
    anchor: &str,
    environment: Environment,
    policy: Policy,
    ocsp: &[&str],
    crls: &[&str],
) -> Result<Vec<Standing>, ChainError> {
    check_at(chain, anchor, environment, policy, ocsp, crls, now())
}

const R2_SECC: [&str; 3] = ["r2/secc", "r2/sub2", "r2/sub1"];
const R2_CONTRACT: [&str; 3] = ["r2/contract", "r2/sub2", "r2/sub1"];
const R20_SECC: [&str; 3] = ["r20/secc", "r20/sub2", "r20/sub1"];
const PE: [&str; 2] = ["pe/leaf", "pe/sub"];

const ISO2_SECC: Policy = Policy::iso2(Profile::SeccCertificate);
const ISO20_SECC: Policy = Policy::iso20(Profile::SeccCertificate);
const ISO2_CONTRACT: Policy = Policy::iso2(Profile::ContractCertificate);

use Environment::{Private, Public};

fn rejected(index: usize, error: EvidenceError) -> ChainError {
    ChainError::EvidenceRejected { index: Some(index), error }
}

// ---------------------------------------------------------------------------
// US1 — the vehicle refuses a station chain it cannot vouch for
// ---------------------------------------------------------------------------

/// \[V2G2-070\] and its NOTE 1: under -2 the Sub-CAs need a good response, the
/// leaf none.
#[test]
fn iso2_public_needs_good_sub_cas_only() {
    let standing =
        check(&R2_SECC, "r2/root", Public, ISO2_SECC, &["r2/sub2-good", "r2/sub1-good"], &[])
            .unwrap();
    assert_eq!(standing[0], Standing::Unknown(Unknown::NoEvidence));
    assert!(standing[1].is_good() && standing[2].is_good());
    assert!(matches!(standing[1], Standing::Good { source: Source::Ocsp, .. }));
}

/// \[V2G2-873\]: a chain to a V2G root with a Sub-CA's response missing is
/// aborted.
#[test]
fn iso2_public_missing_sub_ca_status_is_refused() {
    assert_eq!(
        check(&R2_SECC, "r2/root", Public, ISO2_SECC, &["r2/sub2-good"], &[]),
        Err(ChainError::StatusMissing { index: 2 })
    );
    assert_eq!(
        check(&R2_SECC, "r2/root", Public, ISO2_SECC, &[], &[]),
        Err(ChainError::StatusMissing { index: 1 })
    );
}

/// \[V2G2-872\]/\[V2G2-873\]: a private environment staples nothing, and needs
/// nothing.
#[test]
fn iso2_private_needs_no_status() {
    assert!(check(&PE, "pe/root", Private, ISO2_SECC, &[], &[]).is_ok());
}

/// \[V2G20-1240\]/\[V2G20-2416\]: under -20 every certificate the station sent,
/// the leaf included, needs a good response.
#[test]
fn iso20_public_needs_every_certificate() {
    let all = ["r20/secc-good", "r20/sub2-good", "r20/sub1-good"];
    let standing = check(&R20_SECC, "r20/root", Public, ISO20_SECC, &all, &[]).unwrap();
    assert!(standing.iter().all(Standing::is_good));
    assert_eq!(
        check(&R20_SECC, "r20/root", Public, ISO20_SECC, &all[1..], &[]),
        Err(ChainError::StatusMissing { index: 0 })
    );
}

/// \[V2G20-2415\]: a status other than good fails the whole chain.
#[test]
fn iso20_a_revoked_leaf_fails_the_chain() {
    let evidence = ["r20/secc-revoked", "r20/sub2-good", "r20/sub1-good"];
    assert!(matches!(
        check(&R20_SECC, "r20/root", Public, ISO20_SECC, &evidence, &[]),
        Err(ChainError::Revoked { index: 0, reason: Some(Reason::KeyCompromise), .. })
    ));
}

/// \[V2G20-2410\]/\[V2G20-2417\]: a private SECC staples for none of its
/// certificates or for all of them.
#[test]
fn iso20_private_is_all_or_none() {
    assert!(check(&PE, "pe/root", Private, ISO20_SECC, &[], &[]).is_ok());
    assert_eq!(
        check(&PE, "pe/root", Private, ISO20_SECC, &["pe/leaf-good"], &[]),
        Err(ChainError::StatusMissing { index: 1 })
    );
    assert!(
        check(&PE, "pe/root", Private, ISO20_SECC, &["pe/leaf-good", "pe/sub-good"], &[]).is_ok()
    );
}

/// \[V2G2-876\]: a -2 response may be valid for four weeks and no longer.
#[test]
fn iso2_response_validity_is_at_most_four_weeks() {
    assert!(
        check(&R2_SECC, "r2/root", Public, ISO2_SECC, &["r2/sub2-28days", "r2/sub1-good"], &[])
            .is_ok()
    );
    assert!(matches!(
        check(&R2_SECC, "r2/root", Public, ISO2_SECC, &["r2/sub2-29days", "r2/sub1-good"], &[]),
        Err(ChainError::EvidenceRejected {
            index: Some(1),
            error: EvidenceError::ValidityTooLong { seconds }
        }) if seconds == 29 * DAY
    ));
}

/// \[V2G20-1021\]: a -20 response may be valid for one week and no longer.
#[test]
fn iso20_response_validity_is_at_most_one_week() {
    let evidence = ["r20/secc-8days", "r20/sub2-good", "r20/sub1-good"];
    assert!(matches!(
        check(&R20_SECC, "r20/root", Public, ISO20_SECC, &evidence, &[]),
        Err(ChainError::EvidenceRejected {
            index: Some(0),
            error: EvidenceError::ValidityTooLong { .. }
        })
    ));
}

/// RFC 6960 §3.2 (6)/(7): a response is evidence only between `thisUpdate` and
/// `nextUpdate`.
#[test]
fn a_response_outside_its_window_is_rejected() {
    let evidence = ["r2/sub2-good", "r2/sub1-good"];
    let early = now() - 2 * HOUR;
    let late = now() + 8 * DAY;
    assert_eq!(
        check_at(&R2_SECC, "r2/root", Public, ISO2_SECC, &evidence, &[], early),
        Err(rejected(1, EvidenceError::NotYetValid))
    );
    assert_eq!(
        check_at(&R2_SECC, "r2/root", Public, ISO2_SECC, &evidence, &[], late),
        Err(rejected(1, EvidenceError::Stale))
    );
}

/// RFC 6960 §4.2.2.2, \[V2G2-875\], \[V2G20-2413\]: a delegated responder needs
/// `id-kp-OCSPSigning` from the certificate's own issuer.
#[test]
fn a_responder_without_ocsp_signing_is_not_authorised() {
    assert_eq!(
        check(&R2_SECC, "r2/root", Public, ISO2_SECC, &["r2/sub2-rogue", "r2/sub1-good"], &[]),
        Err(rejected(1, EvidenceError::ResponderNotAuthorized))
    );
}

/// \[V2G20-2414\]: a response whose signature does not verify fails the chain.
#[test]
fn a_bad_response_signature_is_rejected() {
    let chain: Vec<Vec<u8>> = R2_SECC.iter().map(|n| der(n)).collect();
    let mut forged = der("r2/sub1-good");
    // Issued without `certs`, so the last octet is the signature's `s`; its low
    // bit changes the number and nothing about the encoding.
    *forged.last_mut().unwrap() ^= 0x01;
    let good = der("r2/sub2-good");
    let root = der("r2/root");
    assert_eq!(
        run(&refs(&chain), &root, Public, ISO2_SECC, &[&good, &forged], &[], now(), &Backend)
            .map(|_| ()),
        Err(rejected(2, EvidenceError::BadSignature))
    );
}

/// \[V2G20-2415\]: a responder that does not know the certificate has not said
/// it is good.
#[test]
fn an_unknown_status_is_rejected() {
    assert_eq!(
        check(&R2_SECC, "r2/root", Public, ISO2_SECC, &["r2/sub2-unknown", "r2/sub1-good"], &[]),
        Err(rejected(1, EvidenceError::StatusUnknown))
    );
}

/// A revoked Sub-CA is every station beneath it.
#[test]
fn a_revoked_sub_ca_fails_the_chain() {
    assert!(matches!(
        check(&R2_SECC, "r2/root", Public, ISO2_SECC, &["r2/sub2-revoked", "r2/sub1-good"], &[]),
        Err(ChainError::Revoked { index: 1, reason: Some(Reason::KeyCompromise), .. })
    ));
}

/// RFC 6960 §4.1.1: a `CertID` may be hashed with SHA-256 and a `ResponderID`
/// may name the key rather than the subject.
#[test]
fn sha256_cert_ids_and_responder_ids_by_key_match() {
    assert!(
        check(
            &R2_SECC,
            "r2/root",
            Public,
            ISO2_SECC,
            &["r2/sub2-good-sha256-bykey", "r2/sub1-good"],
            &[]
        )
        .is_ok()
    );
}

/// A backend that cannot compute a `CertID`'s hash leaves the response
/// unreadable — never good.
#[test]
fn a_cert_id_the_backend_cannot_hash_is_rejected() {
    struct NoSha1;
    impl VerifyWith for NoSha1 {
        fn verify_with(
            &self,
            suite: Suite,
            key: &[u8],
            data: &[u8],
            sig: &[u8],
        ) -> Result<(), PncError> {
            Backend.verify_with(suite, key, data, sig)
        }
    }
    impl Hasher for NoSha1 {
        fn hash(&self, alg: HashAlgorithm, data: &[u8]) -> Option<Vec<u8>> {
            (alg != HashAlgorithm::Sha1).then(|| Backend.hash(alg, data)).flatten()
        }
    }
    let chain: Vec<Vec<u8>> = R2_SECC.iter().map(|n| der(n)).collect();
    let (sub2, sub1, root) = (der("r2/sub2-good"), der("r2/sub1-good"), der("r2/root"));
    let result = run(&refs(&chain), &root, Public, ISO2_SECC, &[&sub2, &sub1], &[], now(), &NoSha1);
    assert!(matches!(
        result,
        Err(ChainError::EvidenceRejected { error: EvidenceError::UnsupportedHash, .. })
    ));
}

/// Evidence that cannot be read cannot be attributed to a certificate, and is
/// refused rather than ignored.
#[test]
fn unreadable_evidence_is_refused() {
    let chain: Vec<Vec<u8>> = R2_SECC.iter().map(|n| der(n)).collect();
    let root = der("r2/root");
    assert_eq!(
        run(&refs(&chain), &root, Public, ISO2_SECC, &[b"\x30\x03\x0a\x01"], &[], now(), &Backend)
            .map(|_| ()),
        Err(ChainError::EvidenceRejected { index: None, error: EvidenceError::Malformed })
    );
    let many: Vec<&[u8]> = vec![b"".as_slice(); pki::MAX_EVIDENCE + 1];
    assert_eq!(
        run(&refs(&chain), &root, Public, ISO2_SECC, &many, &[], now(), &Backend).map(|_| ()),
        Err(ChainError::EvidenceRejected { index: None, error: EvidenceError::TooLarge })
    );
}

// ---------------------------------------------------------------------------
// US2 — the station knows whether a contract was withdrawn
// ---------------------------------------------------------------------------

/// \[V2G2-693\], \[V2G20-2214\]: a CRL listing the contract certificate refuses
/// it, with the code each generation prescribes.
#[test]
fn a_crl_listing_the_contract_leaf_refuses_it() {
    let error =
        check(&R2_CONTRACT, "r2/root", Public, ISO2_CONTRACT, &[], &["r2/crl-sub2-contract"])
            .unwrap_err();
    assert!(matches!(
        error,
        ChainError::Revoked { index: 0, reason: Some(Reason::KeyCompromise), .. }
    ));
    assert_eq!(
        iso15118::pnc::iso2::response_code(&error),
        iso15118::iso2::ResponseCode::FAILEDCertificateRevoked
    );
    assert_eq!(
        iso15118::pnc::iso20::response_code(&error),
        iso15118::iso20::common::ResponseCode::WARNINGCertificateRevoked
    );
}

/// A withdrawn Sub-CA is every contract beneath it.
#[test]
fn a_crl_listing_a_sub_ca_refuses_the_chain() {
    assert!(matches!(
        check(&R2_CONTRACT, "r2/root", Public, ISO2_CONTRACT, &[], &["r2/crl-sub1-sub2"]),
        Err(ChainError::Revoked { index: 1, reason: Some(Reason::CaCompromise), .. })
    ));
}

/// A current CRL that does not list the certificate is good evidence for it.
#[test]
fn an_empty_crl_vouches_for_the_contract() {
    let standing =
        check(&R2_CONTRACT, "r2/root", Public, ISO2_CONTRACT, &[], &["r2/crl-sub2-empty"]).unwrap();
    assert!(matches!(standing[0], Standing::Good { source: Source::Crl, .. }));
    assert_eq!(standing[1], Standing::Unknown(Unknown::NoEvidence));
}

/// RFC 5280 §5.1.2.5 and §5.2.3: a stale CRL, or one without `CRLNumber`, is
/// not evidence — and evidence handed in that fails refuses.
#[test]
fn a_stale_or_unnumbered_crl_is_rejected() {
    assert_eq!(
        check(&R2_CONTRACT, "r2/root", Public, ISO2_CONTRACT, &[], &["r2/crl-sub2-stale"]),
        Err(rejected(0, EvidenceError::Stale))
    );
    assert_eq!(
        check(&R2_CONTRACT, "r2/root", Public, ISO2_CONTRACT, &[], &["r2/crl-sub2-unnumbered"]),
        Err(rejected(0, EvidenceError::MissingCrlNumber))
    );
}

/// \[V2G20-2214\] leaves fetching to the station: no evidence accepts a
/// contract chain, and says so.
#[test]
fn no_evidence_accepts_a_contract_chain_and_says_so() {
    let standing = check(&R2_CONTRACT, "r2/root", Public, ISO2_CONTRACT, &[], &[]).unwrap();
    assert!(standing.iter().all(|s| *s == Standing::Unknown(Unknown::NoEvidence)));
    assert_eq!(standing.len(), 3);
}

/// A revocation is never outvoted: a good OCSP response does not cancel a CRL
/// listing.
#[test]
fn revoked_beats_good() {
    assert!(matches!(
        check(
            &R2_CONTRACT,
            "r2/root",
            Public,
            ISO2_CONTRACT,
            &["r2/sub2-good"],
            &["r2/crl-sub1-sub2"]
        ),
        Err(ChainError::Revoked { index: 1, .. })
    ));
}

/// \[V2G2-470\], \[V2G2-474\], \[V2G2-824\]; \[V2G20-2212\], \[V2G20-2213\],
/// \[V2G20-2215\]: the codes for the other refusals.
#[test]
fn response_codes_for_both_generations() {
    use iso15118::iso2::ResponseCode as R2;
    use iso15118::iso20::common::ResponseCode as R20;
    use iso15118::pnc::{iso2, iso20};
    let expired = ChainError::Expired { index: 0 };
    let early = ChainError::NotYetValid { index: 0 };
    let other = ChainError::NoTrustAnchor;
    assert_eq!(iso2::response_code(&expired), R2::FAILEDCertificateExpired);
    assert_eq!(iso2::response_code(&early), R2::FAILEDCertificateExpired);
    assert_eq!(iso2::response_code(&other), R2::FAILEDCertChainError);
    assert_eq!(iso20::response_code(&expired), R20::WARNINGCertificateExpired);
    assert_eq!(iso20::response_code(&early), R20::WARNINGCertificateNotYetValid);
    assert_eq!(iso20::response_code(&other), R20::WARNINGCertificateValidationError);
}

/// The path ends where the anchor is reached: `Validated` reports exactly the
/// certificates it walked, and one standing for each.
#[test]
fn the_path_reported_is_the_path_walked() {
    let chain: Vec<Vec<u8>> = R2_CONTRACT.iter().map(|n| der(n)).collect();
    let root = der("r2/root");
    let v = run(&refs(&chain), &root, Public, ISO2_CONTRACT, &[], &[], now(), &Backend).unwrap();
    assert_eq!(v.intermediates.len(), 2);
    assert_eq!(v.standing.len(), 3);
    assert_eq!(v.environment, Public);
}
