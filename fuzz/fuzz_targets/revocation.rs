//! OCSP responses and CRLs — the second hostile DER a vehicle reads.
//!
//! A stapled OCSP response arrives in the TLS handshake beside the station's
//! certificates, before anything about the station is established: the same
//! exposure as a certificate, through two more hand-written ASN.1 readers.
//!
//! The input is read as either kind of evidence (its first byte decides) and
//! checked against a real station chain under both generations' rules, with a
//! verifier that accepts every signature and a hasher that hashes everything to
//! nothing — so a `CertID` of two empty hashes and the right serial matches, and
//! the fuzzer reaches the status logic rather than stopping at a digest.
//!
//! Properties:
//!
//! * nothing panics, whatever the bytes;
//! * parsing is deterministic;
//! * a chain accepted under a public V2G root has every standing the rules
//!   require shown good — -2 the Sub-CAs, -20 every certificate — whatever the
//!   evidence says;
//! * no accepted chain reports a certificate revoked or evidence rejected.
#![no_main]

use iso15118::pnc::pki::{
    self, Crl, Evidence, HashAlgorithm, Hasher, OcspResponse, Policy, Profile, Standing,
    TrustAnchor, TrustAnchors, Unknown, VerifyWith,
};
use iso15118::pnc::{PncError, Suite};
use libfuzzer_sys::fuzz_target;

const ROOT: &[u8] = include_bytes!("../../tests/fixtures/pki/revocation/r2/root.der");
const SUB1: &[u8] = include_bytes!("../../tests/fixtures/pki/revocation/r2/sub1.der");
const SUB2: &[u8] = include_bytes!("../../tests/fixtures/pki/revocation/r2/sub2.der");
const SECC: &[u8] = include_bytes!("../../tests/fixtures/pki/revocation/r2/secc.der");

/// 2030-01-01: inside every fixture certificate's window.
const NOW: i64 = 1_893_456_000;

struct AcceptAll;

impl VerifyWith for AcceptAll {
    fn verify_with(&self, _: Suite, _: &[u8], _: &[u8], _: &[u8]) -> Result<(), PncError> {
        Ok(())
    }
}

impl Hasher for AcceptAll {
    fn hash(&self, _: HashAlgorithm, _: &[u8]) -> Option<Vec<u8>> {
        Some(Vec::new())
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, der)) = data.split_first() else { return };
    let one = [der];
    let evidence =
        if selector & 1 == 0 { Evidence::ocsp(&one) } else { Evidence::crls(&one) };

    if selector & 1 == 0 {
        assert_eq!(OcspResponse::parse(der), OcspResponse::parse(der));
    } else {
        assert_eq!(Crl::parse(der), Crl::parse(der));
    }

    let anchors = [TrustAnchor::public(ROOT, "fuzz")];
    let anchors = TrustAnchors::new(&anchors);
    let chain: [&[u8]; 3] = [SECC, SUB2, SUB1];
    for (policy, required) in [
        (Policy::iso2(Profile::SeccCertificate), 1usize),
        (Policy::iso20(Profile::SeccCertificate), 0usize),
        (Policy::iso2(Profile::ContractCertificate), usize::MAX),
    ] {
        let Ok(path) = pki::validate(&chain, &anchors, policy, &evidence, NOW, &AcceptAll) else {
            continue;
        };
        assert_eq!(path.standing.len(), 3);
        for (index, standing) in path.standing.iter().enumerate() {
            assert!(!matches!(standing, Standing::Revoked { .. }), "{policy:?}: revoked accepted");
            assert!(
                !matches!(standing, Standing::Unknown(Unknown::Rejected(_))),
                "{policy:?}: rejected evidence accepted"
            );
            if index >= required {
                assert!(standing.is_good(), "{policy:?}: certificate {index} accepted without status");
            }
        }
    }
});
