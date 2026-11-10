//! ISO 15118-20 Plug & Charge cryptography against an independent implementation.
//!
//! Envelopes, Ed448 signatures and SHAKE256 digests are minted by `cryptography`
//! (OpenSSL-backed) in `scripts/lib/iso20_crypto.py`; certificates by the OpenSSL
//! CLI (`scripts/make-test-pki.sh iso20-crypto`). Every input there is fixed, so
//! the sealing direction is checked byte for byte.

#![cfg(all(feature = "pnc-rustcrypto", feature = "std"))]

use iso15118::pnc::envelope::iso20::{self, Curve};
use iso15118::pnc::pki::{
    self, CertError, Certificate, ChainError, Evidence, Policy, Profile, TrustAnchor, TrustAnchors,
};
use iso15118::pnc::rustcrypto::{AesGcm, AgreementKey, Backend, Sha2};
use iso15118::pnc::{Algorithms, PncError};

const IN_2030: i64 = 1_893_456_000;
const PCID: &str = "WMIV1234567890ABC1";
const SKI: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
const IV: [u8; 12] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/fixtures/pki/iso20-crypto/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path)
        .unwrap_or_else(|e| panic!("run scripts/make-test-pki.sh iso20-crypto: {path}: {e}"))
}

fn aad() -> [u8; iso20::AAD_LEN] {
    iso20::aad(PCID, &SKI).unwrap()
}

fn open_secp521(
    field: &[u8],
    dh: &[u8],
    aad: &[u8; 34],
    contract: &[u8],
) -> Result<Vec<u8>, PncError> {
    let oem = AgreementKey::p521(&fixture("secp521-oem-private.bin")).unwrap();
    iso20::open(Curve::Secp521r1, field, dh, aad, contract, &oem, &Sha2, &AesGcm)
}

// ---------------------------------------------------------------------------
// US1 — the -20 envelope, secp521r1
// ---------------------------------------------------------------------------

/// \[V2G20-2505\]–\[V2G20-2507\]: an envelope sealed elsewhere opens to the
/// key that was sealed, checked against the contract certificate's key.
#[test]
fn a_secp521_envelope_sealed_elsewhere_opens() {
    let key = open_secp521(
        &fixture("secp521-field.bin"),
        &fixture("secp521-dh-public-key.bin"),
        &aad(),
        &fixture("secp521-contract-public.bin"),
    )
    .unwrap();
    assert_eq!(key, fixture("secp521-contract-private.bin"));
}

/// \[V2G20-2535\]: the session key is the SHA-512 concatenation KDF's leftmost
/// 256 bits — the same 32 bytes the other implementation derived.
#[test]
fn the_session_key_matches_the_other_implementation() {
    use iso15118::pnc::envelope::KeyAgreement as _;
    let oem = AgreementKey::p521(&fixture("secp521-oem-private.bin")).unwrap();
    let z = oem.agree(&fixture("secp521-dh-public-key.bin")).unwrap();
    assert_eq!(iso20::session_key(&z, &Sha2).unwrap().to_vec(), fixture("secp521-session-key.bin"));
}

/// The SA side: sealing here, with the same ephemeral key and IV, produces the
/// other implementation's bytes exactly.
#[test]
fn sealing_here_produces_the_other_implementations_bytes() {
    let ephemeral = AgreementKey::p521(&fixture("secp521-ephemeral-private.bin")).unwrap();
    let field = iso20::seal(
        Curve::Secp521r1,
        &fixture("secp521-contract-private.bin"),
        &fixture("secp521-oem-public.bin"),
        &IV,
        &aad(),
        &ephemeral,
        &Sha2,
        &AesGcm,
    )
    .unwrap();
    assert_eq!(field, fixture("secp521-field.bin"));
    assert_eq!(
        iso20::dh_public_key(Curve::Secp521r1, &ephemeral.public_key()).unwrap(),
        fixture("secp521-dh-public-key.bin")
    );
}

/// \[V2G20-2504\]: one flipped bit anywhere — IV, ciphertext, tag, or the
/// PCID/SKI the AAD is built from — and nothing is returned.
#[test]
fn any_flipped_bit_is_refused() {
    let field = fixture("secp521-field.bin");
    let dh = fixture("secp521-dh-public-key.bin");
    let contract = fixture("secp521-contract-public.bin");
    for i in [0, 11, 12, 40, 77, 78, 93] {
        let mut bad = field.clone();
        bad[i] ^= 0x01;
        assert_eq!(open_secp521(&bad, &dh, &aad(), &contract), Err(PncError::Decrypt), "byte {i}");
    }
    let other_aad = iso20::aad("WMIV1234567890ABC2", &SKI).unwrap();
    assert_eq!(open_secp521(&field, &dh, &other_aad, &contract), Err(PncError::Decrypt));
}

/// \[V2G20-2507\]: a key that decrypts but belongs to another certificate is
/// refused; there is no call that skips the check.
#[test]
fn a_key_for_another_certificate_is_refused() {
    let wrong = fixture("secp521-oem-public.bin");
    assert_eq!(
        open_secp521(
            &fixture("secp521-field.bin"),
            &fixture("secp521-dh-public-key.bin"),
            &aad(),
            &wrong
        ),
        Err(PncError::KeyMismatch)
    );
}

/// \[V2G20-2678\]: the 7 padding bits of the 521-bit key must be zero — on the
/// sealing side too.
#[test]
fn non_zero_padding_bits_are_refused() {
    let ephemeral = AgreementKey::p521(&fixture("secp521-ephemeral-private.bin")).unwrap();
    let mut key = fixture("secp521-contract-private.bin");
    key[0] |= 0x02;
    assert!(matches!(
        iso20::seal(
            Curve::Secp521r1,
            &key,
            &fixture("secp521-oem-public.bin"),
            &IV,
            &aad(),
            &ephemeral,
            &Sha2,
            &AesGcm
        ),
        Err(PncError::BadEnvelope { .. })
    ));
}

/// \[V2G20-2678\] on the receiving side: an authentic envelope whose key has
/// a padding bit set is refused, not truncated to 521 bits.
#[test]
fn an_envelope_with_padding_bits_set_is_refused_on_opening() {
    use iso15118::pnc::envelope::{Aes256Gcm as _, KeyAgreement as _};
    let oem = AgreementKey::p521(&fixture("secp521-oem-private.bin")).unwrap();
    let dh = fixture("secp521-dh-public-key.bin");
    let key = iso20::session_key(&oem.agree(&dh).unwrap(), &Sha2).unwrap();
    let mut scalar = fixture("secp521-contract-private.bin");
    scalar[0] |= 0x80;
    let mut field = IV.to_vec();
    field.extend(AesGcm.seal(&key, &IV, &aad(), &scalar).unwrap());
    assert_eq!(
        open_secp521(&field, &dh, &aad(), &fixture("secp521-contract-public.bin")),
        Err(PncError::Decrypt)
    );
}

/// \[V2G20-2531\]: a `DHPublicKey` of the wrong length or form is refused
/// before any computation.
#[test]
fn a_malformed_dh_public_key_is_refused() {
    let field = fixture("secp521-field.bin");
    let contract = fixture("secp521-contract-public.bin");
    let dh = fixture("secp521-dh-public-key.bin");
    assert!(matches!(
        open_secp521(&field, &dh[..132], &aad(), &contract),
        Err(PncError::BadEnvelope { len: 132 })
    ));
    let mut compressed = dh.clone();
    compressed[0] = 0x02;
    assert!(matches!(
        open_secp521(&field, &compressed, &aad(), &contract),
        Err(PncError::BadEnvelope { .. })
    ));
    assert!(matches!(
        open_secp521(&field[..93], &dh, &aad(), &contract),
        Err(PncError::BadEnvelope { len: 93 })
    ));
}

// ---------------------------------------------------------------------------
// US3 — the -20 algorithm set
// ---------------------------------------------------------------------------

fn validate(chain: &[&[u8]], root: &[u8], policy: Policy) -> Result<(), ChainError> {
    let anchors = [TrustAnchor::private(root, "test")];
    pki::validate(chain, &TrustAnchors::new(&anchors), policy, &Evidence::none(), IN_2030, &Backend)
        .map(|_| ())
}

/// Annex B, \[V2G20-2473\]: a secp521r1 chain signed with SHA-512 is a -20
/// chain; disabling the algorithm \[V2G20-2320\] refuses it by name.
#[test]
fn secp521r1_is_accepted_unless_disabled() {
    let (leaf, root) = (fixture("p521-plain.der"), fixture("p521-proot.der"));
    let policy = Policy::iso20(Profile::SeccCertificate);
    assert_eq!(validate(&[&leaf], &root, policy), Ok(()));
    let off = policy.with_algorithms(Algorithms { secp521r1: false, ed448: true });
    assert_eq!(validate(&[&leaf], &root, off), Err(ChainError::AlgorithmNotAllowed { index: 0 }));
}

// ---------------------------------------------------------------------------
// US4 — Annex B's extensions
// ---------------------------------------------------------------------------

/// \[V2G20-2323\]: an extension Annex B does not name is refused under -20
/// rules and, non-critical, ignored under -2's.
#[test]
fn an_extension_outside_annex_b_is_refused_under_iso20_only() {
    let (leaf, root) = (fixture("p521-commented.der"), fixture("p521-proot.der"));
    assert!(!Certificate::parse(&leaf).unwrap().annex_b_extensions_only);
    assert_eq!(
        validate(&[&leaf], &root, Policy::iso20(Profile::SeccCertificate)),
        Err(ChainError::Certificate { index: 0, error: CertError::ExtensionNotAllowed })
    );
    assert_eq!(validate(&[&leaf], &root, Policy::iso2(Profile::SeccCertificate)), Ok(()));
}

// ---------------------------------------------------------------------------
// US2 — Ed448
// ---------------------------------------------------------------------------

/// RFC 8410: Ed448 certificates parse, with their 57-byte keys and raw
/// 114-byte signatures; the OEM certificate carries its X448 key (Annex B.7.2).
#[test]
fn ed448_certificates_parse() {
    let secc = fixture("ed448-secc.der");
    let cert = Certificate::parse(&secc).unwrap();
    assert_eq!(cert.curve, pki::Curve::Ed448);
    assert_eq!(cert.public_key.len(), 57);
    assert_eq!(cert.signature.as_slice().len(), 114);
    let oem = fixture("ed448-oem.der");
    let cert = Certificate::parse(&oem).unwrap();
    assert_eq!(cert.alt_public_key, Some(fixture("x448-oem-public.bin").as_slice()));
    assert!(cert.annex_b_extensions_only);
}

#[cfg(feature = "pnc-rustcrypto-ed448")]
mod ed448 {
    use super::*;
    use iso15118::pnc::rustcrypto::{SigningKey, VerifyingKey};
    use iso15118::pnc::{Hash as _, Sign as _, Suite, Verify as _};

    /// OpenSSL's Ed448 chain validates under -20 rules; one altered signature
    /// byte refuses; disabling Ed448 refuses by name.
    #[test]
    fn an_ed448_chain_validates() {
        let (secc, sub2, sub1, root) = (
            fixture("ed448-secc.der"),
            fixture("ed448-sub2.der"),
            fixture("ed448-sub1.der"),
            fixture("ed448-root.der"),
        );
        let policy = Policy::iso20(Profile::SeccCertificate);
        assert_eq!(validate(&[&secc, &sub2, &sub1], &root, policy), Ok(()));
        let mut forged = secc.clone();
        *forged.last_mut().unwrap() ^= 0x01;
        assert_eq!(
            validate(&[&forged, &sub2, &sub1], &root, policy),
            Err(ChainError::BadSignature { index: 0 })
        );
        let off = policy.with_algorithms(Algorithms { secp521r1: true, ed448: false });
        assert_eq!(
            validate(&[&secc, &sub2, &sub1], &root, off),
            Err(ChainError::AlgorithmNotAllowed { index: 0 })
        );
    }

    /// Ed448 is deterministic, so signing the vector here gives the other
    /// implementation's signature exactly, and it verifies.
    #[test]
    fn ed448_signatures_agree_with_the_other_implementation() {
        let key = SigningKey::ed448(&fixture("ed448-seed.bin")).unwrap();
        let message = fixture("ed448-message.bin");
        let signature = key.sign(Suite::Ed448, &message).unwrap();
        assert_eq!(signature, fixture("ed448-signature.bin"));
        let public = VerifyingKey::ed448(&fixture("ed448-public.bin")).unwrap();
        public.verify(Suite::Ed448, &message, &signature).unwrap();
        let mut bad = signature.clone();
        bad[0] ^= 1;
        assert_eq!(public.verify(Suite::Ed448, &message, &bad), Err(PncError::BadSignature));
    }

    /// \[V2G20-2474\], \[V2G20-2476\]: an `XMLDSig` signature over a -20
    /// fragment with Ed448 and SHAKE256, made and verified with the real backend.
    #[test]
    fn an_ed448_xmldsig_signature_round_trips() {
        use iso15118::pnc::{Signed, iso20};
        let key = SigningKey::ed448(&fixture("ed448-seed.bin")).unwrap();
        let fragment = [0x80, 0x01, 0x02, 0x03];
        let elements = [Signed::new("ID1", &fragment)];
        let signature = iso20::sign(Suite::Ed448, &elements, &Sha2, &key).unwrap();
        assert_eq!(signature.signature_value.value.len(), 114);
        iso20::verify(&signature, &elements, iso20::SUITES, &Sha2, &key.verifying_key()).unwrap();
        assert!(matches!(
            iso20::verify(
                &signature,
                &elements,
                &[Suite::EcdsaSha512],
                &Sha2,
                &key.verifying_key()
            ),
            Err(PncError::UnsupportedAlgorithm(_))
        ));
    }

    /// \[V2G20-2318\], \[V2G20-2476\]: SHAKE256 at 64 bytes.
    #[test]
    fn shake256_matches_the_other_implementation() {
        let digest = Sha2.digest(Suite::Ed448, &fixture("ed448-message.bin")).unwrap();
        assert_eq!(digest, fixture("shake256-64.bin"));
    }

    /// \[V2G20-2508\]–\[V2G20-2510\]: the X448 envelope opens, and the key is
    /// checked against the Ed448 contract key by `scalar · B` on edwards448.
    #[test]
    fn an_x448_envelope_sealed_elsewhere_opens() {
        let oem = AgreementKey::x448(&fixture("x448-oem-private.bin")).unwrap();
        let key = iso20::open(
            Curve::X448,
            &fixture("x448-field.bin"),
            &fixture("x448-dh-public-key.bin"),
            &aad(),
            &fixture("x448-contract-public.bin"),
            &oem,
            &Sha2,
            &AesGcm,
        )
        .unwrap();
        assert_eq!(key, fixture("x448-contract-private.bin"));
        let ephemeral = AgreementKey::x448(&fixture("x448-ephemeral-private.bin")).unwrap();
        let sealed = iso20::seal(
            Curve::X448,
            &key,
            &fixture("x448-oem-public.bin"),
            &IV,
            &aad(),
            &ephemeral,
            &Sha2,
            &AesGcm,
        )
        .unwrap();
        assert_eq!(sealed, fixture("x448-field.bin"));
        assert_eq!(
            iso20::open(
                Curve::X448,
                &fixture("x448-field.bin"),
                &fixture("x448-dh-public-key.bin"),
                &aad(),
                &fixture("ed448-public.bin"),
                &oem,
                &Sha2,
                &AesGcm,
            ),
            Err(PncError::KeyMismatch)
        );
    }
}
