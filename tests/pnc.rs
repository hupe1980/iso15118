//! The ISO 15118 XML-signature profile: what it builds, and what it refuses.
//!
//! The crypto here is deliberately fake — a "hash" that is the input's length
//! repeated, a "signature" that is the digest of what was signed. That is
//! enough to exercise every decision this crate actually makes, and it keeps
//! the test about the profile rather than about a curve.
//!
//! The refusals are the point. An XML signature is only as trustworthy as the
//! things it is *not* allowed to say, and every check below corresponds to a
//! published way of getting a verifier to trust bytes nobody signed.

#![cfg(all(feature = "pnc", feature = "iso2"))]

use iso15118::iso2::{Signature, Transform, Transforms};
use iso15118::pnc::{self, Hash, PncError, Sign, Signed, Suite, Verify};

/// A stand-in digest: distinct for distinct inputs, and the right length.
struct Sha;

impl Hash for Sha {
    fn digest(&self, suite: Suite, data: &[u8]) -> Vec<u8> {
        let mut acc: u64 = 0xcbf2_9ce4_8422_2325;
        for &b in data {
            acc ^= u64::from(b);
            acc = acc.wrapping_mul(0x0000_0100_0000_01B3);
        }
        acc.to_be_bytes().iter().copied().cycle().take(suite.digest_len()).collect()
    }
}

/// A stand-in key: the "signature" is the digest of the signed bytes, so it is
/// bound to them exactly the way a real one is.
struct Key;

impl Sign for Key {
    fn sign(&self, suite: Suite, data: &[u8]) -> Result<Vec<u8>, PncError> {
        Ok(Sha.digest(suite, data))
    }
}

impl Verify for Key {
    fn verify(&self, suite: Suite, data: &[u8], signature: &[u8]) -> Result<(), PncError> {
        if Sha.digest(suite, data) == signature { Ok(()) } else { Err(PncError::BadSignature) }
    }
}

const AUTHORIZATION: &[u8] = &[0x80, 0x01, 0x02, 0x03];
const SALES_TARIFF: &[u8] = &[0x80, 0xAA, 0xBB];

fn one() -> [Signed<'static>; 1] {
    [Signed::new("ID1", AUTHORIZATION)]
}

fn two() -> [Signed<'static>; 2] {
    [Signed::new("ID1", AUTHORIZATION), Signed::new("ID2", SALES_TARIFF)]
}

fn signed(elements: &[Signed<'_>]) -> Signature {
    pnc::iso2::sign(elements, &Sha, &Key).expect("sign")
}

#[test]
fn a_signature_this_crate_builds_is_one_it_accepts() {
    let signature = signed(&two());
    pnc::iso2::verify(&signature, &two(), &Sha, &Key).expect("verify");
}

#[test]
fn the_signature_has_the_shape_the_profile_prescribes() {
    let signature = signed(&one());
    let info = &signature.signed_info;
    assert_eq!(info.canonicalization_method.algorithm, pnc::CANONICAL_EXI);
    assert_eq!(info.signature_method.algorithm, Suite::EcdsaSha256.signature_algorithm());
    assert_eq!(info.reference.len(), 1);
    let reference = &info.reference[0];
    assert_eq!(reference.uri.as_deref(), Some("#ID1"));
    assert_eq!(reference.digest_method.algorithm, Suite::EcdsaSha256.digest_algorithm());
    assert_eq!(reference.digest_value.len(), 32);
    let transforms = reference.transforms.as_ref().expect("Transforms");
    assert_eq!(transforms.transform.len(), 1);
    assert_eq!(transforms.transform[0].algorithm, pnc::CANONICAL_EXI);
}

/// The signature is over the *canonical `SignedInfo` fragment*, not over the
/// message and not over a document encoding of `SignedInfo`.
#[test]
fn the_signed_bytes_are_the_signed_info_fragment() {
    let signature = signed(&one());
    let canonical = pnc::iso2::canonical_signed_info(&signature).unwrap();
    assert_eq!(signature.signature_value.value, Sha.digest(Suite::EcdsaSha256, &canonical));
    assert_eq!(canonical[0], 0x80, "an EXI stream, header and all");
}

#[test]
fn a_tampered_element_fails_its_digest() {
    let signature = signed(&one());
    let tampered = [0x80, 0x01, 0x02, 0x04];
    let err =
        pnc::iso2::verify(&signature, &[Signed::new("ID1", &tampered)], &Sha, &Key).unwrap_err();
    assert_eq!(err, PncError::DigestMismatch { id: "ID1".into() });
}

#[test]
fn a_tampered_signature_value_fails() {
    let mut signature = signed(&one());
    signature.signature_value.value[0] ^= 0xFF;
    assert_eq!(
        pnc::iso2::verify(&signature, &one(), &Sha, &Key).unwrap_err(),
        PncError::BadSignature
    );
}

/// Re-pointing a reference at a different digest also changes `SignedInfo`,
/// which the signature covers — this is the check that makes the digests
/// meaningful rather than advisory.
#[test]
fn editing_a_digest_breaks_the_outer_signature() {
    let mut signature = signed(&one());
    signature.signed_info.reference[0].digest_value = Sha.digest(Suite::EcdsaSha256, &[0xFF]);
    let err =
        pnc::iso2::verify(&signature, &[Signed::new("ID1", &[0xFF])], &Sha, &Key).unwrap_err();
    assert_eq!(err, PncError::BadSignature, "the digests now agree, the signature does not");
}

// --- the refusals --------------------------------------------------------

/// Signature wrapping: the signature covers one element, the caller is about to
/// trust two. Verifying only what is referenced would pass.
#[test]
fn a_signature_that_covers_less_than_is_being_checked_is_refused() {
    let signature = signed(&one());
    let err = pnc::iso2::verify(&signature, &two(), &Sha, &Key).unwrap_err();
    assert_eq!(err, PncError::ReferenceMismatch { references: 1, elements: 2 });
}

/// And the other direction: a reference to something the caller never supplied
/// is a claim that cannot be checked, so it is not accepted either.
#[test]
fn a_signature_that_covers_more_than_is_being_checked_is_refused() {
    let signature = signed(&two());
    let err = pnc::iso2::verify(&signature, &one(), &Sha, &Key).unwrap_err();
    assert_eq!(err, PncError::ReferenceMismatch { references: 2, elements: 1 });
}

/// Two references naming the same element leave the other element uncovered
/// while keeping the counts equal.
#[test]
fn duplicate_references_do_not_cover_a_missing_element() {
    let mut signature = signed(&two());
    signature.signed_info.reference[1].uri = Some("#ID1".into());
    let err = pnc::iso2::verify(&signature, &two(), &Sha, &Key).unwrap_err();
    assert_eq!(err, PncError::UnknownReference);
}

#[test]
fn a_reference_without_a_same_document_uri_is_refused() {
    let mut signature = signed(&one());
    signature.signed_info.reference[0].uri = Some("http://example.invalid/x".into());
    assert_eq!(
        pnc::iso2::verify(&signature, &one(), &Sha, &Key).unwrap_err(),
        PncError::MissingUri
    );

    let mut signature = signed(&one());
    signature.signed_info.reference[0].uri = None;
    assert_eq!(
        pnc::iso2::verify(&signature, &one(), &Sha, &Key).unwrap_err(),
        PncError::MissingUri
    );
}

#[test]
fn a_canonicalization_outside_the_profile_is_refused() {
    let mut signature = signed(&one());
    signature.signed_info.canonicalization_method.algorithm =
        "http://www.w3.org/2001/10/xml-exc-c14n#".into();
    assert!(matches!(
        pnc::iso2::verify(&signature, &one(), &Sha, &Key).unwrap_err(),
        PncError::BadCanonicalization(_)
    ));
}

#[test]
fn a_signature_algorithm_outside_the_profile_is_refused() {
    let mut signature = signed(&one());
    signature.signed_info.signature_method.algorithm =
        "http://www.w3.org/2000/09/xmldsig#hmac-sha1".into();
    assert!(matches!(
        pnc::iso2::verify(&signature, &one(), &Sha, &Key).unwrap_err(),
        PncError::UnsupportedAlgorithm(_)
    ));
}

/// `HMACOutputLength` is the field behind CVE-2009-0217: an `XMLDSig` verifier
/// that honoured the truncation a signer asked for would accept a signature
/// over one byte of MAC. ISO 15118 has no HMAC suite at all, so a signature
/// that names the field is outside the profile and is refused rather than
/// quietly ignored.
#[test]
fn a_signature_that_asks_for_mac_truncation_is_refused() {
    let mut signature = signed(&one());
    signature.signed_info.signature_method.hmac_output_length = Some(8);
    assert!(matches!(
        pnc::iso2::verify(&signature, &one(), &Sha, &Key).unwrap_err(),
        PncError::UnsupportedAlgorithm(_)
    ));
}

#[test]
fn a_digest_algorithm_that_does_not_match_the_suite_is_refused() {
    let mut signature = signed(&one());
    signature.signed_info.reference[0].digest_method.algorithm =
        "http://www.w3.org/2000/09/xmldsig#sha1".into();
    assert!(matches!(
        pnc::iso2::verify(&signature, &one(), &Sha, &Key).unwrap_err(),
        PncError::UnsupportedAlgorithm(_)
    ));
}

/// A transform is a program that runs over the signed bytes before they are
/// digested. Anything but the one the profile names, or more than one of it, is
/// the signer choosing what was signed.
#[test]
fn an_unexpected_transform_is_refused() {
    let extra = Transform { algorithm: "http://www.w3.org/TR/1999/REC-xpath-19991116".into() };

    let mut signature = signed(&one());
    signature.signed_info.reference[0].transforms =
        Some(Transforms { transform: vec![extra.clone()] });
    assert!(matches!(
        pnc::iso2::verify(&signature, &one(), &Sha, &Key).unwrap_err(),
        PncError::BadCanonicalization(_)
    ));

    let mut signature = signed(&one());
    let transforms = signature.signed_info.reference[0].transforms.as_mut().unwrap();
    transforms.transform.push(extra);
    assert_eq!(
        pnc::iso2::verify(&signature, &one(), &Sha, &Key).unwrap_err(),
        PncError::BadTransforms
    );

    let mut signature = signed(&one());
    signature.signed_info.reference[0].transforms = None;
    assert_eq!(
        pnc::iso2::verify(&signature, &one(), &Sha, &Key).unwrap_err(),
        PncError::BadTransforms
    );
}

/// The signature travels inside the message header, so it has to survive a
/// round trip through the codec unchanged — including the `Vec<u8>` digest and
/// signature values, which are `hexBinary` on the wire.
#[test]
fn a_signature_survives_the_wire() {
    use iso15118::exi::ExiDocument;
    use iso15118::iso2::{Body, BodyChoice, MessageHeader, SessionSetupReq, V2GMessage};

    let signature = signed(&two());
    let message = V2GMessage {
        header: MessageHeader {
            session_id: vec![1, 2, 3, 4, 5, 6, 7, 8],
            notification: None,
            signature: Some(signature.clone()),
        },
        body: Body {
            choice: Some(BodyChoice::SessionSetupReq(SessionSetupReq { evcc_id: vec![9; 6] })),
        },
    };
    let bytes = message.to_vec().unwrap();
    let back = V2GMessage::from_bytes(&bytes).unwrap();
    assert_eq!(back.header.signature.as_ref(), Some(&signature));
    pnc::iso2::verify(back.header.signature.as_ref().unwrap(), &two(), &Sha, &Key).unwrap();
}

#[cfg(feature = "iso20-common")]
mod iso20 {
    use super::{Key, Sha, one};
    use iso15118::pnc::{self, PncError, Suite};

    /// -20 has more than one suite, so which one is in force is stated in the
    /// message — and an attacker would like to state it. The caller says which
    /// ones it will accept.
    #[test]
    fn a_suite_the_caller_did_not_accept_is_refused() {
        let strong = pnc::iso20::sign(Suite::EcdsaSha512, &one(), &Sha, &Key).unwrap();
        pnc::iso20::verify(&strong, &one(), pnc::iso20::SUITES, &Sha, &Key).unwrap();

        let err =
            pnc::iso20::verify(&strong, &one(), &[Suite::EcdsaSha256], &Sha, &Key).unwrap_err();
        assert!(
            matches!(err, PncError::UnsupportedAlgorithm(_)),
            "a peer must not choose the caller's security level"
        );
    }

    #[test]
    fn the_stronger_suite_uses_the_longer_digest() {
        let strong = pnc::iso20::sign(Suite::EcdsaSha512, &one(), &Sha, &Key).unwrap();
        assert_eq!(strong.signed_info.reference[0].digest_value.len(), 64);
        let weak = pnc::iso20::sign(Suite::EcdsaSha256, &one(), &Sha, &Key).unwrap();
        assert_eq!(weak.signed_info.reference[0].digest_value.len(), 32);
    }
}

// ---------------------------------------------------------------------------
// The authorization exchange: binding a signature to a session
// ---------------------------------------------------------------------------

use iso15118::iso2::AuthorizationReq;
use iso15118::pnc::GenChallenge;

const ISSUED: GenChallenge = GenChallenge::new([0x5A; GenChallenge::LEN]);
const OTHER: GenChallenge = GenChallenge::new([0xA5; GenChallenge::LEN]);

/// The vehicle's half: echo the challenge, sign the request that carries it.
fn authorize(challenge: &GenChallenge) -> (AuthorizationReq, Signature) {
    let mut request = AuthorizationReq { id: None, gen_challenge: None };
    let signature =
        pnc::iso2::sign_authorization(&mut request, challenge, &Sha, &Key).expect("sign");
    (request, signature)
}

#[test]
fn an_authorization_this_crate_signs_is_one_it_accepts() {
    let (request, signature) = authorize(&ISSUED);
    assert_eq!(request.gen_challenge.as_deref(), Some(&ISSUED.as_bytes()[..]));
    assert_eq!(request.id.as_deref(), Some("ID1"));
    pnc::iso2::verify_authorization(&request, &signature, &ISSUED, &Sha, &Key).expect("verify");
}

/// The whole point of the challenge. A signature captured from one session is a
/// perfectly valid signature — over a request that names a different nonce, and
/// the station that issued *this* one must not accept it.
#[test]
fn a_signature_from_another_session_does_not_authorize_this_one() {
    let (request, signature) = authorize(&OTHER);
    // On its own the signature is impeccable...
    let fragment = request.to_fragment().expect("fragment");
    let id = request.id.clone().expect("id");
    pnc::iso2::verify(&signature, &[Signed::new(&id, &fragment)], &Sha, &Key)
        .expect("the signature itself is valid");
    // ...and it still does not authorize this session.
    assert_eq!(
        pnc::iso2::verify_authorization(&request, &signature, &ISSUED, &Sha, &Key),
        Err(PncError::ChallengeMismatch)
    );
}

/// Editing the echoed challenge to the right one does not help either: the
/// signature covers the request the challenge is *in*.
#[test]
fn the_challenge_cannot_be_swapped_into_a_signature_made_for_another() {
    let (mut request, signature) = authorize(&OTHER);
    request.gen_challenge = Some(ISSUED.as_bytes().to_vec());
    assert!(matches!(
        pnc::iso2::verify_authorization(&request, &signature, &ISSUED, &Sha, &Key),
        Err(PncError::DigestMismatch { .. })
    ));
}

/// -2 makes `GenChallenge` optional in the schema because the same message
/// carries an EIM authorization, which has nothing to prove. Under a contract
/// its absence is not "no challenge to check".
#[test]
fn a_contract_authorization_without_a_challenge_is_refused() {
    let (mut request, signature) = authorize(&ISSUED);
    request.gen_challenge = None;
    assert_eq!(
        pnc::iso2::verify_authorization(&request, &signature, &ISSUED, &Sha, &Key),
        Err(PncError::MissingChallenge)
    );
}

/// A signature references its element by `Id`. Without one there is nothing for
/// the reference to point at, whatever the signature says.
#[test]
fn a_signed_element_with_no_id_is_refused() {
    let (mut request, signature) = authorize(&ISSUED);
    request.id = None;
    assert_eq!(
        pnc::iso2::verify_authorization(&request, &signature, &ISSUED, &Sha, &Key),
        Err(PncError::MissingId)
    );
}

#[cfg(feature = "iso20-common")]
mod iso20_authorization {
    use super::{ISSUED, Key, OTHER, Sha};
    use iso15118::iso20::messages::{
        ContractCertificateChain, PnCAReqAuthorizationMode, SubCertificates,
    };
    use iso15118::pnc::{self, PncError, Suite};

    fn mode() -> PnCAReqAuthorizationMode {
        PnCAReqAuthorizationMode {
            id: String::new(),
            gen_challenge: Vec::new(),
            contract_certificate_chain: ContractCertificateChain {
                certificate: vec![0x30, 0x82, 0x01],
                sub_certificates: SubCertificates { certificate: vec![vec![0x30, 0x82, 0x02]] },
            },
        }
    }

    #[test]
    fn the_same_binding_holds_in_dash_20() {
        let mut m = mode();
        let signature =
            pnc::iso20::sign_authorization(Suite::EcdsaSha512, &mut m, &ISSUED, &Sha, &Key)
                .expect("sign");
        assert_eq!(m.gen_challenge, ISSUED.as_bytes());
        pnc::iso20::verify_authorization(&m, &signature, &ISSUED, pnc::iso20::SUITES, &Sha, &Key)
            .expect("verify");

        assert_eq!(
            pnc::iso20::verify_authorization(
                &m,
                &signature,
                &OTHER,
                pnc::iso20::SUITES,
                &Sha,
                &Key
            ),
            Err(PncError::ChallengeMismatch)
        );
    }

    /// The suite policy still applies to an authorization: a station that only
    /// accepts the 521-bit curve does not silently take the 256-bit one.
    #[test]
    fn the_suite_policy_still_applies_to_an_authorization() {
        let mut m = mode();
        let signature =
            pnc::iso20::sign_authorization(Suite::EcdsaSha256, &mut m, &ISSUED, &Sha, &Key)
                .expect("sign");
        assert!(matches!(
            pnc::iso20::verify_authorization(
                &m,
                &signature,
                &ISSUED,
                &[Suite::EcdsaSha512],
                &Sha,
                &Key
            ),
            Err(PncError::UnsupportedAlgorithm(_))
        ));
    }
}

// ---------------------------------------------------------------------------
// The metering exchange: binding a signature to the reading that was issued
// ---------------------------------------------------------------------------

use iso15118::iso2::{MeterInfo, MeteringReceiptReq};
use iso15118::session::SessionId;

const SESSION: SessionId = SessionId::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);

/// What the station metered and sent in `ChargingStatusRes`.
fn issued_reading() -> MeterInfo {
    MeterInfo {
        meter_id: "DE*ABC*M01".into(),
        meter_reading: Some(42_195),
        sig_meter_reading: None,
        meter_status: Some(0),
        t_meter: Some(1_725_456_343),
    }
}

/// The vehicle's half: copy the station's values, sign the receipt.
fn receipt_for(reading: &MeterInfo, session: SessionId) -> (MeteringReceiptReq, Signature) {
    let mut receipt = MeteringReceiptReq {
        id: None,
        session_id: session.as_bytes().to_vec(),
        sa_schedule_tuple_id: Some(1),
        meter_info: reading.clone(),
    };
    let signature =
        pnc::iso2::sign_metering_receipt(&mut receipt, &Sha, &Key).expect("sign receipt");
    (receipt, signature)
}

#[test]
fn a_receipt_this_crate_signs_is_one_it_accepts() {
    let issued = issued_reading();
    let (receipt, signature) = receipt_for(&issued, SESSION);
    assert_eq!(receipt.id.as_deref(), Some("ID1"));
    pnc::iso2::verify_metering_receipt(&receipt, &signature, &issued, SESSION, &Sha, &Key)
        .expect("verify");
}

/// The point of the receipt. A vehicle that signs a reading of its own choosing
/// produces a signature that verifies perfectly and evidences nothing — the
/// station has to check the reading is the one it metered.
#[test]
fn a_vehicle_cannot_sign_a_meter_reading_of_its_own() {
    let issued = issued_reading();
    let mut invented = issued.clone();
    invented.meter_reading = Some(1); // a rather cheaper charge

    let (receipt, signature) = receipt_for(&invented, SESSION);
    // The signature itself is impeccable...
    let fragment = receipt.to_fragment().expect("fragment");
    pnc::iso2::verify(&signature, &[Signed::new("ID1", &fragment)], &Sha, &Key)
        .expect("the signature is valid");
    // ...and it evidences nothing about what this station metered.
    assert_eq!(
        pnc::iso2::verify_metering_receipt(&receipt, &signature, &issued, SESSION, &Sha, &Key),
        Err(PncError::NotAsIssued { field: "MeterInfo" })
    );
}

/// ...and a receipt from another session does not settle this one, however
/// genuine the reading inside it is.
#[test]
fn a_receipt_from_another_session_does_not_settle_this_one() {
    let issued = issued_reading();
    let other = SessionId::new([0xAA; 8]);
    let (receipt, signature) = receipt_for(&issued, other);
    assert_eq!(
        pnc::iso2::verify_metering_receipt(&receipt, &signature, &issued, SESSION, &Sha, &Key),
        Err(PncError::SessionMismatch)
    );
}

#[cfg(feature = "iso20-common")]
mod iso20_metering {
    use super::{Key, Sha};
    use iso15118::iso20::common::{MessageHeader, MeterInfo};
    use iso15118::iso20::messages::{
        DynamicSMDTControlMode, MeteringConfirmationReq, SignedMeteringData,
        SignedMeteringDataChoice,
    };
    use iso15118::pnc::{self, PncError, Suite};
    use iso15118::session::SessionId;

    const SESSION: SessionId = SessionId::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);

    fn reading(wh: u64) -> SignedMeteringData {
        SignedMeteringData {
            id: String::new(),
            session_id: SESSION.as_bytes().to_vec(),
            meter_info: MeterInfo {
                meter_id: "DE*ABC*M01".into(),
                charged_energy_reading_wh: wh,
                bpt_discharged_energy_reading_wh: None,
                capacitive_energy_reading_va_rh: None,
                bpt_inductive_energy_reading_va_rh: None,
                meter_signature: None,
                meter_status: None,
                meter_timestamp: Some(1_725_456_343),
            },
            receipt: None,
            choice: SignedMeteringDataChoice::DynamicSMDTControlMode(DynamicSMDTControlMode),
        }
    }

    /// -20 reverses the direction: the station signs the reading and the
    /// vehicle confirms it. Both halves still have to be checked.
    #[test]
    fn the_station_signs_the_reading_and_the_vehicle_checks_the_session() {
        let mut data = reading(42_195);
        let signature = pnc::iso20::sign_metering_data(Suite::EcdsaSha256, &mut data, &Sha, &Key)
            .expect("sign");
        pnc::iso20::verify_metering_data(
            &data,
            &signature,
            SESSION,
            pnc::iso20::SUITES,
            &Sha,
            &Key,
        )
        .expect("verify");

        assert_eq!(
            pnc::iso20::verify_metering_data(
                &data,
                &signature,
                SessionId::new([0xAA; 8]),
                pnc::iso20::SUITES,
                &Sha,
                &Key
            ),
            Err(PncError::SessionMismatch)
        );
    }

    /// The vehicle's confirmation carries no signature of its own, so the only
    /// thing that makes it mean anything is that the echo is exact.
    #[test]
    fn a_confirmation_of_a_reading_nobody_issued_confirms_nothing() {
        let issued = reading(42_195);
        let confirm = |data: SignedMeteringData| MeteringConfirmationReq {
            header: MessageHeader {
                session_id: SESSION.as_bytes().to_vec(),
                time_stamp: 1_725_456_343,
                signature: None,
            },
            signed_metering_data: data,
        };

        pnc::iso20::verify_metering_confirmation(&confirm(issued.clone()), &issued)
            .expect("the honest echo");
        assert_eq!(
            pnc::iso20::verify_metering_confirmation(&confirm(reading(1)), &issued),
            Err(PncError::NotAsIssued { field: "SignedMeteringData" })
        );
    }
}

// ---------------------------------------------------------------------------
// What a `ds:Signature` is not allowed to carry
// ---------------------------------------------------------------------------

/// `SignatureType` has four children; ISO 15118 uses two. `KeyInfo` and
/// `Object` are in the *grammar* — they have to be, or every event code after
/// them shifts and nothing decodes — but they have no Rust form, and the
/// question is what the decoder does when a peer sends one.
///
/// Skipping it would be the dangerous answer. `KeyInfo` is where `XMLDSig` puts
/// key material, and a verifier that reads a key out of the signature it is
/// checking is verifying the signature against itself. ISO 15118 takes the key
/// from the contract certificate chain in the message body and nowhere else, so
/// a `KeyInfo` here is not something to ignore — it is a message this profile
/// does not describe.
#[test]
fn a_signature_carrying_key_info_is_refused_rather_than_skipped() {
    use iso15118::exi::seq::{SeqWriter, Shape};
    use iso15118::exi::{Decoder, Encoder, ExiError, Header};
    use iso15118::iso2::{
        CanonicalizationMethod, DigestMethod, Reference, Signature, SignatureMethod,
        SignatureValue, SignedInfo, Transform, Transforms,
    };

    // The same arithmetic `Signature` is generated with: Id?, SignedInfo,
    // SignatureValue, KeyInfo?, Object*. Restated here so the test writes the
    // event code the generated decoder will read.
    const SIGNATURE: Shape = Shape {
        prod_before: &[0, 1, 2, 3, 4, 5],
        width: &[2, 1, 1, 2, 2, 1],
        repeat_width: &[0, 0, 0, 0, 2],
        min: &[0, 1, 1, 0, 0],
        max: &[1, 1, 1, 1, u32::MAX],
    };

    let info = SignedInfo {
        id: None,
        canonicalization_method: CanonicalizationMethod { algorithm: pnc::CANONICAL_EXI.into() },
        signature_method: SignatureMethod {
            algorithm: Suite::EcdsaSha256.signature_algorithm().into(),
            hmac_output_length: None,
        },
        reference: vec![Reference {
            id: None,
            r#type: None,
            uri: Some("#ID1".into()),
            transforms: Some(Transforms {
                transform: vec![Transform { algorithm: pnc::CANONICAL_EXI.into() }],
            }),
            digest_method: DigestMethod { algorithm: Suite::EcdsaSha256.digest_algorithm().into() },
            digest_value: vec![0u8; 32],
        }],
    };
    let value = SignatureValue { id: None, value: vec![7u8; 64] };

    let mut buf = [0u8; 2048];
    let mut e = Encoder::new(&mut buf);
    e.write_header(Header::ISO15118).unwrap();
    let mut w = SeqWriter::new(SIGNATURE);
    w.start(&mut e, 1, 0).unwrap(); // SE(SignedInfo)
    info.encode_body(&mut e).unwrap();
    w.finish(1, 1);
    w.start(&mut e, 2, 0).unwrap(); // SE(SignatureValue)
    value.encode_body(&mut e).unwrap();
    w.finish(2, 1);
    w.start(&mut e, 3, 0).unwrap(); // SE(KeyInfo) — legal in the grammar
    let len = e.finish().unwrap();

    // Sanity: without the trailing `KeyInfo` the very same bytes decode, so the
    // refusal below is about that element and not about a malformed stream.
    let mut ok = [0u8; 2048];
    let mut e = Encoder::new(&mut ok);
    e.write_header(Header::ISO15118).unwrap();
    let mut w = SeqWriter::new(SIGNATURE);
    w.start(&mut e, 1, 0).unwrap();
    info.encode_body(&mut e).unwrap();
    w.finish(1, 1);
    w.start(&mut e, 2, 0).unwrap();
    value.encode_body(&mut e).unwrap();
    w.finish(2, 1);
    w.end(&mut e).unwrap();
    let ok_len = e.finish().unwrap();
    let mut d = Decoder::new(&ok[..ok_len]);
    d.read_header().unwrap();
    Signature::decode_body(&mut d).expect("the same signature without KeyInfo decodes");

    let mut d = Decoder::new(&buf[..len]);
    d.read_header().unwrap();
    assert_eq!(
        Signature::decode_body(&mut d),
        Err(ExiError::UnsupportedOption),
        "a KeyInfo must be refused, never skipped"
    );
}
