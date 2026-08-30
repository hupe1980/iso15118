//! Building and checking ISO 15118-20 signatures.
//!
//! Unlike -2, -20 defines more than one suite, so the algorithm named in the
//! signature decides which one is in force — and that is a decision an attacker
//! would like to make. [`verify`] therefore takes the suites the caller is
//! willing to accept and refuses anything else, rather than trusting whatever
//! the message asks for.

use alloc::vec::Vec;

use crate::iso20::messages::{
    MeteringConfirmationReq, PnCAReqAuthorizationMode, SignedMeteringData,
};
use crate::session::SessionId;

use crate::iso20::common::{
    CanonicalizationMethod, DigestMethod, Reference, Signature, SignatureMethod, SignatureValue,
    SignedInfo, Transform, Transforms,
};

use super::{
    CANONICAL_EXI, GenChallenge, Hash, PncError, Sign, Signed, Suite, Verify,
    check_canonicalization, check_echo, check_reference, check_session, check_suite,
    check_transforms, pair,
};

/// The suites ISO 15118-20 defines that this crate names.
///
/// -20 also defines an Ed448 suite; its algorithm identifiers and backend are
/// the caller's to supply, because nothing here would be doing any work.
pub const SUITES: &[Suite] = &[Suite::EcdsaSha256, Suite::EcdsaSha512];

/// Builds the `ds:Signature` that covers `elements`, using `suite`.
pub fn sign(
    suite: Suite,
    elements: &[Signed<'_>],
    hash: &impl Hash,
    signer: &impl Sign,
) -> Result<Signature, PncError> {
    let signed_info = build_signed_info(suite, elements, hash);
    let canonical = signed_info.to_xmldsig_fragment()?;
    let value = signer.sign(suite, &canonical)?;
    Ok(Signature { id: None, signed_info, signature_value: SignatureValue { id: None, value } })
}

/// The `SignedInfo` this profile prescribes, ready to be signed.
#[must_use]
pub fn build_signed_info(suite: Suite, elements: &[Signed<'_>], hash: &impl Hash) -> SignedInfo {
    SignedInfo {
        id: None,
        canonicalization_method: CanonicalizationMethod { algorithm: CANONICAL_EXI.into() },
        signature_method: SignatureMethod {
            algorithm: suite.signature_algorithm().into(),
            hmac_output_length: None,
        },
        reference: elements
            .iter()
            .map(|e| Reference {
                id: None,
                r#type: None,
                uri: Some(super::reference_uri(e.id)),
                transforms: Some(Transforms {
                    transform: alloc::vec![Transform { algorithm: CANONICAL_EXI.into() }],
                }),
                digest_method: DigestMethod { algorithm: suite.digest_algorithm().into() },
                digest_value: hash.digest(suite, e.fragment),
            })
            .collect(),
    }
}

/// Checks a `ds:Signature` against the elements it is supposed to cover.
///
/// `accepted` is the caller's policy: only a suite listed there is honoured, so
/// a peer cannot pick the weaker one on the caller's behalf. Pass [`SUITES`] to
/// accept everything -20 defines here.
pub fn verify(
    signature: &Signature,
    elements: &[Signed<'_>],
    accepted: &[Suite],
    hash: &impl Hash,
    verifier: &impl Verify,
) -> Result<(), PncError> {
    let info = &signature.signed_info;
    check_canonicalization(&info.canonicalization_method.algorithm)?;
    let suite = check_suite(
        &info.signature_method.algorithm,
        info.signature_method.hmac_output_length,
        accepted,
    )?;

    for (reference, element) in pair(&info.reference, |r| r.uri.as_deref(), elements)? {
        check_transforms(transform_algorithms(reference.transforms.as_ref()))?;
        check_reference(
            suite,
            &reference.digest_method.algorithm,
            &reference.digest_value,
            element,
            hash,
        )?;
    }

    let canonical = info.to_xmldsig_fragment()?;
    verifier.verify(suite, &canonical, &signature.signature_value.value)
}

/// The algorithms of a `Transforms` list, for [`check_transforms`].
fn transform_algorithms(transforms: Option<&Transforms>) -> Option<impl Iterator<Item = &str>> {
    Some(transforms?.transform.iter().map(|t| t.algorithm.as_str()))
}

/// The `SignedInfo` bytes a signer must sign, for a signature already built.
pub fn canonical_signed_info(signature: &Signature) -> Result<Vec<u8>, PncError> {
    Ok(signature.signed_info.to_xmldsig_fragment()?)
}

// ---------------------------------------------------------------------------
// The authorization exchange
// ---------------------------------------------------------------------------

/// Signs a `PnC_AReqAuthorizationMode` against the station's challenge.
///
/// The -20 shape of `pnc::iso2::sign_authorization`: the challenge arrives in `AuthorizationSetupRes` rather than
/// `PaymentDetailsRes`, and what carries it back — and what the signature
/// covers — is the `PnC_AReqAuthorizationMode` inside `AuthorizationReq`,
/// rather than the request itself. The returned `ds:Signature` goes in the
/// message header.
///
/// `mode.id` is left alone if it is already set, so a caller with an `Id`
/// scheme of its own keeps it.
pub fn sign_authorization(
    suite: Suite,
    mode: &mut PnCAReqAuthorizationMode,
    challenge: &GenChallenge,
    hash: &impl Hash,
    signer: &impl Sign,
) -> Result<Signature, PncError> {
    if mode.id.is_empty() {
        mode.id = super::DEFAULT_ID.into();
    }
    mode.gen_challenge = challenge.as_bytes().to_vec();
    let id = mode.id.clone();
    let fragment = mode.to_fragment()?;
    sign(suite, &[Signed::new(&id, &fragment)], hash, signer)
}

/// Checks a `PnC_AReqAuthorizationMode` against the challenge issued for it.
///
/// Same three obligations as `pnc::iso2::verify_authorization` — the echoed
/// challenge, the coverage, and everything [`verify`] refuses — plus -20's own: `accepted` is the caller's suite policy, so a peer cannot pick
/// the weaker curve on the caller's behalf.
///
/// As there, this says nothing about whether the key in
/// `ContractCertificateChain` is one to trust.
pub fn verify_authorization(
    mode: &PnCAReqAuthorizationMode,
    signature: &Signature,
    challenge: &GenChallenge,
    accepted: &[Suite],
    hash: &impl Hash,
    verifier: &impl Verify,
) -> Result<(), PncError> {
    if !challenge.matches(&mode.gen_challenge) {
        return Err(PncError::ChallengeMismatch);
    }
    if mode.id.is_empty() {
        return Err(PncError::MissingId);
    }
    let fragment = mode.to_fragment()?;
    verify(signature, &[Signed::new(&mode.id, &fragment)], accepted, hash, verifier)
}

// ---------------------------------------------------------------------------
// Metering
// ---------------------------------------------------------------------------

/// Signs a `SignedMeteringData`.
///
/// The -20 counterpart of `pnc::iso2::sign_metering_receipt`, with the
/// direction reversed: here the **station** signs the reading and the vehicle
/// acknowledges it, rather than the other way round. The returned
/// `ds:Signature` goes in the header of the `ChargeLoopRes` that carries the
/// data.
pub fn sign_metering_data(
    suite: Suite,
    data: &mut SignedMeteringData,
    hash: &impl Hash,
    signer: &impl Sign,
) -> Result<Signature, PncError> {
    if data.id.is_empty() {
        data.id = super::DEFAULT_ID.into();
    }
    let id = data.id.clone();
    let fragment = data.to_fragment()?;
    sign(suite, &[Signed::new(&id, &fragment)], hash, signer)
}

/// Checks a `SignedMeteringData` the station issued — the vehicle's side.
///
/// The reading names the session it belongs to, and the signature covers it as
/// an EXI fragment under its `Id`. A vehicle that files a reading without the
/// session check is filing one that may belong to a different charge.
pub fn verify_metering_data(
    data: &SignedMeteringData,
    signature: &Signature,
    session: SessionId,
    accepted: &[Suite],
    hash: &impl Hash,
    verifier: &impl Verify,
) -> Result<(), PncError> {
    check_session(&data.session_id, session)?;
    if data.id.is_empty() {
        return Err(PncError::MissingId);
    }
    let fragment = data.to_fragment()?;
    verify(signature, &[Signed::new(&data.id, &fragment)], accepted, hash, verifier)
}

/// Checks that a `MeteringConfirmationReq` acknowledges the reading that was
/// issued — the station's side.
///
/// -20 splits the exchange the other way from -2: the station signs, and the
/// vehicle's confirmation is an unsigned echo. So the check that matters here
/// is not a signature at all, it is that the echo is exact. A confirmation of a
/// reading nobody issued confirms nothing, and it is the one thing a station
/// can get wrong while every signature in the session verifies.
pub fn verify_metering_confirmation(
    request: &MeteringConfirmationReq,
    issued: &SignedMeteringData,
) -> Result<(), PncError> {
    check_echo(&request.signed_metering_data, issued, "SignedMeteringData")
}
