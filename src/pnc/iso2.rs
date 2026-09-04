//! Building and checking ISO 15118-2 signatures.
//!
//! -2 signs with ECDSA over secp256r1 and SHA-256 only, so there is no suite to
//! negotiate and none to be talked down to.

use alloc::vec::Vec;

use crate::iso2::{
    AuthorizationReq, CanonicalizationMethod, DigestMethod, MeterInfo, MeteringReceiptReq,
    Reference, Signature, SignatureMethod, SignatureValue, SignedInfo, Transform, Transforms,
};
use crate::session::SessionId;

use super::{
    CANONICAL_EXI, GenChallenge, Hash, PncError, Sign, Signed, Suite, Verify,
    check_canonicalization, check_echo, check_forbidden, check_reference, check_session,
    check_suite, check_transforms, pair,
};

/// The only suite ISO 15118-2 defines.
pub const SUITE: Suite = Suite::EcdsaSha256;

/// Builds the `ds:Signature` that covers `elements`.
///
/// Each element is named by its `Id` and given as its EXI fragment — which
/// `to_fragment()` on any generated message type produces. The order of
/// `elements` becomes the order of the references.
///
/// ```
/// use iso15118::pnc::{self, PncError, Signed, Suite};
///
/// # struct Sha;
/// # impl pnc::Hash for Sha {
/// #     fn digest(&self, s: Suite, _: &[u8]) -> Vec<u8> { vec![0; s.digest_len()] }
/// # }
/// # struct Key;
/// # impl pnc::Sign for Key {
/// #     fn sign(&self, _: Suite, _: &[u8]) -> Result<Vec<u8>, PncError> { Ok(vec![7; 64]) }
/// # }
/// // `fragment` is what `element.to_fragment()` returns for the signed element.
/// let fragment = [0x80, 0x01, 0x02];
/// let signature = pnc::iso2::sign(&[Signed::new("ID1", &fragment)], &Sha, &Key)?;
///
/// assert_eq!(signature.signed_info.reference.len(), 1);
/// assert_eq!(signature.signed_info.reference[0].uri.as_deref(), Some("#ID1"));
/// # Ok::<_, PncError>(())
/// ```
pub fn sign(
    elements: &[Signed<'_>],
    hash: &impl Hash,
    signer: &impl Sign,
) -> Result<Signature, PncError> {
    let signed_info = build_signed_info(elements, hash)?;
    let canonical = signed_info.to_xmldsig_fragment()?;
    let value = signer.sign(SUITE, &canonical)?;
    Ok(Signature { id: None, signed_info, signature_value: SignatureValue { id: None, value } })
}

/// The `SignedInfo` this profile prescribes, ready to be signed.
///
/// Exposed separately so a caller with an offline or remote signer can get the
/// exact bytes to sign — [`SignedInfo::to_xmldsig_fragment`] — without this
/// crate holding the key.
///
/// Refuses more than [`MAX_SIGNED_ELEMENTS`] elements \[V2G2-909\]. Refusing
/// on the way out as well as on the way in is the point: a station whose
/// signatures no conforming vehicle accepts finds out here rather than in the
/// field, and the requirement exists to bound the header a peer has to buffer.
///
/// [`MAX_SIGNED_ELEMENTS`]: super::MAX_SIGNED_ELEMENTS
#[allow(clippy::missing_errors_doc, reason = "the one error is named above")]
pub fn build_signed_info(
    elements: &[Signed<'_>],
    hash: &impl Hash,
) -> Result<SignedInfo, PncError> {
    if elements.len() > super::MAX_SIGNED_ELEMENTS {
        return Err(PncError::TooManyReferences { references: elements.len() });
    }
    Ok(SignedInfo {
        id: None,
        canonicalization_method: CanonicalizationMethod { algorithm: CANONICAL_EXI.into() },
        signature_method: SignatureMethod {
            algorithm: SUITE.signature_algorithm().into(),
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
                digest_method: DigestMethod { algorithm: SUITE.digest_algorithm().into() },
                digest_value: hash.digest(SUITE, e.fragment),
            })
            .collect(),
    })
}

/// Checks a `ds:Signature` against the elements it is supposed to cover.
///
/// See the [module documentation](super) for what this refuses and why.
pub fn verify(
    signature: &Signature,
    elements: &[Signed<'_>],
    hash: &impl Hash,
    verifier: &impl Verify,
) -> Result<(), PncError> {
    let info = &signature.signed_info;
    // \[V2G2-771\]: three attributes the schema carries and the profile
    // forbids. Checked first, because a signature that uses one is not a
    // signature to spend a hash on.
    check_forbidden(
        info.id.as_deref(),
        signature.signature_value.id.as_deref(),
        info.reference.iter().map(|r| r.r#type.as_deref()),
    )?;
    check_canonicalization(&info.canonicalization_method.algorithm)?;
    // -2 defines exactly one suite, so the "policy" is a one-element list.
    let suite = check_suite(
        &info.signature_method.algorithm,
        info.signature_method.hmac_output_length,
        &[SUITE],
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
///
/// Useful when re-checking a signature by hand, or when handing the bytes to a
/// remote signing service.
pub fn canonical_signed_info(signature: &Signature) -> Result<Vec<u8>, PncError> {
    Ok(signature.signed_info.to_xmldsig_fragment()?)
}

// ---------------------------------------------------------------------------
// The authorization exchange
// ---------------------------------------------------------------------------

/// Signs a Plug & Charge `AuthorizationReq` against the station's challenge.
///
/// Fills in `request.id` and `request.gen_challenge` and returns the
/// `ds:Signature` to put in the `V2G_Message` header. The two go together: the
/// signature covers the request *including* the echoed challenge, which is what
/// makes it a proof about this session rather than about the contract in
/// general. See [`GenChallenge`].
///
/// ```
/// use iso15118::iso2::AuthorizationReq;
/// use iso15118::pnc::{self, GenChallenge, PncError, Suite};
///
/// # struct Sha;
/// # impl pnc::Hash for Sha {
/// #     fn digest(&self, s: Suite, _: &[u8]) -> Vec<u8> { vec![0; s.digest_len()] }
/// # }
/// # struct Key;
/// # impl pnc::Sign for Key {
/// #     fn sign(&self, _: Suite, _: &[u8]) -> Result<Vec<u8>, PncError> { Ok(vec![7; 64]) }
/// # }
/// // The challenge arrived in `PaymentDetailsRes`.
/// let challenge = GenChallenge::new([0x5A; GenChallenge::LEN]);
///
/// let mut request = AuthorizationReq { id: None, gen_challenge: None };
/// let signature = pnc::iso2::sign_authorization(&mut request, &challenge, &Sha, &Key)?;
///
/// assert_eq!(request.gen_challenge.as_deref(), Some(&challenge.as_bytes()[..]));
/// assert_eq!(signature.signed_info.reference[0].uri.as_deref(), Some("#ID1"));
/// # Ok::<_, PncError>(())
/// ```
pub fn sign_authorization(
    request: &mut AuthorizationReq,
    challenge: &GenChallenge,
    hash: &impl Hash,
    signer: &impl Sign,
) -> Result<Signature, PncError> {
    request.id.get_or_insert_with(|| super::DEFAULT_ID.into());
    request.gen_challenge = Some(challenge.as_bytes().to_vec());
    let id = request.id.clone().unwrap_or_default();
    let fragment = authorization_fragment(request)?;
    sign(&[Signed::new(&id, &fragment)], hash, signer)
}

/// Checks a Plug & Charge `AuthorizationReq` against the challenge that was
/// issued for it.
///
/// Three things have to hold, and dropping any one of them leaves a check that
/// looks like it is doing this job and is not:
///
/// 1. the request echoes **this session's** challenge — otherwise the signature
///    is a valid signature over somebody else's session, which is what a
///    replayed one is;
/// 2. the signature covers the request, as an EXI fragment, under its `Id`;
/// 3. everything [`verify`] refuses is still refused — the algorithm profile,
///    the transforms, the truncation request, the coverage in both directions.
///
/// What it does **not** establish is that `verifier` holds a key anyone should
/// trust. That comes from validating the contract certificate chain in
/// `ContractSignatureCertChain`, which this crate does not do; a signature
/// verified against a key from an unvalidated certificate proves only that
/// whoever sent the certificate also made the signature.
pub fn verify_authorization(
    request: &AuthorizationReq,
    signature: &Signature,
    challenge: &GenChallenge,
    hash: &impl Hash,
    verifier: &impl Verify,
) -> Result<(), PncError> {
    let echoed = request.gen_challenge.as_deref().ok_or(PncError::MissingChallenge)?;
    if !challenge.matches(echoed) {
        return Err(PncError::ChallengeMismatch);
    }
    let id = request.id.as_deref().ok_or(PncError::MissingId)?;
    let fragment = authorization_fragment(request)?;
    verify(signature, &[Signed::new(id, &fragment)], hash, verifier)
}

/// The `AuthorizationReq` as the EXI fragment its signature is computed over.
fn authorization_fragment(request: &AuthorizationReq) -> Result<Vec<u8>, PncError> {
    Ok(request.to_fragment()?)
}

// ---------------------------------------------------------------------------
// The metering receipt
// ---------------------------------------------------------------------------

/// Signs a `MeteringReceiptReq`.
///
/// The vehicle's acknowledgement of a meter reading, which is what the energy
/// on the invoice is evidenced by. Fills in `receipt.id` if the caller has not,
/// and returns the `ds:Signature` for the `V2G_Message` header.
///
/// The receipt must already carry the `SessionID`, the `SAScheduleTupleID` and
/// the `MeterInfo` the station sent — those are what the signature is *over*,
/// and copying the station's own values is the whole content of the message.
pub fn sign_metering_receipt(
    receipt: &mut MeteringReceiptReq,
    hash: &impl Hash,
    signer: &impl Sign,
) -> Result<Signature, PncError> {
    receipt.id.get_or_insert_with(|| super::DEFAULT_ID.into());
    let id = receipt.id.clone().unwrap_or_default();
    let fragment = receipt.to_fragment()?;
    sign(&[Signed::new(&id, &fragment)], hash, signer)
}

/// Checks a `MeteringReceiptReq` against the reading the station actually
/// metered.
///
/// The signature says the contract's key signed *a* meter reading. On its own
/// that is worth nothing: the vehicle chose the bytes. What makes a receipt
/// evidence is that the reading inside it is the one this station issued, in
/// this session — so all three are checked together and there is no way to ask
/// for only the signature:
///
/// 1. the receipt names **this** session;
/// 2. its `MeterInfo` is byte-for-byte the one the station sent in
///    `ChargingStatusRes` or `CurrentDemandRes`;
/// 3. the signature covers the receipt, as an EXI fragment, under its `Id`.
///
/// Skipping (2) is the billing analogue of skipping the `GenChallenge` check:
/// the vehicle signs whatever reading it likes and the station files it as
/// proof. As with [`verify_authorization`], this says nothing about whether the
/// key is one to trust.
pub fn verify_metering_receipt(
    receipt: &MeteringReceiptReq,
    signature: &Signature,
    issued: &MeterInfo,
    session: SessionId,
    hash: &impl Hash,
    verifier: &impl Verify,
) -> Result<(), PncError> {
    check_session(&receipt.session_id, session)?;
    check_echo(&receipt.meter_info, issued, "MeterInfo")?;
    let id = receipt.id.as_deref().ok_or(PncError::MissingId)?;
    let fragment = receipt.to_fragment()?;
    verify(signature, &[Signed::new(id, &fragment)], hash, verifier)
}
