//! Plug & Charge: the ISO 15118 profile of XML Signature, over EXI.
//!
//! A V2G signature is an XML signature in shape only. Everything that makes
//! `XMLDSig` hard — canonicalisation choices, arbitrary transforms, `KeyInfo`,
//! enveloped signatures, `Object` — is nailed shut by ISO 15118, and what is
//! left is small enough to state exactly:
//!
//! ```text
//! SignedInfo
//!   CanonicalizationMethod  Algorithm = http://www.w3.org/TR/canonical-exi/
//!   SignatureMethod         Algorithm = ...#ecdsa-sha256   (or ecdsa-sha512)
//!   Reference URI="#<Id>"                  one per signed element
//!     Transforms/Transform  Algorithm = http://www.w3.org/TR/canonical-exi/
//!     DigestMethod          Algorithm = ...#sha256         (or sha512)
//!     DigestValue           = H(EXI fragment of that element)
//! SignatureValue            = ECDSA(H(EXI fragment of SignedInfo))
//! ```
//!
//! Two details decide whether anyone else can verify what this produces, and
//! both are invisible from the XML:
//!
//! 1. The bytes that get digested are the element as an **EXI fragment**, not
//!    as an EXI document. The two differ from their very first event code,
//!    because a fragment is indexed by every element qname the schema
//!    *declares* and a document only by its global elements.
//! 2. `SignedInfo` itself is encoded against the **xmldsig schema alone** —
//!    ISO 15118-2 Annex J — and not against the V2G schema set that imports it.
//!    `OpenV2G` originally did the latter and changed for interoperability.
//!
//! Both are pinned here by vectors from the EXI reference implementation, in
//! `tests/iso2_messages.rs` and `tests/reference_messages.rs`.
//!
//! # Crypto is yours
//!
//! This module computes *what* to hash and *what* to sign, and checks the
//! result. It does not contain a hash or a curve: [`Hash`], [`Sign`] and
//! [`Verify`] are one-method traits, so the same code runs on `RustCrypto`, on a
//! TPM, or on a secure element — which is what ISO 15118-20 anticipates for
//! contract keys, and what an ECU with a hardware key store needs.
//!
//! For the case where the key really is just bytes in memory — a charging
//! station on a general-purpose CPU, or a test — the `pnc-rustcrypto` feature
//! ships [`rustcrypto`], which is those three traits over `sha2`, `p256` and
//! `p521` and nothing else.
//!
//! # Verification is the security boundary
//!
//! [`iso2::verify`] and [`iso20::verify`] refuse a signature that:
//!
//! * names a canonicalisation, transform or digest algorithm outside the
//!   profile — a signature is only as strong as the weakest algorithm it is
//!   allowed to name;
//! * asks for MAC truncation through `HMACOutputLength`, the field behind
//!   CVE-2009-0217. ISO 15118 has no HMAC suite at all, so a signature naming it
//!   is not one this profile describes;
//! * covers an element the caller did not supply, or leaves one the caller did
//!   supply uncovered. Both directions matter: the first is a signature over
//!   something you are not checking, the second is content nobody signed. XML
//!   signature wrapping is exactly this, and it is why the check is on both
//!   sides rather than "every reference I recognise verifies".
//!
//! Digests are compared without an early return, so a mismatch does not leak
//! where it first differed.
//!
//! # ...and a valid signature is not an authorization
//!
//! All of that establishes that *the contract's key signed these bytes*. It
//! does not establish that the bytes belong to the session in front of you: a
//! signature captured from a charge last week is a perfectly valid signature.
//! What separates the two is the `GenChallenge` the station issues and the
//! vehicle signs back, and the check that closes the loop is the one that gets
//! left out — the signature is verified, the echoed nonce is not looked at, and
//! the binding it exists to provide is not there.
//!
//! So `iso2::verify_authorization` and `iso20::verify_authorization` do both
//! halves in one call and offer no way to ask for only the first. See
//! [`GenChallenge`].
//!
//! It still does not establish that the *key* is one to trust. That is
//! certificate-chain validation, and it is [`pki`] — a separate question with a
//! separate answer, because the two are independent: the challenge binding says
//! *which session* a signature is about, and the chain says *whose key* made
//! it. A crate that did one and implied the other would be the more dangerous
//! kind of half-done.
//!
//! And [`envelope`] is the third question, which only comes up once: when a
//! contract certificate is *delivered*, its private key comes with it, encrypted
//! under an ECDH secret. That is the one place in ISO 15118 where a secret
//! crosses the wire.
//!
//! What none of them establishes is that the vehicle is plugged into this
//! station rather than into a relay, which the standard does not let anyone
//! establish.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::exi::ExiError;

mod challenge;
pub use challenge::GenChallenge;

#[cfg(feature = "iso2")]
#[cfg_attr(docsrs, doc(cfg(feature = "iso2")))]
pub mod iso2;

#[cfg(feature = "iso20-common")]
#[cfg_attr(docsrs, doc(cfg(feature = "iso20-common")))]
pub mod iso20;

pub mod envelope;
pub mod pki;

#[cfg(feature = "pnc-rustcrypto")]
#[cfg_attr(docsrs, doc(cfg(feature = "pnc-rustcrypto")))]
pub mod rustcrypto;

/// The only canonicalisation and transform ISO 15118 permits.
pub const CANONICAL_EXI: &str = "http://www.w3.org/TR/canonical-exi/";

/// The `Id` this crate gives a signed element when the caller has not chosen
/// one.
///
/// Any `xs:ID` would do — a `Reference/@URI` points at whatever is there — but
/// every implementation in the field uses this one for a message's single
/// signed element, and a value nobody has to think about is a value nobody gets
/// wrong. Every `sign_*` helper here fills it in when the field is empty and
/// leaves a caller's own scheme alone when it is not.
pub const DEFAULT_ID: &str = "ID1";

/// The signature suites ISO 15118 defines.
///
/// -2 has one; -20 adds the 521-bit curve for its higher security level and an
/// Ed448 suite, which is not here because its algorithm identifiers are the
/// caller's to supply along with the backend that implements them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum Suite {
    /// ECDSA over secp256r1 with SHA-256 — ISO 15118-2, and -20's baseline.
    EcdsaSha256,
    /// ECDSA over secp521r1 with SHA-512 — ISO 15118-20's higher level.
    EcdsaSha512,
}

impl Suite {
    /// The `SignatureMethod/@Algorithm` URI.
    #[must_use]
    pub const fn signature_algorithm(self) -> &'static str {
        match self {
            Self::EcdsaSha256 => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
            Self::EcdsaSha512 => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512",
        }
    }

    /// The `DigestMethod/@Algorithm` URI.
    #[must_use]
    pub const fn digest_algorithm(self) -> &'static str {
        match self {
            Self::EcdsaSha256 => "http://www.w3.org/2001/04/xmlenc#sha256",
            Self::EcdsaSha512 => "http://www.w3.org/2001/04/xmlenc#sha512",
        }
    }

    /// Length of this suite's digest, in bytes.
    #[must_use]
    pub const fn digest_len(self) -> usize {
        match self {
            Self::EcdsaSha256 => 32,
            Self::EcdsaSha512 => 64,
        }
    }

    /// Recognises a suite from its `SignatureMethod/@Algorithm` URI.
    #[must_use]
    pub fn from_signature_algorithm(uri: &str) -> Option<Self> {
        [Self::EcdsaSha256, Self::EcdsaSha512].into_iter().find(|s| s.signature_algorithm() == uri)
    }
}

/// One element a signature covers.
///
/// `fragment` is the element encoded as an EXI fragment — `to_fragment()` on
/// any generated message type produces it. `id` is the value of that element's
/// `Id` attribute, which the `Reference/@URI` points at with a leading `#`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signed<'a> {
    /// The `Id` attribute value, without the `#`.
    pub id: &'a str,
    /// The element as an EXI fragment.
    pub fragment: &'a [u8],
}

impl<'a> Signed<'a> {
    /// Names a fragment.
    #[must_use]
    pub const fn new(id: &'a str, fragment: &'a [u8]) -> Self {
        Self { id, fragment }
    }
}

/// Computes the digests a signature is built from.
pub trait Hash {
    /// `SHA-256` or `SHA-512`, as the suite requires.
    fn digest(&self, suite: Suite, data: &[u8]) -> Vec<u8>;
}

/// Produces a signature over the canonical `SignedInfo` bytes.
///
/// The value must be the raw `r ‖ s` pair — 64 bytes for P-256, 132 for
/// P-521 — which is what `XMLDSig`'s `ECDSAKeyValue` encoding is, *not* the
/// ASN.1 DER wrapper most libraries return by default.
pub trait Sign {
    /// Signs `data`, which is already the `SignedInfo` fragment.
    fn sign(&self, suite: Suite, data: &[u8]) -> Result<Vec<u8>, PncError>;
}

/// Checks a signature over the canonical `SignedInfo` bytes.
pub trait Verify {
    /// Verifies `signature` over `data`.
    fn verify(&self, suite: Suite, data: &[u8], signature: &[u8]) -> Result<(), PncError>;
}

/// Compares two digests without revealing where they first differ.
///
/// A digest comparison that returns early leaks, one byte at a time, how much
/// of a forged digest was right — which is enough to construct one given
/// retries. A charging session offers plenty of retries.
#[must_use]
pub fn digests_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Most elements one V2G signature may cover.
///
/// \[V2G2-909\], and it is a bound with a stated purpose: "This allows to
/// determine an upper bound for the size of the signature header". The schema
/// does **not** say so — `ds:Reference` is `maxOccurs="unbounded"` in the
/// xmldsig schema ISO 15118 imports unchanged — so it is a protocol rule, which
/// is exactly the kind this crate holds rather than leaving to each caller.
///
/// ISO 15118-20 imports the same unbounded schema and this project does not
/// have its text, so the same limit is applied there as **this crate's policy**
/// carried over from -2, on the reasoning that a header bound is a header bound.
/// A caller who has the -20 text and finds a different number has one constant
/// to change.
pub const MAX_SIGNED_ELEMENTS: usize = 4;

/// The `Reference/@URI` for an element id.
#[must_use]
pub fn reference_uri(id: &str) -> String {
    let mut uri = String::with_capacity(id.len() + 1);
    uri.push('#');
    uri.push_str(id);
    uri
}

// ---------------------------------------------------------------------------
// The profile checks, in one place
// ---------------------------------------------------------------------------
//
// The two generations differ in the *types* they carry a signature in and in
// one rule — -2 pins a single suite, -20 takes the caller's policy — and in
// nothing else. Two copies of a security decision is one copy too many: the
// interesting failure is a check tightened in one and forgotten in the other,
// and it would not show up as a test failure anywhere, only as a signature the
// other generation still accepts.

/// `CanonicalizationMethod` and every `Transform` must name canonical EXI, and
/// nothing else.
pub(crate) fn check_canonicalization(algorithm: &str) -> Result<(), PncError> {
    if algorithm == CANONICAL_EXI {
        Ok(())
    } else {
        Err(PncError::BadCanonicalization(String::from(algorithm)))
    }
}

/// `Transforms` must be exactly one canonical-EXI transform — no more, no
/// fewer, and nothing else.
///
/// A transform is a program that runs over the signed bytes before they are
/// digested, so allowing an unexpected one is allowing the signer to decide what
/// was signed. `None` is the absent list, which is not "no transforms" but a
/// signature that does not say what it covers.
pub(crate) fn check_transforms<'a>(
    algorithms: Option<impl IntoIterator<Item = &'a str>>,
) -> Result<(), PncError> {
    let Some(algorithms) = algorithms else { return Err(PncError::BadTransforms) };
    let mut algorithms = algorithms.into_iter();
    let Some(only) = algorithms.next() else { return Err(PncError::BadTransforms) };
    if algorithms.next().is_some() {
        return Err(PncError::BadTransforms);
    }
    check_canonicalization(only)
}

/// Resolves `SignatureMethod` to a suite the caller accepts.
///
/// `HMACOutputLength` belongs to the HMAC signature methods and has no meaning
/// for ECDSA — the only kind ISO 15118 permits. It is the field behind
/// CVE-2009-0217, where an `XMLDSig` verifier honoured a truncation the signer
/// chose and a signature over one byte of MAC verified. Nothing here would
/// honour it, but a signature that names it is not one this profile describes,
/// so it is refused rather than ignored.
pub(crate) fn check_suite(
    algorithm: &str,
    hmac_output_length: Option<i64>,
    accepted: &[Suite],
) -> Result<Suite, PncError> {
    let suite = Suite::from_signature_algorithm(algorithm)
        .filter(|s| accepted.contains(s))
        .ok_or_else(|| PncError::UnsupportedAlgorithm(String::from(algorithm)))?;
    if hmac_output_length.is_some() {
        return Err(PncError::UnsupportedAlgorithm(String::from(algorithm)));
    }
    Ok(suite)
}

/// The three attributes \[V2G2-771\] forbids that the schema still carries.
///
/// The rest of that list is refused elsewhere and for a different reason:
/// `HMACOutputLength` in [`check_suite`], and `KeyInfo` and `Object` by the
/// codec, which does not model them at all. These three are ordinary optional
/// `xs:ID` and `xs:anyURI` attributes, so nothing refuses them by accident —
/// which is precisely why they need a clause. The argument is `HMACOutputLength`'s
/// argument: a signature that uses a field the profile forbids is not a
/// signature this profile describes, and "we would have ignored it anyway" is
/// how a verifier comes to accept things its own specification excluded.
///
/// They are checked on the way *in* only. Building one is not possible —
/// `sign` leaves all three `None` — so there is nothing to refuse on the way
/// out.
pub(crate) fn check_forbidden<'a>(
    signed_info_id: Option<&str>,
    signature_value_id: Option<&str>,
    reference_types: impl IntoIterator<Item = Option<&'a str>>,
) -> Result<(), PncError> {
    if signed_info_id.is_some() {
        return Err(PncError::ForbiddenField { field: "SignedInfo/@Id" });
    }
    if signature_value_id.is_some() {
        return Err(PncError::ForbiddenField { field: "SignatureValue/@Id" });
    }
    for r#type in reference_types {
        if r#type.is_some() {
            return Err(PncError::ForbiddenField { field: "Reference/@Type" });
        }
    }
    Ok(())
}

/// Checks one `Reference` against the element it claims to cover.
///
/// The digest algorithm has to be the suite's own: pairing a 512-bit signature
/// with 256-bit digests would let a peer pick the weaker hash without touching
/// `SignatureMethod` at all.
pub(crate) fn check_reference(
    suite: Suite,
    digest_algorithm: &str,
    digest_value: &[u8],
    element: &Signed<'_>,
    hash: &impl Hash,
) -> Result<(), PncError> {
    if digest_algorithm != suite.digest_algorithm() {
        return Err(PncError::UnsupportedAlgorithm(String::from(digest_algorithm)));
    }
    let expected = hash.digest(suite, element.fragment);
    if digests_equal(&expected, digest_value) {
        Ok(())
    } else {
        Err(PncError::DigestMismatch { id: element.id.into() })
    }
}

/// Checks that a signed element names the session it arrived in.
///
/// Both generations put a `SessionID` inside the element the signature covers,
/// which is what makes a receipt about *this* charge rather than about any
/// charge the same contract ever made.
pub(crate) fn check_session(
    signed: &[u8],
    session: crate::session::SessionId,
) -> Result<(), PncError> {
    match crate::session::SessionId::from_slice(signed) {
        Ok(id) if id == session => Ok(()),
        _ => Err(PncError::SessionMismatch),
    }
}

/// Checks that an echoed value is the one this side issued.
pub(crate) fn check_echo<T: PartialEq>(
    echoed: &T,
    issued: &T,
    field: &'static str,
) -> Result<(), PncError> {
    if echoed == issued { Ok(()) } else { Err(PncError::NotAsIssued { field }) }
}

/// Matches supplied elements to a signature's references, in both directions.
///
/// Returns the pairing in the signature's own reference order, or an error
/// naming what did not line up. Every supplied element must be referenced and
/// every reference must be supplied: a signature that covers less than the
/// caller is about to trust, or more, is not a signature the caller can reason
/// about.
pub(crate) fn pair<'a, R>(
    references: &'a [R],
    uri_of: impl Fn(&'a R) -> Option<&'a str>,
    elements: &'a [Signed<'a>],
) -> Result<Vec<(&'a R, &'a Signed<'a>)>, PncError> {
    // \[V2G2-909\], checked before the pairing rather than after: a signature
    // naming a thousand references is not one this profile describes, and the
    // count is the cheapest thing about it to look at. The equality below would
    // refuse it too — but only because *this* caller happened to supply four
    // elements, which makes the bound a property of the call site rather than
    // of the profile.
    if references.len() > MAX_SIGNED_ELEMENTS {
        return Err(PncError::TooManyReferences { references: references.len() });
    }
    if references.len() != elements.len() {
        return Err(PncError::ReferenceMismatch {
            references: references.len(),
            elements: elements.len(),
        });
    }
    let mut used = alloc::vec![false; elements.len()];
    let mut paired = Vec::with_capacity(references.len());
    for reference in references {
        let uri = uri_of(reference).ok_or(PncError::MissingUri)?;
        let id = uri.strip_prefix('#').ok_or(PncError::MissingUri)?;
        // `!used[i]` is what stops two references naming one element while a
        // second element goes uncovered — the counts alone would not catch it.
        let index = elements
            .iter()
            .enumerate()
            .find(|&(i, e)| e.id == id && !used[i])
            .map(|(i, _)| i)
            .ok_or(PncError::UnknownReference)?;
        used[index] = true;
        paired.push((reference, &elements[index]));
    }
    Ok(paired)
}

/// Why a signature could not be built or could not be trusted.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PncError {
    /// A fragment could not be encoded.
    Exi(ExiError),
    /// The signature names an algorithm outside the ISO 15118 profile.
    UnsupportedAlgorithm(String),
    /// `CanonicalizationMethod` or a `Transform` is not canonical EXI.
    BadCanonicalization(String),
    /// A `Reference` has no `URI`, or one that is not a same-document
    /// reference.
    MissingUri,
    /// A `Reference` names an element the caller did not supply.
    UnknownReference,
    /// The signature covers a different set of elements than the caller
    /// supplied.
    ReferenceMismatch {
        /// References in the signature.
        references: usize,
        /// Elements the caller supplied.
        elements: usize,
    },
    /// A `Transforms` list is not exactly one canonical-EXI transform.
    BadTransforms,
    /// The signature names more elements than \[V2G2-909\] allows.
    TooManyReferences {
        /// References the signature carries.
        references: usize,
    },
    /// The signature uses a field \[V2G2-771\] forbids in a V2G message
    /// header.
    ///
    /// `SignedInfo/@Id`, `Reference/@Type` and `SignatureValue/@Id` are on that
    /// list, alongside `HMACOutputLength`, `Object` and `KeyInfo`. The last two
    /// are refused by the codec because this crate does not model them at all;
    /// these three are attributes the schema does carry, so refusing them is a
    /// decision rather than an accident — and it is the same decision
    /// `HMACOutputLength` gets. A signature that uses a field the profile
    /// forbids is not a signature this profile describes.
    ForbiddenField {
        /// Which field, by its path in the signature.
        field: &'static str,
    },
    /// A digest did not match the element it claims to cover.
    DigestMismatch {
        /// The element id whose digest was wrong.
        id: String,
    },
    /// The signature over `SignedInfo` did not verify.
    BadSignature,
    /// A `ContractSignatureEncryptedPrivateKey` or a `DHpublickey` is not the
    /// length ISO 15118 fixes for it. See [`envelope`].
    BadEnvelope {
        /// The length that arrived.
        len: usize,
    },
    /// A delivered contract private key does not generate the public key of the
    /// certificate it came with. \[V2G2-823\]
    KeyMismatch,
    /// A `GenChallenge` was not [`GenChallenge::LEN`] bytes.
    BadChallengeLength {
        /// The length that arrived.
        len: usize,
    },
    /// The vehicle echoed a `GenChallenge` other than the one the station sent.
    ///
    /// The signature may well be valid; it is a valid signature over the wrong
    /// session. See [`GenChallenge`].
    ChallengeMismatch,
    /// The signed element carries no `Id`, so nothing can reference it.
    ///
    /// ISO 15118 signatures are same-document references — `URI="#ID1"` — so an
    /// element with no `Id` cannot be covered by one, whatever the signature
    /// says.
    MissingId,
    /// A Plug & Charge `AuthorizationReq` carried no `GenChallenge`.
    ///
    /// ISO 15118-2 makes the element optional in the schema because the same
    /// message carries an EIM authorization, which has nothing to prove. Under
    /// a contract it is not optional.
    MissingChallenge,
    /// A signed element named a session other than the one it arrived in.
    ///
    /// The signature is over content the *peer* chose, so a receipt that names
    /// somebody else's session is a valid signature over the wrong charge.
    SessionMismatch,
    /// A signed element echoed content other than what this side issued.
    ///
    /// The same failure as [`PncError::ChallengeMismatch`] in a different
    /// exchange: a meter reading signed by the vehicle proves the vehicle signed
    /// *a* reading, and is worth nothing until it is the reading the station
    /// actually metered.
    NotAsIssued {
        /// The element whose echo did not match.
        field: &'static str,
    },
    /// The crypto backend failed or does not implement the suite.
    Backend(&'static str),
}

impl From<ExiError> for PncError {
    fn from(e: ExiError) -> Self {
        Self::Exi(e)
    }
}

impl fmt::Display for PncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exi(e) => write!(f, "EXI: {e}"),
            Self::UnsupportedAlgorithm(uri) => {
                write!(f, "algorithm {uri} is outside the ISO 15118 profile")
            }
            Self::BadCanonicalization(uri) => {
                write!(f, "canonicalization {uri} is not {CANONICAL_EXI}")
            }
            Self::MissingUri => f.write_str("a Reference has no same-document URI"),
            Self::UnknownReference => {
                f.write_str("a Reference names an element that was not given")
            }
            Self::ReferenceMismatch { references, elements } => write!(
                f,
                "the signature covers {references} elements, {elements} were given to check"
            ),
            Self::BadTransforms => {
                f.write_str("Transforms must be exactly one canonical-EXI transform")
            }
            Self::BadEnvelope { len } => {
                write!(f, "{len} is not a length ISO 15118 gives that field")
            }
            Self::KeyMismatch => f.write_str(
                "the delivered private key does not belong to the certificate it came with",
            ),
            Self::TooManyReferences { references } => write!(
                f,
                "the signature covers {references} elements; ISO 15118 allows at most \
                 {MAX_SIGNED_ELEMENTS}"
            ),
            Self::ForbiddenField { field } => {
                write!(f, "{field} is not permitted in a V2G signature")
            }
            Self::DigestMismatch { id } => write!(f, "the digest of {id} does not match"),
            Self::BadSignature => f.write_str("the signature over SignedInfo does not verify"),
            Self::BadChallengeLength { len } => {
                write!(f, "GenChallenge is {len} bytes, the schema requires {}", GenChallenge::LEN)
            }
            Self::ChallengeMismatch => {
                f.write_str("the signed GenChallenge is not the one this session issued")
            }
            Self::MissingId => f.write_str("the signed element has no Id to reference"),
            Self::MissingChallenge => {
                f.write_str("a Plug & Charge AuthorizationReq carried no GenChallenge")
            }
            Self::SessionMismatch => f.write_str("the signed element names a different session"),
            Self::NotAsIssued { field } => {
                write!(f, "the signed {field} is not the one this side issued")
            }
            Self::Backend(what) => write!(f, "crypto backend: {what}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PncError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Exi(e) => Some(e),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_comparison_is_length_safe() {
        assert!(digests_equal(&[1, 2, 3], &[1, 2, 3]));
        assert!(!digests_equal(&[1, 2, 3], &[1, 2, 4]));
        assert!(!digests_equal(&[1, 2, 3], &[1, 2]));
        assert!(digests_equal(&[], &[]));
    }

    #[test]
    fn suites_round_trip_through_their_uris() {
        for suite in [Suite::EcdsaSha256, Suite::EcdsaSha512] {
            assert_eq!(Suite::from_signature_algorithm(suite.signature_algorithm()), Some(suite));
        }
        assert_eq!(Suite::from_signature_algorithm("http://example/rsa"), None);
        // The two suites must not share a digest algorithm, or a peer could
        // pair a 512-bit signature with 256-bit digests.
        assert_ne!(Suite::EcdsaSha256.digest_algorithm(), Suite::EcdsaSha512.digest_algorithm());
    }

    #[test]
    fn a_reference_uri_is_a_same_document_pointer() {
        assert_eq!(reference_uri("ID1"), "#ID1");
    }
}
