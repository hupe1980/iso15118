//! Walking a certificate chain to a trust anchor, under the ISO 15118 profile.
//!
//! RFC 5280 §6.1 is a large algorithm and this is a small part of it, which is
//! not a shortcut — it is what ISO 15118 leaves. \[V2G2-885\] requires
//! validation "in conformance with RFC 5280", and Annex F then fixes almost
//! every input that algorithm takes: one signature algorithm, one curve per
//! generation, a depth of three \[V2G2-009\], no name constraints, no policy
//! mapping, no policy qualifiers that decide anything. What is left is the
//! basic path validation, and that is what is here.
//!
//! What is **not** here is revocation. See [`super`].

use alloc::vec::Vec;

use super::cert::{Certificate, KeyUsage};
use super::{Profile, VerifyWith};
use crate::pnc::PncError;

/// Maximum number of non-self-signed certificates in a path.
///
/// \[V2G2-009\]: "The path length constraint of the PKI certificate tree shall
/// be limited to 3", and the note beside it says what that counts — "there will
/// be up to 3 certificate layers derived from the root certificate", i.e. two
/// Sub-CAs and a leaf.
///
/// The schema bounds the wire independently (`SubCertificates` is
/// `maxOccurs="4"`), which is a different number for a different reason and
/// does not make this one redundant: a chain assembled from a store rather than
/// from a message never passed through that schema.
pub const MAX_PATH_LEN: usize = 3;

/// A validated path, from the leaf to the anchor it was validated against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Validated<'a> {
    /// The leaf — the certificate whose key the caller came here to trust.
    pub leaf: Certificate<'a>,
    /// The intermediates, leaf-first.
    pub intermediates: Vec<Certificate<'a>>,
    /// The trust anchor the path reached.
    pub anchor: Certificate<'a>,
}

impl<'a> Validated<'a> {
    /// The key the leaf's signatures are checked against.
    #[must_use]
    pub const fn public_key(&self) -> &'a [u8] {
        self.leaf.public_key
    }

    /// The `Common Name` of the leaf's subject.
    ///
    /// For a contract certificate this is the `EMAID` (Table F.4); for an SECC
    /// certificate the `CPID` (Table F.2); for an OEM provisioning certificate
    /// the `CertID` \[V2G2-933\].
    #[must_use]
    pub const fn subject_common_name(&self) -> Option<&'a str> {
        self.leaf.subject.common_name
    }
}

/// Why a chain does not establish that the leaf's key is one to trust.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChainError {
    /// A certificate in the path did not parse or does not meet the profile.
    Certificate {
        /// Position in the path, leaf first.
        index: usize,
        /// What was wrong with it.
        error: super::cert::CertError,
    },
    /// The chain was empty.
    Empty,
    /// The path is longer than \[V2G2-009\] allows.
    TooLong {
        /// Non-self-signed certificates the path holds.
        len: usize,
    },
    /// A certificate's issuer names no certificate that follows it, and no
    /// configured trust anchor.
    ///
    /// \[V2G2-924\]: a chain that does not trace up to a root the peer holds is
    /// one the peer must refuse.
    NoTrustAnchor,
    /// A certificate was outside its validity period at the stated time.
    Expired {
        /// Position in the path, leaf first.
        index: usize,
    },
    /// An issuer is not permitted to have signed what it signed.
    ///
    /// Either it is not a CA, or its `pathLenConstraint` does not reach this
    /// far, or its `KeyUsage` does not include `keyCertSign`.
    NotAnIssuer {
        /// Position in the path, leaf first.
        index: usize,
    },
    /// A signature did not verify against the issuer's key.
    BadSignature {
        /// Position in the path, leaf first.
        index: usize,
    },
    /// The leaf does not meet the profile the caller asked for — a missing
    /// `KeyUsage` bit, a `Domain Component` the profile requires
    /// \[V2G2-925\], or a leaf that claims to be a CA \[V2G2-867\].
    Profile {
        /// What the profile wanted and did not get.
        wanted: &'static str,
    },
    /// Two certificates in the path are on different curves.
    ///
    /// Every Annex F profile fixes one curve for a whole cluster, and a path
    /// that changes curve partway is not one of them.
    MixedCurves,
}

/// Checks that `chain` leads from a leaf to one of `anchors`, at time `now`.
///
/// `chain` is leaf-first, as both generations put it on the wire: the
/// `Certificate` of a `CertificateChainType` followed by its `SubCertificates`,
/// in order. `anchors` are the trust anchors this side holds — the V2G Roots,
/// the MO Root, or a Private Operator Root \[V2G2-927\] — as DER.
///
/// `now` is seconds since the Unix epoch, supplied by the caller. This crate
/// reads no clock, and the choice matters more here than elsewhere:
/// \[V2G2-886\] lets a vehicle pick its own time accuracy and warns about the
/// consequences, and a vehicle with no trustworthy time cannot check a validity
/// period at all. Passing a time this side does not actually know is worse than
/// saying so.
///
/// # What this establishes
///
/// That the leaf's key is certified, by an unbroken chain of signatures this
/// side checked, up to a certificate the caller decided to trust — and that
/// every certificate on the way meets its Annex F profile.
///
/// # What it does not
///
/// That no certificate on the path has been **revoked**. There is no OCSP and
/// no CRL here; see [`super`] for why, and for what a deployment has to do
/// about it.
pub fn validate<'a>(
    chain: &[&'a [u8]],
    anchors: &[&'a [u8]],
    profile: Profile,
    now: i64,
    verifier: &impl VerifyWith,
) -> Result<Validated<'a>, ChainError> {
    // \[V2G2-009\], before anything is parsed. Counted over what *arrived*
    // rather than over what gets used: a peer that sends a hundred certificates
    // should not have a hundred DER parses done for it before the count is
    // looked at, and the count is the cheapest thing about the chain.
    if chain.len() > MAX_PATH_LEN {
        return Err(ChainError::TooLong { len: chain.len() });
    }
    let parsed = parse_all(chain)?;
    let (leaf, intermediates) = parsed.split_first().ok_or(ChainError::Empty)?;

    profile.check_leaf(leaf)?;

    // Every certificate in one Annex F cluster is on one curve. Checking it
    // here rather than per-signature makes "the chain changed curve halfway" a
    // named failure instead of a signature that happens not to verify.
    if parsed.iter().any(|c| c.curve != leaf.curve) {
        return Err(ChainError::MixedCurves);
    }

    for (index, cert) in parsed.iter().enumerate() {
        if !cert.is_valid_at(now) {
            return Err(ChainError::Expired { index });
        }
    }

    // Walk up, leaf first: at each step the path either reaches a configured
    // trust anchor, or the next certificate in the chain has to be the issuer.
    //
    // Anchors are tried at *every* step, not only at the top, so a deployment
    // may pin an intermediate. RFC 5280 puts no constraint on where an anchor
    // sits and ISO 15118 needs that: \[V2G2-927\] makes a Private Operator
    // Root an anchor for SECC certificates and \[V2G2-868\] has it sign
    // leaves directly.
    //
    // `below` is RFC 5280 §6.1.4(m)'s count — certificates between an issuer
    // and the leaf, the leaf excluded — which is what `pathLenConstraint`
    // bounds, so it is measured from the position rather than from the chain's
    // length.
    for (index, cert) in parsed.iter().enumerate() {
        let below = index;
        if let Ok(anchor) = find_anchor(anchors, cert, below, now, verifier, index) {
            return Ok(Validated { leaf: *leaf, intermediates: intermediates.to_vec(), anchor });
        }
        // Not an anchor's, so the chain has to carry the issuer itself.
        let issuer = parsed.get(index + 1).copied().ok_or(ChainError::NoTrustAnchor)?;
        if issuer.subject.encoded != cert.issuer.encoded {
            return Err(ChainError::NoTrustAnchor);
        }
        check_issuer(&issuer, below, index + 1)?;
        verify_signature(cert, &issuer, verifier, index)?;
    }
    // Every certificate that arrived was consumed and none of them reached an
    // anchor: the chain is well-formed and ends somewhere this side does not
    // trust. \[V2G2-924\].
    Err(ChainError::NoTrustAnchor)
}

/// Parses every certificate, naming which one failed.
fn parse_all<'a>(chain: &[&'a [u8]]) -> Result<Vec<Certificate<'a>>, ChainError> {
    chain
        .iter()
        .enumerate()
        .map(|(index, der)| {
            Certificate::parse(der).map_err(|error| ChainError::Certificate { index, error })
        })
        .collect()
}

/// Finds the anchor that issued `cert`, if this side holds it.
///
/// Every condition is part of the *selection* rather than applied to whichever
/// anchor matched first, and that is deliberate: \[V2G2-878\] allows up to ten
/// concurrently valid V2G Root Certificates for one Root CA, so several anchors
/// can legitimately share a subject across a rollover. Picking by name and then
/// checking would fail a chain that a different, equally configured anchor
/// validates — which is a charge refused during a key rollover, at every station
/// at once.
///
/// The signature is verified last, because it is the expensive condition and the
/// cheap ones exclude most candidates. It is verified **once**: the anchor comes
/// back already checked.
fn find_anchor<'a>(
    anchors: &[&'a [u8]],
    cert: &Certificate<'a>,
    below: usize,
    now: i64,
    verifier: &impl VerifyWith,
    index: usize,
) -> Result<Certificate<'a>, ChainError> {
    for der in anchors {
        let Ok(anchor) = Certificate::parse(der) else { continue };
        if anchor.subject.encoded != cert.issuer.encoded {
            continue;
        }
        // An anchor that has expired is not one to build on. \[V2G2-011\] gives
        // a V2G Root forty years precisely so this never bites in practice, and
        // a deployment whose root *has* expired needs to be told rather than to
        // keep charging.
        if !anchor.is_valid_at(now) {
            continue;
        }
        // A configured anchor is trusted by configuration, not by its own
        // signature — but it still has to be something that may *issue*, or a
        // leaf certificate dropped into the anchor list would validate anything
        // it happens to have signed.
        if check_issuer(&anchor, below, index).is_err() {
            continue;
        }
        if verify_signature(cert, &anchor, verifier, index).is_ok() {
            return Ok(anchor);
        }
    }
    Err(ChainError::NoTrustAnchor)
}

/// Whether `issuer` was allowed to sign the certificate `below` positions under
/// it.
fn check_issuer(issuer: &Certificate<'_>, below: usize, index: usize) -> Result<(), ChainError> {
    // RFC 5280 §6.1.4(k): an issuer must assert `cA`. A certificate with no
    // `BasicConstraints` at all asserts nothing, and Annex F marks the
    // extension critical in every profile — so absence is a failure, not a
    // default.
    let constraints = issuer.basic_constraints.ok_or(ChainError::NotAnIssuer { index })?;
    if !constraints.ca {
        return Err(ChainError::NotAnIssuer { index });
    }
    // RFC 5280 §6.1.4(m): `pathLenConstraint` is the number of non-self-issued
    // intermediates that may follow. `below` is how many certificates sit
    // between this issuer and the leaf, the leaf itself excluded.
    if let Some(limit) = constraints.path_len
        && below > limit as usize
    {
        return Err(ChainError::NotAnIssuer { index });
    }
    // RFC 5280 §6.1.4(n), and Annex F's `keyCertSign (x)` on every CA row. The
    // extension is critical there, so a CA that carries one and leaves this bit
    // clear has said its key does not sign certificates.
    if issuer.key_usage.is_some_and(|ku| !ku.contains(KeyUsage::KEY_CERT_SIGN)) {
        return Err(ChainError::NotAnIssuer { index });
    }
    Ok(())
}

/// Verifies `cert`'s signature against `issuer`'s key.
fn verify_signature(
    cert: &Certificate<'_>,
    issuer: &Certificate<'_>,
    verifier: &impl VerifyWith,
    index: usize,
) -> Result<(), ChainError> {
    verifier
        .verify_with(issuer.curve.suite(), issuer.public_key, cert.tbs, cert.signature.as_slice())
        .map_err(|_: PncError| ChainError::BadSignature { index })
}

impl core::fmt::Display for ChainError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Certificate { index, error } => write!(f, "certificate {index}: {error}"),
            Self::Empty => f.write_str("the chain is empty"),
            Self::TooLong { len } => write!(
                f,
                "the path holds {len} certificates; ISO 15118 allows at most {MAX_PATH_LEN}"
            ),
            Self::NoTrustAnchor => {
                f.write_str("the chain does not reach a configured trust anchor")
            }
            Self::Expired { index } => {
                write!(f, "certificate {index} is outside its validity period")
            }
            Self::NotAnIssuer { index } => {
                write!(f, "certificate {index} is not permitted to issue what it signed")
            }
            Self::BadSignature { index } => {
                write!(f, "certificate {index} is not signed by the certificate above it")
            }
            Self::Profile { wanted } => write!(f, "the leaf certificate is missing {wanted}"),
            Self::MixedCurves => f.write_str("the chain changes elliptic curve partway"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ChainError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Certificate { error, .. } => Some(error),
            _ => None,
        }
    }
}
