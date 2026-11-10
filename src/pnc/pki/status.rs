//! A certificate's revocation status: good, revoked, or unknown — and if
//! unknown, whether evidence was absent or rejected.
//!
//! Evidence is read by [`super::ocsp`] and [`super::crl`]; what a standing means
//! for a chain is decided in [`super::chain`].

use super::der::{Der, DerError, tag};

/// Which kind of evidence a standing rests on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum Source {
    /// An OCSP response (RFC 6960) — stapled in the TLS handshake, cached, or
    /// fetched by a back end.
    Ocsp,
    /// A certificate revocation list (RFC 5280 §5).
    Crl,
}

/// Why a certificate was withdrawn — RFC 5280 §5.3.1 `CRLReason`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum Reason {
    /// `unspecified (0)`.
    Unspecified,
    /// `keyCompromise (1)`.
    KeyCompromise,
    /// `cACompromise (2)`.
    CaCompromise,
    /// `affiliationChanged (3)`.
    AffiliationChanged,
    /// `superseded (4)`.
    Superseded,
    /// `cessationOfOperation (5)`.
    CessationOfOperation,
    /// `certificateHold (6)` — suspended, and as unusable while it lasts.
    CertificateHold,
    /// `removeFromCRL (8)`.
    RemoveFromCrl,
    /// `privilegeWithdrawn (9)`.
    PrivilegeWithdrawn,
    /// `aACompromise (10)`.
    AaCompromise,
}

impl Reason {
    /// Reads the enumeration value; `7` is unused in the ASN.1 and refused.
    pub(super) const fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            0 => Self::Unspecified,
            1 => Self::KeyCompromise,
            2 => Self::CaCompromise,
            3 => Self::AffiliationChanged,
            4 => Self::Superseded,
            5 => Self::CessationOfOperation,
            6 => Self::CertificateHold,
            8 => Self::RemoveFromCrl,
            9 => Self::PrivilegeWithdrawn,
            10 => Self::AaCompromise,
            _ => return None,
        })
    }
}

/// What this side can say about one certificate's revocation status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum Standing {
    /// Verified evidence, current at the time given, that does not list it.
    Good {
        /// What the evidence was.
        source: Source,
        /// When it was compiled (`thisUpdate`), Unix seconds.
        this_update: i64,
        /// When it stops being evidence (`nextUpdate`), Unix seconds.
        next_update: i64,
    },
    /// Verified evidence that lists it as withdrawn.
    Revoked {
        /// What the evidence was.
        source: Source,
        /// When it was withdrawn, as the evidence says, Unix seconds.
        revoked_at: i64,
        /// Why, where the evidence says.
        reason: Option<Reason>,
    },
    /// No verdict.
    Unknown(Unknown),
}

impl Standing {
    /// Whether this standing vouches for the certificate. Only [`Self::Good`]
    /// does.
    #[must_use]
    pub const fn is_good(&self) -> bool {
        matches!(self, Self::Good { .. })
    }
}

/// Why a [`Standing::Unknown`] is unknown.
///
/// No evidence refuses only where the rules require a status; rejected
/// evidence always refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum Unknown {
    /// Nothing handed in concerns this certificate.
    NoEvidence,
    /// Evidence concerning this certificate was handed in and failed.
    Rejected(EvidenceError),
}

/// Why a piece of revocation evidence was not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum EvidenceError {
    /// The DER did not parse, or a value in it is impossible.
    Malformed,
    /// More evidence, responses or responder certificates than this crate
    /// reads ([`super::MAX_EVIDENCE`], [`super::ocsp::MAX_SINGLE_RESPONSES`],
    /// [`super::ocsp::MAX_RESPONDER_CERTS`]).
    TooLarge,
    /// The OCSP response type is not `id-pkix-ocsp-basic` (RFC 6960 §4.2.1).
    UnsupportedResponseType,
    /// The `CertID` or `ResponderID` hash is one the backend cannot compute, or
    /// one RFC 6960 does not name for it.
    UnsupportedHash,
    /// The signature algorithm is not ECDSA with SHA-256 or SHA-512, or does not
    /// match the signer's curve.
    UnsupportedSignatureAlgorithm,
    /// The responder is neither the certificate's issuer nor a certificate the
    /// issuer signed directly with `id-kp-OCSPSigning`, valid at the time given
    /// (RFC 6960 §4.2.2.2, \[V2G2-875\], \[V2G20-2413\]).
    ResponderNotAuthorized,
    /// The `ResponderID` names no candidate signer.
    ResponderIdMismatch,
    /// The signature does not verify (\[V2G20-2414\]).
    BadSignature,
    /// `thisUpdate` is after the time given.
    NotYetValid,
    /// `nextUpdate` is before the time given.
    Stale,
    /// No `nextUpdate`: a status with no end cannot meet either generation's
    /// bound, and RFC 5280 §5.1.2.5 requires one in a CRL.
    NoNextUpdate,
    /// The response's validity period is longer than the generation allows —
    /// four weeks under ISO 15118-2 \[V2G2-876\], one week under
    /// ISO 15118-20 \[V2G20-1021\].
    ValidityTooLong {
        /// `nextUpdate − thisUpdate`, in seconds.
        seconds: i64,
    },
    /// The responder answered `unknown` for this certificate.
    StatusUnknown,
    /// A critical extension this crate does not implement.
    UnknownCriticalExtension,
    /// An indirect, partitioned or delta CRL, which this crate does not
    /// implement.
    UnsupportedCrl,
    /// The CRL lacks `CRLNumber`, which RFC 5280 §5.2.3 makes mandatory.
    MissingCrlNumber,
    /// `CRLNumber` is marked critical, which RFC 5280 §5.2.3 forbids.
    CriticalCrlNumber,
    /// A serial number is listed twice.
    DuplicateSerial,
    /// The CRL is not version 2.
    NotV2Crl,
    /// The CRL's issuer carries `KeyUsage` without `cRLSign`.
    IssuerMayNotSignCrls,
}

impl From<DerError> for EvidenceError {
    fn from(_: DerError) -> Self {
        Self::Malformed
    }
}

impl From<super::cert::CertError> for EvidenceError {
    fn from(e: super::cert::CertError) -> Self {
        use super::cert::CertError;
        match e {
            CertError::UnsupportedSignatureAlgorithm | CertError::AlgorithmMismatch => {
                Self::UnsupportedSignatureAlgorithm
            }
            CertError::BadSignature => Self::BadSignature,
            CertError::UnknownCriticalExtension => Self::UnknownCriticalExtension,
            _ => Self::Malformed,
        }
    }
}

/// Walks the contents of an `Extensions` `SEQUENCE OF`, handing each
/// `(extnID, critical, extnValue contents)` to `visit`.
///
/// An extension listed twice is refused (RFC 5280 §4.2 and §5.2 say "MUST NOT
/// include more than one instance"), by the same allocation-free scan
/// certificates use.
pub(super) fn scan_extensions<'a>(
    list: &'a [u8],
    mut visit: impl FnMut(&'a [u8], bool, &'a [u8]) -> Result<(), EvidenceError>,
) -> Result<(), EvidenceError> {
    let mut reader = Der::new(list);
    let mut seen = 0usize;
    while !reader.is_empty() {
        let mut ext = reader.nested(tag::SEQUENCE)?;
        let id = ext.expect(tag::OID)?;
        let critical = if ext.peek() == Some(tag::BOOLEAN) { ext.boolean()? } else { false };
        let value = ext.expect(tag::OCTET_STRING)?;
        ext.finish()?;
        let mut earlier = Der::new(list);
        for _ in 0..seen {
            if earlier.nested(tag::SEQUENCE)?.expect(tag::OID)? == id {
                return Err(EvidenceError::Malformed);
            }
        }
        seen += 1;
        visit(id, critical, value)?;
    }
    Ok(())
}

/// Combines what several pieces of evidence say about one certificate:
/// revoked beats good, good beats rejected, rejected beats no evidence.
pub(super) fn combine(a: Standing, b: Standing) -> Standing {
    match (a, b) {
        (r @ Standing::Revoked { .. }, _) | (_, r @ Standing::Revoked { .. }) => r,
        (g @ Standing::Good { .. }, _) | (_, g @ Standing::Good { .. }) => g,
        (r @ Standing::Unknown(Unknown::Rejected(_)), _)
        | (_, r @ Standing::Unknown(Unknown::Rejected(_))) => r,
        _ => Standing::Unknown(Unknown::NoEvidence),
    }
}

impl core::fmt::Display for Standing {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Good { source, next_update, .. } => {
                write!(f, "not revoked, by {source} evidence valid until {next_update}")
            }
            Self::Revoked { source, revoked_at, reason } => {
                write!(f, "revoked at {revoked_at}, by {source} evidence")?;
                if let Some(reason) = reason {
                    write!(f, " ({reason:?})")?;
                }
                Ok(())
            }
            Self::Unknown(Unknown::NoEvidence) => f.write_str("no revocation evidence"),
            Self::Unknown(Unknown::Rejected(e)) => write!(f, "revocation evidence rejected: {e}"),
        }
    }
}

impl core::fmt::Display for Source {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Ocsp => "OCSP",
            Self::Crl => "CRL",
        })
    }
}

impl core::fmt::Display for EvidenceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Malformed => f.write_str("the evidence does not parse"),
            Self::TooLarge => f.write_str("more evidence than this crate reads"),
            Self::UnsupportedResponseType => f.write_str("the OCSP response is not basic"),
            Self::UnsupportedHash => f.write_str("a hash the backend cannot compute"),
            Self::UnsupportedSignatureAlgorithm => {
                f.write_str("the signature algorithm is not one the signer's curve uses")
            }
            Self::ResponderNotAuthorized => {
                f.write_str("the responder is not authorised to answer for this certificate")
            }
            Self::ResponderIdMismatch => f.write_str("the ResponderID names no candidate signer"),
            Self::BadSignature => f.write_str("the signature does not verify"),
            Self::NotYetValid => f.write_str("thisUpdate is in the future"),
            Self::Stale => f.write_str("nextUpdate has passed"),
            Self::NoNextUpdate => f.write_str("there is no nextUpdate"),
            Self::ValidityTooLong { seconds } => {
                write!(f, "a validity period of {seconds} s exceeds the generation's bound")
            }
            Self::StatusUnknown => f.write_str("the responder does not know the certificate"),
            Self::UnknownCriticalExtension => {
                f.write_str("a critical extension this build cannot process")
            }
            Self::UnsupportedCrl => f.write_str("an indirect, partitioned or delta CRL"),
            Self::MissingCrlNumber => f.write_str("the CRL has no CRLNumber"),
            Self::CriticalCrlNumber => f.write_str("the CRL's CRLNumber is critical"),
            Self::DuplicateSerial => f.write_str("a serial number is listed twice"),
            Self::NotV2Crl => f.write_str("the CRL is not version 2"),
            Self::IssuerMayNotSignCrls => f.write_str("the CRL's issuer lacks cRLSign"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for EvidenceError {}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: Standing = Standing::Good { source: Source::Ocsp, this_update: 0, next_update: 1 };
    const REVOKED: Standing =
        Standing::Revoked { source: Source::Crl, revoked_at: 0, reason: None };
    const REJECTED: Standing = Standing::Unknown(Unknown::Rejected(EvidenceError::Stale));
    const NONE: Standing = Standing::Unknown(Unknown::NoEvidence);

    #[test]
    fn a_revocation_is_never_outvoted() {
        assert_eq!(combine(GOOD, REVOKED), REVOKED);
        assert_eq!(combine(REVOKED, GOOD), REVOKED);
        assert_eq!(combine(REJECTED, REVOKED), REVOKED);
    }

    #[test]
    fn verified_evidence_beats_a_rejection_and_a_rejection_beats_silence() {
        assert_eq!(combine(REJECTED, GOOD), GOOD);
        assert_eq!(combine(NONE, REJECTED), REJECTED);
        assert_eq!(combine(NONE, NONE), NONE);
    }

    #[test]
    fn reason_seven_does_not_exist() {
        assert_eq!(Reason::from_code(7), None);
        assert_eq!(Reason::from_code(1), Some(Reason::KeyCompromise));
    }
}
