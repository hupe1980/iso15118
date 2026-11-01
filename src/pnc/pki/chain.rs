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
use super::{Policy, Rules, TrustAnchors, VerifyWith};
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

/// The largest certificate ISO 15118-20 permits, in bytes of DER.
///
/// ISO 15118-20 Amd 1 raises -2's 800 bytes \[V2G2-010\] to 1 600. Under
/// [`Rules::Iso20`] a larger certificate is refused before anything inside it is
/// parsed: the length of a slice is the cheapest fact about it, and the bytes
/// arrive before anything about the peer is established.
pub const ISO20_MAX_CERTIFICATE_LEN: usize = 1600;

/// A validated path, from the leaf to the anchor it was validated against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Validated<'a> {
    /// The leaf — the certificate whose key the caller came here to trust.
    pub leaf: Certificate<'a>,
    /// The intermediates, leaf-first.
    pub intermediates: Vec<Certificate<'a>>,
    /// The trust anchor the path reached.
    pub anchor: Certificate<'a>,
    /// Where that anchor came from — its [`TrustAnchor::source`].
    ///
    /// [`TrustAnchor::source`]: super::TrustAnchor::source
    pub anchor_source: &'a str,
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
    /// Under [`Rules::Iso20`], a certificate is larger than
    /// [`ISO20_MAX_CERTIFICATE_LEN`].
    TooLarge {
        /// Position in the path, leaf first.
        index: usize,
        /// Its length in bytes.
        len: usize,
    },
    /// Under [`Rules::Iso20`], a certificate is valid outside its issuer's
    /// validity period \[V2G20-3000\]/\[V2G20-3001\].
    ///
    /// A certificate that outlives the certificate that vouches for it claims a
    /// trust nobody granted for that long. -2 does not have the rule, and a -2
    /// chain is not refused for it.
    OutlivesIssuer {
        /// Position in the path, leaf first, of the certificate that outlives
        /// its issuer.
        index: usize,
    },
    /// Two certificates in the path are on different curves.
    ///
    /// Every Annex F profile fixes one curve for a whole cluster, and a path
    /// that changes curve partway is not one of them.
    MixedCurves,
}

/// Checks that `chain` leads from a leaf to one of `anchors`, at time `now`,
/// under `policy`.
///
/// `chain` is leaf-first, as both generations put it on the wire: the
/// `Certificate` of a `CertificateChainType` followed by its `SubCertificates`,
/// in order. `anchors` are the trust anchors this side holds — the V2G Roots,
/// the MO Root, or a Private Operator Root \[V2G2-927\]. `policy` names the
/// leaf's Annex F profile and the generation whose rules apply ([`Rules`]).
///
/// A chain may end in a **cross-certificate** (RFC 5280 §7.1): another
/// ecosystem's root, certified by an anchor this side holds. It is validated as
/// the intermediate it is, and counts toward [`MAX_PATH_LEN`] — so it fits only
/// beneath a single Sub-CA; leaf, two Sub-CAs and a cross-certificate are four
/// certificates and are refused.
///
/// `now` is wall-clock seconds since the Unix epoch; a vehicle without
/// trustworthy time must not invent one \[V2G2-886\].
///
/// `Ok` means the leaf's key is certified by an unbroken chain of checked
/// signatures up to an anchor the caller trusts, every certificate meeting its
/// Annex F profile. It does not mean no certificate was **revoked** — see
/// [`super`].
pub fn validate<'a>(
    chain: &[&'a [u8]],
    anchors: &TrustAnchors<'_, 'a>,
    policy: Policy,
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
    // Amd 1's size bound, also before anything is parsed — for the same reason.
    if policy.rules == Rules::Iso20
        && let Some((index, der)) =
            chain.iter().enumerate().find(|(_, der)| der.len() > ISO20_MAX_CERTIFICATE_LEN)
    {
        return Err(ChainError::TooLarge { index, len: der.len() });
    }
    let parsed = parse_all(chain)?;
    let (leaf, intermediates) = parsed.split_first().ok_or(ChainError::Empty)?;

    policy.profile.check_leaf(leaf)?;

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
        let at_anchor = find_anchor(anchors, cert, below, now, policy.rules, verifier, index);
        if let Ok((anchor, anchor_source)) = at_anchor {
            return Ok(Validated {
                leaf: *leaf,
                intermediates: intermediates.to_vec(),
                anchor,
                anchor_source,
            });
        }
        // Not an anchor's, so the chain has to carry the issuer itself. When it
        // does not, the anchor search's own reason is the answer: an anchor that
        // matched and was refused (say, because this certificate outlives it) is
        // a different failure from no anchor at all.
        let Some(issuer) = parsed.get(index + 1).copied() else {
            return Err(at_anchor.err().unwrap_or(ChainError::NoTrustAnchor));
        };
        if issuer.subject.encoded != cert.issuer.encoded {
            return Err(ChainError::NoTrustAnchor);
        }
        check_issuer(&issuer, below, index + 1)?;
        verify_signature(cert, &issuer, verifier, index)?;
        if !nests(policy.rules, cert, &issuer) {
            return Err(ChainError::OutlivesIssuer { index });
        }
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
    anchors: &TrustAnchors<'_, 'a>,
    cert: &Certificate<'a>,
    below: usize,
    now: i64,
    rules: Rules,
    verifier: &impl VerifyWith,
    index: usize,
) -> Result<(Certificate<'a>, &'a str), ChainError> {
    let mut outlived = false;
    for entry in anchors {
        let Ok(anchor) = Certificate::parse(entry.der) else { continue };
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
        // Amd 1's nesting rule is part of the selection too: across a rollover
        // the anchor whose window contains this certificate is the one that
        // vouches for it, and an earlier one sharing its name does not.
        if !nests(rules, cert, &anchor) {
            outlived = true;
            continue;
        }
        if verify_signature(cert, &anchor, verifier, index).is_ok() {
            return Ok((anchor, entry.source));
        }
    }
    // A matching anchor existed and the certificate outlives it: that is the
    // reason, and "no trust anchor" would hide it.
    if outlived {
        return Err(ChainError::OutlivesIssuer { index });
    }
    Err(ChainError::NoTrustAnchor)
}

/// Whether `cert`'s validity lies within `issuer`'s, as the rules require.
///
/// \[V2G20-3000\]/\[V2G20-3001\] under [`Rules::Iso20`]; -2 has no such rule.
const fn nests(rules: Rules, cert: &Certificate<'_>, issuer: &Certificate<'_>) -> bool {
    match rules {
        Rules::Iso2 => true,
        Rules::Iso20 => issuer.not_before <= cert.not_before && cert.not_after <= issuer.not_after,
    }
}

/// Picks, from several candidate chains, the first that reaches one of the
/// authorities a peer listed.
///
/// ISO 15118-20 Amd 1 has the holder of more than one chain — one per
/// ecosystem, or one through a cross-certificate — send the chain that reaches
/// the certificate authorities its peer names \[V2G20-3373\]..\[V2G20-3385\],
/// which TLS carries as `certificate_authorities` (RFC 8446 §4.2.4): a list of
/// DER-encoded distinguished names. [`TrustAnchors::authorities`] produces that
/// list on the validating side.
///
/// `candidates` are leaf-first chains in order of preference. A chain matches
/// when any of its certificates is *issued by* a listed name, or *is* one —
/// so a listed root and a listed intermediate both select. A candidate whose
/// certificates do not parse is skipped, not chosen. Returns the index of the
/// chosen candidate, or `None` when no chain reaches any listed authority.
///
/// Selection only: the chosen chain still has to validate at the peer.
#[must_use]
pub fn select_chain(candidates: &[&[&[u8]]], authorities: &[&[u8]]) -> Option<usize> {
    let listed = |name: &[u8]| authorities.contains(&name);
    candidates.iter().position(|chain| {
        let mut reaches = false;
        for der in *chain {
            let Ok(cert) = Certificate::parse(der) else { return false };
            reaches |= listed(cert.issuer.encoded) || listed(cert.subject.encoded);
        }
        reaches
    })
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
            Self::TooLarge { index, len } => write!(
                f,
                "certificate {index} is {len} bytes; ISO 15118-20 allows at most \
                 {ISO20_MAX_CERTIFICATE_LEN}"
            ),
            Self::OutlivesIssuer { index } => {
                write!(f, "certificate {index} is valid outside its issuer's validity period")
            }
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
