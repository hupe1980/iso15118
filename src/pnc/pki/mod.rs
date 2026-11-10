//! The V2G PKI: reading ISO 15118 certificates and validating a chain to a
//! trust anchor.
//!
//! A verified signature says nothing about **whose** key made it. The
//! `GenChallenge` binding in [`super`] answers *which session*; this module
//! answers whose key.
//!
//! # What ISO 15118 fixes
//!
//! ISO 15118 pins almost every input to X.509 and RFC 5280 §6.1, which keeps
//! this small enough for a `no_std` crate with no dependencies:
//!
//! | | |
//! |---|---|
//! | Signature algorithm | `ecdsa-with-SHA256` \[V2G2-006\] (`-SHA512` for -20's higher level) |
//! | Curve | `secp256r1` \[V2G2-007\], `secp521r1` in -20 |
//! | Path length | at most 3 non-self-signed certificates \[V2G2-009\] |
//! | Certificate size | at most 800 bytes DER \[V2G2-010\], which the -2 schema enforces on the wire; at most 1 600 for -20 (Amd 1), which [`validate`] enforces under [`Rules::Iso20`] |
//! | Extensions | the set in Annex F, `KeyUsage` and `BasicConstraints` critical in every profile |
//! | Name constraints, policy mapping | not used |
//!
//! What is implemented is basic path validation — signatures, validity periods,
//! `BasicConstraints`, `pathLenConstraint`, `KeyUsage`, the critical-extension
//! rule — plus the Annex F profile of whichever leaf the caller names, plus the
//! rules of the generation the caller names ([`Rules`]).
//!
//! # ISO 15118-20 Amd 1
//!
//! [`Rules::Iso20`] applies the rules the amendment's public text shows: a
//! certificate is at most 1 600 bytes, refused before it is read; a certificate
//! is valid only within its issuer's validity, on every link
//! \[V2G20-3000\]/\[V2G20-3001\]; and a holder of several chains sends the one
//! reaching the authorities its peer lists — [`select_chain`] and
//! [`TrustAnchors::authorities`] \[V2G20-3373\]..\[V2G20-3385\]. A
//! cross-certificate (RFC 5280 §7.1) is an intermediate whose issuer is an
//! anchor this side holds; it counts toward [`MAX_PATH_LEN`], so it fits only
//! beneath a single Sub-CA. A trust anchor may sit anywhere in the path: a
//! Private Operator Root anchors SECC certificates \[V2G2-927\] and may sign
//! leaves directly \[V2G2-868\].
//!
//! # Revocation
//!
//! [`validate`] takes the OCSP responses and CRLs the caller holds
//! ([`Evidence`]) and verifies them. Nothing is fetched.
//!
//!
//! | Chain | Rules | Must be shown good | Source |
//! |---|---|---|---|
//! | SECC, public V2G root | -2 | every Sub-CA (not the leaf) | \[V2G2-070\], \[V2G2-873\] |
//! | SECC, public V2G root | -20 | every certificate below the anchor | \[V2G20-1240\], \[V2G20-2416\] |
//! | SECC, private root | -2 | nothing | \[V2G2-872\] |
//! | SECC, private root | -20 | all or none | \[V2G20-2410\], \[V2G20-2417\] |
//! | contract, OEM provisioning, unchecked | both | nothing — fetching is the station's call | \[V2G2-693\], \[V2G20-2214\] |
//!
//! In every row a certificate shown revoked, or evidence that does not verify,
//! refuses the chain (\[V2G2-875\], \[V2G20-2413\]–\[V2G20-2415\]).
//! [`Validated::standing`] reports each certificate. Public or private is set
//! on the anchor: [`TrustAnchor::public`], [`TrustAnchor::private`].
//!
//! # Time is a real input
//!
//! [`chain::validate`] takes wall-clock seconds since the Unix epoch, not
//! [`session::Instant`](crate::session::Instant). \[V2G2-886\] lets a vehicle
//! choose its own time accuracy and \[V2G2-910\] makes checking validity a
//! *should*; a vehicle with no trustworthy time must not invent one.
//!
//! # Example
//!
//! ```no_run
//! use iso15118::pnc::pki::{Evidence, Policy, Profile, TrustAnchor, TrustAnchors, chain};
//! # use iso15118::pnc::{PncError, Suite};
//! # use iso15118::pnc::pki::HashAlgorithm;
//! # struct Backend;
//! # impl iso15118::pnc::pki::VerifyWith for Backend {
//! #     fn verify_with(&self, _: Suite, _: &[u8], _: &[u8], _: &[u8]) -> Result<(), PncError> { Ok(()) }
//! # }
//! # impl iso15118::pnc::pki::Hasher for Backend {
//! #     fn hash(&self, _: HashAlgorithm, _: &[u8]) -> Option<Vec<u8>> { None }
//! # }
//! # fn f(leaf: &[u8], sub_ca: &[u8], mo_root: &[u8], crl: &[u8], now: i64) -> Result<(), chain::ChainError> {
//! // Leaf first, as both generations put it on the wire.
//! let anchors = [TrustAnchor::public(mo_root, "MO Root")];
//! let validated = chain::validate(
//!     &[leaf, sub_ca],
//!     &TrustAnchors::new(&anchors),
//!     Policy::iso2(Profile::ContractCertificate),
//!     &Evidence::crls(&[crl]),
//!     now,
//!     &Backend,
//! )?;
//!
//! // ...and *this* is the key a Plug & Charge signature is checked against.
//! let emaid = validated.subject_common_name();
//! let key = validated.public_key();
//! # let _ = (emaid, key);
//! # Ok(())
//! # }
//! ```

pub mod cert;
pub mod chain;
pub mod crl;
mod der;
pub mod ocsp;
mod oid;
pub mod status;

use alloc::vec::Vec;

pub use cert::{BasicConstraints, CertError, Certificate, Curve, KeyUsage, Name};
pub use chain::{
    ChainError, ISO20_MAX_CERTIFICATE_LEN, MAX_PATH_LEN, Validated, select_chain, validate,
};
pub use crl::Crl;
pub use der::DerError;
pub use ocsp::OcspResponse;
pub use status::{EvidenceError, Reason, Source, Standing, Unknown};

use crate::pnc::{PncError, Suite};

/// A digest named by an OCSP `CertID` or `ResponderID`.
///
/// SHA-1 is used only to find a response, never to verify one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum HashAlgorithm {
    /// SHA-1 (RFC 3174) — lookup only.
    Sha1,
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

/// Computes the digests revocation evidence names certificates by.
pub trait Hasher {
    /// `alg` over `data`, or `None` when this backend does not implement `alg` —
    /// which makes evidence that needs it [`EvidenceError::UnsupportedHash`],
    /// never good.
    fn hash(&self, alg: HashAlgorithm, data: &[u8]) -> Option<Vec<u8>>;
}

/// The most OCSP responses, and separately the most CRLs, one validation reads.
pub const MAX_EVIDENCE: usize = 16;

/// Revocation evidence the caller holds, as DER: OCSP responses and CRLs, in
/// any order, from any source.
///
/// Matched to certificates by what they say, never by position: a response by
/// its `CertID`, a list by its issuer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Evidence<'s, 'a> {
    /// DER `OCSPResponse`s.
    pub ocsp: &'s [&'a [u8]],
    /// DER `CertificateList`s.
    pub crls: &'s [&'a [u8]],
}

impl<'s, 'a> Evidence<'s, 'a> {
    /// No evidence. An SECC chain under a public anchor does not pass with it.
    #[must_use]
    pub const fn none() -> Self {
        Self { ocsp: &[], crls: &[] }
    }

    /// OCSP responses only — what a vehicle has from the TLS handshake.
    #[must_use]
    pub const fn ocsp(responses: &'s [&'a [u8]]) -> Self {
        Self { ocsp: responses, crls: &[] }
    }

    /// CRLs only.
    #[must_use]
    pub const fn crls(lists: &'s [&'a [u8]]) -> Self {
        Self { ocsp: &[], crls: lists }
    }

    /// Both.
    #[must_use]
    pub const fn new(ocsp: &'s [&'a [u8]], crls: &'s [&'a [u8]]) -> Self {
        Self { ocsp, crls }
    }
}

/// Whether a trust anchor roots the public V2G PKI or a private one; the anchor
/// a chain reaches selects the revocation rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Environment {
    /// A V2G root, an MO / eMSP root, an OEM root.
    Public,
    /// A private environment's root — a PE or Private Operator Root
    /// \[V2G2-868\]\[V2G2-927\].
    Private,
}

/// Verifies a signature against a public key that arrived in a certificate.
///
/// A sibling of [`Verify`](crate::pnc::Verify) and separate from it on purpose.
/// `Verify` is implemented by a type that *holds* a key — a session's contract
/// key, a station's own key — and that is the right shape when the key is
/// configuration. A chain's keys are not configuration: each one arrives inside
/// the certificate below it, and there is a new one at every step.
///
/// `public_key` is an uncompressed SEC1 point (`0x04 ‖ X ‖ Y`), exactly as the
/// certificate carried it. `signature` is the raw `r ‖ s` pair — this crate
/// converts X.509's DER `ECDSA-Sig-Value` before calling, so a backend
/// implements one signature format rather than two.
pub trait VerifyWith {
    /// Verifies `signature` over `data` under `public_key`.
    fn verify_with(
        &self,
        suite: Suite,
        public_key: &[u8],
        data: &[u8],
        signature: &[u8],
    ) -> Result<(), PncError>;
}

/// Which generation's PKI rules apply, on top of RFC 5280 basic path
/// validation and the leaf's Annex F profile.
///
/// A separate axis from [`Profile`], because a contract certificate is a
/// contract certificate in both generations: what differs is the rules around
/// it. It is chosen per call, never globally — one station validates -2 and -20
/// chains in the same process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum Rules {
    /// ISO 15118-2: Annex F as published in 2014. The 800-byte certificate
    /// bound \[V2G2-010\] is the schema's, on the wire, and not repeated here.
    Iso2,
    /// ISO 15118-20 with Amd 1:2026: certificates of at most
    /// [`ISO20_MAX_CERTIFICATE_LEN`] bytes, every certificate valid only within
    /// its issuer's validity \[V2G20-3000\]/\[V2G20-3001\], only secp521r1
    /// with `ecdsa-with-SHA512` or Ed448 as [`Policy::algorithms`] allows
    /// (Annex B, \[V2G20-2322\]), and only Annex B's extensions
    /// \[V2G20-2323\].
    Iso20,
}

/// What a chain is validated *for*: the leaf's Annex F profile, and the
/// generation whose rules apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Policy {
    /// The profile the leaf must meet.
    pub profile: Profile,
    /// The generation's rules.
    pub rules: Rules,
    /// The ISO 15118-20 algorithms accepted under [`Rules::Iso20`]
    /// \[V2G20-2320\]; both by default. Ignored under [`Rules::Iso2`].
    pub algorithms: crate::pnc::Algorithms,
}

impl Policy {
    /// `profile` under ISO 15118-2's rules.
    #[must_use]
    pub const fn iso2(profile: Profile) -> Self {
        Self {
            profile,
            rules: Rules::Iso2,
            algorithms: crate::pnc::Algorithms { secp521r1: true, ed448: true },
        }
    }

    /// `profile` under ISO 15118-20's rules, Amd 1 included.
    #[must_use]
    pub const fn iso20(profile: Profile) -> Self {
        Self {
            profile,
            rules: Rules::Iso20,
            algorithms: crate::pnc::Algorithms { secp521r1: true, ed448: true },
        }
    }

    /// The same policy with only `algorithms` accepted under ISO 15118-20.
    #[must_use]
    pub const fn with_algorithms(self, algorithms: crate::pnc::Algorithms) -> Self {
        Self { algorithms, ..self }
    }
}

/// A trust anchor, and where it came from.
///
/// `source` is provenance: the list or store this anchor was taken from — a
/// pool's root store, a deployment's private root, an entry of a certificate
/// trust list. [`Validated::anchor_source`] reports it back, so a caller can
/// apply \[V2G2-925\]'s "the specific root certificate required for a certain
/// use" by where an anchor came from and not only by its name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustAnchor<'a> {
    /// The anchor certificate, DER.
    pub der: &'a [u8],
    /// Where the anchor came from.
    pub source: &'a str,
    /// Which PKI it roots — and so which revocation rules a chain reaching it
    /// is held to.
    pub environment: Environment,
}

impl<'a> TrustAnchor<'a> {
    /// An anchor of the public V2G PKI — a V2G root, an MO or OEM root — and
    /// its provenance.
    #[must_use]
    pub const fn public(der: &'a [u8], source: &'a str) -> Self {
        Self { der, source, environment: Environment::Public }
    }

    /// A private environment's anchor \[V2G2-868\]\[V2G2-927\] and its
    /// provenance.
    #[must_use]
    pub const fn private(der: &'a [u8], source: &'a str) -> Self {
        Self { der, source, environment: Environment::Private }
    }
}

/// The set of trust anchors one side holds.
///
/// A set rather than a file: the European Certificate Trust List the EU's
/// Sustainable Transport Forum is working towards has no published format yet,
/// and whatever carries the anchors in — a trust list, a pool's root store, a
/// deployment's configuration — ends up as this. Borrowed, so it costs nothing
/// on a target without a heap to spare.
///
/// Two lifetimes, on purpose: `'s` is the slice of entries, `'a` the DER and
/// provenance they point at. A [`Validated`] path borrows only `'a`, so it can
/// outlive a set the caller built on the stack for one call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustAnchors<'s, 'a> {
    anchors: &'s [TrustAnchor<'a>],
}

impl<'s, 'a> TrustAnchors<'s, 'a> {
    /// A set over `anchors`.
    #[must_use]
    pub const fn new(anchors: &'s [TrustAnchor<'a>]) -> Self {
        Self { anchors }
    }

    /// The anchors, in the order given.
    pub fn iter(&self) -> core::slice::Iter<'s, TrustAnchor<'a>> {
        self.anchors.iter()
    }

    /// How many anchors the set holds.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.anchors.len()
    }

    /// True when the set holds none — and then nothing validates.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }

    /// The DER subject name of every anchor that parses, in order.
    ///
    /// This is the list a TLS `certificate_authorities` extension carries, and
    /// the other half of [`select_chain`]: a validator advertises what it
    /// holds, and the holder of several chains sends the one that reaches it
    /// \[V2G20-3373\]..\[V2G20-3385\]. An anchor that does not parse cannot
    /// anchor anything, so it is not advertised either.
    pub fn authorities(&self) -> impl Iterator<Item = &'a [u8]> + 's {
        self.anchors
            .iter()
            .filter_map(|a| Certificate::parse(a.der).ok().map(|c| c.subject.encoded))
    }
}

impl<'s, 'a> IntoIterator for &TrustAnchors<'s, 'a> {
    type Item = &'s TrustAnchor<'a>;
    type IntoIter = core::slice::Iter<'s, TrustAnchor<'a>>;

    fn into_iter(self) -> Self::IntoIter {
        self.anchors.iter()
    }
}

/// The `Domain Component` a V2G Root Certificate must carry — Table F.1.
pub const DC_V2G: &str = "V2G";
/// The `Domain Component` an SECC Certificate must carry — Table F.2.
pub const DC_CPO: &str = "CPO";

/// Which Annex F profile a chain's leaf is supposed to meet.
///
/// \[V2G2-884\]: "Each certificate used in this standard shall comply to the
/// appropriate profile specified in this annex". Which profile applies is a
/// fact about *why* the caller is validating, and nothing in the certificate
/// says it — so the caller does.
///
/// That it is a parameter rather than a guess is the point of \[V2G2-925\]: a
/// leaf "shall be treated as invalid, if the trust anchor at the end of the
/// chain does not match the specific root certificate required for a certain
/// use". A chain that validates beautifully to the wrong root is exactly the
/// failure that requirement names, and only the caller knows which root was
/// meant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum Profile {
    /// The station's own certificate — Table F.2, `SECC Cert`.
    ///
    /// `digitalSignature`, and the `Domain Component` `"CPO"`, which
    /// \[V2G2-925\] makes a validity condition rather than a label.
    SeccCertificate,
    /// A contract certificate — Table F.4, `Contract Cert`.
    ///
    /// `digitalSignature` and `nonRepudiation`: the second is what a metering
    /// receipt is for. The `Common Name` is the `EMAID` \[V2G2-108\].
    ContractCertificate,
    /// An OEM provisioning certificate — Table F.5, `OEM Prov. Cert`.
    ///
    /// The `Common Name` is the `CertID` \[V2G2-933\].
    OemProvisioningCertificate,
    /// A leaf whose profile the caller checks itself.
    ///
    /// Basic path validation still applies in full — signatures, validity,
    /// `BasicConstraints`, `pathLenConstraint`, the critical-extension rule —
    /// and only the leaf's own `KeyUsage` and naming are left alone. For the
    /// certificates Annex F profiles that this enumeration does not name yet:
    /// the provisioning service certificate of Table F.3, and the OCSP signer
    /// of Table F.2.
    Unchecked,
}

impl Profile {
    /// The key-usage bits Annex F requires of this profile's leaf.
    #[allow(
        clippy::match_same_arms,
        reason = "one arm per Annex F table; merging the ones that happen to \
                  agree today would hide which table each came from"
    )]
    const fn required_key_usage(self) -> Option<KeyUsage> {
        match self {
            Self::SeccCertificate => Some(KeyUsage::DIGITAL_SIGNATURE),
            // Table F.4 marks `digitalSignature`, `nonRepudiation`,
            // `keyEncipherment` and `keyAgreement` on the contract certificate.
            // Only the first two are required *here*, and the reason is that
            // this profile is about the certificate a vehicle **authorizes**
            // with. `keyAgreement` is what \[V2G2-822\] needs for the
            // `CertificateInstallation` envelope — which [`envelope`] does
            // implement — but that bit belongs to the certificate doing the
            // ECDH, and demanding it of every contract certificate presented
            // for authorization would refuse certificates that work.
            //
            // [`envelope`]: crate::pnc::envelope
            Self::ContractCertificate => {
                Some(KeyUsage::DIGITAL_SIGNATURE.and(KeyUsage::NON_REPUDIATION))
            }
            Self::OemProvisioningCertificate => Some(KeyUsage::DIGITAL_SIGNATURE),
            Self::Unchecked => None,
        }
    }

    /// The `Domain Component` \[V2G2-925\] makes a validity condition for this
    /// profile's leaf.
    const fn required_domain_component(self) -> Option<&'static str> {
        match self {
            Self::SeccCertificate => Some(DC_CPO),
            // Table F.4 and Table F.5 mark the leaf's `Domain Component`
            // optional, so requiring one would refuse conforming certificates.
            _ => None,
        }
    }

    /// Checks a leaf against this profile.
    fn check_leaf(self, leaf: &Certificate<'_>) -> Result<(), ChainError> {
        // \[V2G2-867\]: "A V2G root shall not issue a leaf certificate", and
        // every Annex F leaf row is `CA = false`. A leaf that asserts `cA` is
        // asking to be treated as an issuer by anything that reads it next.
        if leaf.basic_constraints.is_some_and(|bc| bc.ca) {
            return Err(ChainError::Profile { wanted: "a leaf that is not a CA" });
        }
        if let Some(wanted) = self.required_key_usage() {
            // Annex F marks `KeyUsage` critical in every profile, so a leaf
            // without one has not said what its key is for — which for a
            // profile that names required bits is a failure rather than a
            // silence to fill in.
            let usage = leaf.key_usage.ok_or(ChainError::Profile { wanted: "a KeyUsage" })?;
            if !usage.contains(wanted) {
                return Err(ChainError::Profile {
                    wanted: "the KeyUsage bits its profile requires",
                });
            }
        }
        if let Some(wanted) = self.required_domain_component()
            && leaf.subject.domain_component != Some(wanted)
        {
            return Err(ChainError::Profile {
                wanted: "the Domain Component its profile requires",
            });
        }
        Ok(())
    }
}
