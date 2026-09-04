//! The V2G PKI: reading ISO 15118 certificates and validating a chain to a
//! trust anchor.
//!
//! A signature that verifies proves *the key that signed these bytes made this
//! signature*, and nothing about **whose** key that was. The `GenChallenge`
//! binding in [`super`] narrows *which session*; this module is the other half.
//! Without both, a signature verified against a key from an unvalidated
//! certificate proves only that whoever sent the certificate also made it.
//!
//! # What ISO 15118 fixes
//!
//! X.509 is a large grammar and RFC 5280 §6.1 a large algorithm. ISO 15118 pins
//! almost every input to both, which is what makes this tractable in a `no_std`
//! crate with no dependencies:
//!
//! | | |
//! |---|---|
//! | Signature algorithm | `ecdsa-with-SHA256` \[V2G2-006\] (`-SHA512` for -20's higher level) |
//! | Curve | `secp256r1` \[V2G2-007\], `secp521r1` in -20 |
//! | Path length | at most 3 non-self-signed certificates \[V2G2-009\] |
//! | Certificate size | at most 800 bytes DER \[V2G2-010\]; the schema enforces it |
//! | Extensions | the set in Annex F, `KeyUsage` and `BasicConstraints` critical in every profile |
//! | Name constraints, policy mapping | not used |
//!
//! What is implemented is basic path validation — signatures, validity periods,
//! `BasicConstraints`, `pathLenConstraint`, `KeyUsage`, the critical-extension
//! rule — plus the Annex F profile of whichever leaf the caller names. A trust
//! anchor may sit anywhere in the path: \[V2G2-927\] makes a Private Operator
//! Root an anchor for SECC certificates and \[V2G2-868\] has it sign leaves
//! directly.
//!
//! # What is **not** here: revocation
//!
//! No OCSP, no CRL. A revoked contract certificate validates here exactly as a
//! live one does, and that is a limitation to plan around.
//!
//! The standard says why it is hard rather than merely undone — Annex F's note
//! that "as access to OCSP services can not be guaranteed during charging, the
//! usage of OCSP can only be recommended but not be mandatory", and
//! \[V2G2-868\] dropping it from private environments. A vehicle in a basement
//! has no path to a responder; a station has one and a clearing house behind it.
//!
//! So the answer belongs where it already exists. That back end is asking
//! whether to authorize this contract at all, and
//! [`Validated::subject_common_name`] is the `EMAID` to ask about. An OCSP
//! client inside a sans-I/O crate would put a network round trip in a charge
//! loop with a 25 ms budget.
//!
//! # Time is a real input
//!
//! [`chain::validate`] takes seconds since the Unix epoch — deliberately not
//! [`session::Instant`](crate::session::Instant), which is a monotonic count for
//! measuring timeouts where a validity period needs a wall clock. \[V2G2-886\]
//! lets a vehicle choose its own time accuracy and \[V2G2-910\] makes checking
//! validity periods a *should*, so a vehicle with no trustworthy time has to say
//! so rather than pass a number it does not have.
//!
//! # Example
//!
//! ```no_run
//! use iso15118::pnc::pki::{Profile, chain};
//! # use iso15118::pnc::{PncError, Suite};
//! # struct Backend;
//! # impl iso15118::pnc::pki::VerifyWith for Backend {
//! #     fn verify_with(&self, _: Suite, _: &[u8], _: &[u8], _: &[u8]) -> Result<(), PncError> { Ok(()) }
//! # }
//! # fn f(leaf: &[u8], sub_ca: &[u8], v2g_root: &[u8], now: i64) -> Result<(), chain::ChainError> {
//! // Leaf first, as both generations put it on the wire.
//! let validated = chain::validate(
//!     &[leaf, sub_ca],
//!     &[v2g_root],
//!     Profile::ContractCertificate,
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
mod der;
mod oid;

pub use cert::{BasicConstraints, CertError, Certificate, Curve, KeyUsage, Name};
pub use chain::{ChainError, MAX_PATH_LEN, Validated, validate};
pub use der::DerError;

use crate::pnc::{PncError, Suite};

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
            // Only the first two are required here: `keyAgreement` is what
            // \[V2G2-822\] needs for the `CertificateInstallation` envelope,
            // which this crate does not implement, and demanding a bit for a
            // flow that is not here would refuse certificates that work.
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
