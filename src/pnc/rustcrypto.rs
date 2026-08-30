//! A `RustCrypto` binding for the [`Hash`], [`Sign`] and [`Verify`] traits.
//!
//! The rest of `pnc` deliberately contains no cryptography: ISO 15118-20
//! expects contract keys to live in a secure element, and an ECU with a
//! hardware key store must be able to sign without the private key ever
//! reaching this crate. That is why the three traits exist.
//!
//! It does mean that the obvious case — a charging station on a general-purpose
//! CPU, or a test — had to write the obvious binding itself. This module is
//! that binding, behind the `pnc-rustcrypto` feature: `sha2` for the digests,
//! `p256` and `p521` for the curves. It adds no policy of its own.
//!
//! ```
//! use iso15118::pnc::rustcrypto::{Sha2, SigningKey};
//! use iso15118::pnc::{self, Signed, Suite};
//!
//! // A private scalar, from wherever the contract certificate's key lives.
//! let key = SigningKey::p256(&[0x42; 32])?;
//! let fragment = [0x80, 0x01, 0x02];
//!
//! let signature = pnc::iso2::sign(&[Signed::new("ID1", &fragment)], &Sha2, &key)?;
//! pnc::iso2::verify(
//!     &signature,
//!     &[Signed::new("ID1", &fragment)],
//!     &Sha2,
//!     &key.verifying_key(),
//! )?;
//! # Ok::<_, pnc::PncError>(())
//! ```
//!
//! # What this does not do
//!
//! Certificate handling. A `VerifyingKey` here is a public key, not a trusted
//! one: nothing in this crate parses X.509, walks a V2G chain, or checks a
//! revocation status. Verifying a signature with a key you took out of an
//! unvalidated certificate proves only that whoever sent the certificate also
//! made the signature — see the crate-level notes on V2G PKI.

use alloc::vec::Vec;

use p256::ecdsa::signature::{Signer as _, Verifier as _};
use sha2::Digest as _;

use super::{Hash, PncError, Sign, Suite, Verify};

/// SHA-256 and SHA-512, from `sha2`.
///
/// A unit struct because a hash has no state and no key: one value serves the
/// whole process.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Sha2;

impl Hash for Sha2 {
    fn digest(&self, suite: Suite, data: &[u8]) -> Vec<u8> {
        match suite {
            Suite::EcdsaSha256 => sha2::Sha256::digest(data).to_vec(),
            Suite::EcdsaSha512 => sha2::Sha512::digest(data).to_vec(),
        }
    }
}

/// An ECDSA private key on one of the two ISO 15118 curves.
///
/// The suite the signature asks for and the curve the key is on must agree;
/// signing a `EcdsaSha512` request with a P-256 key is refused rather than
/// silently downgraded, because a suite mismatch is how a peer talks a
/// signature down to the weaker of two algorithms.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum SigningKey {
    /// secp256r1 — ISO 15118-2, and -20's baseline.
    P256(p256::ecdsa::SigningKey),
    /// secp521r1 — ISO 15118-20's higher security level.
    P521(p521::ecdsa::SigningKey),
}

impl SigningKey {
    /// Builds a P-256 key from its 32-byte private scalar, big-endian.
    pub fn p256(scalar: &[u8]) -> Result<Self, PncError> {
        p256::ecdsa::SigningKey::from_slice(scalar)
            .map(Self::P256)
            .map_err(|_| PncError::Backend("not a valid P-256 private scalar"))
    }

    /// Builds a P-521 key from its 66-byte private scalar, big-endian.
    pub fn p521(scalar: &[u8]) -> Result<Self, PncError> {
        p521::ecdsa::SigningKey::from_slice(scalar)
            .map(Self::P521)
            .map_err(|_| PncError::Backend("not a valid P-521 private scalar"))
    }

    /// The suite this key can sign for.
    #[must_use]
    pub const fn suite(&self) -> Suite {
        match self {
            Self::P256(_) => Suite::EcdsaSha256,
            Self::P521(_) => Suite::EcdsaSha512,
        }
    }

    /// The matching public key.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        match self {
            Self::P256(k) => VerifyingKey::P256(*k.verifying_key()),
            Self::P521(k) => VerifyingKey::P521(*k.verifying_key()),
        }
    }
}

impl Sign for SigningKey {
    fn sign(&self, suite: Suite, data: &[u8]) -> Result<Vec<u8>, PncError> {
        if suite != self.suite() {
            return Err(PncError::Backend("the signing key is not on this suite's curve"));
        }
        // ISO 15118 wants the raw `r ‖ s` pair that XMLDSig's ECDSA encoding
        // uses — 64 bytes for P-256, 132 for P-521 — not the ASN.1 DER wrapper
        // most libraries hand back by default. `to_bytes` is that pair.
        //
        // Signing is RFC 6979 deterministic, so this needs no RNG. That is not
        // a convenience: the crate has no randomness by design, and a repeated
        // ECDSA nonce leaks the private key.
        Ok(match self {
            Self::P256(k) => {
                let sig: p256::ecdsa::Signature = k.sign(data);
                sig.to_bytes().to_vec()
            }
            Self::P521(k) => {
                let sig: p521::ecdsa::Signature = k.sign(data);
                sig.to_bytes().to_vec()
            }
        })
    }
}

/// An ECDSA public key on one of the two ISO 15118 curves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerifyingKey {
    /// secp256r1.
    P256(p256::ecdsa::VerifyingKey),
    /// secp521r1.
    P521(p521::ecdsa::VerifyingKey),
}

impl VerifyingKey {
    /// Builds a P-256 key from a SEC1 encoded point.
    ///
    /// That is the `subjectPublicKey` bit string of an X.509
    /// `SubjectPublicKeyInfo` verbatim — `04 ‖ X ‖ Y` uncompressed, or the
    /// compressed form — which is what an X.509 parser hands over.
    pub fn p256_sec1(point: &[u8]) -> Result<Self, PncError> {
        p256::ecdsa::VerifyingKey::from_sec1_bytes(point)
            .map(Self::P256)
            .map_err(|_| PncError::Backend("not a valid P-256 public point"))
    }

    /// The same for P-521.
    pub fn p521_sec1(point: &[u8]) -> Result<Self, PncError> {
        p521::ecdsa::VerifyingKey::from_sec1_bytes(point)
            .map(Self::P521)
            .map_err(|_| PncError::Backend("not a valid P-521 public point"))
    }

    /// The suite this key can verify.
    #[must_use]
    pub const fn suite(&self) -> Suite {
        match self {
            Self::P256(_) => Suite::EcdsaSha256,
            Self::P521(_) => Suite::EcdsaSha512,
        }
    }
}

impl Verify for VerifyingKey {
    fn verify(&self, suite: Suite, data: &[u8], signature: &[u8]) -> Result<(), PncError> {
        // A suite the key is not on is a refusal, not an attempt: this is where
        // an attacker would try to have a P-521 signature checked against a
        // P-256 key, or the reverse.
        if suite != self.suite() {
            return Err(PncError::Backend("the verifying key is not on this suite's curve"));
        }
        match self {
            Self::P256(k) => {
                let sig = p256::ecdsa::Signature::from_slice(signature)
                    .map_err(|_| PncError::BadSignature)?;
                k.verify(data, &sig).map_err(|_| PncError::BadSignature)
            }
            Self::P521(k) => {
                let sig = p521::ecdsa::Signature::from_slice(signature)
                    .map_err(|_| PncError::BadSignature)?;
                k.verify(data, &sig).map_err(|_| PncError::BadSignature)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pnc::Signed;

    fn keys() -> (SigningKey, SigningKey) {
        // P-521's order is 521 bits, so the top seven bits of the first byte
        // of a 66-byte scalar have to be zero.
        let mut p521_scalar = [0x17u8; 66];
        p521_scalar[0] = 0x00;
        (SigningKey::p256(&[0x42; 32]).unwrap(), SigningKey::p521(&p521_scalar).unwrap())
    }

    #[test]
    fn digest_lengths_match_the_suites() {
        assert_eq!(Sha2.digest(Suite::EcdsaSha256, b"x").len(), Suite::EcdsaSha256.digest_len());
        assert_eq!(Sha2.digest(Suite::EcdsaSha512, b"x").len(), Suite::EcdsaSha512.digest_len());
    }

    /// `XMLDSig` carries `r ‖ s`, not DER. A backend that returns DER produces a
    /// signature nobody else can verify, and it is the mistake to make here.
    #[test]
    fn signatures_are_the_raw_r_s_pair() {
        let (p256_key, p521_key) = keys();
        assert_eq!(p256_key.sign(Suite::EcdsaSha256, b"data").unwrap().len(), 64);
        assert_eq!(p521_key.sign(Suite::EcdsaSha512, b"data").unwrap().len(), 132);
    }

    #[test]
    fn a_signature_verifies_against_its_own_key() {
        for key in [keys().0, keys().1] {
            let suite = key.suite();
            let sig = key.sign(suite, b"data").unwrap();
            key.verifying_key().verify(suite, b"data", &sig).unwrap();
            assert_eq!(
                key.verifying_key().verify(suite, b"other", &sig),
                Err(PncError::BadSignature)
            );
        }
    }

    #[test]
    fn a_public_point_round_trips_through_sec1() {
        let (p256_key, p521_key) = keys();
        let VerifyingKey::P256(vk) = p256_key.verifying_key() else { panic!("wrong curve") };
        let point = vk.to_sec1_point(false);
        assert_eq!(VerifyingKey::p256_sec1(point.as_bytes()).unwrap(), p256_key.verifying_key());

        let VerifyingKey::P521(vk) = p521_key.verifying_key() else { panic!("wrong curve") };
        let point = vk.to_sec1_point(false);
        assert_eq!(VerifyingKey::p521_sec1(point.as_bytes()).unwrap(), p521_key.verifying_key());
    }

    /// Signing a 512-bit request with a 256-bit key, or checking one against
    /// the other, is the shape of a suite downgrade. Both directions refuse.
    #[test]
    fn a_key_will_not_stand_in_for_the_other_curve() {
        let (p256_key, p521_key) = keys();
        assert!(p256_key.sign(Suite::EcdsaSha512, b"data").is_err());
        assert!(p521_key.sign(Suite::EcdsaSha256, b"data").is_err());

        let sig = p256_key.sign(Suite::EcdsaSha256, b"data").unwrap();
        assert!(p521_key.verifying_key().verify(Suite::EcdsaSha256, b"data", &sig).is_err());
    }

    /// The whole ISO 15118-2 profile, end to end, with real cryptography.
    #[cfg(feature = "iso2")]
    #[test]
    fn a_real_iso2_signature_verifies() {
        let key = SigningKey::p256(&[0x42; 32]).unwrap();
        let fragment = [0x80, 0x11, 0x22, 0x33];
        let elements = [Signed::new("ID1", &fragment)];

        let signature = crate::pnc::iso2::sign(&elements, &Sha2, &key).unwrap();
        crate::pnc::iso2::verify(&signature, &elements, &Sha2, &key.verifying_key()).unwrap();

        // A different element under the same id must not verify: the digest is
        // over the fragment, not over the name.
        let other = [0x80, 0x44];
        assert!(
            crate::pnc::iso2::verify(
                &signature,
                &[Signed::new("ID1", &other)],
                &Sha2,
                &key.verifying_key(),
            )
            .is_err()
        );
    }
}
