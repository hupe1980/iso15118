//! A `RustCrypto` binding for the [`Hash`], [`Sign`] and [`Verify`] traits.
//!
//! The rest of `pnc` contains no cryptography, so a secure element can hold the
//! contract key. This module is the binding for a key in memory — a station on
//! a general-purpose CPU, or a test — behind the `pnc-rustcrypto` feature:
//! `sha2` for the digests, `p256` and `p521` for the curves, `aes`, `cbc` and
//! `aes-gcm` for the contract-key [`envelope`](super::envelope). Ed448, X448
//! and SHAKE256 need `pnc-rustcrypto-ed448` as well. It adds no policy.
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
//! # Certificates
//!
//! [`Backend`] is this module's [`VerifyWith`] implementation, which is what
//! [`pnc::pki`](super::pki) needs to walk a chain: a key arrives inside each
//! certificate rather than being configured, so the verification takes the
//! point rather than a key object.
//!
use alloc::vec::Vec;

use p256::ecdsa::signature::{Signer as _, Verifier as _};
use sha2::Digest as _;

use super::envelope::iso2::{Aes128Cbc, IV_LEN};
use super::envelope::tpm::{Aes256Cfb, HmacSha512};
use super::envelope::{Aes256Gcm, KeyAgreement};
use super::pki::{HashAlgorithm, Hasher, VerifyWith};
use super::{Hash, PncError, Sign, Suite, Verify};

/// SHA-256 and SHA-512 from `sha2`; SHAKE256 (64 bytes) from `sha3` with
/// `pnc-rustcrypto-ed448`.
///
/// A unit struct because a hash has no state and no key: one value serves the
/// whole process.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Sha2;

impl Hash for Sha2 {
    fn digest(&self, suite: Suite, data: &[u8]) -> Result<Vec<u8>, PncError> {
        Ok(match suite {
            Suite::EcdsaSha256 => sha2::Sha256::digest(data).to_vec(),
            Suite::EcdsaSha512 => sha2::Sha512::digest(data).to_vec(),
            #[cfg(feature = "pnc-rustcrypto-ed448")]
            Suite::Ed448 => {
                use ed448_goldilocks::shake::{ExtendableOutput as _, Update as _};
                let mut out = alloc::vec![0u8; Suite::Ed448.digest_len()];
                let mut shake = ed448_goldilocks::shake::Shake256::default();
                shake.update(data);
                shake.finalize_xof_into(&mut out);
                out
            }
            #[cfg(not(feature = "pnc-rustcrypto-ed448"))]
            Suite::Ed448 => return Err(PncError::Backend(NO_ED448)),
        })
    }
}

/// The refusal for an Ed448 operation without `pnc-rustcrypto-ed448`.
#[cfg(not(feature = "pnc-rustcrypto-ed448"))]
const NO_ED448: &str = "Ed448, X448 and SHAKE256 need the pnc-rustcrypto-ed448 feature";

/// A private signing key on one of the ISO 15118 algorithms.
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
    /// secp521r1 — ISO 15118-20 \[V2G20-2674\].
    P521(p521::ecdsa::SigningKey),
    /// Ed448 — ISO 15118-20 \[V2G20-2319\].
    #[cfg(feature = "pnc-rustcrypto-ed448")]
    Ed448(alloc::boxed::Box<ed448_goldilocks::SigningKey>),
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

    /// Builds an Ed448 key from its 57-byte RFC 8032 secret.
    #[cfg(feature = "pnc-rustcrypto-ed448")]
    pub fn ed448(secret: &[u8]) -> Result<Self, PncError> {
        ed448_goldilocks::SigningKey::try_from(secret)
            .map(|k| Self::Ed448(alloc::boxed::Box::new(k)))
            .map_err(|_| PncError::Backend("not a 57-byte Ed448 secret"))
    }

    /// The suite this key can sign for.
    #[must_use]
    pub const fn suite(&self) -> Suite {
        match self {
            Self::P256(_) => Suite::EcdsaSha256,
            Self::P521(_) => Suite::EcdsaSha512,
            #[cfg(feature = "pnc-rustcrypto-ed448")]
            Self::Ed448(_) => Suite::Ed448,
        }
    }

    /// The matching public key.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        match self {
            Self::P256(k) => VerifyingKey::P256(*k.verifying_key()),
            Self::P521(k) => VerifyingKey::P521(*k.verifying_key()),
            #[cfg(feature = "pnc-rustcrypto-ed448")]
            Self::Ed448(k) => VerifyingKey::Ed448(k.verifying_key()),
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
            // Pure Ed448 (RFC 8032, empty context): 114 bytes.
            #[cfg(feature = "pnc-rustcrypto-ed448")]
            Self::Ed448(k) => {
                let sig: ed448_goldilocks::Signature = k.sign(data);
                sig.to_bytes().to_vec()
            }
        })
    }
}

/// A public verifying key on one of the ISO 15118 algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerifyingKey {
    /// secp256r1.
    P256(p256::ecdsa::VerifyingKey),
    /// secp521r1.
    P521(p521::ecdsa::VerifyingKey),
    /// Ed448.
    #[cfg(feature = "pnc-rustcrypto-ed448")]
    Ed448(ed448_goldilocks::VerifyingKey),
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

    /// An Ed448 key from its 57-byte RFC 8032 encoding.
    #[cfg(feature = "pnc-rustcrypto-ed448")]
    pub fn ed448(bytes: &[u8]) -> Result<Self, PncError> {
        let bytes: &[u8; 57] =
            bytes.try_into().map_err(|_| PncError::Backend("not a 57-byte Ed448 key"))?;
        ed448_goldilocks::VerifyingKey::from_bytes(bytes)
            .map(Self::Ed448)
            .map_err(|_| PncError::Backend("not a valid Ed448 public key"))
    }

    /// The suite this key can verify.
    #[must_use]
    pub const fn suite(&self) -> Suite {
        match self {
            Self::P256(_) => Suite::EcdsaSha256,
            Self::P521(_) => Suite::EcdsaSha512,
            #[cfg(feature = "pnc-rustcrypto-ed448")]
            Self::Ed448(_) => Suite::Ed448,
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
            #[cfg(feature = "pnc-rustcrypto-ed448")]
            Self::Ed448(k) => {
                let sig = ed448_goldilocks::Signature::try_from(signature)
                    .map_err(|_| PncError::BadSignature)?;
                k.verify(data, &sig).map_err(|_| PncError::BadSignature)
            }
        }
    }
}

/// The stateless half of this backend: verification against a key that arrived
/// in a certificate.
///
/// A unit struct, because there is nothing to configure. [`VerifyingKey`]
/// implements [`Verify`] for a key this side *holds*; this implements
/// [`VerifyWith`] for a key that comes out of the DER being checked, which is
/// every key in a chain above the trust anchor the caller configured.
///
/// ```no_run
/// use iso15118::pnc::pki::{Evidence, Policy, Profile, TrustAnchor, TrustAnchors, chain};
/// use iso15118::pnc::rustcrypto::Backend;
/// # fn f(leaf: &[u8], sub: &[u8], root: &[u8], stapled: &[&[u8]], now: i64) -> Result<(), chain::ChainError> {
/// // A vehicle validating the station's chain with the stapled OCSP responses.
/// let anchors = [TrustAnchor::public(root, "V2G Root")];
/// let policy = Policy::iso2(Profile::SeccCertificate);
/// let evidence = Evidence::ocsp(stapled);
/// let path =
///     chain::validate(&[leaf, sub], &TrustAnchors::new(&anchors), policy, &evidence, now, &Backend)?;
/// # let _ = path;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Backend;

/// SHA-1, SHA-256, SHA-384 and SHA-512 for OCSP `CertID`s and `ResponderID`s.
impl Hasher for Backend {
    fn hash(&self, alg: HashAlgorithm, data: &[u8]) -> Option<Vec<u8>> {
        Some(match alg {
            HashAlgorithm::Sha1 => sha1::Sha1::digest(data).to_vec(),
            HashAlgorithm::Sha256 => sha2::Sha256::digest(data).to_vec(),
            HashAlgorithm::Sha384 => sha2::Sha384::digest(data).to_vec(),
            HashAlgorithm::Sha512 => sha2::Sha512::digest(data).to_vec(),
        })
    }
}

impl VerifyWith for Backend {
    fn verify_with(
        &self,
        suite: Suite,
        public_key: &[u8],
        data: &[u8],
        signature: &[u8],
    ) -> Result<(), PncError> {
        let key = match suite {
            Suite::EcdsaSha256 => VerifyingKey::p256_sec1(public_key)?,
            Suite::EcdsaSha512 => VerifyingKey::p521_sec1(public_key)?,
            #[cfg(feature = "pnc-rustcrypto-ed448")]
            Suite::Ed448 => VerifyingKey::ed448(public_key)?,
            #[cfg(not(feature = "pnc-rustcrypto-ed448"))]
            Suite::Ed448 => return Err(PncError::Backend(NO_ED448)),
        };
        key.verify(suite, data, signature)
    }
}

/// A private key used for **key agreement** rather than for signing.
///
/// A separate type from [`SigningKey`]: only certificates carrying
/// `keyAgreement` do ECDH \[V2G2-822\] \[V2G20-822\]. The vehicle holds the
/// static key (its OEM provisioning key, or under ISO 15118-20 its alternate
/// X448 key \[V2G20-2534\]); the sender holds an ephemeral one, which needs
/// randomness this crate does not have.
#[derive(Clone)]
#[non_exhaustive]
pub enum AgreementKey {
    /// secp256r1 — the ISO 15118-2 envelope.
    P256(p256::SecretKey),
    /// secp521r1 — the ISO 15118-20 envelope \[V2G20-2526\].
    P521(p521::SecretKey),
    /// X448 — the ISO 15118-20 envelope's alternative \[V2G20-2527\].
    #[cfg(feature = "pnc-rustcrypto-ed448")]
    X448([u8; 56]),
}

impl core::fmt::Debug for AgreementKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::P256(_) => "AgreementKey::P256(..)",
            Self::P521(_) => "AgreementKey::P521(..)",
            #[cfg(feature = "pnc-rustcrypto-ed448")]
            Self::X448(_) => "AgreementKey::X448(..)",
        })
    }
}

impl AgreementKey {
    /// A secp256r1 scalar, 32 bytes big-endian, in `1..n`.
    pub fn p256(scalar: &[u8]) -> Result<Self, PncError> {
        p256::SecretKey::from_slice(scalar)
            .map(Self::P256)
            .map_err(|_| PncError::Backend("not a valid P-256 private scalar"))
    }

    /// A secp521r1 scalar, 66 bytes big-endian, in `1..n`.
    pub fn p521(scalar: &[u8]) -> Result<Self, PncError> {
        p521::SecretKey::from_slice(scalar)
            .map(Self::P521)
            .map_err(|_| PncError::Backend("not a valid P-521 private scalar"))
    }

    /// An X448 private key, 56 bytes (RFC 7748).
    #[cfg(feature = "pnc-rustcrypto-ed448")]
    pub fn x448(key: &[u8]) -> Result<Self, PncError> {
        <[u8; 56]>::try_from(key)
            .map(Self::X448)
            .map_err(|_| PncError::Backend("not a 56-byte X448 private key"))
    }

    /// The public key to send: an uncompressed point (secp256r1 is -2's
    /// `DHpublickey` \[V2G2-819\]), or the 56-byte X448 key.
    #[must_use]
    pub fn public_key(&self) -> Vec<u8> {
        match self {
            Self::P256(k) => {
                use p256::elliptic_curve::sec1::ToSec1Point as _;
                k.public_key().to_sec1_point(false).as_bytes().to_vec()
            }
            Self::P521(k) => {
                use p521::elliptic_curve::sec1::ToSec1Point as _;
                k.public_key().to_sec1_point(false).as_bytes().to_vec()
            }
            #[cfg(feature = "pnc-rustcrypto-ed448")]
            Self::X448(k) => x448::x448_unchecked(*k, x448::X448_BASEPOINT_BYTES).to_vec(),
        }
    }
}

impl KeyAgreement for AgreementKey {
    fn agree(&self, peer_public_key: &[u8]) -> Result<Vec<u8>, PncError> {
        // `diffie_hellman` is NIST's C(1, 1, ECC CDH) and returns the shared
        // x-coordinate, which is Z; hashing it is the envelope's KDF.
        match self {
            Self::P256(k) => {
                let peer = p256::PublicKey::from_sec1_bytes(peer_public_key)
                    .map_err(|_| PncError::Backend("not a valid P-256 public point"))?;
                let shared = p256::ecdh::diffie_hellman(k.to_nonzero_scalar(), peer.as_affine());
                Ok(shared.raw_secret_bytes().to_vec())
            }
            Self::P521(k) => {
                let peer = p521::PublicKey::from_sec1_bytes(peer_public_key)
                    .map_err(|_| PncError::Backend("not a valid P-521 public point"))?;
                let shared = p521::ecdh::diffie_hellman(k.to_nonzero_scalar(), peer.as_affine());
                Ok(shared.raw_secret_bytes().to_vec())
            }
            // RFC 7748 §6.2: a low-order peer key gives an all-zero secret,
            // which `x448` reports as `None` and is refused.
            #[cfg(feature = "pnc-rustcrypto-ed448")]
            Self::X448(k) => {
                let peer = <[u8; 56]>::try_from(peer_public_key)
                    .map_err(|_| PncError::Backend("not a 56-byte X448 public key"))?;
                x448::x448(*k, peer)
                    .map(|z| z.to_vec())
                    .ok_or(PncError::Backend("the X448 shared secret is zero"))
            }
        }
    }

    fn public_key_of(&self, scalar: &[u8]) -> Result<Vec<u8>, PncError> {
        match self {
            // `from_slice` refuses a scalar outside `1..n` — the first half of
            // [V2G2-823] / [V2G20-2507]; the caller compares the second.
            Self::P256(_) => Ok(Self::p256(scalar)?.public_key()),
            Self::P521(_) => Ok(Self::p521(scalar)?.public_key()),
            // [V2G20-2510]: the scalar, little-endian as RFC 7748/8032 encode
            // it, below the edwards448 group order, times the base point,
            // encoded as an Ed448 public key.
            #[cfg(feature = "pnc-rustcrypto-ed448")]
            Self::X448(_) => {
                use ed448_goldilocks::{EdwardsPoint, EdwardsScalar, EdwardsScalarBytes};
                if scalar.len() != 56 {
                    return Err(PncError::Backend("not a 56-byte X448 scalar"));
                }
                let mut bytes = EdwardsScalarBytes::default();
                bytes[..56].copy_from_slice(scalar);
                let s = Option::<EdwardsScalar>::from(EdwardsScalar::from_canonical_bytes(&bytes))
                    .ok_or(PncError::Backend("the scalar is not below the group order"))?;
                Ok(EdwardsPoint::GENERATOR.scalar_mul(&s).to_affine().compress().0.to_vec())
            }
        }
    }
}

/// HMAC-SHA-512, for the TPM duplication wrapper.
impl HmacSha512 for Backend {
    fn hmac_sha512(&self, key: &[u8], data: &[u8]) -> Result<[u8; 64], PncError> {
        use hmac::{KeyInit as _, Mac as _};
        let mut mac = hmac::Hmac::<sha2::Sha512>::new_from_slice(key)
            .map_err(|_| PncError::Backend("HMAC key"))?;
        mac.update(data);
        Ok(mac.finalize().into_bytes().into())
    }
}

/// AES-256-CFB with an all-zero IV, for the TPM duplication wrapper.
impl Aes256Cfb for Backend {
    fn encrypt_zero_iv(&self, key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, PncError> {
        use cfb_mode::cipher::KeyIvInit as _;
        let mut out = data.to_vec();
        cfb_mode::Encryptor::<aes::Aes256>::new(key.into(), &[0u8; 16].into()).encrypt(&mut out);
        Ok(out)
    }
}

/// AES-GCM-256 with a 96-bit IV and a 128-bit tag — the ISO 15118-20
/// envelope's cipher \[V2G20-2497\].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AesGcm;

impl Aes256Gcm for AesGcm {
    fn open(
        &self,
        key: &[u8; 32],
        iv: &[u8; 12],
        aad: &[u8],
        ciphertext_and_tag: &[u8],
    ) -> Result<Vec<u8>, PncError> {
        use aes_gcm::aead::{Aead as _, KeyInit as _, Payload};
        aes_gcm::Aes256Gcm::new(key.into())
            .decrypt(iv.into(), Payload { msg: ciphertext_and_tag, aad })
            .map_err(|_| PncError::Decrypt)
    }

    fn seal(
        &self,
        key: &[u8; 32],
        iv: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, PncError> {
        use aes_gcm::aead::{Aead as _, KeyInit as _, Payload};
        aes_gcm::Aes256Gcm::new(key.into())
            .encrypt(iv.into(), Payload { msg: plaintext, aad })
            .map_err(|_| PncError::Backend("AES-GCM encryption failed"))
    }
}

/// AES-128-CBC over whole blocks, with no padding.
///
/// ISO 15118 needs one shape of this and no other: two blocks each way, a
/// private key already a multiple of the block size, and therefore no padding
/// scheme for two implementations to disagree about \[V2G2-815\] NOTE 7. A
/// length that is not a whole number of blocks is refused rather than padded,
/// because padding something the standard says is not padded is how a plaintext
/// grows a block nobody expected.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Aes128;

impl Aes128Cbc for Aes128 {
    fn decrypt(&self, key: &[u8; 16], iv: &[u8; IV_LEN], data: &[u8]) -> Result<Vec<u8>, PncError> {
        use cbc::cipher::{BlockModeDecrypt as _, KeyIvInit as _};

        if data.is_empty() || !data.len().is_multiple_of(16) {
            return Err(PncError::Backend("the ciphertext is not a whole number of AES blocks"));
        }
        let mut out = data.to_vec();
        cbc::Decryptor::<aes::Aes128>::new(key.into(), iv.into())
            .decrypt_padded::<cbc::cipher::block_padding::NoPadding>(&mut out)
            .map_err(|_| PncError::Backend("AES-CBC decryption failed"))?;
        Ok(out)
    }

    fn encrypt(&self, key: &[u8; 16], iv: &[u8; IV_LEN], data: &[u8]) -> Result<Vec<u8>, PncError> {
        use cbc::cipher::{BlockModeEncrypt as _, KeyIvInit as _};

        if data.is_empty() || !data.len().is_multiple_of(16) {
            return Err(PncError::Backend("the plaintext is not a whole number of AES blocks"));
        }
        let mut out = data.to_vec();
        let len = out.len();
        cbc::Encryptor::<aes::Aes128>::new(key.into(), iv.into())
            .encrypt_padded::<cbc::cipher::block_padding::NoPadding>(&mut out, len)
            .map_err(|_| PncError::Backend("AES-CBC encryption failed"))?;
        Ok(out)
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
        assert_eq!(
            Sha2.digest(Suite::EcdsaSha256, b"x").unwrap().len(),
            Suite::EcdsaSha256.digest_len()
        );
        assert_eq!(
            Sha2.digest(Suite::EcdsaSha512, b"x").unwrap().len(),
            Suite::EcdsaSha512.digest_len()
        );
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
