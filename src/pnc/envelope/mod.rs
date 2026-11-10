//! The contract private key, and the envelope it travels in.
//!
//! `CertificateInstallationRes` (and -2's `CertificateUpdateRes`) deliver a
//! contract certificate *and its private key*, encrypted under a key both ends
//! derive by one-pass ECDH (NIST SP 800-56A C(1,1,ECC CDH)) and the
//! concatenation KDF. The generations differ in curve, hash and cipher:
//!
//! | | ISO 15118-2 ([`iso2`]) | ISO 15118-20 ([`iso20`]) |
//! |---|---|---|
//! | ECDH | secp256r1 | secp521r1 or X448 |
//! | KDF hash, key | SHA-256, 128 bits | SHA-512, 256 bits |
//! | Cipher | AES-128-CBC | AES-GCM-256, AAD = PCID ‖ SKI |
//!
//! A -20 vehicle with TPM 2.0 receives a TPM duplication blob instead ([`tpm`]).
//!
//! [`iso2`] and [`iso20`] check that the delivered key belongs to the contract
//! certificate (\[V2G2-823\], \[V2G20-2507\], \[V2G20-2510\]); no call skips
//! it. The arithmetic and ciphers are traits; the randomness (IV, ephemeral key)
//! is the caller's.

use alloc::vec::Vec;

use super::PncError;

pub mod iso2;
pub mod iso20;
pub mod tpm;

/// The `AlgorithmID`, `IDU` and `IDV` both generations' KDF concatenates
/// \[V2G2-818\] \[V2G20-2535\].
pub(crate) const OTHER_INFO: [u8; 3] = [0x01, b'U', b'V'];

/// The elliptic-curve operations the envelope needs, beyond signing.
///
/// Separate from [`Sign`](super::Sign): only certificates with the
/// `keyAgreement` usage do ECDH \[V2G2-822\] \[V2G20-822\].
pub trait KeyAgreement {
    /// One-pass ECDH against `peer_public_key`, returning the shared secret
    /// **Z** — the x-coordinate (secp256r1, secp521r1) or the X448 output, the
    /// field's full width — not a hash of it.
    ///
    /// `peer_public_key` is an uncompressed SEC1 point (secp256r1, secp521r1)
    /// or a 56-byte X448 key.
    fn agree(&self, peer_public_key: &[u8]) -> Result<Vec<u8>, PncError>;

    /// The public key a contract certificate carries for `scalar`, checking
    /// that the scalar is below the group order: an uncompressed point for
    /// secp256r1 and secp521r1; for the X448 path, the RFC 8032 encoding of
    /// `scalar · B` on edwards448, as \[V2G20-2510\] compares it with the Ed448
    /// contract certificate.
    fn public_key_of(&self, scalar: &[u8]) -> Result<Vec<u8>, PncError>;
}

/// AES-GCM-256 with a 96-bit IV and a 128-bit tag (NIST SP 800-38D).
pub trait Aes256Gcm {
    /// Decrypts and authenticates `ciphertext_and_tag`.
    ///
    /// # Errors
    ///
    /// [`PncError::Decrypt`] when the tag does not verify.
    fn open(
        &self,
        key: &[u8; 32],
        iv: &[u8; 12],
        aad: &[u8],
        ciphertext_and_tag: &[u8],
    ) -> Result<Vec<u8>, PncError>;

    /// Encrypts `plaintext`, returning ciphertext ‖ tag.
    fn seal(
        &self,
        key: &[u8; 32],
        iv: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, PncError>;
}
