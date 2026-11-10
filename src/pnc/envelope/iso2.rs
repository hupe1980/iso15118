//! The ISO 15118-2 contract-key envelope (§7.9.2.4.3).
//!
//! ```text
//! ContractSignatureEncryptedPrivateKey
//!   = IV (16) ‖ AES-128-CBC(K, private key (32))   [V2G2-815]–[V2G2-817]
//! K = leftmost 128 bits of SHA-256(00000001 ‖ Z ‖ 01 55 56)   [V2G2-818]
//! DHpublickey = 04 ‖ X ‖ Y, secp256r1 (65)          [V2G2-819]
//! ```
//!
//! The receiver's static key is the OEM provisioning key for an installation
//! \[V2G2-820\], the current contract key for an update \[V2G2-821\]. [`open`]
//! checks the delivered key against the contract certificate \[V2G2-823\]; no
//! call skips it. The IV must be random and never reused; it is the caller's.

use alloc::vec::Vec;

use super::{KeyAgreement, OTHER_INFO};
use crate::pnc::{Hash, PncError, Suite};

/// Length of the initialisation vector, in bytes. \[V2G2-815\]
pub const IV_LEN: usize = 16;

/// Length of a contract private key, in bytes.
///
/// ISO 15118-2 uses secp256r1 throughout \[V2G2-007\], so the scalar is 256
/// bits — and NOTE 7 of \[V2G2-815\] points out that this is already a multiple
/// of AES's block size, which is why the ciphertext carries no padding.
pub const PRIVATE_KEY_LEN: usize = 32;

/// Length of `DHpublickey` — an uncompressed SEC1 point on secp256r1.
///
/// \[V2G2-819\] and its NOTE 9: `DHpublickey` "is 65 bytes long. The first
/// byte has the fixed value 0x04 indicating the uncompressed form." The
/// compressed form is excluded outright.
pub const DH_PUBLIC_KEY_LEN: usize = 65;

/// Total length of `ContractSignatureEncryptedPrivateKey`.
pub const ENVELOPE_LEN: usize = IV_LEN + PRIVATE_KEY_LEN;

/// AES-128 in CBC mode, over whole blocks and with no padding.
///
/// ISO 15118 needs exactly this and nothing more: two blocks in each direction,
/// a private key that is already a multiple of the block size, and therefore no
/// padding scheme to disagree about \[V2G2-815\] NOTE 7.
pub trait Aes128Cbc {
    /// Decrypts `data`, whose length is a whole number of blocks.
    fn decrypt(&self, key: &[u8; 16], iv: &[u8; IV_LEN], data: &[u8]) -> Result<Vec<u8>, PncError>;

    /// Encrypts `data`, whose length is a whole number of blocks.
    fn encrypt(&self, key: &[u8; 16], iv: &[u8; IV_LEN], data: &[u8]) -> Result<Vec<u8>, PncError>;
}

/// Derives the session key from an ECDH shared secret. \[V2G2-818\]
///
/// The concatenation KDF of NIST SP 800-56A with SHA-256, one round.
///
/// # Errors
///
/// When the backend has no SHA-256.
pub fn session_key(shared_secret: &[u8], hash: &impl Hash) -> Result<[u8; 16], PncError> {
    let mut input = Vec::with_capacity(4 + shared_secret.len() + OTHER_INFO.len());
    input.extend_from_slice(&1u32.to_be_bytes());
    input.extend_from_slice(shared_secret);
    input.extend_from_slice(&OTHER_INFO);
    let digest = hash.digest(Suite::EcdsaSha256, &input)?;
    let mut key = [0u8; 16];
    // A `Hash` implementation that returns a short digest for SHA-256 is a
    // broken backend rather than an input, but truncating silently would turn
    // it into a key of zeros — so the length is taken from the digest and the
    // copy is bounded by both.
    let n = key.len().min(digest.len());
    key[..n].copy_from_slice(&digest[..n]);
    Ok(key)
}

/// Opens a `ContractSignatureEncryptedPrivateKey`, returning the contract
/// private key.
///
/// * `envelope` — the field as it arrived: [`IV_LEN`] bytes of IV followed by
///   the ciphertext \[V2G2-815\].
/// * `dh_public_key` — the sender's `DHpublickey` \[V2G2-819\].
/// * `certificate_public_key` — the public key of the contract certificate this
///   key is supposed to belong to, uncompressed, as
///   [`pki::Certificate::public_key`](crate::pnc::pki::Certificate::public_key)
///   hands it over.
///
/// The last one is not optional, and that is the point: \[V2G2-823\] makes the
/// check part of receiving a contract certificate, and a signature made with a
/// key that does not match its certificate verifies perfectly and is refused by
/// every station.
///
/// # Errors
///
/// [`PncError::BadEnvelope`] for a field that is not [`ENVELOPE_LEN`] bytes or a
/// `DHpublickey` that is not an uncompressed point;
/// [`PncError::KeyMismatch`] when the delivered key does not generate the
/// certificate's public key; and whatever the backend returns for a shared
/// secret it could not compute.
pub fn open(
    envelope: &[u8],
    dh_public_key: &[u8],
    certificate_public_key: &[u8],
    agreement: &impl KeyAgreement,
    hash: &impl Hash,
    cipher: &impl Aes128Cbc,
) -> Result<Vec<u8>, PncError> {
    if envelope.len() != ENVELOPE_LEN {
        return Err(PncError::BadEnvelope { len: envelope.len() });
    }
    if dh_public_key.len() != DH_PUBLIC_KEY_LEN || dh_public_key[0] != 0x04 {
        return Err(PncError::BadEnvelope { len: dh_public_key.len() });
    }
    let (iv, ciphertext) = envelope.split_at(IV_LEN);
    let iv: &[u8; IV_LEN] = iv.try_into().map_err(|_| PncError::BadEnvelope { len: iv.len() })?;

    let shared = agreement.agree(dh_public_key)?;
    let key = session_key(&shared, hash)?;
    let scalar = cipher.decrypt(&key, iv, ciphertext)?;
    if scalar.len() != PRIVATE_KEY_LEN {
        return Err(PncError::BadEnvelope { len: scalar.len() });
    }

    // \[V2G2-823\]. `public_key_of` refuses a scalar outside `1..n`, which is
    // the first half of the requirement; this comparison is the second.
    let derived = agreement.public_key_of(&scalar)?;
    if derived != certificate_public_key {
        return Err(PncError::KeyMismatch);
    }
    Ok(scalar)
}

/// Builds a `ContractSignatureEncryptedPrivateKey`. \[V2G2-815\]
///
/// The secondary actor's half, and the one a test needs to have any confidence
/// in the other. `iv` must be randomly generated and **never reused** under one
/// session key: two private keys encrypted under the same key and IV differ by
/// exactly the XOR of their first blocks. This crate has no RNG, so the caller
/// supplies it, and the requirement is stated here rather than assumed.
///
/// `agreement` is the *sender's* ephemeral key, against the receiver's static
/// public key — the reverse of [`open`]'s pairing, which is what makes the two
/// arrive at the same secret.
///
/// # Errors
///
/// [`PncError::BadEnvelope`] for a private key that is not
/// [`PRIVATE_KEY_LEN`] bytes, and whatever the backend returns otherwise.
pub fn seal(
    private_key: &[u8],
    receiver_public_key: &[u8],
    iv: &[u8; IV_LEN],
    agreement: &impl KeyAgreement,
    hash: &impl Hash,
    cipher: &impl Aes128Cbc,
) -> Result<Vec<u8>, PncError> {
    if private_key.len() != PRIVATE_KEY_LEN {
        return Err(PncError::BadEnvelope { len: private_key.len() });
    }
    let shared = agreement.agree(receiver_public_key)?;
    let key = session_key(&shared, hash)?;
    let ciphertext = cipher.encrypt(&key, iv, private_key)?;
    let mut out = Vec::with_capacity(ENVELOPE_LEN);
    out.extend_from_slice(iv);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}
