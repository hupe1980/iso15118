//! The contract private key, and the envelope it travels in.
//!
//! `CertificateInstallationRes` and `CertificateUpdateRes` deliver a contract
//! certificate *and its private key* — which is the one place in ISO 15118
//! where a secret crosses the wire. \[V2G2-814\] permits it only encrypted, and
//! the rest of §7.9.2.4.3 pins every choice:
//!
//! ```text
//! ContractSignatureEncryptedPrivateKey
//!   = IV ‖ AES-128-CBC( K, private key )          [V2G2-815], [V2G2-817]
//!         IV   16 bytes, random, never reused
//!         K    the ECDH session key, below
//!         key  32 bytes, big-endian, no padding   [V2G2-816]
//!
//! K = leftmost 128 bits of                        [V2G2-818]
//!     SHA-256( 00 00 00 01 ‖ Z ‖ 01 55 56 )
//!         Z    the ECDH shared secret's x-coordinate
//!         01   AlgorithmID
//!         55   IDU, the sender ("U")
//!         56   IDV, the receiver ("V")
//!
//! DHpublickey = the sender's ephemeral public key, uncompressed  [V2G2-819]
//! ```
//!
//! The ECDH is the ephemeral-static one-pass scheme of NIST SP 800-56A
//! §6.2.2.2: the sender is party U with an ephemeral key pair, and the receiver
//! is party V, whose *static* key is the one already in a certificate — the OEM
//! Provisioning Certificate for an installation \[V2G2-820\], the existing
//! Contract Certificate for an update \[V2G2-821\]. The key derivation is the
//! concatenation KDF with SHA-256, and 128 bits fits in one round, which is why
//! the counter above is `1` and appears once.
//!
//! # The check that is easy to leave out
//!
//! \[V2G2-823\] is explicit, and it is the only thing standing between a
//! vehicle and a contract key that does not belong to the certificate it
//! arrived with: the value "must be strictly smaller than the order of the base
//! point, and multiplication of the base point with this value must generate a
//! key matching the public key of the contract certificate".
//!
//! So [`open`] takes the certificate's public key and does that comparison, and
//! there is no call that skips it. A vehicle that installs an unchecked key has
//! a contract it can never use and cannot diagnose — every later signature it
//! makes is valid, over the wrong key, and every station refuses it.
//!
//! # What is still the caller's
//!
//! The randomness, as everywhere in this crate. Sealing needs an ephemeral key
//! pair and an IV that is "randomly generated ... and never reused"
//! \[V2G2-815\]; both are parameters, and a repeated IV under one session key
//! leaks the difference between two private keys.
//!
//! The elliptic-curve arithmetic and the block cipher, as traits —
//! [`KeyAgreement`] and [`Aes128Cbc`] — for the same reason [`Sign`](super::Sign)
//! is one: a contract key that is meant to live in a secure element must never
//! materialise in this crate's address space, and on that hardware the ECDH
//! happens inside the element too.

use alloc::vec::Vec;

use super::{Hash, PncError, Suite};

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

/// The `AlgorithmID`, `IDU` and `IDV` of \[V2G2-818\], in the order the KDF
/// concatenates them.
const OTHER_INFO: [u8; 3] = [0x01, b'U', b'V'];

/// The elliptic-curve operations the envelope needs, beyond signing.
///
/// Separate from [`Sign`](super::Sign) because they are a different capability
/// on the same key: a secure element that will sign with a contract key may or
/// may not agree with it, and ISO 15118 says so — \[V2G2-822\] requires the
/// `keyAgreement` usage flag on exactly the certificates whose keys do this,
/// and on no others.
pub trait KeyAgreement {
    /// One-pass ECDH against `peer_public_key`, returning the shared secret.
    ///
    /// `peer_public_key` is the sender's `DHpublickey`, uncompressed and
    /// [`DH_PUBLIC_KEY_LEN`] bytes. The result is **Z** — the x-coordinate of
    /// the shared point, big-endian, the field's full width — and not a hash of
    /// it: NIST SP 800-56A's derivation is [`session_key`]'s job, and a backend
    /// that pre-hashes would produce a key nothing else agrees with.
    fn agree(&self, peer_public_key: &[u8]) -> Result<Vec<u8>, PncError>;

    /// The uncompressed public point for a private scalar.
    ///
    /// What \[V2G2-823\] compares a delivered contract key against. It takes no
    /// key of its own: this is arithmetic on the curve rather than an operation
    /// on *this* key, and a backend that cannot do it out of band cannot make
    /// the check the requirement asks for.
    fn public_key_of(&self, scalar: &[u8]) -> Result<Vec<u8>, PncError>;
}

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
/// The concatenation KDF of NIST SP 800-56A with SHA-256, over the fixed
/// `OtherInfo` ISO 15118 pins. 128 bits fit in one round of a 256-bit hash, so
/// the counter is `1` and appears once — which is why the whole derivation is
/// one digest and needs nothing from the caller but the [`Hash`] it already has.
///
/// Exposed because a caller doing the SA's half, or checking a capture by hand,
/// needs the same sixteen bytes and should not re-derive the layout from prose.
#[must_use]
pub fn session_key(shared_secret: &[u8], hash: &impl Hash) -> [u8; 16] {
    let mut input = Vec::with_capacity(4 + shared_secret.len() + OTHER_INFO.len());
    input.extend_from_slice(&1u32.to_be_bytes());
    input.extend_from_slice(shared_secret);
    input.extend_from_slice(&OTHER_INFO);
    let digest = hash.digest(Suite::EcdsaSha256, &input);
    let mut key = [0u8; 16];
    // A `Hash` implementation that returns a short digest for SHA-256 is a
    // broken backend rather than an input, but truncating silently would turn
    // it into a key of zeros — so the length is taken from the digest and the
    // copy is bounded by both.
    let n = key.len().min(digest.len());
    key[..n].copy_from_slice(&digest[..n]);
    key
}

/// Opens a `ContractSignatureEncryptedPrivateKey`, returning the contract
/// private key.
///
/// * `envelope` — the field as it arrived: [`IV_LEN`] bytes of IV followed by
///   the ciphertext \[V2G2-815\].
/// * `dh_public_key` — the sender's `DHpublickey` \[V2G2-819\].
/// * `certificate_public_key` — the public key of the contract certificate this
///   key is supposed to belong to, uncompressed, as
///   [`pki::Certificate::public_key`](super::pki::Certificate::public_key)
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
    let key = session_key(&shared, hash);
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
    let key = session_key(&shared, hash);
    let ciphertext = cipher.encrypt(&key, iv, private_key)?;
    let mut out = Vec::with_capacity(ENVELOPE_LEN);
    out.extend_from_slice(iv);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}
