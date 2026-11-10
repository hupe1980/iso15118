//! The ISO 15118-20 contract-key envelope, for an EVCC without TPM 2.0.
//!
//! ```text
//! SECP521_EncryptedPrivateKey  = IV (12) ‖ C (66) ‖ tag (16)   [V2G20-2499]
//! X448_EncryptedPrivateKey     = IV (12) ‖ C (56) ‖ tag (16)   [V2G20-2502]
//!
//! C, tag = AES-GCM-256(K, IV, AAD, private key)                [V2G20-2497] [V2G20-2500]
//! AAD    = PCID (18 ASCII) ‖ hex(contract SKI) (16 ASCII)      [V2G20-2492]
//! K      = leftmost 256 bits of SHA-512(00000001 ‖ Z ‖ 01 55 56)   [V2G20-2535]
//! DHPublicKey = 04 ‖ X ‖ Y (133, secp521r1) | 00 ‖ u (57, X448)    [V2G20-2531] [V2G20-2532]
//! ```
//!
//! The 521-bit key is carried in 66 bytes with its top 7 bits zero, and an
//! envelope whose are not is refused \[V2G20-2678\]. The EVCC with TPM 2.0
//! imports the key into the TPM instead (7.9.2.5.3); that path is not here.

use alloc::vec::Vec;

use super::{Aes256Gcm, KeyAgreement, OTHER_INFO};
use crate::pnc::{Hash, PncError, Suite};

/// IV length \[V2G20-2497\].
pub const IV_LEN: usize = 12;
/// Tag length \[V2G20-2494\].
pub const TAG_LEN: usize = 16;
/// AAD length: PCID (18) and the SKI in hexadecimal (16) \[V2G20-2492\].
pub const AAD_LEN: usize = 34;

/// The curve the envelope's ECDH ran on — `ECDHCurve` in the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Curve {
    /// secp521r1 — `SECP521_EncryptedPrivateKey` \[V2G20-2674\].
    Secp521r1,
    /// X448 — `X448_EncryptedPrivateKey` \[V2G20-2319\].
    X448,
}

impl Curve {
    /// Length of the private key the envelope carries.
    #[must_use]
    pub const fn private_key_len(self) -> usize {
        match self {
            Self::Secp521r1 => 66,
            Self::X448 => 56,
        }
    }

    /// Length of the encrypted-private-key field.
    #[must_use]
    pub const fn field_len(self) -> usize {
        IV_LEN + self.private_key_len() + TAG_LEN
    }

    /// Length of `DHPublicKey`.
    #[must_use]
    pub const fn dh_public_key_len(self) -> usize {
        match self {
            Self::Secp521r1 => 133,
            Self::X448 => 57,
        }
    }
}

/// The additional authenticated data: the PCID, then the contract certificate's
/// `SubjectKeyIdentifier` as uppercase hexadecimal \[V2G20-2492\].
///
/// # Errors
///
/// [`PncError::BadEnvelope`] when the PCID is not 18 uppercase letters and
/// digits, or the SKI is not 8 bytes.
pub fn aad(pcid: &str, contract_ski: &[u8]) -> Result<[u8; AAD_LEN], PncError> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let pcid = pcid.as_bytes();
    if pcid.len() != 18 || !pcid.iter().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit()) {
        return Err(PncError::BadEnvelope { len: pcid.len() });
    }
    if contract_ski.len() != 8 {
        return Err(PncError::BadEnvelope { len: contract_ski.len() });
    }
    let mut out = [0u8; AAD_LEN];
    out[..18].copy_from_slice(pcid);
    for (i, b) in contract_ski.iter().enumerate() {
        out[18 + 2 * i] = HEX[usize::from(b >> 4)];
        out[19 + 2 * i] = HEX[usize::from(b & 0x0F)];
    }
    Ok(out)
}

/// The session key from the ECDH shared secret: the concatenation KDF with
/// SHA-512, one round, the leftmost 256 bits \[V2G20-2535\].
///
/// # Errors
///
/// When the backend has no SHA-512.
pub fn session_key(shared_secret: &[u8], hash: &impl Hash) -> Result<[u8; 32], PncError> {
    let mut input = Vec::with_capacity(4 + shared_secret.len() + OTHER_INFO.len());
    input.extend_from_slice(&1u32.to_be_bytes());
    input.extend_from_slice(shared_secret);
    input.extend_from_slice(&OTHER_INFO);
    let digest = hash.digest(Suite::EcdsaSha512, &input)?;
    digest
        .get(..32)
        .and_then(|d| <[u8; 32]>::try_from(d).ok())
        .ok_or(PncError::Backend("SHA-512 returned a short digest"))
}

/// The peer key `KeyAgreement::agree` takes, from `DHPublicKey`.
fn peer_key(curve: Curve, dh_public_key: &[u8]) -> Result<&[u8], PncError> {
    let bad = PncError::BadEnvelope { len: dh_public_key.len() };
    if dh_public_key.len() != curve.dh_public_key_len() {
        return Err(bad);
    }
    match (curve, dh_public_key.first()) {
        // An uncompressed SEC1 point; its 1056 LSB are X ‖ Y [V2G20-2531].
        (Curve::Secp521r1, Some(0x04)) => Ok(dh_public_key),
        // Its 448 LSB are the X448 key [V2G20-2532]; the leading byte is zero.
        (Curve::X448, Some(0x00)) => Ok(&dh_public_key[1..]),
        _ => Err(bad),
    }
}

/// `DHPublicKey` for an ephemeral public key: an uncompressed secp521r1 point
/// as is, or an X448 key behind one zero byte.
///
/// # Errors
///
/// [`PncError::BadEnvelope`] for a key of the wrong length.
pub fn dh_public_key(curve: Curve, ephemeral_public_key: &[u8]) -> Result<Vec<u8>, PncError> {
    let mut out = Vec::with_capacity(curve.dh_public_key_len());
    if curve == Curve::X448 {
        out.push(0x00);
    }
    out.extend_from_slice(ephemeral_public_key);
    peer_key(curve, &out)?;
    Ok(out)
}

/// Opens an encrypted contract private key (EVCC side), returning the key.
///
/// * `field` — `SECP521_EncryptedPrivateKey` or `X448_EncryptedPrivateKey`.
/// * `dh_public_key` — the SA's `DHPublicKey`.
/// * `aad` — from [`aad`]: the PCID sent in `CertificateInstallationReq` and
///   the received contract certificate's SKI.
/// * `contract_public_key` — the received contract certificate's key.
/// * `agreement` — the OEM provisioning key \[V2G20-2533\], or its alternate
///   X448 key \[V2G20-2534\].
///
/// # Errors
///
/// [`PncError::BadEnvelope`] for a wrong length or encoding;
/// [`PncError::Decrypt`] when authentication fails \[V2G20-2504\] or the 521-bit
/// key's 7 padding bits are not zero \[V2G20-2678\]; [`PncError::KeyMismatch`]
/// when the key is not the contract certificate's \[V2G20-2507\]
/// \[V2G20-2510\].
#[allow(clippy::too_many_arguments, reason = "every input the requirement names")]
pub fn open(
    curve: Curve,
    field: &[u8],
    dh_public_key: &[u8],
    aad: &[u8; AAD_LEN],
    contract_public_key: &[u8],
    agreement: &impl KeyAgreement,
    hash: &impl Hash,
    gcm: &impl Aes256Gcm,
) -> Result<Vec<u8>, PncError> {
    if field.len() != curve.field_len() {
        return Err(PncError::BadEnvelope { len: field.len() });
    }
    let peer = peer_key(curve, dh_public_key)?;
    let key = session_key(&agreement.agree(peer)?, hash)?;
    let (iv, rest) = field.split_at(IV_LEN);
    let iv: &[u8; IV_LEN] = iv.try_into().map_err(|_| PncError::BadEnvelope { len: iv.len() })?;
    let private_key = gcm.open(&key, iv, aad, rest)?;
    if private_key.len() != curve.private_key_len() {
        return Err(PncError::Decrypt);
    }
    if curve == Curve::Secp521r1 && private_key[0] & 0xFE != 0 {
        return Err(PncError::Decrypt);
    }
    if agreement.public_key_of(&private_key)? != contract_public_key {
        return Err(PncError::KeyMismatch);
    }
    Ok(private_key)
}

/// Builds an encrypted contract private key (SA side).
///
/// `agreement` is the SA's ephemeral key, against the OEM provisioning
/// certificate's key (`receiver_public_key`: an uncompressed secp521r1 point or
/// the 56-byte X448 alternate key). `iv` must be random and never reused under
/// one session key; this crate has no RNG. Send the ephemeral public key as
/// [`dh_public_key`].
///
/// # Errors
///
/// [`PncError::BadEnvelope`] for a private key of the wrong length or, on
/// secp521r1, with any of its top 7 bits set.
#[allow(clippy::too_many_arguments, reason = "every input the requirement names")]
pub fn seal(
    curve: Curve,
    private_key: &[u8],
    receiver_public_key: &[u8],
    iv: &[u8; IV_LEN],
    aad: &[u8; AAD_LEN],
    agreement: &impl KeyAgreement,
    hash: &impl Hash,
    gcm: &impl Aes256Gcm,
) -> Result<Vec<u8>, PncError> {
    if private_key.len() != curve.private_key_len()
        || (curve == Curve::Secp521r1 && private_key[0] & 0xFE != 0)
    {
        return Err(PncError::BadEnvelope { len: private_key.len() });
    }
    let key = session_key(&agreement.agree(receiver_public_key)?, hash)?;
    let sealed = gcm.seal(&key, iv, aad, private_key)?;
    let mut out = Vec::with_capacity(curve.field_len());
    out.extend_from_slice(iv);
    out.extend_from_slice(&sealed);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_aad_is_pcid_then_uppercase_hex_ski() {
        let a =
            aad("WMIV1234567890ABC1", &[0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]).unwrap();
        assert_eq!(&a, b"WMIV1234567890ABC10123456789ABCDEF");
        assert!(aad("wmiv1234567890abc1", &[0; 8]).is_err());
        assert!(aad("SHORT", &[0; 8]).is_err());
        assert!(aad("WMIV1234567890ABC1", &[0; 20]).is_err());
    }

    #[test]
    fn dh_public_keys_have_one_encoding_per_curve() {
        assert!(peer_key(Curve::Secp521r1, &[0x04; 133]).is_ok());
        assert!(peer_key(Curve::Secp521r1, &[0x03; 133]).is_err());
        assert!(peer_key(Curve::Secp521r1, &[0x04; 132]).is_err());
        let mut x = [0x11u8; 57];
        x[0] = 0;
        assert_eq!(peer_key(Curve::X448, &x).unwrap().len(), 56);
        x[0] = 1;
        assert!(peer_key(Curve::X448, &x).is_err());
    }
}
