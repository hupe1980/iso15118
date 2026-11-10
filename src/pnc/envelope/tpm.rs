//! The ISO 15118-20 contract key for an EVCC with TPM 2.0 (§7.9.2.5.3).
//!
//! When the OEM provisioning certificate carries TPM information, the SA
//! encrypts the contract key under the vehicle's TPM storage key as a TPM 2.0
//! outer duplication wrapper (\[V2G20-2518\], \[V2G20-2595\]), and the vehicle
//! hands it to `TPM2_Import` (\[V2G20-2523\]). [`seal`] is the SA's half;
//! [`import_inputs`] turns the message into `TPM2_Import`'s three arguments.
//!
//! ```text
//! seed      = KDFe(SHA-512, Z, "DUPLICATE", Qe.x, Qs.x, 512)      ECDH with the storage key
//! name      = 000D ‖ SHA-512(TPMT_PUBLIC of the contract key)      Table 19
//! symKey    = KDFa(SHA-512, seed, "STORAGE", name, ∅, 256)
//! hmacKey   = KDFa(SHA-512, seed, "INTEGRITY", ∅, ∅, 512)
//! encSens   = AES-256-CFB(symKey, IV 0, TPM2B_SENSITIVE)
//! TPM_EncryptedPrivateKey = TPM2B_DIGEST(HMAC-SHA-512(hmacKey, encSens ‖ name)) ‖ encSens
//! ```
//!
//! The seed is derived with the TPM's `KDFe`, because `TPM2_Import` derives it
//! that way and accepts nothing else; \[V2G20-2519\]'s reference to
//! \[V2G20-2535\] is read as the ECDH. Only secp521r1: TCG defines no Curve448
//! profile yet (Table 19, NOTE 4). Driving the TPM is the caller's.

use alloc::vec::Vec;

use super::KeyAgreement;
use crate::pnc::pki::Certificate;
use crate::pnc::{Hash, PncError, Suite};

/// The largest `TPM_EncryptedPrivateKey` \[V2G20-2521\].
pub const MAX_ENCRYPTED_PRIVATE_KEY_LEN: usize = 206;
/// secp521r1 coordinate and scalar length.
const P521: usize = 66;
/// SHA-512 digest length — the storage key's and the contract key's `nameAlg`.
const SHA512: usize = 64;

const TPM_ALG_ECC: u16 = 0x0023;
const TPM_ALG_SHA512: u16 = 0x000D;
const TPM_ALG_NULL: u16 = 0x0010;
const TPM_ECC_NIST_P521: u16 = 0x0005;
const SENSITIVE_DATA_ORIGIN: u32 = 1 << 5;
const USER_WITH_AUTH: u32 = 1 << 6;
const ADMIN_WITH_POLICY: u32 = 1 << 7;
const SIGN: u32 = 1 << 18;

/// HMAC-SHA-512, for the `KDFa` and the wrapper's integrity.
pub trait HmacSha512 {
    /// HMAC-SHA-512 of `data` under `key`.
    fn hmac_sha512(&self, key: &[u8], data: &[u8]) -> Result<[u8; SHA512], PncError>;
}

/// AES-256 in full-block CFB mode with an all-zero IV, as the outer wrapper
/// uses it (TPM 2.0 Part 1 §23.3.2).
pub trait Aes256Cfb {
    /// Encrypts `data` of any length.
    fn encrypt_zero_iv(&self, key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, PncError>;
}

/// The vehicle's TPM information from its OEM provisioning certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TpmInfo {
    /// The storage key, X ‖ Y on secp521r1 \[V2G20-2516\].
    pub storage_key: [u8; 2 * P521],
    /// The contract key's policy digest, when the OEM seals it to one
    /// \[V2G20-2517\].
    pub policy_digest: Option<[u8; SHA512]>,
}

/// Whether the TPM method applies: the certificate carries `TPMStorageKey` or
/// `TpmPolicyDigest` \[V2G20-2595\].
#[must_use]
pub const fn applies(oem_certificate: &Certificate<'_>) -> bool {
    oem_certificate.tpm_storage_key.is_some() || oem_certificate.tpm_policy_digest.is_some()
}

/// Decodes the certificate's TPM information.
///
/// # Errors
///
/// [`PncError::BadEnvelope`] when a value is not canonical base64 of 132 or 64
/// bytes, or a policy digest comes without a storage key.
pub fn tpm_info(oem_certificate: &Certificate<'_>) -> Result<Option<TpmInfo>, PncError> {
    let Some(key) = oem_certificate.tpm_storage_key else {
        return match oem_certificate.tpm_policy_digest {
            Some(_) => Err(PncError::BadEnvelope { len: 0 }),
            None => Ok(None),
        };
    };
    let storage_key = base64::<{ 2 * P521 }>(key)?;
    let policy_digest = oem_certificate.tpm_policy_digest.map(base64::<SHA512>).transpose()?;
    Ok(Some(TpmInfo { storage_key, policy_digest }))
}

/// What the SA sends: `TPM_EncryptedPrivateKey` and `DHPublicKey`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    /// `TPM_EncryptedPrivateKey`: the integrity digest and the encrypted
    /// sensitive area, unpadded \[V2G20-2521\].
    pub encrypted_private_key: Vec<u8>,
    /// `DHPublicKey`: the SA's ephemeral point, `04 ‖ X ‖ Y` \[V2G20-2520\].
    pub dh_public_key: Vec<u8>,
}

/// `TPM2_Import`'s three inputs, marshaled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportInputs {
    /// `objectPublic`: `TPM2B_PUBLIC` of the contract key (Table 19).
    pub public: Vec<u8>,
    /// `duplicate`: `TPM2B_PRIVATE`.
    pub duplicate: Vec<u8>,
    /// `inSymSeed`: `TPM2B_ENCRYPTED_SECRET` holding the SA's ephemeral point.
    pub in_sym_seed: Vec<u8>,
}

/// Seals a secp521r1 contract key for the vehicle's TPM (SA side).
///
/// `ephemeral` is the SA's fresh key and `ephemeral_public` its point
/// (`04 ‖ X ‖ Y`); `contract_public` the contract certificate's point.
///
/// # Errors
///
/// [`PncError::BadEnvelope`] for a key or point of the wrong length; whatever
/// the backend returns otherwise.
#[allow(clippy::too_many_arguments, reason = "every input the wrapper names")]
pub fn seal(
    contract_scalar: &[u8],
    contract_public: &[u8],
    tpm: &TpmInfo,
    ephemeral: &impl KeyAgreement,
    ephemeral_public: &[u8],
    hash: &impl Hash,
    hmac: &impl HmacSha512,
    cfb: &impl Aes256Cfb,
) -> Result<Sealed, PncError> {
    if contract_scalar.len() != P521 {
        return Err(PncError::BadEnvelope { len: contract_scalar.len() });
    }
    let (qe_x, _) = point(ephemeral_public)?;
    let public = public_area(contract_public, tpm.policy_digest.as_ref())?;
    let name = name(&public, hash)?;

    let mut storage = Vec::with_capacity(1 + 2 * P521);
    storage.push(0x04);
    storage.extend_from_slice(&tpm.storage_key);
    let z = ephemeral.agree(&storage)?;
    let seed = kdfe(hash, &z, b"DUPLICATE", qe_x, &tpm.storage_key[..P521])?;

    let sym_key = kdfa(hmac, &seed, b"STORAGE", &name, 32)?;
    let hmac_key = kdfa(hmac, &seed, b"INTEGRITY", &[], SHA512)?;
    let sym_key: [u8; 32] =
        sym_key.try_into().map_err(|_| PncError::Backend("KDFa returned a short key"))?;
    let encrypted = cfb.encrypt_zero_iv(&sym_key, &sensitive(contract_scalar))?;
    let mut integrity_input = encrypted.clone();
    integrity_input.extend_from_slice(&name);
    let integrity = hmac.hmac_sha512(&hmac_key, &integrity_input)?;

    let mut encrypted_private_key = Vec::with_capacity(2 + SHA512 + encrypted.len());
    tpm2b(&mut encrypted_private_key, &integrity);
    encrypted_private_key.extend_from_slice(&encrypted);
    Ok(Sealed { encrypted_private_key, dh_public_key: ephemeral_public.to_vec() })
}

/// `TPM2_Import`'s inputs from what the vehicle received (vehicle side).
///
/// # Errors
///
/// [`PncError::BadEnvelope`] when `TPM_EncryptedPrivateKey` is over 206 bytes
/// \[V2G20-2521\] or not an integrity digest followed by an encrypted sensitive
/// area of a secp521r1 key, or `DHPublicKey` is not `04 ‖ X ‖ Y`.
pub fn import_inputs(
    contract_public: &[u8],
    policy_digest: Option<&[u8; SHA512]>,
    encrypted_private_key: &[u8],
    dh_public_key: &[u8],
) -> Result<ImportInputs, PncError> {
    let bad = PncError::BadEnvelope { len: encrypted_private_key.len() };
    if encrypted_private_key.len() > MAX_ENCRYPTED_PRIVATE_KEY_LEN {
        return Err(bad);
    }
    // TPM2B_DIGEST (SHA-512) then the encrypted TPM2B_SENSITIVE, whose length
    // CFB keeps: 2 + 2 + 2 + 2 + seedValue (0..=64) + 2 + 66 bytes.
    let rest = match encrypted_private_key {
        [0x00, 0x40, rest @ ..] if rest.len() >= SHA512 => &rest[SHA512..],
        _ => return Err(bad),
    };
    if !(76..=76 + SHA512).contains(&rest.len()) {
        return Err(bad);
    }
    let (x, y) = point(dh_public_key)?;
    let public = public_area(contract_public, policy_digest)?;

    let mut public_2b = Vec::with_capacity(2 + public.len());
    tpm2b(&mut public_2b, &public);
    let mut duplicate = Vec::with_capacity(2 + encrypted_private_key.len());
    tpm2b(&mut duplicate, encrypted_private_key);
    let mut point_bytes = Vec::with_capacity(4 + 2 * P521);
    tpm2b(&mut point_bytes, x);
    tpm2b(&mut point_bytes, y);
    let mut in_sym_seed = Vec::with_capacity(2 + point_bytes.len());
    tpm2b(&mut in_sym_seed, &point_bytes);
    Ok(ImportInputs { public: public_2b, duplicate, in_sym_seed })
}

/// Splits an uncompressed secp521r1 point into X and Y.
fn point(bytes: &[u8]) -> Result<(&[u8], &[u8]), PncError> {
    match bytes {
        [0x04, xy @ ..] if xy.len() == 2 * P521 => Ok(xy.split_at(P521)),
        _ => Err(PncError::BadEnvelope { len: bytes.len() }),
    }
}

/// The contract key's `TPMT_PUBLIC` per Table 19.
fn public_area(contract_public: &[u8], policy: Option<&[u8; SHA512]>) -> Result<Vec<u8>, PncError> {
    let (x, y) = point(contract_public)?;
    let attributes = SENSITIVE_DATA_ORIGIN
        | SIGN
        | if policy.is_some() { ADMIN_WITH_POLICY } else { USER_WITH_AUTH };
    let mut out = Vec::with_capacity(16 + SHA512 + 4 + 2 * P521);
    out.extend_from_slice(&TPM_ALG_ECC.to_be_bytes());
    out.extend_from_slice(&TPM_ALG_SHA512.to_be_bytes());
    out.extend_from_slice(&attributes.to_be_bytes());
    tpm2b(&mut out, policy.map_or(&[][..], |p| &p[..]));
    out.extend_from_slice(&TPM_ALG_NULL.to_be_bytes()); // symmetric
    out.extend_from_slice(&TPM_ALG_NULL.to_be_bytes()); // scheme
    out.extend_from_slice(&TPM_ECC_NIST_P521.to_be_bytes());
    out.extend_from_slice(&TPM_ALG_NULL.to_be_bytes()); // kdf
    tpm2b(&mut out, x);
    tpm2b(&mut out, y);
    Ok(out)
}

/// The object's Name: `nameAlg ‖ H(TPMT_PUBLIC)`.
fn name(public: &[u8], hash: &impl Hash) -> Result<Vec<u8>, PncError> {
    let mut out = TPM_ALG_SHA512.to_be_bytes().to_vec();
    out.extend_from_slice(&hash.digest(Suite::EcdsaSha512, public)?);
    Ok(out)
}

/// `TPM2B_SENSITIVE` of an ECC private key with empty `authValue` and
/// `seedValue`.
fn sensitive(scalar: &[u8]) -> Vec<u8> {
    let mut inner = Vec::with_capacity(8 + P521);
    inner.extend_from_slice(&TPM_ALG_ECC.to_be_bytes());
    tpm2b(&mut inner, &[]);
    tpm2b(&mut inner, &[]);
    tpm2b(&mut inner, scalar);
    let mut out = Vec::with_capacity(2 + inner.len());
    tpm2b(&mut out, &inner);
    out
}

/// TPM 2.0 `KDFe` with SHA-512, one round (Part 1 §11.4.10.3).
fn kdfe(
    hash: &impl Hash,
    z: &[u8],
    label: &[u8],
    party_u: &[u8],
    party_v: &[u8],
) -> Result<Vec<u8>, PncError> {
    let mut input = 1u32.to_be_bytes().to_vec();
    input.extend_from_slice(z);
    input.extend_from_slice(label);
    input.push(0);
    input.extend_from_slice(party_u);
    input.extend_from_slice(party_v);
    hash.digest(Suite::EcdsaSha512, &input)
}

/// TPM 2.0 `KDFa` with HMAC-SHA-512, for up to 64 bytes (Part 1 §11.4.10.2).
fn kdfa(
    hmac: &impl HmacSha512,
    key: &[u8],
    label: &[u8],
    context_u: &[u8],
    len: usize,
) -> Result<Vec<u8>, PncError> {
    let mut input = 1u32.to_be_bytes().to_vec();
    input.extend_from_slice(label);
    input.push(0);
    input.extend_from_slice(context_u);
    let bits = u32::try_from(len * 8).map_err(|_| PncError::Backend("KDFa length"))?;
    input.extend_from_slice(&bits.to_be_bytes());
    Ok(hmac.hmac_sha512(key, &input)?[..len].to_vec())
}

/// Appends `data` as a TPM2B: a big-endian `u16` size, then the bytes.
fn tpm2b(out: &mut Vec<u8>, data: &[u8]) {
    let len = u16::try_from(data.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&data[..usize::from(len)]);
}

/// Strict base64 (RFC 4648 §4, padded, canonical) of exactly `N` bytes.
fn base64<const N: usize>(text: &[u8]) -> Result<[u8; N], PncError> {
    let bad = || PncError::BadEnvelope { len: text.len() };
    if text.len() != N.div_ceil(3) * 4 {
        return Err(bad());
    }
    let value = |c: u8| -> Option<u32> {
        Some(u32::from(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        }))
    };
    let mut out = [0u8; N];
    let mut written = 0;
    for chunk in text.chunks(4) {
        let pad = chunk.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && written + 3 - pad != N) {
            return Err(bad());
        }
        let mut acc = 0u32;
        for &c in &chunk[..4 - pad] {
            acc = (acc << 6) | value(c).ok_or_else(bad)?;
        }
        acc <<= 6 * u32::try_from(pad).unwrap_or(0);
        let bytes = acc.to_be_bytes();
        let take = 3 - pad;
        // Canonical: the bits a padded group leaves over must be zero.
        if pad > 0 && bytes[1 + take..].iter().any(|&b| b != 0) {
            return Err(bad());
        }
        out[written..written + take].copy_from_slice(&bytes[1..=take]);
        written += take;
    }
    if written == N { Ok(out) } else { Err(bad()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_is_strict() {
        assert_eq!(base64::<3>(b"TWFu").unwrap(), *b"Man");
        assert_eq!(base64::<2>(b"TWE=").unwrap(), *b"Ma");
        assert!(base64::<2>(b"TWF=").is_err()); // non-canonical trailing bits
        assert!(base64::<3>(b"TWE=").is_err()); // wrong length
        assert!(base64::<3>(b"TW-u").is_err());
    }

    #[test]
    fn the_public_area_follows_table_19() {
        let mut point = [0u8; 133];
        point[0] = 0x04;
        let public = public_area(&point, None).unwrap();
        assert_eq!(&public[..8], &[0x00, 0x23, 0x00, 0x0D, 0x00, 0x04, 0x00, 0x60]);
        assert_eq!(public.len(), 2 + 2 + 4 + 2 + 2 + 2 + 2 + 2 + 2 * 68);
        let with_policy = public_area(&point, Some(&[7; 64])).unwrap();
        assert_eq!(&with_policy[4..8], &[0x00, 0x04, 0x00, 0xA0]);
    }
}
