//! The object identifiers an ISO 15118 certificate can carry, as encoded bytes.
//!
//! Comparing OIDs as byte slices rather than decoding them to arc sequences is
//! not a shortcut: DER gives each OID exactly one encoding, so byte equality
//! *is* OID equality, and a decoder is a place for two of them to compare equal
//! when they are not.
//!
//! Each constant is the OID's **contents**, without the `0x06` tag and length —
//! which is what [`Der::expect`](super::der::Der::expect) hands back.

/// `id-ecPublicKey`, 1.2.840.10045.2.1.
pub(crate) const EC_PUBLIC_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
/// `prime256v1` / `secp256r1`, 1.2.840.10045.3.1.7.
pub(crate) const PRIME256V1: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
/// `secp521r1`, 1.3.132.0.35.
pub(crate) const SECP521R1: &[u8] = &[0x2B, 0x81, 0x04, 0x00, 0x23];
/// `ecdsa-with-SHA256`, 1.2.840.10045.4.3.2.
pub(crate) const ECDSA_WITH_SHA256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
/// `ecdsa-with-SHA512`, 1.2.840.10045.4.3.4.
pub(crate) const ECDSA_WITH_SHA512: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04];

/// `id-at-commonName`, 2.5.4.3.
pub(crate) const COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
/// `id-at-organizationName`, 2.5.4.10.
pub(crate) const ORGANIZATION: &[u8] = &[0x55, 0x04, 0x0A];
/// `id-domainComponent`, 0.9.2342.19200300.100.1.25.
pub(crate) const DOMAIN_COMPONENT: &[u8] =
    &[0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64, 0x01, 0x19];

/// `id-ce-subjectKeyIdentifier`, 2.5.29.14.
pub(crate) const SUBJECT_KEY_IDENTIFIER: &[u8] = &[0x55, 0x1D, 0x0E];
/// `id-ce-keyUsage`, 2.5.29.15.
pub(crate) const KEY_USAGE: &[u8] = &[0x55, 0x1D, 0x0F];
/// `id-ce-basicConstraints`, 2.5.29.19.
pub(crate) const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1D, 0x13];
/// `id-ce-certificatePolicies`, 2.5.29.32.
pub(crate) const CERTIFICATE_POLICIES: &[u8] = &[0x55, 0x1D, 0x20];
/// `id-ce-cRLDistributionPoints`, 2.5.29.31.
pub(crate) const CRL_DISTRIBUTION_POINTS: &[u8] = &[0x55, 0x1D, 0x1F];
/// `id-ce-authorityKeyIdentifier`, 2.5.29.35.
pub(crate) const AUTHORITY_KEY_IDENTIFIER: &[u8] = &[0x55, 0x1D, 0x23];
/// `id-ce-extKeyUsage`, 2.5.29.37.
pub(crate) const EXT_KEY_USAGE: &[u8] = &[0x55, 0x1D, 0x25];
/// `id-pe-authorityInfoAccess`, 1.3.6.1.5.5.7.1.1.
pub(crate) const AUTHORITY_INFO_ACCESS: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01];
