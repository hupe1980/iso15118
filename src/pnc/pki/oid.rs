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

/// `id-ce-cRLNumber`, 2.5.29.20.
pub(crate) const CRL_NUMBER: &[u8] = &[0x55, 0x1D, 0x14];
/// `id-ce-cRLReasons`, 2.5.29.21 — a CRL entry's `reasonCode`.
pub(crate) const CRL_REASON: &[u8] = &[0x55, 0x1D, 0x15];
/// `id-ce-invalidityDate`, 2.5.29.24.
pub(crate) const INVALIDITY_DATE: &[u8] = &[0x55, 0x1D, 0x18];
/// `id-ce-deltaCRLIndicator`, 2.5.29.27.
pub(crate) const DELTA_CRL_INDICATOR: &[u8] = &[0x55, 0x1D, 0x1B];
/// `id-ce-issuingDistributionPoint`, 2.5.29.28.
pub(crate) const ISSUING_DISTRIBUTION_POINT: &[u8] = &[0x55, 0x1D, 0x1C];
/// `id-ce-certificateIssuer`, 2.5.29.29 — what makes a CRL indirect.
pub(crate) const CERTIFICATE_ISSUER: &[u8] = &[0x55, 0x1D, 0x1D];
/// `id-ce-freshestCRL`, 2.5.29.46.
pub(crate) const FRESHEST_CRL: &[u8] = &[0x55, 0x1D, 0x2E];

/// `id-kp-OCSPSigning`, 1.3.6.1.5.5.7.3.9 — the extended key usage a delegated
/// OCSP responder carries (RFC 6960 §4.2.2.2).
pub(crate) const KP_OCSP_SIGNING: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09];
/// `id-pkix-ocsp-basic`, 1.3.6.1.5.5.7.48.1.1.
pub(crate) const OCSP_BASIC: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01];
/// `id-pkix-ocsp-nonce`, 1.3.6.1.5.5.7.48.1.2.
pub(crate) const OCSP_NONCE: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02];
/// `id-pkix-ocsp-crl`, 1.3.6.1.5.5.7.48.1.3.
pub(crate) const OCSP_CRL: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x03];
/// `id-pkix-ocsp-nocheck`, 1.3.6.1.5.5.7.48.1.5.
pub(crate) const OCSP_NO_CHECK: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x05];
/// `id-pkix-ocsp-archive-cutoff`, 1.3.6.1.5.5.7.48.1.6.
pub(crate) const OCSP_ARCHIVE_CUTOFF: &[u8] =
    &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x06];

/// `id-sha1`, 1.3.14.3.2.26.
pub(crate) const SHA1: &[u8] = &[0x2B, 0x0E, 0x03, 0x02, 0x1A];
/// `id-sha256`, 2.16.840.1.101.3.4.2.1.
pub(crate) const SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
/// `id-sha384`, 2.16.840.1.101.3.4.2.2.
pub(crate) const SHA384: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
/// `id-sha512`, 2.16.840.1.101.3.4.2.3.
pub(crate) const SHA512: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];

/// `id-Ed448`, 1.3.101.113 (RFC 8410) — key and signature algorithm.
pub(crate) const ED448: &[u8] = &[0x2B, 0x65, 0x71];
/// `id-X448`, 1.3.101.111 (RFC 8410).
pub(crate) const X448: &[u8] = &[0x2B, 0x65, 0x6F];
/// `id-ce-subjectAltPublicKeyInfo`, 2.5.29.72 (ITU-T X.509) — the OEM
/// provisioning certificate's X448 key (ISO 15118-20 Annex B.7.2).
pub(crate) const SUBJECT_ALT_PUBLIC_KEY_INFO: &[u8] = &[0x55, 0x1D, 0x48];
/// `id-pe-subjectInfoAccess`, 1.3.6.1.5.5.7.1.11.
pub(crate) const SUBJECT_INFO_ACCESS: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x0B];
/// ISO 15118-20's own extensions, 1.0.15118.20.0.{1..6} (Annex B.2.3): the
/// arc, without the last component.
pub(crate) const ISO15118_20_EXTENSIONS: &[u8] = &[0x28, 0xF6, 0x0E, 0x14, 0x00];

/// The signature algorithm OID a suite signs with.
pub(crate) const fn signature_algorithm(suite: crate::pnc::Suite) -> &'static [u8] {
    match suite {
        crate::pnc::Suite::EcdsaSha256 => ECDSA_WITH_SHA256,
        crate::pnc::Suite::EcdsaSha512 => ECDSA_WITH_SHA512,
        crate::pnc::Suite::Ed448 => ED448,
    }
}
