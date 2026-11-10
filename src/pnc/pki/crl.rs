//! Certificate revocation lists (RFC 5280 §5), parsed and checked; never
//! downloaded.
//!
//! A station matches a contract or OEM provisioning chain against a CRL before
//! answering `FAILED_CertificateRevoked` \[V2G2-693\]–\[V2G2-695\] or
//! `WARNING_CertificateRevoked` \[V2G20-1412\]\[V2G20-2214\].
//!
//! Complete CRLs from the certificate's issuer only (RFC 5280 §6.3). Indirect,
//! partitioned and delta CRLs are refused as [`EvidenceError::UnsupportedCrl`].

use alloc::vec::Vec;

use super::cert::{Certificate, KeyUsage, read_name, read_signature_algorithm, read_time};
use super::der::{Der, tag};
use super::oid;
use super::status::{EvidenceError, Reason, Source, Standing, Unknown, scan_extensions};
use super::{Hasher, VerifyWith};

/// One DER `CertificateList`, borrowed and structurally checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Crl<'a> {
    /// `tbsCertList`, tag and length included — what the issuer signed.
    tbs: &'a [u8],
    version: Option<u32>,
    inner_algorithm: &'a [u8],
    algorithm: &'a [u8],
    signature: &'a [u8],
    /// The issuer `Name`, as encoded.
    issuer: &'a [u8],
    this_update: i64,
    next_update: Option<i64>,
    /// The contents of `revokedCertificates`, empty when absent.
    revoked: &'a [u8],
    /// The contents of `crlExtensions`' `SEQUENCE OF`, empty when absent.
    extensions: &'a [u8],
}

impl<'a> Crl<'a> {
    /// Parses one DER `CertificateList`.
    ///
    /// Structure only; the entries are read when a certificate is checked.
    ///
    /// # Errors
    ///
    /// [`EvidenceError::Malformed`] for anything that is not RFC 5280's grammar
    /// in DER, [`EvidenceError::UnsupportedSignatureAlgorithm`] for a signature
    /// algorithm outside the V2G profile.
    pub fn parse(der: &'a [u8]) -> Result<Self, EvidenceError> {
        let mut outer = Der::new(der);
        let mut list = outer.nested(tag::SEQUENCE)?;
        outer.finish()?;
        let (tbs_tag, tbs, tbs_contents) = list.any_raw()?;
        if tbs_tag != tag::SEQUENCE {
            return Err(EvidenceError::Malformed);
        }
        let algorithm = read_signature_algorithm(&mut list)?;
        let (unused, signature) = list.bit_string()?;
        if unused != 0 {
            return Err(EvidenceError::Malformed);
        }
        list.finish()?;

        let mut t = Der::new(tbs_contents);
        let version = if t.peek() == Some(tag::INTEGER) { Some(t.small_uint()?) } else { None };
        let inner_algorithm = read_signature_algorithm(&mut t)?;
        let issuer = read_name(&mut t)?.encoded;
        let this_update = read_time(&mut t)?;
        let next_update = match t.peek() {
            Some(tag::UTC_TIME | tag::GENERALIZED_TIME) => Some(read_time(&mut t)?),
            _ => None,
        };
        let revoked = t.optional(tag::SEQUENCE)?.unwrap_or(&[]);
        let extensions = match t.optional(tag::context(0))? {
            Some(wrapped) => {
                let mut reader = Der::new(wrapped);
                let list = reader.expect(tag::SEQUENCE)?;
                reader.finish()?;
                list
            }
            None => &[],
        };
        t.finish()?;
        Ok(Self {
            tbs,
            version,
            inner_algorithm,
            algorithm,
            signature,
            issuer,
            this_update,
            next_update,
            revoked,
            extensions,
        })
    }

    /// What this list says about `cert`, issued by `issuer`, at `now` — or
    /// `None` when it is not `issuer`'s list and so says nothing about `cert`.
    ///
    /// The list is evidence only if (RFC 5280 §5, §6.3.3): it is version 2;
    /// its signature algorithm agrees with itself and with `issuer`'s curve;
    /// `issuer` may sign CRLs (`cRLSign`, where it carries `KeyUsage`); the
    /// signature verifies; `thisUpdate ≤ now ≤ nextUpdate`, with a
    /// `nextUpdate`; `CRLNumber` is present and non-critical; it is not
    /// indirect, partitioned or delta; it holds no critical extension this
    /// crate does not implement, at list or entry level; and no serial is
    /// listed twice. `cert` is revoked if its serial is listed, whatever the
    /// entry's `revocationDate`.
    pub fn check(
        &self,
        cert: &Certificate<'_>,
        issuer: &Certificate<'_>,
        now: i64,
        backend: &(impl VerifyWith + Hasher),
    ) -> Option<Standing> {
        if self.issuer != cert.issuer.encoded || self.issuer != issuer.subject.encoded {
            return None;
        }
        Some(match self.evaluate(cert, issuer, now, backend) {
            Ok(standing) => standing,
            Err(e) => Standing::Unknown(Unknown::Rejected(e)),
        })
    }

    fn evaluate(
        &self,
        cert: &Certificate<'_>,
        issuer: &Certificate<'_>,
        now: i64,
        verifier: &impl VerifyWith,
    ) -> Result<Standing, EvidenceError> {
        // RFC 5280 §5.1.2.1: v2 is `1`, and required because a conforming CRL
        // carries `CRLNumber`, an extension.
        if self.version != Some(1) {
            return Err(EvidenceError::NotV2Crl);
        }
        if self.inner_algorithm != self.algorithm {
            return Err(EvidenceError::UnsupportedSignatureAlgorithm);
        }
        if issuer.key_usage.is_some_and(|ku| !ku.contains(KeyUsage::CRL_SIGN)) {
            return Err(EvidenceError::IssuerMayNotSignCrls);
        }
        let suite = issuer.curve.suite();
        let expected = oid::signature_algorithm(suite);
        if self.algorithm != expected {
            return Err(EvidenceError::UnsupportedSignatureAlgorithm);
        }
        let raw = super::cert::raw_signature(self.signature, issuer.curve)
            .map_err(|_| EvidenceError::BadSignature)?;
        verifier
            .verify_with(suite, issuer.public_key, self.tbs, raw.as_slice())
            .map_err(|_| EvidenceError::BadSignature)?;

        if self.this_update > now {
            return Err(EvidenceError::NotYetValid);
        }
        let next_update = self.next_update.ok_or(EvidenceError::NoNextUpdate)?;
        if next_update < now {
            return Err(EvidenceError::Stale);
        }

        let mut crl_number = false;
        scan_extensions(self.extensions, |id, critical, _| {
            match id {
                oid::CRL_NUMBER if critical => return Err(EvidenceError::CriticalCrlNumber),
                oid::CRL_NUMBER => crl_number = true,
                oid::ISSUING_DISTRIBUTION_POINT | oid::DELTA_CRL_INDICATOR => {
                    return Err(EvidenceError::UnsupportedCrl);
                }
                oid::AUTHORITY_KEY_IDENTIFIER | oid::AUTHORITY_INFO_ACCESS | oid::FRESHEST_CRL
                    if !critical => {}
                _ if critical => return Err(EvidenceError::UnknownCriticalExtension),
                _ => {}
            }
            Ok(())
        })?;
        if !crl_number {
            return Err(EvidenceError::MissingCrlNumber);
        }

        let mut serials: Vec<&[u8]> = Vec::new();
        let mut listed = None;
        let mut entries = Der::new(self.revoked);
        while !entries.is_empty() {
            let mut entry = entries.nested(tag::SEQUENCE)?;
            let serial = entry.expect(tag::INTEGER)?;
            let revoked_at = read_time(&mut entry)?;
            let mut reason = None;
            if let Some(list) = entry.optional(tag::SEQUENCE)? {
                scan_extensions(list, |id, critical, value| {
                    match id {
                        oid::CRL_REASON => {
                            let mut reader = Der::new(value);
                            let code = reader.enumerated()?;
                            reader.finish()?;
                            reason = Some(Reason::from_code(code).ok_or(EvidenceError::Malformed)?);
                        }
                        oid::CERTIFICATE_ISSUER => return Err(EvidenceError::UnsupportedCrl),
                        oid::INVALIDITY_DATE if !critical => {}
                        _ if critical => return Err(EvidenceError::UnknownCriticalExtension),
                        _ => {}
                    }
                    Ok(())
                })?;
            }
            entry.finish()?;
            if serial == cert.serial {
                listed = Some((revoked_at, reason));
            }
            serials.push(serial);
        }
        serials.sort_unstable();
        if serials.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(EvidenceError::DuplicateSerial);
        }

        Ok(match listed {
            Some((revoked_at, reason)) => {
                Standing::Revoked { source: Source::Crl, revoked_at, reason }
            }
            None => {
                Standing::Good { source: Source::Crl, this_update: self.this_update, next_update }
            }
        })
    }
}
