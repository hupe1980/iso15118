//! OCSP responses (RFC 6960), parsed and checked; never requested.
//!
//! The vehicle checks the responses stapled in the TLS handshake: the Sub-CAs
//! under ISO 15118-2 \[V2G2-070\]\[V2G2-875\], every certificate under
//! ISO 15118-20 \[V2G20-1240\]\[V2G20-2413\]\[V2G20-2414\]. A response
//! obtained any other way is checked the same way.
//!
//! A response is matched to a certificate by its `CertID`, not by its position
//! in the handshake: the position is not signed, the `CertID` is.

use super::cert::{Certificate, raw_signature, read_signature_algorithm, read_time};
use super::der::{Der, DerError, tag};
use super::oid;
use super::status::{EvidenceError, Reason, Source, Standing, Unknown, scan_extensions};
use super::{HashAlgorithm, Hasher, Rules, VerifyWith};

/// The most `SingleResponse`s one response may carry.
pub const MAX_SINGLE_RESPONSES: usize = 16;

/// The most certificates a response's `certs` field may carry: a responder, two
/// Sub-CAs and a cross-certificate \[V2G20-1008\].
pub const MAX_RESPONDER_CERTS: usize = 4;

/// The longest validity period an OCSP response may claim under ISO 15118-2:
/// four weeks \[V2G2-876\].
pub const ISO2_MAX_RESPONSE_VALIDITY: i64 = 28 * 86_400;

/// The longest validity period an OCSP response may claim under ISO 15118-20:
/// one week \[V2G20-1021\].
pub const ISO20_MAX_RESPONSE_VALIDITY: i64 = 7 * 86_400;

/// The validity bound of `rules`' generation.
#[must_use]
pub const fn max_response_validity(rules: Rules) -> i64 {
    match rules {
        Rules::Iso2 => ISO2_MAX_RESPONSE_VALIDITY,
        Rules::Iso20 => ISO20_MAX_RESPONSE_VALIDITY,
    }
}

/// One DER `OCSPResponse`, borrowed and structurally checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OcspResponse<'a> {
    status: u8,
    basic: Option<Basic<'a>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Basic<'a> {
    /// `tbsResponseData`, tag and length included — what the responder signed.
    tbs: &'a [u8],
    responder: ResponderId<'a>,
    /// The contents of `responses`.
    responses: &'a [u8],
    /// A critical `responseExtensions` entry this crate does not implement.
    unknown_critical: bool,
    signature_algorithm: &'a [u8],
    /// The `ECDSA-Sig-Value`, DER.
    signature: &'a [u8],
    /// The contents of `certs`, empty when absent.
    certs: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResponderId<'a> {
    /// The responder's subject `Name`, as encoded.
    ByName(&'a [u8]),
    /// SHA-1 of the responder's public key bits (RFC 6960 §4.2.1).
    ByKey(&'a [u8]),
}

/// A `CertStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    Good,
    Revoked { at: i64, reason: Option<Reason> },
    Unknown,
}

/// One `SingleResponse`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Single<'a> {
    hash: Option<HashAlgorithm>,
    name_hash: &'a [u8],
    key_hash: &'a [u8],
    serial: &'a [u8],
    status: Status,
    this_update: i64,
    next_update: Option<i64>,
    unknown_critical: bool,
}

impl<'a> OcspResponse<'a> {
    /// Parses one DER `OCSPResponse`.
    ///
    /// Structure only: every field is read and bounded here, and nothing is
    /// believed until [`Self::check`] has verified who signed it.
    ///
    /// # Errors
    ///
    /// [`EvidenceError::Malformed`] for anything that is not the RFC 6960
    /// grammar in DER, [`EvidenceError::UnsupportedResponseType`] for a
    /// response that is not `id-pkix-ocsp-basic`, [`EvidenceError::TooLarge`]
    /// past [`MAX_SINGLE_RESPONSES`] or [`MAX_RESPONDER_CERTS`].
    pub fn parse(der: &'a [u8]) -> Result<Self, EvidenceError> {
        let mut outer = Der::new(der);
        let mut response = outer.nested(tag::SEQUENCE)?;
        outer.finish()?;
        let status = response.enumerated()?;
        // successful(0) malformedRequest(1) internalError(2) tryLater(3)
        // sigRequired(5) unauthorized(6); 4 is unused.
        if status > 6 || status == 4 {
            return Err(EvidenceError::Malformed);
        }
        let bytes = response.optional(tag::context(0))?;
        response.finish()?;
        if status != 0 {
            // Only a successful response carries `responseBytes`.
            return if bytes.is_some() {
                Err(EvidenceError::Malformed)
            } else {
                Ok(Self { status, basic: None })
            };
        }
        let mut wrapper = Der::new(bytes.ok_or(EvidenceError::Malformed)?);
        let mut response_bytes = wrapper.nested(tag::SEQUENCE)?;
        wrapper.finish()?;
        let response_type = response_bytes.expect(tag::OID)?;
        let inner = response_bytes.expect(tag::OCTET_STRING)?;
        response_bytes.finish()?;
        if response_type != oid::OCSP_BASIC {
            return Err(EvidenceError::UnsupportedResponseType);
        }
        Ok(Self { status, basic: Some(parse_basic(inner)?) })
    }

    /// The `responseStatus`: `0` is `successful`.
    #[must_use]
    pub const fn status(&self) -> u8 {
        self.status
    }

    /// What this response says about `cert`, issued by `issuer`, at `now`,
    /// under `rules` — or `None` when it says nothing about it (no
    /// `SingleResponse` names it, or the response was not `successful` and so
    /// names nothing).
    ///
    /// A `SingleResponse` names `cert` when its `CertID` hashes `issuer`'s
    /// subject and key to the values it carries and its serial is `cert`'s
    /// (RFC 6960 §4.1.1). It is then believed only if all of RFC 6960
    /// §3.2's checks pass: the signer is `issuer` or a certificate `issuer`
    /// signed directly carrying `id-kp-OCSPSigning` and valid at `now`
    /// (§4.2.2.2; \[V2G2-875\], \[V2G20-2413\]); the `ResponderID` names that
    /// signer; the signature verifies \[V2G20-2414\]; `thisUpdate ≤ now ≤
    /// nextUpdate`; and `nextUpdate − thisUpdate` is within the generation's
    /// bound ([`max_response_validity`]).
    pub fn check(
        &self,
        cert: &Certificate<'_>,
        issuer: &Certificate<'_>,
        rules: Rules,
        now: i64,
        backend: &(impl VerifyWith + Hasher),
    ) -> Option<Standing> {
        let basic = self.basic.as_ref()?;
        let single = match find_single(basic, cert, issuer, backend) {
            Ok(Some(single)) => single,
            Ok(None) => return None,
            Err(e) => return Some(Standing::Unknown(Unknown::Rejected(e))),
        };
        Some(match evaluate(basic, &single, issuer, rules, now, backend) {
            Ok(standing) => standing,
            Err(e) => Standing::Unknown(Unknown::Rejected(e)),
        })
    }
}

/// Parses `BasicOCSPResponse`.
fn parse_basic(der: &[u8]) -> Result<Basic<'_>, EvidenceError> {
    let mut outer = Der::new(der);
    let mut basic = outer.nested(tag::SEQUENCE)?;
    outer.finish()?;
    let (tbs_tag, tbs, tbs_contents) = basic.any_raw()?;
    if tbs_tag != tag::SEQUENCE {
        return Err(EvidenceError::Malformed);
    }
    let signature_algorithm = read_signature_algorithm(&mut basic)?;
    let (unused, signature) = basic.bit_string()?;
    if unused != 0 {
        return Err(EvidenceError::Malformed);
    }
    let certs = match basic.optional(tag::context(0))? {
        Some(wrapped) => {
            let mut reader = Der::new(wrapped);
            let certs = reader.expect(tag::SEQUENCE)?;
            reader.finish()?;
            certs
        }
        None => &[],
    };
    basic.finish()?;
    if count(certs)? > MAX_RESPONDER_CERTS {
        return Err(EvidenceError::TooLarge);
    }

    let mut data = Der::new(tbs_contents);
    // version [0] EXPLICIT Version DEFAULT v1 — DER omits a default, so a
    // present version must be something other than v1, and there is no other.
    if data.optional(tag::context(0))?.is_some() {
        return Err(EvidenceError::Malformed);
    }
    let responder = match data.peek() {
        Some(t) if t == tag::context(1) => {
            let name = data.expect(t)?;
            let mut reader = Der::new(name);
            let (name_tag, _) = reader.any()?;
            reader.finish()?;
            if name_tag != tag::SEQUENCE {
                return Err(EvidenceError::Malformed);
            }
            ResponderId::ByName(name)
        }
        Some(t) if t == tag::context(2) => {
            let mut reader = Der::new(data.expect(t)?);
            let key = reader.expect(tag::OCTET_STRING)?;
            reader.finish()?;
            ResponderId::ByKey(key)
        }
        _ => return Err(EvidenceError::Malformed),
    };
    // producedAt: read for well-formedness only.
    if data.peek() != Some(tag::GENERALIZED_TIME) {
        return Err(EvidenceError::Malformed);
    }
    let _produced_at = read_time(&mut data)?;
    let responses = data.expect(tag::SEQUENCE)?;
    let mut unknown_critical = false;
    if let Some(extensions) = data.optional(tag::context(1))? {
        unknown_critical = has_unknown_critical(extensions)?;
    }
    data.finish()?;

    let n = count(responses)?;
    if n == 0 {
        return Err(EvidenceError::Malformed);
    }
    if n > MAX_SINGLE_RESPONSES {
        return Err(EvidenceError::TooLarge);
    }
    // Parsed once here so `check` never meets a malformed one.
    let mut list = Der::new(responses);
    while !list.is_empty() {
        parse_single(list.expect(tag::SEQUENCE)?)?;
    }
    Ok(Basic { tbs, responder, responses, unknown_critical, signature_algorithm, signature, certs })
}

/// How many values a `SEQUENCE OF`'s contents hold.
fn count(contents: &[u8]) -> Result<usize, DerError> {
    let mut reader = Der::new(contents);
    let mut n = 0;
    while !reader.is_empty() {
        reader.any()?;
        n += 1;
    }
    Ok(n)
}

/// Whether an `[n] EXPLICIT Extensions` wrapper holds a critical extension
/// this crate does not implement.
fn has_unknown_critical(wrapped: &[u8]) -> Result<bool, EvidenceError> {
    let mut reader = Der::new(wrapped);
    let list = reader.expect(tag::SEQUENCE)?;
    reader.finish()?;
    let mut unknown = false;
    scan_extensions(list, |id, critical, _| {
        let known = matches!(
            id,
            oid::OCSP_NONCE | oid::OCSP_CRL | oid::OCSP_ARCHIVE_CUTOFF | oid::CRL_REASON
        );
        unknown |= critical && !known;
        Ok(())
    })?;
    Ok(unknown)
}

/// Parses one `SingleResponse`'s contents.
fn parse_single(contents: &[u8]) -> Result<Single<'_>, EvidenceError> {
    let mut single = Der::new(contents);
    let mut cert_id = single.nested(tag::SEQUENCE)?;
    let mut algorithm = cert_id.nested(tag::SEQUENCE)?;
    let hash_oid = algorithm.expect(tag::OID)?;
    // RFC 5754 §2: the parameters are absent, though `NULL` is widespread and
    // RFC 5754 says implementations must accept it.
    if !algorithm.is_empty() {
        if !algorithm.expect(tag::NULL)?.is_empty() {
            return Err(EvidenceError::Malformed);
        }
        algorithm.finish()?;
    }
    let hash = match hash_oid {
        oid::SHA1 => Some(HashAlgorithm::Sha1),
        oid::SHA256 => Some(HashAlgorithm::Sha256),
        oid::SHA384 => Some(HashAlgorithm::Sha384),
        oid::SHA512 => Some(HashAlgorithm::Sha512),
        _ => None,
    };
    let name_hash = cert_id.expect(tag::OCTET_STRING)?;
    let key_hash = cert_id.expect(tag::OCTET_STRING)?;
    let serial = cert_id.expect(tag::INTEGER)?;
    cert_id.finish()?;

    let status = match single.peek() {
        Some(t) if t == tag::context_primitive(0) => {
            if !single.expect(t)?.is_empty() {
                return Err(EvidenceError::Malformed);
            }
            Status::Good
        }
        Some(t) if t == tag::context(1) => {
            let mut info = Der::new(single.expect(t)?);
            if info.peek() != Some(tag::GENERALIZED_TIME) {
                return Err(EvidenceError::Malformed);
            }
            let at = read_time(&mut info)?;
            let reason = match info.optional(tag::context(0))? {
                Some(wrapped) => {
                    let mut reader = Der::new(wrapped);
                    let code = reader.enumerated()?;
                    reader.finish()?;
                    Some(Reason::from_code(code).ok_or(EvidenceError::Malformed)?)
                }
                None => None,
            };
            info.finish()?;
            Status::Revoked { at, reason }
        }
        Some(t) if t == tag::context_primitive(2) => {
            if !single.expect(t)?.is_empty() {
                return Err(EvidenceError::Malformed);
            }
            Status::Unknown
        }
        _ => return Err(EvidenceError::Malformed),
    };
    if single.peek() != Some(tag::GENERALIZED_TIME) {
        return Err(EvidenceError::Malformed);
    }
    let this_update = read_time(&mut single)?;
    let next_update = match single.optional(tag::context(0))? {
        Some(wrapped) => {
            let mut reader = Der::new(wrapped);
            if reader.peek() != Some(tag::GENERALIZED_TIME) {
                return Err(EvidenceError::Malformed);
            }
            let t = read_time(&mut reader)?;
            reader.finish()?;
            Some(t)
        }
        None => None,
    };
    let mut unknown_critical = false;
    if let Some(extensions) = single.optional(tag::context(1))? {
        unknown_critical = has_unknown_critical(extensions)?;
    }
    single.finish()?;
    Ok(Single {
        hash,
        name_hash,
        key_hash,
        serial,
        status,
        this_update,
        next_update,
        unknown_critical,
    })
}

/// The `SingleResponse` naming `cert`, if any.
///
/// A `CertID` with `cert`'s serial whose hash the backend cannot compute is
/// reported as [`EvidenceError::UnsupportedHash`], not skipped.
fn find_single<'a>(
    basic: &Basic<'a>,
    cert: &Certificate<'_>,
    issuer: &Certificate<'_>,
    hasher: &impl Hasher,
) -> Result<Option<Single<'a>>, EvidenceError> {
    let mut unreadable = false;
    let mut list = Der::new(basic.responses);
    while !list.is_empty() {
        let single = parse_single(list.expect(tag::SEQUENCE)?)?;
        if single.serial != cert.serial {
            continue;
        }
        let Some(alg) = single.hash else {
            unreadable = true;
            continue;
        };
        let (Some(name), Some(key)) =
            (hasher.hash(alg, issuer.subject.encoded), hasher.hash(alg, issuer.public_key))
        else {
            unreadable = true;
            continue;
        };
        if name == single.name_hash && key == single.key_hash {
            return Ok(Some(single));
        }
    }
    if unreadable { Err(EvidenceError::UnsupportedHash) } else { Ok(None) }
}

/// Believes `single` or says why not.
fn evaluate(
    basic: &Basic<'_>,
    single: &Single<'_>,
    issuer: &Certificate<'_>,
    rules: Rules,
    now: i64,
    backend: &(impl VerifyWith + Hasher),
) -> Result<Standing, EvidenceError> {
    if basic.unknown_critical || single.unknown_critical {
        return Err(EvidenceError::UnknownCriticalExtension);
    }
    let delegate;
    let signed_by = match signer(basic, issuer, now, backend)? {
        Signer::Issuer => issuer,
        Signer::Delegate(cert) => {
            delegate = *cert;
            &delegate
        }
    };
    verify(basic.signature_algorithm, basic.signature, basic.tbs, signed_by, backend)?;

    if single.this_update > now {
        return Err(EvidenceError::NotYetValid);
    }
    let next_update = single.next_update.ok_or(EvidenceError::NoNextUpdate)?;
    if next_update < now {
        return Err(EvidenceError::Stale);
    }
    let seconds = next_update - single.this_update;
    if seconds > max_response_validity(rules) {
        return Err(EvidenceError::ValidityTooLong { seconds });
    }
    match single.status {
        Status::Good => Ok(Standing::Good {
            source: Source::Ocsp,
            this_update: single.this_update,
            next_update,
        }),
        Status::Revoked { at, reason } => {
            Ok(Standing::Revoked { source: Source::Ocsp, revoked_at: at, reason })
        }
        Status::Unknown => Err(EvidenceError::StatusUnknown),
    }
}

/// Whether `responder` names `candidate`.
fn names(
    responder: ResponderId<'_>,
    candidate: &Certificate<'_>,
    hasher: &impl Hasher,
) -> Result<bool, EvidenceError> {
    match responder {
        ResponderId::ByName(name) => Ok(name == candidate.subject.encoded),
        ResponderId::ByKey(key) => {
            let hash = hasher
                .hash(HashAlgorithm::Sha1, candidate.public_key)
                .ok_or(EvidenceError::UnsupportedHash)?;
            Ok(hash == key)
        }
    }
}

/// Who signed a response.
enum Signer<'r> {
    /// The CA that issued the certificate in question.
    Issuer,
    /// A responder that CA certified directly for the purpose.
    Delegate(alloc::boxed::Box<Certificate<'r>>),
}

/// Finds the certificate that signed the response and checks it may have.
///
/// Of RFC 6960 §4.2.2.2's three signers, two are accepted: the issuing CA and a
/// responder it certified directly. A locally trusted responder is not.
fn signer<'r>(
    basic: &Basic<'r>,
    issuer: &Certificate<'_>,
    now: i64,
    backend: &(impl VerifyWith + Hasher),
) -> Result<Signer<'r>, EvidenceError> {
    if names(basic.responder, issuer, backend)? {
        return Ok(Signer::Issuer);
    }
    let mut list = Der::new(basic.certs);
    let mut named_but_refused = false;
    while !list.is_empty() {
        let (_, raw, _) = list.any_raw()?;
        let candidate = Certificate::parse(raw)?;
        if !names(basic.responder, &candidate, backend)? {
            continue;
        }
        if authorised(&candidate, issuer, now, backend) {
            return Ok(Signer::Delegate(alloc::boxed::Box::new(candidate)));
        }
        named_but_refused = true;
    }
    Err(if named_but_refused {
        EvidenceError::ResponderNotAuthorized
    } else {
        EvidenceError::ResponderIdMismatch
    })
}

/// Whether `candidate` is a responder `issuer` delegated to (RFC 6960
/// §4.2.2.2): issued by it directly, signed by its key, carrying
/// `id-kp-OCSPSigning`, valid at `now`, and on the issuer's curve (Annex F
/// fixes one curve per cluster, and Table B.15 the responder's with it).
fn authorised(
    candidate: &Certificate<'_>,
    issuer: &Certificate<'_>,
    now: i64,
    verifier: &impl VerifyWith,
) -> bool {
    candidate.ocsp_signing
        && candidate.issuer.encoded == issuer.subject.encoded
        && candidate.curve == issuer.curve
        && candidate.is_valid_at(now)
        && candidate.basic_constraints.is_none_or(|bc| !bc.ca)
        && verifier
            .verify_with(
                issuer.curve.suite(),
                issuer.public_key,
                candidate.tbs,
                candidate.signature.as_slice(),
            )
            .is_ok()
}

/// Verifies the response signature under `signer`.
fn verify(
    algorithm: &[u8],
    signature: &[u8],
    tbs: &[u8],
    signer: &Certificate<'_>,
    verifier: &impl VerifyWith,
) -> Result<(), EvidenceError> {
    let suite = signer.curve.suite();
    let expected = oid::signature_algorithm(suite);
    if algorithm != expected {
        return Err(EvidenceError::UnsupportedSignatureAlgorithm);
    }
    let raw = raw_signature(signature, signer.curve).map_err(|_| EvidenceError::BadSignature)?;
    verifier
        .verify_with(suite, signer.public_key, tbs, raw.as_slice())
        .map_err(|_| EvidenceError::BadSignature)
}
