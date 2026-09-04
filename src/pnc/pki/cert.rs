//! An X.509 certificate, read down to the fields ISO 15118 Annex F constrains.
//!
//! Deliberately not a general X.509 implementation. Everything here exists
//! because a rule in [Annex F](super) or in RFC 5280 §6.1 needs it, and the
//! fields nothing checks are not parsed — an unread field is one that cannot be
//! read wrongly.
//!
//! Every value borrows from the caller's DER, so a `Certificate` is a view and
//! not a copy.

use super::der::{Der, DerError, tag};
use super::oid;

/// The public key algorithm and curve a certificate carries.
///
/// ISO 15118-2 pins both: `id-ecPublicKey` over `secp256r1`, in every profile
/// in Annex F \[V2G2-006\], \[V2G2-007\]. ISO 15118-20 adds `secp521r1` for its
/// higher security level, so the enumeration has two members and a chain says
/// which it will accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum Curve {
    /// `secp256r1` / `prime256v1` — ISO 15118-2's only curve.
    P256,
    /// `secp521r1` — ISO 15118-20's higher security level.
    P521,
}

impl Curve {
    /// Length of one coordinate, and so half of a raw `r ‖ s` signature.
    #[must_use]
    pub const fn field_len(self) -> usize {
        match self {
            Self::P256 => 32,
            Self::P521 => 66,
        }
    }

    /// The signature suite this curve is used with.
    #[must_use]
    pub const fn suite(self) -> crate::pnc::Suite {
        match self {
            Self::P256 => crate::pnc::Suite::EcdsaSha256,
            Self::P521 => crate::pnc::Suite::EcdsaSha512,
        }
    }
}

/// The key-usage bits, as Annex F names them.
///
/// A `KeyUsage` extension is marked **critical** in every ISO 15118 profile, so
/// a certificate that carries one has asserted that these bits are the whole of
/// what its key may do — and a verifier that ignores them is ignoring an
/// assertion the issuer marked as one it must not ignore.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct KeyUsage(u16);

impl KeyUsage {
    /// `digitalSignature`, bit 0.
    pub const DIGITAL_SIGNATURE: Self = Self(1 << 0);
    /// `nonRepudiation` / `contentCommitment`, bit 1.
    pub const NON_REPUDIATION: Self = Self(1 << 1);
    /// `keyEncipherment`, bit 2.
    pub const KEY_ENCIPHERMENT: Self = Self(1 << 2);
    /// `dataEncipherment`, bit 3.
    pub const DATA_ENCIPHERMENT: Self = Self(1 << 3);
    /// `keyAgreement`, bit 4.
    pub const KEY_AGREEMENT: Self = Self(1 << 4);
    /// `keyCertSign`, bit 5.
    pub const KEY_CERT_SIGN: Self = Self(1 << 5);
    /// `cRLSign`, bit 6.
    pub const CRL_SIGN: Self = Self(1 << 6);

    /// Both sets of bits, for a profile that requires several.
    #[must_use]
    pub const fn and(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// True when every bit of `wanted` is set here.
    #[must_use]
    pub const fn contains(self, wanted: Self) -> bool {
        self.0 & wanted.0 == wanted.0
    }

    /// The bits, for a log line.
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }
}

/// `BasicConstraints`, which decides whether a certificate may sign others.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BasicConstraints {
    /// The `cA` flag.
    pub ca: bool,
    /// `pathLenConstraint`, when present.
    pub path_len: Option<u32>,
}

/// A distinguished name, kept both ways.
///
/// The **encoded** form is what chaining compares: RFC 5280 §6.1.3 matches an
/// issuer to a subject, and the only comparison that cannot be argued with is
/// byte equality of the DER. Two names that differ in string encoding, case or
/// whitespace are two names here, which is stricter than RFC 5280's full name
/// comparison and is the direction to be strict in.
///
/// The **attributes** are what Annex F names — the profiles constrain
/// `Organization`, `Common Name` and `Domain Component`, and \[V2G2-925\] makes
/// one of them a validity condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Name<'a> {
    /// The name as it is encoded, tag and length included.
    pub encoded: &'a [u8],
    /// `CN`, the last one if a name carries several.
    pub common_name: Option<&'a str>,
    /// `O`.
    pub organization: Option<&'a str>,
    /// `DC`, the *first* one — an ISO 15118 name carries at most one, and the
    /// first is the most significant in a name read left to right.
    pub domain_component: Option<&'a str>,
}

/// One X.509 certificate, borrowed from its DER.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Certificate<'a> {
    /// The whole encoding, as it arrived.
    pub der: &'a [u8],
    /// `tbsCertificate`, tag and length included — the bytes the issuer signed.
    pub tbs: &'a [u8],
    /// `serialNumber`, as encoded.
    pub serial: &'a [u8],
    /// Who issued it.
    pub issuer: Name<'a>,
    /// Who it is about.
    pub subject: Name<'a>,
    /// `notBefore`, in seconds since the Unix epoch.
    pub not_before: i64,
    /// `notAfter`, in seconds since the Unix epoch.
    pub not_after: i64,
    /// The curve the subject's key is on.
    pub curve: Curve,
    /// The subject's public key, as an uncompressed SEC1 point (`0x04 ‖ X ‖ Y`).
    pub public_key: &'a [u8],
    /// `KeyUsage`, when the certificate carries one.
    pub key_usage: Option<KeyUsage>,
    /// `BasicConstraints`, when the certificate carries one.
    pub basic_constraints: Option<BasicConstraints>,
    /// The `signatureValue`, converted to the raw `r ‖ s` form
    /// [`Verify`](crate::pnc::Verify) takes.
    ///
    /// X.509 carries an ECDSA signature as `SEQUENCE { r INTEGER, s INTEGER }`;
    /// `XMLDSig` — and therefore this crate's signing traits — uses the fixed
    /// width pair. Converting here rather than in the backend keeps the trait
    /// one-shaped, and keeps the two places a signature is checked using the
    /// same one.
    pub signature: heapless_sig::Sig,
}

/// A fixed-capacity buffer for a raw `r ‖ s` signature.
///
/// P-521's pair is 132 bytes; nothing here is larger. An inline array keeps
/// [`Certificate`] `Copy` and allocation-free, which is what lets a chain be
/// validated on a target with no allocator to spare.
pub mod heapless_sig {
    /// Largest raw signature this crate handles — P-521's `r ‖ s`.
    pub const MAX: usize = 132;

    /// A raw `r ‖ s` signature.
    #[derive(Debug, Clone, Copy)]
    pub struct Sig {
        pub(crate) bytes: [u8; MAX],
        pub(crate) len: usize,
    }

    impl PartialEq for Sig {
        fn eq(&self, other: &Self) -> bool {
            self.as_slice() == other.as_slice()
        }
    }

    impl Eq for Sig {}

    impl Sig {
        /// The signature.
        #[must_use]
        pub fn as_slice(&self) -> &[u8] {
            &self.bytes[..self.len]
        }
    }
}

/// Why a certificate could not be read or does not meet the profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CertError {
    /// The DER did not parse.
    Der(DerError),
    /// The certificate is not X.509 **v3**. Every Annex F profile says
    /// `2 (X.509v3)`, and a v1 certificate carries no extensions at all — so
    /// no `BasicConstraints`, which is the field that says whether it may sign
    /// others.
    NotV3,
    /// The subject's key is not on a curve ISO 15118 permits \[V2G2-006\].
    UnsupportedCurve,
    /// The public key is not an uncompressed SEC1 point of the curve's width.
    ///
    /// Compressed points are legal X.509 and are refused here: ISO 15118's
    /// profiles do not use them, and a decompression routine is arithmetic this
    /// crate has no reason to carry.
    BadPublicKey,
    /// The signature algorithm is not `ecdsa-with-SHA256` or
    /// `ecdsa-with-SHA512`.
    UnsupportedSignatureAlgorithm,
    /// `signatureAlgorithm` and `tbsCertificate.signature` disagree.
    ///
    /// RFC 5280 §4.1.1.2 requires them to match. They are the same fact written
    /// twice, and only one of them is inside what the issuer signed — so a
    /// verifier that reads the outer one is reading a value the issuer never
    /// covered.
    AlgorithmMismatch,
    /// The signature is not a well-formed `ECDSA-Sig-Value`, or a coordinate is
    /// wider than the curve.
    BadSignature,
    /// A `notBefore` or `notAfter` could not be read as a time.
    BadValidity,
    /// The certificate carries a **critical** extension this crate does not
    /// implement.
    ///
    /// RFC 5280, quoted verbatim in Annex F: "A certificate-using system MUST
    /// reject the certificate if it encounters a critical extension it does not
    /// recognize". Marking an extension critical is the issuer saying the
    /// certificate means nothing without it, and honouring that is not
    /// optional.
    UnknownCriticalExtension,
    /// An extension appeared twice, which RFC 5280 §4.2 forbids.
    DuplicateExtension,
}

impl From<DerError> for CertError {
    fn from(e: DerError) -> Self {
        Self::Der(e)
    }
}

impl<'a> Certificate<'a> {
    /// Parses one DER-encoded certificate.
    ///
    /// Everything the ISO 15118 profiles fix is checked here — the version, the
    /// curve, the algorithm agreement, the point encoding — because they are
    /// properties of *this* certificate and need no chain to decide. What needs
    /// a chain is in [`super::chain`].
    pub fn parse(der: &'a [u8]) -> Result<Self, CertError> {
        let mut outer = Der::new(der);
        let mut cert = outer.nested(tag::SEQUENCE)?;
        outer.finish()?;

        let (_, tbs, tbs_contents) = cert.any_raw()?;
        let mut tbs_reader = Der::new(tbs_contents);

        // version [0] EXPLICIT INTEGER. Absent means v1, which has no
        // extensions and therefore no BasicConstraints.
        let version = tbs_reader.optional(tag::context(0))?.ok_or(CertError::NotV3)?;
        if Der::new(version).small_uint()? != 2 {
            return Err(CertError::NotV3);
        }

        let serial = tbs_reader.expect(tag::INTEGER)?;
        let inner_alg = read_signature_algorithm(&mut tbs_reader)?;
        let issuer = read_name(&mut tbs_reader)?;
        let (not_before, not_after) = read_validity(&mut tbs_reader)?;
        let subject = read_name(&mut tbs_reader)?;
        let (curve, public_key) = read_spki(&mut tbs_reader)?;

        // issuerUniqueID [1] and subjectUniqueID [2] are v2 fields ISO 15118
        // does not use; skipped rather than refused, because they are legal.
        let _ = tbs_reader.optional(0x81)?;
        let _ = tbs_reader.optional(0x82)?;

        let mut key_usage = None;
        let mut basic_constraints = None;
        if let Some(extensions) = tbs_reader.optional(tag::context(3))? {
            let mut list = Der::new(extensions);
            let mut list = list.nested(tag::SEQUENCE)?;
            let mut seen = ExtensionsSeen::default();
            while !list.is_empty() {
                let mut ext = list.nested(tag::SEQUENCE)?;
                let id = ext.expect(tag::OID)?;
                let critical =
                    if ext.peek() == Some(tag::BOOLEAN) { ext.boolean()? } else { false };
                let value = ext.expect(tag::OCTET_STRING)?;
                ext.finish()?;
                match id {
                    oid::KEY_USAGE => {
                        seen.mark(Extension::KeyUsage)?;
                        key_usage = Some(read_key_usage(value)?);
                    }
                    oid::BASIC_CONSTRAINTS => {
                        seen.mark(Extension::BasicConstraints)?;
                        basic_constraints = Some(read_basic_constraints(value)?);
                    }
                    // Recognised, and nothing here acts on them. Every Annex F
                    // profile marks all four non-critical, so ignoring one is
                    // what RFC 5280 says to do — and refusing a *critical*
                    // spelling of them is what the arm below is for.
                    oid::SUBJECT_KEY_IDENTIFIER
                    | oid::AUTHORITY_KEY_IDENTIFIER
                    | oid::CERTIFICATE_POLICIES
                    | oid::CRL_DISTRIBUTION_POINTS
                    | oid::AUTHORITY_INFO_ACCESS
                    | oid::EXT_KEY_USAGE
                        if !critical => {}
                    _ if critical => return Err(CertError::UnknownCriticalExtension),
                    _ => {}
                }
            }
        }

        let outer_alg = read_signature_algorithm(&mut cert)?;
        if outer_alg != inner_alg {
            return Err(CertError::AlgorithmMismatch);
        }
        let (unused, sig_der) = cert.bit_string()?;
        if unused != 0 {
            return Err(CertError::BadSignature);
        }
        cert.finish()?;

        let signature = raw_signature(sig_der, curve)?;

        Ok(Self {
            der,
            tbs,
            serial,
            issuer,
            subject,
            not_before,
            not_after,
            curve,
            public_key,
            key_usage,
            basic_constraints,
            signature,
        })
    }

    /// True when this certificate names itself as its own issuer.
    ///
    /// A trust anchor does; nothing below one should.
    #[must_use]
    pub fn is_self_issued(&self) -> bool {
        self.issuer.encoded == self.subject.encoded
    }

    /// True when `at` falls inside the validity period.
    #[must_use]
    pub const fn is_valid_at(&self, at: i64) -> bool {
        self.not_before <= at && at <= self.not_after
    }
}

/// The extensions this parser tracks for the "at most once" rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Extension {
    KeyUsage,
    BasicConstraints,
}

#[derive(Debug, Default)]
struct ExtensionsSeen {
    key_usage: bool,
    basic_constraints: bool,
}

impl ExtensionsSeen {
    /// RFC 5280 §4.2: "A certificate MUST NOT include more than one instance of
    /// a particular extension." A second `BasicConstraints` is the difference
    /// between "this is a CA" and "this is not", decided by which one a parser
    /// happens to keep.
    fn mark(&mut self, which: Extension) -> Result<(), CertError> {
        let slot = match which {
            Extension::KeyUsage => &mut self.key_usage,
            Extension::BasicConstraints => &mut self.basic_constraints,
        };
        if core::mem::replace(slot, true) { Err(CertError::DuplicateExtension) } else { Ok(()) }
    }
}

/// Reads an `AlgorithmIdentifier`, returning the curve-independent algorithm
/// OID.
fn read_signature_algorithm<'a>(reader: &mut Der<'a>) -> Result<&'a [u8], CertError> {
    let mut alg = reader.nested(tag::SEQUENCE)?;
    let id = alg.expect(tag::OID)?;
    // ECDSA `AlgorithmIdentifier`s take absent parameters (RFC 5758 §3.2), and
    // this crate has no other kind. Anything present is not this profile.
    if !alg.is_empty() {
        return Err(CertError::UnsupportedSignatureAlgorithm);
    }
    match id {
        oid::ECDSA_WITH_SHA256 | oid::ECDSA_WITH_SHA512 => Ok(id),
        _ => Err(CertError::UnsupportedSignatureAlgorithm),
    }
}

/// Reads a `Name`, keeping its encoding and the three attributes Annex F names.
fn read_name<'a>(reader: &mut Der<'a>) -> Result<Name<'a>, CertError> {
    let (_, encoded, contents) = reader.any_raw()?;
    let mut rdns = Der::new(contents);
    let mut name = Name { encoded, common_name: None, organization: None, domain_component: None };
    while !rdns.is_empty() {
        let mut rdn = rdns.nested(tag::SET)?;
        while !rdn.is_empty() {
            let mut attr = rdn.nested(tag::SEQUENCE)?;
            let id = attr.expect(tag::OID)?;
            let (_, value) = attr.any()?;
            attr.finish()?;
            // Only the string types a V2G name uses. A `BMPString` subject is
            // legal X.509 and is not something these profiles produce, so it is
            // left unread rather than transcoded.
            let Ok(text) = core::str::from_utf8(value) else { continue };
            match id {
                oid::COMMON_NAME => name.common_name = Some(text),
                oid::ORGANIZATION => name.organization = Some(text),
                // The first DC wins: a name is read most-significant first, and
                // ISO 15118 gives a certificate at most one.
                oid::DOMAIN_COMPONENT if name.domain_component.is_none() => {
                    name.domain_component = Some(text);
                }
                _ => {}
            }
        }
    }
    Ok(name)
}

/// Reads `Validity`, as Unix seconds.
fn read_validity(reader: &mut Der<'_>) -> Result<(i64, i64), CertError> {
    let mut validity = reader.nested(tag::SEQUENCE)?;
    let not_before = read_time(&mut validity)?;
    let not_after = read_time(&mut validity)?;
    validity.finish()?;
    Ok((not_before, not_after))
}

/// Reads one `Time`, which RFC 5280 §4.1.2.5 makes a choice of two encodings.
fn read_time(reader: &mut Der<'_>) -> Result<i64, CertError> {
    let (tag, bytes) = reader.any()?;
    let text = core::str::from_utf8(bytes).map_err(|_| CertError::BadValidity)?;
    let (year, rest) = match tag {
        // RFC 5280 §4.1.2.5.1: two-digit years 00..49 are 20xx, 50..99 are
        // 19xx. There is no other reading and the standard leaves no room for
        // one, which is the only reason a two-digit year is safe to parse at
        // all.
        tag::UTC_TIME => {
            let (yy, rest) = split_digits(text, 2)?;
            (if yy < 50 { 2000 + yy } else { 1900 + yy }, rest)
        }
        tag::GENERALIZED_TIME => {
            let (yyyy, rest) = split_digits(text, 4)?;
            (yyyy, rest)
        }
        _ => return Err(CertError::BadValidity),
    };
    let (month, rest) = split_digits(rest, 2)?;
    let (day, rest) = split_digits(rest, 2)?;
    let (hour, rest) = split_digits(rest, 2)?;
    let (minute, rest) = split_digits(rest, 2)?;
    let (second, rest) = split_digits(rest, 2)?;
    // RFC 5280 requires the `Z` form: no local time, no offset. A certificate
    // that states an offset states a time two verifiers can read differently.
    if rest != "Z" {
        return Err(CertError::BadValidity);
    }
    if !(1..=12).contains(&month) || day == 0 || day > 31 || hour > 23 || minute > 59 || second > 60
    {
        return Err(CertError::BadValidity);
    }
    Ok(unix_seconds(i64::from(year), month, day, hour, minute, second))
}

/// Splits `n` decimal digits off the front of `text`.
fn split_digits(text: &str, n: usize) -> Result<(u32, &str), CertError> {
    let (head, rest) = text.split_at_checked(n).ok_or(CertError::BadValidity)?;
    let value = head.bytes().try_fold(0u32, |acc, b| {
        b.is_ascii_digit().then(|| acc * 10 + u32::from(b - b'0')).ok_or(CertError::BadValidity)
    })?;
    Ok((value, rest))
}

/// Civil date to Unix seconds — Howard Hinnant's `days_from_civil`, which is
/// exact for every proleptic Gregorian date and needs no table.
fn unix_seconds(year: i64, month: u32, day: u32, hour: u32, minute: u32, second: u32) -> i64 {
    let m = i64::from(month);
    let d = i64::from(day);
    let y = if m <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    days * 86_400 + i64::from(hour) * 3600 + i64::from(minute) * 60 + i64::from(second)
}

/// Reads `SubjectPublicKeyInfo`, returning the curve and the point.
fn read_spki<'a>(reader: &mut Der<'a>) -> Result<(Curve, &'a [u8]), CertError> {
    let mut spki = reader.nested(tag::SEQUENCE)?;
    let mut alg = spki.nested(tag::SEQUENCE)?;
    if alg.expect(tag::OID)? != oid::EC_PUBLIC_KEY {
        return Err(CertError::UnsupportedCurve);
    }
    // ISO 15118 uses named curves throughout; the explicit-parameters form is
    // legal X.509 and lets a certificate describe a curve of its own, which is
    // not something this profile has any use for.
    let curve = match alg.expect(tag::OID)? {
        oid::PRIME256V1 => Curve::P256,
        oid::SECP521R1 => Curve::P521,
        _ => return Err(CertError::UnsupportedCurve),
    };
    alg.finish()?;
    let (unused, point) = spki.bit_string()?;
    spki.finish()?;
    if unused != 0 {
        return Err(CertError::BadPublicKey);
    }
    // SEC1 uncompressed: `0x04 ‖ X ‖ Y`, each coordinate the field's width.
    if point.first() != Some(&0x04) || point.len() != 1 + 2 * curve.field_len() {
        return Err(CertError::BadPublicKey);
    }
    Ok((curve, point))
}

/// Reads `KeyUsage`, a `BIT STRING` of named bits.
fn read_key_usage(value: &[u8]) -> Result<KeyUsage, CertError> {
    let mut reader = Der::new(value);
    let (unused, bytes) = reader.bit_string()?;
    reader.finish()?;
    let mut bits = 0u16;
    for (index, &byte) in bytes.iter().take(2).enumerate() {
        for bit in 0..8u32 {
            // `take(2)` caps `index` at 1, so the shift is at most 15.
            let position = u32::try_from(index).unwrap_or(u32::MAX) * 8 + bit;
            // Trailing bits the encoding declares unused are not set.
            if index == bytes.len() - 1 && bit >= 8 - u32::from(unused) {
                break;
            }
            if byte & (0x80 >> bit) != 0 {
                bits |= 1u16 << position;
            }
        }
    }
    Ok(KeyUsage(bits))
}

/// Reads `BasicConstraints`.
fn read_basic_constraints(value: &[u8]) -> Result<BasicConstraints, CertError> {
    let mut reader = Der::new(value);
    let mut seq = reader.nested(tag::SEQUENCE)?;
    reader.finish()?;
    // DER omits a field at its default, so an absent `cA` is `false`.
    let ca = if seq.peek() == Some(tag::BOOLEAN) { seq.boolean()? } else { false };
    let path_len = if seq.peek() == Some(tag::INTEGER) { Some(seq.small_uint()?) } else { None };
    seq.finish()?;
    Ok(BasicConstraints { ca, path_len })
}

/// Converts an X.509 `ECDSA-Sig-Value` to the raw `r ‖ s` form the
/// [`Verify`](crate::pnc::Verify) trait takes.
///
/// The two encodings are the same numbers and nothing else: X.509 writes them
/// as DER integers, which are variable-width and two's complement, and
/// `XMLDSig` writes them as fixed-width unsigned big-endian. Doing the
/// conversion here is what keeps the crate's signing traits one shape — a
/// backend implements `verify` once and it serves both a message signature and
/// a certificate.
fn raw_signature(der: &[u8], curve: Curve) -> Result<heapless_sig::Sig, CertError> {
    let width = curve.field_len();
    let mut reader = Der::new(der);
    let mut seq = reader.nested(tag::SEQUENCE).map_err(|_| CertError::BadSignature)?;
    reader.finish().map_err(|_| CertError::BadSignature)?;

    let mut bytes = [0u8; heapless_sig::MAX];
    for half in 0..2 {
        let value = seq.expect(tag::INTEGER).map_err(|_| CertError::BadSignature)?;
        // A DER integer is signed, so a coordinate with its top bit set carries
        // a leading zero. Anything else leading-zero is non-minimal and is not
        // DER.
        let value = match value {
            [] => return Err(CertError::BadSignature),
            [0x00, rest @ ..] if rest.first().is_some_and(|&b| b & 0x80 != 0) => rest,
            [first, ..] if *first & 0x80 != 0 => return Err(CertError::BadSignature),
            other => other,
        };
        if value.is_empty() || value.len() > width {
            return Err(CertError::BadSignature);
        }
        // Left-pad into the fixed width.
        let start = half * width + (width - value.len());
        bytes[start..half * width + width].copy_from_slice(value);
    }
    seq.finish().map_err(|_| CertError::BadSignature)?;
    Ok(heapless_sig::Sig { bytes, len: 2 * width })
}

impl core::fmt::Display for CertError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Der(e) => write!(f, "{e}"),
            Self::NotV3 => f.write_str("the certificate is not X.509v3"),
            Self::UnsupportedCurve => {
                f.write_str("the public key is not on secp256r1 or secp521r1")
            }
            Self::BadPublicKey => f.write_str("the public key is not an uncompressed SEC1 point"),
            Self::UnsupportedSignatureAlgorithm => {
                f.write_str("the signature algorithm is not ECDSA with SHA-256 or SHA-512")
            }
            Self::AlgorithmMismatch => f.write_str(
                "signatureAlgorithm and tbsCertificate.signature name different algorithms",
            ),
            Self::BadSignature => f.write_str("the signature is not a well-formed ECDSA-Sig-Value"),
            Self::BadValidity => f.write_str("a validity time could not be read"),
            Self::UnknownCriticalExtension => f.write_str(
                "the certificate carries a critical extension this build cannot process",
            ),
            Self::DuplicateExtension => f.write_str("an extension appears more than once"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CertError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Der(e) => Some(e),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_epoch_and_a_leap_day_convert_exactly() {
        assert_eq!(unix_seconds(1970, 1, 1, 0, 0, 0), 0);
        assert_eq!(unix_seconds(2000, 3, 1, 0, 0, 0), 951_868_800);
        assert_eq!(unix_seconds(2024, 2, 29, 12, 0, 0), 1_709_208_000);
        assert_eq!(unix_seconds(2038, 1, 19, 3, 14, 7), 2_147_483_647);
    }

    /// RFC 5280 §4.1.2.5.1 pivots two-digit years at 50, and there is no other
    /// reading — which is the only reason a two-digit year is safe to parse.
    #[test]
    fn utc_time_pivots_at_fifty() {
        let read = |text: &str| {
            let mut der = alloc::vec![tag::UTC_TIME, u8::try_from(text.len()).unwrap()];
            der.extend_from_slice(text.as_bytes());
            read_time(&mut Der::new(&der)).unwrap()
        };
        assert_eq!(read("490101000000Z"), unix_seconds(2049, 1, 1, 0, 0, 0));
        assert_eq!(read("500101000000Z"), unix_seconds(1950, 1, 1, 0, 0, 0));
    }

    /// A time with an offset is one two verifiers can read differently, and
    /// RFC 5280 requires the `Z` form for exactly that reason.
    #[test]
    fn a_time_that_is_not_utc_is_refused() {
        let text = b"9912312359+0100";
        let mut der = alloc::vec![tag::UTC_TIME, u8::try_from(text.len()).unwrap()];
        der.extend_from_slice(text);
        assert_eq!(read_time(&mut Der::new(&der)), Err(CertError::BadValidity));
    }

    #[test]
    fn key_usage_bits_read_in_the_order_x509_numbers_them() {
        // `digitalSignature` alone: one byte, seven unused bits.
        let ku = read_key_usage(&[0x03, 0x02, 0x07, 0x80]).unwrap();
        assert!(ku.contains(KeyUsage::DIGITAL_SIGNATURE));
        assert!(!ku.contains(KeyUsage::KEY_CERT_SIGN));
        // `keyCertSign | cRLSign`: bits 5 and 6.
        let ku = read_key_usage(&[0x03, 0x02, 0x01, 0x06]).unwrap();
        assert!(ku.contains(KeyUsage::KEY_CERT_SIGN));
        assert!(ku.contains(KeyUsage::CRL_SIGN));
        assert!(!ku.contains(KeyUsage::DIGITAL_SIGNATURE));
    }

    #[test]
    fn basic_constraints_defaults_to_not_a_ca() {
        // An empty SEQUENCE: `cA` absent, so false.
        assert_eq!(
            read_basic_constraints(&[0x30, 0x00]).unwrap(),
            BasicConstraints { ca: false, path_len: None }
        );
        // cA = TRUE, pathLenConstraint = 1.
        assert_eq!(
            read_basic_constraints(&[0x30, 0x06, 0x01, 0x01, 0xFF, 0x02, 0x01, 0x01]).unwrap(),
            BasicConstraints { ca: true, path_len: Some(1) }
        );
    }

    #[test]
    fn a_der_signature_becomes_a_fixed_width_pair() {
        // r = 0x01, s = 0x02, which pad out to 32 bytes each on P-256.
        let der = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
        let sig = raw_signature(&der, Curve::P256).unwrap();
        assert_eq!(sig.as_slice().len(), 64);
        assert_eq!(sig.as_slice()[31], 1);
        assert_eq!(sig.as_slice()[63], 2);
        assert!(sig.as_slice()[..31].iter().all(|&b| b == 0));
    }

    #[test]
    fn a_negative_or_over_wide_coordinate_is_refused() {
        // High bit set with no leading zero: a negative DER integer.
        let der = [0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x02];
        assert_eq!(raw_signature(&der, Curve::P256), Err(CertError::BadSignature));
    }
}
