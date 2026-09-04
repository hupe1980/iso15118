//! Just enough DER to read an ISO 15118 certificate.
//!
//! This is not a general ASN.1 library and is not trying to be. X.509 is a
//! large grammar; the part ISO 15118 constrains is small, fixed, and
//! [pinned to one algorithm and one curve](super) — so what is here is a
//! forward-only reader over a borrowed slice, with every length checked against
//! what is left before it is believed.
//!
//! Three properties are worth stating, because they are what makes a parser on
//! this surface safe rather than merely correct:
//!
//! * **Nothing is allocated.** Every value is a subslice of the caller's
//!   buffer. A certificate arrives before anything is authenticated and is
//!   bounded at 800 bytes by the schema \[V2G2-010\], but a parser that
//!   allocates per field turns a bounded input into an unbounded one anyway.
//! * **Definite lengths only.** BER's indefinite form is not DER, and accepting
//!   it is how two parsers come to disagree about where a field ends — which,
//!   in a certificate, is how one of them reads a different subject than the
//!   other.
//! * **Non-minimal lengths are refused.** DER has exactly one encoding per
//!   value. A length written in more octets than it needs is a second encoding
//!   of the same certificate, and the whole of chain validation rests on the
//!   issuer's signature covering exactly the bytes this side re-read.

/// A tag byte, as it appears on the wire.
///
/// Only the tags an ISO 15118 certificate can contain; anything else is
/// content this reader steps over without interpreting.
pub(crate) mod tag {
    /// `BOOLEAN`.
    pub(crate) const BOOLEAN: u8 = 0x01;
    /// `INTEGER`.
    pub(crate) const INTEGER: u8 = 0x02;
    /// `BIT STRING`.
    pub(crate) const BIT_STRING: u8 = 0x03;
    /// `OCTET STRING`.
    pub(crate) const OCTET_STRING: u8 = 0x04;
    /// `OBJECT IDENTIFIER`.
    pub(crate) const OID: u8 = 0x06;
    /// `UTCTime`.
    pub(crate) const UTC_TIME: u8 = 0x17;
    /// `GeneralizedTime`.
    pub(crate) const GENERALIZED_TIME: u8 = 0x18;
    /// `SEQUENCE`, constructed.
    pub(crate) const SEQUENCE: u8 = 0x30;
    /// `SET`, constructed.
    pub(crate) const SET: u8 = 0x31;

    /// Context-specific constructed tag `n` — `[0]`, `[3]` and friends.
    #[must_use]
    pub(crate) const fn context(n: u8) -> u8 {
        0xA0 | n
    }
}

/// Why a certificate could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DerError {
    /// The encoding ended in the middle of a value.
    Truncated,
    /// A tag was not the one the grammar requires at that position.
    UnexpectedTag {
        /// The tag the grammar wanted.
        expected: u8,
        /// The tag that was there.
        found: u8,
    },
    /// A length used the indefinite form, or more octets than it needed.
    ///
    /// Both are BER and neither is DER. The second matters as much as the
    /// first: DER is a *canonical* encoding, and a certificate with two
    /// encodings is one whose signature covers a different byte string than the
    /// one a verifier re-reads.
    NonCanonicalLength,
    /// A length field wider than this platform's `usize`, which no certificate
    /// bounded at 800 bytes can legitimately carry.
    LengthTooLarge,
    /// Bytes were left over after a value the grammar says is complete.
    TrailingData,
    /// A value was structurally fine and semantically impossible — a
    /// `BOOLEAN` that is neither `0x00` nor `0xFF`, an empty `INTEGER`, a
    /// `BIT STRING` claiming more unused bits than a byte has.
    Malformed,
}

/// A forward-only reader over one DER value's contents.
#[derive(Debug, Clone)]
pub(crate) struct Der<'a> {
    rest: &'a [u8],
}

impl<'a> Der<'a> {
    /// Reads over `input`.
    pub(crate) const fn new(input: &'a [u8]) -> Self {
        Self { rest: input }
    }

    /// True once everything has been consumed.
    pub(crate) const fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    /// Fails unless everything has been consumed.
    pub(crate) const fn finish(self) -> Result<(), DerError> {
        if self.rest.is_empty() { Ok(()) } else { Err(DerError::TrailingData) }
    }

    /// The tag of the next value, without consuming it.
    pub(crate) fn peek(&self) -> Option<u8> {
        self.rest.first().copied()
    }

    /// Reads the next value, returning its tag and contents.
    pub(crate) fn any(&mut self) -> Result<(u8, &'a [u8]), DerError> {
        let (&tag, after_tag) = self.rest.split_first().ok_or(DerError::Truncated)?;
        let (len, after_len) = read_length(after_tag)?;
        let contents = after_len.get(..len).ok_or(DerError::Truncated)?;
        self.rest = &after_len[len..];
        Ok((tag, contents))
    }

    /// Reads the next value *with* its tag and length octets, as they appear.
    ///
    /// What a signature is computed over is the encoded `TBSCertificate`, tag
    /// and length included — so re-serialising the parsed form would not do,
    /// and this hands back the original bytes instead.
    pub(crate) fn any_raw(&mut self) -> Result<(u8, &'a [u8], &'a [u8]), DerError> {
        let before = self.rest;
        let (tag, contents) = self.any()?;
        let consumed = before.len() - self.rest.len();
        Ok((tag, &before[..consumed], contents))
    }

    /// Reads the next value, requiring `expected` as its tag.
    pub(crate) fn expect(&mut self, expected: u8) -> Result<&'a [u8], DerError> {
        let (tag, contents) = self.any()?;
        if tag == expected {
            Ok(contents)
        } else {
            Err(DerError::UnexpectedTag { expected, found: tag })
        }
    }

    /// Reads the next value as a nested reader.
    pub(crate) fn nested(&mut self, expected: u8) -> Result<Self, DerError> {
        Ok(Self::new(self.expect(expected)?))
    }

    /// Reads the next value only if it carries `expected`.
    pub(crate) fn optional(&mut self, expected: u8) -> Result<Option<&'a [u8]>, DerError> {
        if self.peek() == Some(expected) { self.expect(expected).map(Some) } else { Ok(None) }
    }

    /// Reads a `BOOLEAN`.
    ///
    /// DER admits exactly two encodings, and `0x01` for true is BER.
    pub(crate) fn boolean(&mut self) -> Result<bool, DerError> {
        match self.expect(tag::BOOLEAN)? {
            [0x00] => Ok(false),
            [0xFF] => Ok(true),
            _ => Err(DerError::Malformed),
        }
    }

    /// Reads a small non-negative `INTEGER`.
    ///
    /// Everything an ISO 15118 certificate needs as a number — the version, a
    /// path-length constraint — is small. A serial number is not read as a
    /// number at all; it is kept as bytes, because that is how it is compared.
    pub(crate) fn small_uint(&mut self) -> Result<u32, DerError> {
        let bytes = self.expect(tag::INTEGER)?;
        let (&first, rest) = bytes.split_first().ok_or(DerError::Malformed)?;
        // DER integers are two's complement and minimally encoded: a leading
        // 0x00 appears only to keep a value positive, and only where the next
        // octet has its high bit set. A lone `0x00` is the number zero — which
        // is not a padded encoding of anything, and is what a
        // `pathLenConstraint` of 0 looks like.
        if first == 0x00 && rest.first().is_some_and(|&b| b & 0x80 == 0) {
            return Err(DerError::Malformed);
        }
        if first & 0x80 != 0 {
            return Err(DerError::Malformed);
        }
        let bytes = if first == 0x00 { rest } else { bytes };
        if bytes.len() > 4 {
            return Err(DerError::LengthTooLarge);
        }
        Ok(bytes.iter().fold(0u32, |acc, &b| (acc << 8) | u32::from(b)))
    }

    /// Reads a `BIT STRING`, returning `(unused_bits, bytes)`.
    pub(crate) fn bit_string(&mut self) -> Result<(u8, &'a [u8]), DerError> {
        let contents = self.expect(tag::BIT_STRING)?;
        let (&unused, bytes) = contents.split_first().ok_or(DerError::Malformed)?;
        if unused > 7 || (unused > 0 && bytes.is_empty()) {
            return Err(DerError::Malformed);
        }
        Ok((unused, bytes))
    }
}

/// Reads a DER length, returning it and the bytes after it.
///
/// The indefinite form (`0x80`) and any non-minimal long form are refused: DER
/// permits exactly one encoding of each length, and a parser that accepts two
/// is a parser that can be made to disagree with the one that signed.
fn read_length(input: &[u8]) -> Result<(usize, &[u8]), DerError> {
    let (&first, rest) = input.split_first().ok_or(DerError::Truncated)?;
    if first < 0x80 {
        return Ok((usize::from(first), rest));
    }
    if first == 0x80 {
        // Indefinite length: BER, not DER.
        return Err(DerError::NonCanonicalLength);
    }
    if first == 0xFF {
        return Err(DerError::Malformed);
    }
    let count = usize::from(first & 0x7F);
    let (octets, rest) = rest.split_at_checked(count).ok_or(DerError::Truncated)?;
    if octets.first() == Some(&0x00) {
        // A leading zero octet means the length was written wider than needed.
        return Err(DerError::NonCanonicalLength);
    }
    if count > core::mem::size_of::<usize>() {
        return Err(DerError::LengthTooLarge);
    }
    let len = octets.iter().fold(0usize, |acc, &b| (acc << 8) | usize::from(b));
    if len < 0x80 {
        // Short form would have expressed it.
        return Err(DerError::NonCanonicalLength);
    }
    Ok((len, rest))
}

impl core::fmt::Display for DerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Truncated => f.write_str("the DER encoding ends inside a value"),
            Self::UnexpectedTag { expected, found } => {
                write!(f, "expected DER tag {expected:#04x}, found {found:#04x}")
            }
            Self::NonCanonicalLength => f.write_str("the length is not in DER's canonical form"),
            Self::LengthTooLarge => f.write_str("the length field is wider than this platform"),
            Self::TrailingData => f.write_str("bytes follow a value the grammar says is complete"),
            Self::Malformed => f.write_str("a value is structurally impossible"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DerError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_short_form_length_reads() {
        let mut d = Der::new(&[0x02, 0x01, 0x07]);
        assert_eq!(d.small_uint().unwrap(), 7);
        assert!(d.finish().is_ok());
    }

    #[test]
    fn the_indefinite_length_form_is_refused() {
        // BER's `0x80` marker, which DER does not have.
        let mut d = Der::new(&[0x30, 0x80, 0x00, 0x00]);
        assert_eq!(d.any(), Err(DerError::NonCanonicalLength));
    }

    /// DER is a canonical encoding, and the whole of chain validation rests on
    /// that: a signature covers a byte string, and a certificate with two legal
    /// spellings is one where the verifier and the signer can be reading
    /// different bytes.
    #[test]
    fn a_length_written_wider_than_it_needs_is_refused() {
        // `0x81 0x05` says "long form, five bytes" where `0x05` would do.
        let mut d = Der::new(&[0x04, 0x81, 0x05, 1, 2, 3, 4, 5]);
        assert_eq!(d.any(), Err(DerError::NonCanonicalLength));
        // ...and a long form padded with a leading zero.
        let mut d = Der::new(&[0x04, 0x82, 0x00, 0x05, 1, 2, 3, 4, 5]);
        assert_eq!(d.any(), Err(DerError::NonCanonicalLength));
    }

    #[test]
    fn a_boolean_must_be_der_not_ber() {
        assert!(Der::new(&[0x01, 0x01, 0xFF]).boolean().unwrap());
        assert!(!Der::new(&[0x01, 0x01, 0x00]).boolean().unwrap());
        // `0x01` is "true" in BER and is not DER.
        assert_eq!(Der::new(&[0x01, 0x01, 0x01]).boolean(), Err(DerError::Malformed));
    }

    #[test]
    fn a_non_minimal_integer_is_refused() {
        // 0x00 0x07 is 7 written with a pad byte it does not need.
        assert_eq!(Der::new(&[0x02, 0x02, 0x00, 0x07]).small_uint(), Err(DerError::Malformed));
        // 0x00 0x80 is 128, and the pad *is* needed.
        assert_eq!(Der::new(&[0x02, 0x02, 0x00, 0x80]).small_uint().unwrap(), 128);
        // A lone 0x00 is zero, which is what `pathLenConstraint: 0` — the whole
        // reason a CPO Sub-CA 2 cannot be extended — is encoded as.
        assert_eq!(Der::new(&[0x02, 0x01, 0x00]).small_uint().unwrap(), 0);
    }

    #[test]
    fn a_truncated_value_is_refused() {
        assert_eq!(Der::new(&[0x04, 0x05, 1, 2]).any(), Err(DerError::Truncated));
    }

    #[test]
    fn raw_bytes_include_the_tag_and_length() {
        let mut d = Der::new(&[0x04, 0x02, 0xAA, 0xBB]);
        let (tag, raw, contents) = d.any_raw().unwrap();
        assert_eq!(tag, tag::OCTET_STRING);
        assert_eq!(raw, &[0x04, 0x02, 0xAA, 0xBB]);
        assert_eq!(contents, &[0xAA, 0xBB]);
    }
}
