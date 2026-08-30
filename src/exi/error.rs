//! Errors raised by the EXI codec.

use core::fmt;

/// Result alias for EXI operations.
pub type ExiResult<T> = Result<T, ExiError>;

/// Everything that can go wrong encoding or decoding an EXI stream.
///
/// The decoder is the crate's primary attack surface — it runs on bytes that
/// arrive over the charging cable before anything has been authenticated — so
/// every variant here represents a *rejection*, never a partial acceptance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExiError {
    /// The output buffer ran out of room.
    OutputFull,
    /// The stream ended in the middle of a value.
    UnexpectedEnd,
    /// Trailing padding bits were not zero, so the stream is malformed.
    NonZeroPadding,
    /// An integer would not fit the target type.
    IntegerOverflow,
    /// A value exceeded the length its schema type allows.
    ValueTooLong,
    /// A value was shorter than its schema type allows.
    ///
    /// `minLength`, and the lower half of `length`. The types that have one are
    /// the ones where a short value is not a small value but a broken one — a
    /// `GenChallenge` with a byte missing, a truncated ECDH public key.
    ValueTooShort,
    /// A character was not a valid Unicode scalar value.
    InvalidCodePoint,
    /// A float used the special exponent with a mantissa other than -1, 0 or 1.
    InvalidFloat,
    /// A date-time field was outside its permitted range.
    InvalidDateTime,
    /// The EXI header was missing, or announced options/versions we do not
    /// implement.
    BadHeader,
    /// The grammar had no production for the event code that was read.
    UnknownEventCode,
    /// A string table index pointed past the end of its partition.
    BadStringTableIndex,
    /// An enumeration index had no corresponding schema value.
    UnknownEnumValue,
    /// A restricted integer decoded to a value outside its schema facets.
    ///
    /// EXI codes a bounded integer as an index into its range, so a range of
    /// twenty values still travels in five bits and twelve of the thirty-two
    /// encodings are unused. A peer that sends one of those is out of spec, and
    /// accepting it would produce a message this crate could not re-encode.
    ValueOutOfRange,
    /// The stream held more data after the document ended.
    TrailingData,
    /// A required element was absent from the stream.
    MissingElement,
    /// A configured EXI option is valid but not implemented here.
    UnsupportedOption,
    /// Nesting exceeded the depth limit, which a hostile stream could otherwise
    /// use to exhaust the call stack.
    DepthLimitExceeded,
}

impl fmt::Display for ExiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::OutputFull => "output buffer full",
            Self::UnexpectedEnd => "unexpected end of EXI stream",
            Self::NonZeroPadding => "non-zero padding bits at end of EXI stream",
            Self::IntegerOverflow => "integer out of range",
            Self::ValueTooLong => "value exceeds the length permitted by its schema type",
            Self::ValueTooShort => "value is shorter than its schema type permits",
            Self::InvalidCodePoint => "invalid Unicode code point",
            Self::InvalidFloat => "invalid EXI float",
            Self::InvalidDateTime => "invalid EXI date-time",
            Self::BadHeader => "malformed or unsupported EXI header",
            Self::UnknownEventCode => "event code has no production in the grammar",
            Self::BadStringTableIndex => "string table index out of range",
            Self::UnknownEnumValue => "unknown enumeration value",
            Self::ValueOutOfRange => "value outside the range its schema type permits",
            Self::TrailingData => "trailing data after end of EXI document",
            Self::MissingElement => "required element missing",
            Self::UnsupportedOption => "unsupported EXI option",
            Self::DepthLimitExceeded => "maximum element nesting depth exceeded",
        };
        f.write_str(msg)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ExiError {}
