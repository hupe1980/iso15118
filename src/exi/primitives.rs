//! EXI built-in datatype representations (EXI 1.0 §7.1).
//!
//! These are the context-free primitives: everything here depends only on the
//! bit stream, not on grammars or string tables. String *values* additionally
//! participate in the string table and therefore live on
//! [`Encoder`](super::Encoder) / [`Decoder`](super::Decoder) instead.

use alloc::string::String;

use super::{BitReader, BitWriter, ExiError, ExiResult};

/// Largest number of 7-bit octets an EXI Unsigned Integer may use before it
/// can no longer fit in a `u64` (`ceil(64 / 7) == 10`).
const MAX_UINT_OCTETS: u32 = 10;

/// The exponent value that marks a special float (NaN / ±INF) — EXI 1.0 §7.1.5.
const FLOAT_SPECIAL_EXPONENT: i64 = -(1 << 14);

// ---------------------------------------------------------------------------
// Unsigned Integer (§7.1.5)
// ---------------------------------------------------------------------------

/// Writes an EXI Unsigned Integer: 7-bit groups, least-significant first, each
/// octet's high bit set while more groups follow.
pub fn write_uint(w: &mut BitWriter<'_>, mut value: u64) -> ExiResult<()> {
    loop {
        #[allow(clippy::cast_possible_truncation)]
        let mut octet = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            octet |= 0x80;
        }
        w.write_byte(octet)?;
        if value == 0 {
            return Ok(());
        }
    }
}

/// Reads an EXI Unsigned Integer.
///
/// Rejects encodings that would overflow a `u64`.
///
/// Non-minimal encodings — extra continuation octets carrying no bits — are
/// *accepted*. EXI does not require minimality outside Canonical EXI, every
/// encoder in the field produces the minimal form anyway, and refusing them
/// would only turn another implementation's harmless quirk into a failed
/// charging session. Nothing downstream can be confused by it: the decoded
/// value is the same, and Plug & Charge signatures are verified against the
/// bytes as received rather than against a re-encoding.
pub fn read_uint(r: &mut BitReader<'_>) -> ExiResult<u64> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    for _ in 0..MAX_UINT_OCTETS {
        let octet = r.read_byte()?;
        let payload = u64::from(octet & 0x7F);
        // On the final permissible octet only the bits that still fit may be set.
        if shift >= 64 || (shift == 63 && payload > 1) {
            return Err(ExiError::IntegerOverflow);
        }
        value |= payload << shift;
        if octet & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
    }
    Err(ExiError::IntegerOverflow)
}

// ---------------------------------------------------------------------------
// Signed Integer (§7.1.6)
// ---------------------------------------------------------------------------

/// Writes an EXI Integer: a sign bit followed by the magnitude, where negative
/// values store `-value - 1` so that `-1` costs a single zero octet.
pub fn write_int(w: &mut BitWriter<'_>, value: i64) -> ExiResult<()> {
    let negative = value < 0;
    w.write_bit(negative)?;
    // For negative v this is exactly `-v - 1`, computed without overflowing at
    // `i64::MIN`.
    #[allow(clippy::cast_sign_loss)]
    let magnitude = if negative { !value as u64 } else { value as u64 };
    write_uint(w, magnitude)
}

/// Reads an EXI Integer.
pub fn read_int(r: &mut BitReader<'_>) -> ExiResult<i64> {
    let negative = r.read_bit()?;
    let magnitude = read_uint(r)?;
    if negative {
        // -magnitude - 1; valid iff magnitude <= i64::MAX.
        i64::try_from(magnitude).map(|m| -m - 1).map_err(|_| ExiError::IntegerOverflow)
    } else {
        i64::try_from(magnitude).map_err(|_| ExiError::IntegerOverflow)
    }
}

// ---------------------------------------------------------------------------
// n-bit Unsigned Integer (§7.1.9) and Boolean (§7.1.2)
// ---------------------------------------------------------------------------

/// Writes an `n`-bit unsigned integer (used for event codes and enumerations).
pub fn write_nbit_uint(w: &mut BitWriter<'_>, value: u64, n: u32) -> ExiResult<()> {
    w.write_bits(value, n)
}

/// Reads an `n`-bit unsigned integer.
pub fn read_nbit_uint(r: &mut BitReader<'_>, n: u32) -> ExiResult<u64> {
    r.read_bits(n)
}

/// Writes a Boolean as a single bit.
pub fn write_bool(w: &mut BitWriter<'_>, value: bool) -> ExiResult<()> {
    w.write_bit(value)
}

/// Reads a Boolean.
pub fn read_bool(r: &mut BitReader<'_>) -> ExiResult<bool> {
    r.read_bit()
}

/// Number of bits needed to distinguish `count` alternatives.
///
/// EXI encodes a choice among `count` values in `ceil(log2(count))` bits, which
/// is zero bits when there is only one possibility.
#[must_use]
pub const fn bit_width(count: u64) -> u32 {
    match count {
        0 | 1 => 0,
        n => u64::BITS - (n - 1).leading_zeros(),
    }
}

// ---------------------------------------------------------------------------
// Binary (§7.1.7)
// ---------------------------------------------------------------------------

/// Writes `hexBinary` / `base64Binary` content: an Unsigned Integer length in
/// bytes followed by the raw bytes.
pub fn write_binary(w: &mut BitWriter<'_>, bytes: &[u8]) -> ExiResult<()> {
    write_uint(w, u64::try_from(bytes.len()).map_err(|_| ExiError::ValueTooLong)?)?;
    w.write_bytes(bytes)
}

/// Reads binary content into a fresh vector, rejecting anything longer than
/// `max_len` (the schema's `maxLength` facet).
///
/// The bound is checked *before* allocating, so a forged length field cannot
/// make us reserve memory the stream could never fill.
pub fn read_binary(r: &mut BitReader<'_>, max_len: usize) -> ExiResult<alloc::vec::Vec<u8>> {
    let len = read_uint(r)?;
    let len = usize::try_from(len).map_err(|_| ExiError::ValueTooLong)?;
    if len > max_len {
        return Err(ExiError::ValueTooLong);
    }
    if len.saturating_mul(8) > r.bits_remaining() {
        return Err(ExiError::UnexpectedEnd);
    }
    let mut out = alloc::vec![0u8; len];
    r.read_bytes(&mut out)?;
    Ok(out)
}

/// Reads binary content into a caller-provided buffer, returning its length.
///
/// The `no_std`-friendly counterpart to [`read_binary`].
pub fn read_binary_into(r: &mut BitReader<'_>, out: &mut [u8]) -> ExiResult<usize> {
    let len = read_uint(r)?;
    let len = usize::try_from(len).map_err(|_| ExiError::ValueTooLong)?;
    if len > out.len() {
        return Err(ExiError::ValueTooLong);
    }
    r.read_bytes(&mut out[..len])?;
    Ok(len)
}

// ---------------------------------------------------------------------------
// Characters (§7.1.10) — the raw part of String, shared with the string table
// ---------------------------------------------------------------------------

/// Writes the characters of `s` as Unsigned Integer Unicode code points.
///
/// The caller writes the length prefix, because its meaning depends on whether
/// the string participates in a string table partition.
pub fn write_chars(w: &mut BitWriter<'_>, s: &str) -> ExiResult<()> {
    for ch in s.chars() {
        write_uint(w, u64::from(ch as u32))?;
    }
    Ok(())
}

/// Reads exactly `count` Unicode code points.
pub fn read_chars(r: &mut BitReader<'_>, count: usize) -> ExiResult<String> {
    // Every code point costs at least one octet, so a count larger than the
    // remaining octets is a forgery — reject before allocating.
    if count.saturating_mul(8) > r.bits_remaining() {
        return Err(ExiError::UnexpectedEnd);
    }
    let mut out = String::with_capacity(count);
    for _ in 0..count {
        let cp = read_uint(r)?;
        let cp = u32::try_from(cp).map_err(|_| ExiError::InvalidCodePoint)?;
        out.push(char::from_u32(cp).ok_or(ExiError::InvalidCodePoint)?);
    }
    Ok(out)
}

/// Number of Unicode code points in `s` — EXI string lengths count characters,
/// not UTF-8 bytes.
#[must_use]
pub fn char_len(s: &str) -> usize {
    s.chars().count()
}

// ---------------------------------------------------------------------------
// Fraction — the reverse-order digit string EXI uses for fractional parts
// ---------------------------------------------------------------------------

/// The fractional part of a [`Decimal`] or a [`DateTime`], in EXI's own form.
///
/// EXI stores a fractional part as an Unsigned Integer **with the digits
/// reversed** (§7.1.3, §7.1.8): `.05` travels as `50`, so the leading zero
/// survives and a trailing zero — which carries no value — disappears. Keeping
/// that integer verbatim rather than un-reversing it into a value/precision
/// pair is what makes `decode(encode(x)) == x` hold exactly: every `Fraction`
/// has exactly one wire form and every wire form has exactly one `Fraction`.
///
/// # Invariant
///
/// The reversed digit string is at most [`Fraction::MAX_DIGITS`] digits long.
/// That is not a stylistic bound: un-reversing a twenty-digit `u64` — anything
/// above `9_999_999_999_999_999_999` — can produce a number `u64` cannot hold,
/// and [`Fraction::value`] would then overflow on a value that arrived over the
/// wire. Constructing one is fallible instead, and [`read_fraction`] rejects
/// the encodings that would break it, so `value()` is total by construction.
///
/// ```
/// # use iso15118::exi::Fraction;
/// let f = Fraction::from_digits(5, 2).unwrap(); // ".05"
/// assert_eq!(f.digits(), 2);
/// assert_eq!(f.value(), 5);
/// assert_eq!(f.as_reversed(), 50);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Fraction(u64);

impl Fraction {
    /// The fractional part `.0` — one digit, value zero.
    pub const ZERO: Self = Self(0);

    /// Most fractional digits a `Fraction` can hold; see the type's invariant.
    pub const MAX_DIGITS: u32 = 19;

    /// Largest reversed digit string that satisfies the invariant.
    const MAX_REVERSED: u64 = 9_999_999_999_999_999_999;

    /// Wraps an already-reversed digit string, exactly as it appears on the
    /// wire.
    ///
    /// `None` for a string of more than [`Fraction::MAX_DIGITS`] digits, which
    /// no `xs:decimal` or `xs:dateTime` facet in any V2G schema permits and
    /// which the type could not un-reverse.
    #[must_use]
    pub const fn from_reversed(reversed: u64) -> Option<Self> {
        if reversed > Self::MAX_REVERSED { None } else { Some(Self(reversed)) }
    }

    /// The reversed digit string, ready to write.
    #[must_use]
    pub const fn as_reversed(self) -> u64 {
        self.0
    }

    /// Builds `.<value padded to `digits` places>`.
    ///
    /// Returns `None` when `value` does not fit in `digits` decimal places, or
    /// when the reversal would overflow a `u64`.
    #[must_use]
    pub const fn from_digits(value: u64, digits: u32) -> Option<Self> {
        if digits == 0 {
            return if value == 0 { Some(Self::ZERO) } else { None };
        }
        if digits > Self::MAX_DIGITS {
            return None;
        }
        // `value` must be expressible in `digits` places.
        let mut limit: u64 = 1;
        let mut i = 0;
        while i < digits {
            let Some(next) = limit.checked_mul(10) else { return None };
            limit = next;
            i += 1;
        }
        if value >= limit {
            return None;
        }
        let mut reversed: u64 = 0;
        let mut rest = value;
        let mut i = 0;
        while i < digits {
            let Some(scaled) = reversed.checked_mul(10) else { return None };
            let Some(next) = scaled.checked_add(rest % 10) else { return None };
            reversed = next;
            rest /= 10;
            i += 1;
        }
        Some(Self(reversed))
    }

    /// Number of digits after the decimal point.
    ///
    /// Always at least one: `.0` and `.00` are the same number, and EXI's
    /// canonical form keeps the shorter one.
    #[must_use]
    pub const fn digits(self) -> u32 {
        let mut digits = 1;
        let mut rest = self.0 / 10;
        while rest != 0 {
            digits += 1;
            rest /= 10;
        }
        digits
    }

    /// The fractional digits read left to right, as an integer: `.05` is `5`.
    #[must_use]
    pub const fn value(self) -> u64 {
        let mut out: u64 = 0;
        let mut rest = self.0;
        loop {
            // Cannot overflow: the type's invariant caps the digit count at 19,
            // and un-reversing preserves it.
            out = out * 10 + rest % 10;
            rest /= 10;
            if rest == 0 {
                return out;
            }
        }
    }

    /// True for `.0`.
    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }
}

/// Writes a fractional part.
pub fn write_fraction(w: &mut BitWriter<'_>, f: Fraction) -> ExiResult<()> {
    write_uint(w, f.as_reversed())
}

/// Reads a fractional part.
///
/// A reversed digit string longer than [`Fraction::MAX_DIGITS`] is refused
/// rather than truncated: it is outside every V2G schema's facets, and letting
/// one through would put a `Fraction` in a state its own accessors could not
/// evaluate.
pub fn read_fraction(r: &mut BitReader<'_>) -> ExiResult<Fraction> {
    Fraction::from_reversed(read_uint(r)?).ok_or(ExiError::IntegerOverflow)
}

// ---------------------------------------------------------------------------
// Decimal (§7.1.3)
// ---------------------------------------------------------------------------

/// A decimal value as EXI represents it: a sign, an integral part, and a
/// [`Fraction`].
///
/// Kept exact rather than converted to a float: V2G carries prices and energy
/// amounts where a rounding error is a billing error.
///
/// Note that EXI's Decimal, unlike its Integer, *can* represent minus zero
/// (§7.1.3), so `-0.0` and `0.0` are distinct values here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Decimal {
    /// True when the value is negative.
    pub negative: bool,
    /// Digits before the decimal point.
    pub integral: u64,
    /// Digits after the decimal point.
    pub fractional: Fraction,
}

impl Decimal {
    /// Builds `[-]integral.fractional`, where `fractional` is padded to
    /// `fractional_digits` places.
    ///
    /// Returns `None` if `fractional` does not fit in that many digits.
    #[must_use]
    pub const fn new(
        negative: bool,
        integral: u64,
        fractional: u64,
        fractional_digits: u32,
    ) -> Option<Self> {
        match Fraction::from_digits(fractional, fractional_digits) {
            Some(fractional) => Some(Self { negative, integral, fractional }),
            None => None,
        }
    }

    /// A whole number, with no fractional digits.
    #[must_use]
    pub const fn integer(negative: bool, integral: u64) -> Self {
        Self { negative, integral, fractional: Fraction::ZERO }
    }
}

/// Writes an EXI Decimal.
pub fn write_decimal(w: &mut BitWriter<'_>, d: Decimal) -> ExiResult<()> {
    write_bool(w, d.negative)?;
    write_uint(w, d.integral)?;
    write_fraction(w, d.fractional)
}

/// Reads an EXI Decimal.
pub fn read_decimal(r: &mut BitReader<'_>) -> ExiResult<Decimal> {
    let negative = read_bool(r)?;
    let integral = read_uint(r)?;
    let fractional = read_fraction(r)?;
    Ok(Decimal { negative, integral, fractional })
}

// ---------------------------------------------------------------------------
// Float (§7.1.5)
// ---------------------------------------------------------------------------

/// An EXI Float: `mantissa × 10^exponent`, kept in its exact wire form.
///
/// The mantissa spans the whole of `i64`; the exponent is limited to
/// [`Float::MIN_EXPONENT`]`..=`[`Float::MAX_EXPONENT`], with the single value
/// below that reserved for NaN and the infinities (EXI 1.0 §7.1.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Float {
    /// Signed mantissa.
    pub mantissa: i64,
    /// Base-10 exponent. The reserved value `-2^14` marks NaN and ±infinity;
    /// see [`Float::is_special`].
    pub exponent: i64,
}

impl Float {
    /// Smallest exponent an ordinary value may use.
    pub const MIN_EXPONENT: i64 = -(1 << 14) + 1;
    /// Largest exponent an ordinary value may use.
    pub const MAX_EXPONENT: i64 = (1 << 14) - 1;

    /// Zero.
    pub const ZERO: Self = Self { mantissa: 0, exponent: 0 };
    /// The canonical not-a-number.
    ///
    /// EXI encodes NaN as the special exponent with *any* mantissa other than
    /// ±1, so a decoded NaN may carry a different mantissa than this one and
    /// still be NaN; [`Float::is_nan`] is the test, not equality.
    pub const NAN: Self = Self { mantissa: 0, exponent: -(1 << 14) };
    /// Positive infinity.
    pub const INFINITY: Self = Self { mantissa: 1, exponent: -(1 << 14) };
    /// Negative infinity.
    pub const NEG_INFINITY: Self = Self { mantissa: -1, exponent: -(1 << 14) };

    /// True for NaN or ±infinity.
    #[must_use]
    pub const fn is_special(self) -> bool {
        self.exponent == FLOAT_SPECIAL_EXPONENT
    }

    /// True for not-a-number.
    #[must_use]
    pub const fn is_nan(self) -> bool {
        self.is_special() && self.mantissa != 1 && self.mantissa != -1
    }

    /// True for ±infinity.
    #[must_use]
    pub const fn is_infinite(self) -> bool {
        self.is_special() && (self.mantissa == 1 || self.mantissa == -1)
    }

    /// True when the exponent is inside the range EXI permits for an ordinary
    /// value, or is the reserved special exponent.
    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.is_special()
            || (self.exponent >= Self::MIN_EXPONENT && self.exponent <= Self::MAX_EXPONENT)
    }

    /// Lossy conversion to `f64`, for display and arithmetic.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn to_f64(self) -> f64 {
        if self.is_special() {
            return match self.mantissa {
                1 => f64::INFINITY,
                -1 => f64::NEG_INFINITY,
                _ => f64::NAN,
            };
        }
        self.mantissa as f64 * pow10(self.exponent)
    }
}

/// `10^exp` without pulling in `libm` — exponents in V2G are small.
fn pow10(exp: i64) -> f64 {
    let mut acc = 1.0f64;
    let n = exp.unsigned_abs().min(308);
    for _ in 0..n {
        acc *= 10.0;
    }
    if exp < 0 { 1.0 / acc } else { acc }
}

/// Writes an EXI Float.
///
/// An exponent outside the range EXI permits is refused: the spec says such a
/// value "MUST NOT be used in the Float datatype representation", and emitting
/// one would produce a stream a conforming decoder is entitled to reject.
pub fn write_float(w: &mut BitWriter<'_>, f: Float) -> ExiResult<()> {
    if !f.is_valid() {
        return Err(ExiError::InvalidFloat);
    }
    write_int(w, f.mantissa)?;
    write_int(w, f.exponent)
}

/// Reads an EXI Float.
///
/// The special exponent with a mantissa other than ±1 is *not* an error — EXI
/// defines every such combination as NaN (§7.1.4) — but the mantissa is kept as
/// received so that re-encoding reproduces the same bytes.
pub fn read_float(r: &mut BitReader<'_>) -> ExiResult<Float> {
    let mantissa = read_int(r)?;
    let exponent = read_int(r)?;
    let f = Float { mantissa, exponent };
    if !f.is_valid() {
        return Err(ExiError::InvalidFloat);
    }
    Ok(f)
}

// ---------------------------------------------------------------------------
// Date-Time (§7.1.11)
// ---------------------------------------------------------------------------

/// An EXI `dateTime` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DateTime {
    /// Full year (EXI stores it as an offset from 2000).
    pub year: i64,
    /// Month, 1-12.
    pub month: u8,
    /// Day of month, 1-31.
    pub day: u8,
    /// Hour, 0-24 (24 is midnight at the end of the day, as XML Schema allows).
    pub hour: u8,
    /// Minute, 0-59.
    pub minute: u8,
    /// Second, 0-60 (60 for a leap second).
    pub second: u8,
    /// Fractional seconds, if present.
    pub fractional_secs: Option<Fraction>,
    /// Timezone offset in minutes from UTC, if present.
    pub timezone_minutes: Option<i16>,
}

/// EXI stores the year relative to this epoch.
const DATETIME_YEAR_OFFSET: i64 = 2000;
/// Largest hour XML Schema permits: 24 denotes midnight ending the day.
const MAX_HOUR: u8 = 24;
/// EXI stores the timezone as `minutes + 896` in 11 bits.
const TZ_BIAS: i64 = 896;

/// Writes an EXI `dateTime`.
pub fn write_datetime(w: &mut BitWriter<'_>, dt: DateTime) -> ExiResult<()> {
    if dt.month == 0 || dt.month > 12 || dt.day == 0 || dt.day > 31 {
        return Err(ExiError::InvalidDateTime);
    }
    if dt.hour > MAX_HOUR || dt.minute > 59 || dt.second > 60 {
        return Err(ExiError::InvalidDateTime);
    }
    let year_offset = dt.year.checked_sub(DATETIME_YEAR_OFFSET).ok_or(ExiError::InvalidDateTime)?;
    write_int(w, year_offset)?;
    let month_day = u64::from(dt.month) * 32 + u64::from(dt.day);
    write_nbit_uint(w, month_day, 9)?;
    let time = (u64::from(dt.hour) * 64 + u64::from(dt.minute)) * 64 + u64::from(dt.second);
    write_nbit_uint(w, time, 17)?;
    match dt.fractional_secs {
        Some(f) => {
            write_bool(w, true)?;
            write_fraction(w, f)?;
        }
        None => write_bool(w, false)?,
    }
    match dt.timezone_minutes {
        Some(tz) => {
            write_bool(w, true)?;
            let biased = i64::from(tz) + TZ_BIAS;
            if !(0..2048).contains(&biased) {
                return Err(ExiError::InvalidDateTime);
            }
            #[allow(clippy::cast_sign_loss)]
            write_nbit_uint(w, biased as u64, 11)?;
        }
        None => write_bool(w, false)?,
    }
    Ok(())
}

/// Reads an EXI `dateTime`.
pub fn read_datetime(r: &mut BitReader<'_>) -> ExiResult<DateTime> {
    // The year travels as a signed offset from 2000, so a hostile stream can
    // name a year that does not fit an i64 once the epoch is added back.
    let year = read_int(r)?.checked_add(DATETIME_YEAR_OFFSET).ok_or(ExiError::InvalidDateTime)?;
    let month_day = read_nbit_uint(r, 9)?;
    let time = read_nbit_uint(r, 17)?;
    let fractional_secs = if read_bool(r)? { Some(read_fraction(r)?) } else { None };
    let timezone_minutes = if read_bool(r)? {
        let biased =
            i64::try_from(read_nbit_uint(r, 11)?).map_err(|_| ExiError::InvalidDateTime)?;
        Some(i16::try_from(biased - TZ_BIAS).map_err(|_| ExiError::InvalidDateTime)?)
    } else {
        None
    };

    #[allow(clippy::cast_possible_truncation)]
    let dt = DateTime {
        year,
        month: (month_day / 32) as u8,
        day: (month_day % 32) as u8,
        hour: (time / 4096) as u8,
        minute: ((time / 64) % 64) as u8,
        second: (time % 64) as u8,
        fractional_secs,
        timezone_minutes,
    };
    if dt.month == 0 || dt.month > 12 || dt.day == 0 || dt.day > 31 {
        return Err(ExiError::InvalidDateTime);
    }
    if dt.hour > MAX_HOUR || dt.minute > 59 || dt.second > 60 {
        return Err(ExiError::InvalidDateTime);
    }
    Ok(dt)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[allow(clippy::needless_pass_by_value, reason = "test helper takes ownership for ergonomics")]
    fn roundtrip<T: PartialEq + core::fmt::Debug>(
        value: T,
        write: impl Fn(&mut BitWriter<'_>, &T) -> ExiResult<()>,
        read: impl Fn(&mut BitReader<'_>) -> ExiResult<T>,
    ) {
        let mut buf = [0u8; 256];
        let mut w = BitWriter::new(&mut buf);
        write(&mut w, &value).unwrap();
        let len = w.finish().unwrap();
        let mut r = BitReader::new(&buf[..len]);
        assert_eq!(read(&mut r).unwrap(), value);
    }

    #[test]
    fn uint_matches_the_spec_example() {
        // The ISO 15118-20 SessionStop golden vector carries this timestamp;
        // these are the exact five octets it occupies on the wire.
        let mut buf = [0u8; 16];
        let mut w = BitWriter::new(&mut buf);
        write_uint(&mut w, 1_725_456_343).unwrap();
        let len = w.finish().unwrap();
        assert_eq!(&buf[..len], &[0xD7, 0xBF, 0xE1, 0xB6, 0x06]);
    }

    #[test]
    fn uint_zero_is_one_octet() {
        let mut buf = [0u8; 4];
        let mut w = BitWriter::new(&mut buf);
        write_uint(&mut w, 0).unwrap();
        assert_eq!(w.finish().unwrap(), 1);
        assert_eq!(buf[0], 0);
    }

    #[test]
    fn uint_overflow_is_rejected() {
        // Eleven continuation octets can never be a u64.
        let bytes = [0xFFu8; 11];
        let mut r = BitReader::new(&bytes);
        assert_eq!(read_uint(&mut r), Err(ExiError::IntegerOverflow));
    }

    #[test]
    fn non_minimal_uint_is_accepted() {
        // 0x80 0x00 = "value 0, padded to two octets". Not what we emit, but
        // decoding it as anything other than 0 would be wrong.
        let mut r = BitReader::new(&[0x80, 0x00]);
        assert_eq!(read_uint(&mut r).unwrap(), 0);
    }

    #[test]
    fn int_extremes_roundtrip() {
        for v in [0i64, -1, 1, i64::MAX, i64::MIN, -12345, 12345] {
            roundtrip(v, |w, &v| write_int(w, v), read_int);
        }
    }

    #[test]
    fn negative_one_is_a_single_zero_octet() {
        let mut buf = [0u8; 4];
        let mut w = BitWriter::new(&mut buf);
        write_int(&mut w, -1).unwrap();
        assert_eq!(w.bit_len(), 9, "sign bit plus one octet");
    }

    #[test]
    fn bit_width_is_ceil_log2() {
        assert_eq!(bit_width(0), 0);
        assert_eq!(bit_width(1), 0);
        assert_eq!(bit_width(2), 1);
        assert_eq!(bit_width(3), 2);
        assert_eq!(bit_width(4), 2);
        assert_eq!(bit_width(5), 3);
        assert_eq!(bit_width(55), 6, "ISO 15118-20 CommonMessages document productions");
        assert_eq!(bit_width(64), 6);
        assert_eq!(bit_width(65), 7);
    }

    #[test]
    fn oversized_binary_is_rejected_before_allocating() {
        // Length says 1 MiB, stream holds two bytes.
        let mut buf = [0u8; 8];
        let mut w = BitWriter::new(&mut buf);
        write_uint(&mut w, 1_048_576).unwrap();
        let len = w.finish().unwrap();
        let mut r = BitReader::new(&buf[..len]);
        assert_eq!(read_binary(&mut r, 64), Err(ExiError::ValueTooLong));
    }

    #[test]
    fn binary_length_beyond_the_stream_is_rejected() {
        let mut buf = [0u8; 8];
        let mut w = BitWriter::new(&mut buf);
        write_uint(&mut w, 4096).unwrap();
        let len = w.finish().unwrap();
        let mut r = BitReader::new(&buf[..len]);
        assert_eq!(read_binary(&mut r, usize::MAX), Err(ExiError::UnexpectedEnd));
    }

    #[test]
    fn float_specials_roundtrip() {
        for f in [Float::NAN, Float::INFINITY, Float::NEG_INFINITY] {
            roundtrip(f, |w, &f| write_float(w, f), read_float);
        }
        assert!(Float::NAN.to_f64().is_nan());
        assert!(Float::INFINITY.to_f64().is_infinite() && Float::INFINITY.to_f64() > 0.0);
        assert!(Float::NAN.is_nan() && !Float::NAN.is_infinite());
        assert!(Float::NEG_INFINITY.is_infinite() && !Float::NEG_INFINITY.is_nan());
    }

    /// EXI 1.0 §7.1.4: the special exponent with *any* mantissa other than ±1
    /// is NaN, not a malformed value. Rejecting those would refuse streams the
    /// reference implementation produces.
    #[test]
    fn the_special_exponent_with_any_other_mantissa_is_nan() {
        let mut buf = [0u8; 16];
        let mut w = BitWriter::new(&mut buf);
        write_int(&mut w, 7).unwrap();
        write_int(&mut w, FLOAT_SPECIAL_EXPONENT).unwrap();
        let len = w.finish().unwrap();
        let mut r = BitReader::new(&buf[..len]);
        let f = read_float(&mut r).unwrap();
        assert!(f.is_nan());
        assert!(f.to_f64().is_nan());
        assert_eq!(f.mantissa, 7, "the mantissa is kept so re-encoding is exact");
    }

    /// The spec bounds the exponent at ±(2^14 - 1); anything wider "MUST NOT be
    /// used", so it is refused in both directions.
    #[test]
    fn an_out_of_range_exponent_is_refused() {
        let mut buf = [0u8; 16];
        let mut w = BitWriter::new(&mut buf);
        assert_eq!(
            write_float(&mut w, Float { mantissa: 1, exponent: 16_384 }),
            Err(ExiError::InvalidFloat)
        );

        let mut w = BitWriter::new(&mut buf);
        write_int(&mut w, 1).unwrap();
        write_int(&mut w, -16_385).unwrap();
        let len = w.finish().unwrap();
        let mut r = BitReader::new(&buf[..len]);
        assert_eq!(read_float(&mut r), Err(ExiError::InvalidFloat));
    }

    #[test]
    fn decimal_keeps_leading_fractional_zeros() {
        // 1.05 must not decode as 1.5.
        let d = Decimal::new(false, 1, 5, 2).unwrap();
        assert_eq!(d.fractional.digits(), 2);
        assert_eq!(d.fractional.value(), 5);
        roundtrip(d, |w, &d| write_decimal(w, d), read_decimal);
    }

    /// The fractional part is stored in EXI's own reverse-digit form, so every
    /// value has exactly one encoding and every encoding exactly one value.
    #[test]
    fn every_fraction_survives_a_round_trip_exactly() {
        for reversed in [0u64, 1, 5, 50, 500, 12_345, Fraction::MAX_REVERSED] {
            let f = Fraction::from_reversed(reversed).unwrap();
            let d = Decimal { negative: true, integral: 7, fractional: f };
            roundtrip(d, |w, &d| write_decimal(w, d), read_decimal);
        }
    }

    /// Un-reversing a twenty-digit string overflows a `u64`, so such a string
    /// is not a `Fraction` at all — refused at the constructor and refused on
    /// the wire, rather than left to panic inside `value()` later.
    #[test]
    fn a_fraction_too_long_to_un_reverse_is_refused() {
        assert_eq!(Fraction::from_reversed(u64::MAX), None);
        assert_eq!(Fraction::from_reversed(Fraction::MAX_REVERSED + 1), None);
        assert!(Fraction::from_reversed(Fraction::MAX_REVERSED).is_some());
        assert_eq!(Fraction::from_digits(0, Fraction::MAX_DIGITS + 1), None);

        let mut buf = [0u8; 32];
        let mut w = BitWriter::new(&mut buf);
        write_uint(&mut w, u64::MAX).unwrap();
        let len = w.finish().unwrap();
        let mut r = BitReader::new(&buf[..len]);
        assert_eq!(read_fraction(&mut r), Err(ExiError::IntegerOverflow));
    }

    /// Every `Fraction` the wire can produce must survive `value()` and
    /// `digits()` without overflowing — the invariant, exercised at its edge.
    #[test]
    fn value_is_total_over_every_representable_fraction() {
        for reversed in [
            Fraction::MAX_REVERSED,
            Fraction::MAX_REVERSED - 1,
            1_000_000_000_000_000_000,
            9_000_000_000_000_000_009,
        ] {
            let f = Fraction::from_reversed(reversed).unwrap();
            assert!(f.digits() <= Fraction::MAX_DIGITS);
            let _ = f.value();
        }
    }

    #[test]
    fn a_fraction_that_does_not_fit_its_digits_is_refused() {
        assert_eq!(Fraction::from_digits(100, 2), None);
        assert_eq!(Fraction::from_digits(1, 0), None);
        assert_eq!(Fraction::from_digits(0, 0), Some(Fraction::ZERO));
        assert_eq!(Decimal::new(false, 0, 1000, 3), None);
    }

    #[test]
    fn datetime_roundtrips() {
        let dt = DateTime {
            year: 2024,
            month: 9,
            day: 4,
            hour: 13,
            minute: 25,
            second: 43,
            fractional_secs: Some(Fraction::from_digits(5, 3).unwrap()),
            timezone_minutes: Some(-120),
        };
        roundtrip(dt, |w, &d| write_datetime(w, d), read_datetime);
    }

    /// Found by `cargo fuzz`: the year is a signed offset from 2000, and
    /// adding the epoch back to an extreme offset overflowed.
    #[test]
    fn an_extreme_datetime_year_does_not_overflow() {
        let mut buf = [0u8; 32];
        let mut w = BitWriter::new(&mut buf);
        write_int(&mut w, i64::MAX).unwrap();
        write_nbit_uint(&mut w, 32 + 1, 9).unwrap(); // month 1, day 1
        write_nbit_uint(&mut w, 0, 17).unwrap();
        write_bool(&mut w, false).unwrap();
        write_bool(&mut w, false).unwrap();
        let len = w.finish().unwrap();
        let mut r = BitReader::new(&buf[..len]);
        assert_eq!(read_datetime(&mut r), Err(ExiError::InvalidDateTime));

        // ...and symmetrically on the way out.
        let mut out = [0u8; 32];
        let mut w = BitWriter::new(&mut out);
        let dt = DateTime { year: i64::MIN, month: 1, day: 1, ..DateTime::default() };
        assert_eq!(write_datetime(&mut w, dt), Err(ExiError::InvalidDateTime));
    }

    /// XML Schema (and EXI's Table 7-3) allow hour 24, meaning midnight at the
    /// end of the day. Rejecting it would refuse a legal `xs:dateTime`.
    #[test]
    fn hour_twenty_four_is_legal() {
        let dt = DateTime { year: 2024, month: 1, day: 1, hour: 24, ..DateTime::default() };
        roundtrip(dt, |w, &d| write_datetime(w, d), read_datetime);

        let bad = DateTime { hour: 25, ..dt };
        let mut buf = [0u8; 32];
        assert_eq!(
            write_datetime(&mut BitWriter::new(&mut buf), bad),
            Err(ExiError::InvalidDateTime)
        );
    }

    #[test]
    fn invalid_datetime_is_rejected() {
        let mut buf = [0u8; 16];
        let mut w = BitWriter::new(&mut buf);
        write_int(&mut w, 24).unwrap();
        write_nbit_uint(&mut w, 13 * 32 + 40, 9).unwrap(); // month 13, day 40
        write_nbit_uint(&mut w, 0, 17).unwrap();
        write_bool(&mut w, false).unwrap();
        write_bool(&mut w, false).unwrap();
        let len = w.finish().unwrap();
        let mut r = BitReader::new(&buf[..len]);
        assert_eq!(read_datetime(&mut r), Err(ExiError::InvalidDateTime));
    }

    #[test]
    fn chars_count_code_points_not_bytes() {
        assert_eq!(char_len("größe"), 5);
        assert_eq!("größe".len(), 7, "two of those characters are two bytes each");
    }

    proptest! {
        #[test]
        fn uint_roundtrip(v: u64) {
            roundtrip(v, |w, &v| write_uint(w, v), read_uint);
        }

        #[test]
        fn int_roundtrip(v: i64) {
            roundtrip(v, |w, &v| write_int(w, v), read_int);
        }

        #[test]
        fn chars_roundtrip(s in ".{0,64}") {
            let n = char_len(&s);
            roundtrip(s, |w, s| write_chars(w, s), |r| read_chars(r, n));
        }

        #[test]
        fn float_roundtrip(mantissa: i64, exponent in Float::MIN_EXPONENT..=Float::MAX_EXPONENT) {
            roundtrip(Float { mantissa, exponent }, |w, &f| write_float(w, f), read_float);
        }

        /// A `Fraction` preserves the *number* it was built from. Trailing
        /// zeros are not part of that number and EXI drops them, so `.17835`
        /// and `.178350` are one value with one encoding.
        #[test]
        fn a_fraction_preserves_its_value_modulo_trailing_zeros(
            raw in 0u64..1_000_000,
            digits in 1u32..=6,
        ) {
            let value = raw % 10u64.pow(digits);
            let f = Fraction::from_digits(value, digits).unwrap();
            prop_assert!(f.digits() <= digits);
            prop_assert_eq!(f.value() * 10u64.pow(digits - f.digits()), value);
        }

        /// No input, however malformed, may panic any primitive decoder.
        #[test]
        fn decoders_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..48)) {
            let _ = read_uint(&mut BitReader::new(&bytes));
            let _ = read_int(&mut BitReader::new(&bytes));
            let _ = read_decimal(&mut BitReader::new(&bytes));
            let _ = read_float(&mut BitReader::new(&bytes));
            let _ = read_datetime(&mut BitReader::new(&bytes));
            let _ = read_binary(&mut BitReader::new(&bytes), 4096);
        }
    }
}
