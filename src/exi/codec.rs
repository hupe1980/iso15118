//! The stateful EXI encoder and decoder.
//!
//! [`Encoder`] and [`Decoder`] pair a bit stream with the document-scoped state
//! a schema-informed EXI body needs — the value string table and a nesting
//! depth counter. Generated (and hand-written) message codecs are written
//! against these two types and nothing else.

use alloc::string::String;

use super::string_table::{ExiOptions, Hit, ValueCtx, ValueTable};
use super::{BitReader, BitWriter, ExiError, ExiResult, Header, header, primitives as prim};

/// The length facets a schema puts on a string or binary value.
///
/// XML Schema has three — `minLength`, `maxLength` and `length` — and the third
/// is not the second: `genChallengeType` is `length = 16`, and a fifteen-byte
/// one is not a short challenge, it is not a challenge. Carrying only the
/// maximum is how a codec comes to accept a truncated ECDH public key, or a
/// nonce with a byte missing, and then re-encode it into a message no
/// conforming peer will take.
///
/// So the facets travel together, and every string and binary value is checked
/// against both on the way in and on the way out.
///
/// ```
/// # use iso15118::exi::Lengths;
/// assert!(Lengths::exact(16).admits(16));
/// assert!(!Lengths::exact(16).admits(15));
/// assert!(Lengths::max(800).admits(0));
/// assert!(Lengths::new(7, 37).admits(7) && !Lengths::new(7, 37).admits(6));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Lengths {
    min: usize,
    max: usize,
}

impl Lengths {
    /// `maxLength` only — any length up to `max`.
    #[must_use]
    pub const fn max(max: usize) -> Self {
        Self { min: 0, max }
    }

    /// `length` — exactly this many, no fewer and no more.
    #[must_use]
    pub const fn exact(len: usize) -> Self {
        Self { min: len, max: len }
    }

    /// `minLength` and `maxLength` together.
    #[must_use]
    pub const fn new(min: usize, max: usize) -> Self {
        Self { min, max }
    }

    /// The smallest permitted length.
    #[must_use]
    pub const fn min_len(self) -> usize {
        self.min
    }

    /// The largest permitted length.
    #[must_use]
    pub const fn max_len(self) -> usize {
        self.max
    }

    /// Whether a value of `len` units satisfies both facets.
    #[must_use]
    pub const fn admits(self, len: usize) -> bool {
        len >= self.min && len <= self.max
    }

    /// The error a value of `len` units earns, if any.
    const fn check(self, len: usize) -> ExiResult<()> {
        if len > self.max {
            Err(ExiError::ValueTooLong)
        } else if len < self.min {
            Err(ExiError::ValueTooShort)
        } else {
            Ok(())
        }
    }
}

/// Hard ceiling on element nesting.
///
/// The deepest ISO 15118 schema nests well under a dozen levels; a stream that
/// claims more is malformed or hostile, and refusing it keeps recursive
/// generated decoders off the edge of the stack.
pub const MAX_DEPTH: u16 = 64;

/// Writes a schema-informed EXI body into a caller-owned buffer.
#[derive(Debug)]
pub struct Encoder<'a> {
    bits: BitWriter<'a>,
    values: ValueTable,
    opts: ExiOptions,
    depth: u16,
}

impl<'a> Encoder<'a> {
    /// Creates an encoder over `buf` using the ISO 15118 EXI options.
    #[must_use]
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self::with_options(buf, ExiOptions::ISO15118)
    }

    /// Creates an encoder with explicit EXI options.
    #[must_use]
    pub fn with_options(buf: &'a mut [u8], opts: ExiOptions) -> Self {
        Self { bits: BitWriter::new(buf), values: ValueTable::new(), opts, depth: 0 }
    }

    /// Writes the EXI header. Call once, before any event.
    pub fn write_header(&mut self, header: Header) -> ExiResult<()> {
        header::write_header(&mut self.bits, header)
    }

    /// Writes an event code of `width` bits.
    ///
    /// A width of zero writes nothing, which is the common case: a grammar
    /// state with a single possible production costs no bits at all.
    pub fn event(&mut self, code: u64, width: u32) -> ExiResult<()> {
        prim::write_nbit_uint(&mut self.bits, code, width)
    }

    /// Enters a nested element, enforcing [`MAX_DEPTH`].
    pub fn enter(&mut self) -> ExiResult<()> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(ExiError::DepthLimitExceeded);
        }
        Ok(())
    }

    /// Leaves a nested element.
    pub fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    /// Writes an Unsigned Integer.
    pub fn uint(&mut self, v: u64) -> ExiResult<()> {
        prim::write_uint(&mut self.bits, v)
    }

    /// Writes a Signed Integer.
    pub fn int(&mut self, v: i64) -> ExiResult<()> {
        prim::write_int(&mut self.bits, v)
    }

    /// Writes an `n`-bit unsigned integer (enumeration index, restricted int).
    pub fn nbit(&mut self, v: u64, n: u32) -> ExiResult<()> {
        prim::write_nbit_uint(&mut self.bits, v, n)
    }

    /// Writes a Boolean.
    pub fn boolean(&mut self, v: bool) -> ExiResult<()> {
        prim::write_bool(&mut self.bits, v)
    }

    /// Writes a schema-restricted integer (EXI 1.0 §7.1.9).
    ///
    /// A type whose `minInclusive`/`maxInclusive` span 4096 values or fewer
    /// travels as an index into that range rather than as a general integer, so
    /// `priorityType` (1..=20) costs five bits and not an octet.
    pub fn restricted(&mut self, value: i64, min: i64, max: i64) -> ExiResult<()> {
        debug_assert!(min <= max, "empty range {min}..={max}");
        if value < min || value > max {
            return Err(ExiError::ValueOutOfRange);
        }
        // The bounds may straddle zero, so the differences are computed in
        // i128: `max - min` can overflow i64 for a range wide enough, even
        // though EXI only codes ranges of 4096 values this way. Both are
        // non-negative here, because `min <= value <= max`.
        let span = u64::try_from(i128::from(max) - i128::from(min))
            .map_err(|_| ExiError::ValueOutOfRange)?;
        let index = u64::try_from(i128::from(value) - i128::from(min))
            .map_err(|_| ExiError::ValueOutOfRange)?;
        self.nbit(index, prim::bit_width(span + 1))
    }

    /// Writes binary content, rejecting anything outside the schema's length
    /// facets.
    pub fn binary(&mut self, bytes: &[u8], lengths: Lengths) -> ExiResult<()> {
        lengths.check(bytes.len())?;
        prim::write_binary(&mut self.bits, bytes)
    }

    /// Writes a Decimal.
    pub fn decimal(&mut self, v: prim::Decimal) -> ExiResult<()> {
        prim::write_decimal(&mut self.bits, v)
    }

    /// Writes a Float.
    pub fn float(&mut self, v: prim::Float) -> ExiResult<()> {
        prim::write_float(&mut self.bits, v)
    }

    /// Writes a date-time.
    pub fn datetime(&mut self, v: prim::DateTime) -> ExiResult<()> {
        prim::write_datetime(&mut self.bits, v)
    }

    /// Writes a string value through the string table.
    ///
    /// `ctx` selects the local partition — it must identify the element or
    /// attribute the value belongs to, and must match what the decoder uses.
    pub fn string(&mut self, ctx: ValueCtx, value: &str, lengths: Lengths) -> ExiResult<()> {
        let n = prim::char_len(value);
        lengths.check(n)?;

        if self.opts.table_enabled() {
            match self.values.find(ctx, value) {
                Hit::Local(idx) => {
                    let width = self.values.local_index_width(ctx);
                    self.uint(0)?;
                    return self.nbit(idx, width);
                }
                Hit::Global(idx) => {
                    let width = self.values.global_index_width();
                    self.uint(1)?;
                    // Deliberately *not* added to this context's local
                    // partition. EXI populates partitions only when a value is
                    // coded literally (§7.3.3); a global hit leaves the local
                    // one empty, so the next occurrence here is another global
                    // hit. Adding it here desynchronises from any conforming
                    // peer the moment one string appears under two element
                    // names — which is most messages.
                    return self.nbit(idx, width);
                }
                Hit::Miss => {}
            }
        }

        // Literal: the length is offset by two so that 0 and 1 stay free as the
        // local- and global-hit markers.
        self.uint(n as u64 + 2)?;
        prim::write_chars(&mut self.bits, value)?;
        if self.opts.table_enabled() && self.opts.admits(n) {
            self.values.insert(ctx, value);
        }
        Ok(())
    }

    /// Bits written so far, header included.
    #[must_use]
    pub const fn bit_len(&self) -> usize {
        self.bits.bit_len()
    }

    /// Finishes the document, padding the last byte, and returns its length.
    pub fn finish(self) -> ExiResult<usize> {
        self.bits.finish()
    }
}

/// Reads a schema-informed EXI body.
#[derive(Debug)]
pub struct Decoder<'a> {
    bits: BitReader<'a>,
    values: ValueTable,
    opts: ExiOptions,
    depth: u16,
}

impl<'a> Decoder<'a> {
    /// Creates a decoder over `buf` using the ISO 15118 EXI options.
    #[must_use]
    pub const fn new(buf: &'a [u8]) -> Self {
        Self {
            bits: BitReader::new(buf),
            values: ValueTable::new(),
            opts: ExiOptions::ISO15118,
            depth: 0,
        }
    }

    /// Creates a decoder with explicit EXI options.
    #[must_use]
    pub fn with_options(buf: &'a [u8], opts: ExiOptions) -> Self {
        Self { bits: BitReader::new(buf), values: ValueTable::new(), opts, depth: 0 }
    }

    /// Reads and validates the EXI header.
    pub fn read_header(&mut self) -> ExiResult<Header> {
        header::read_header(&mut self.bits)
    }

    /// Reads an event code of `width` bits.
    pub fn event(&mut self, width: u32) -> ExiResult<u64> {
        prim::read_nbit_uint(&mut self.bits, width)
    }

    /// Reads an event code and requires it to be `code`.
    ///
    /// Used where the grammar leaves no choice — the `CH` and `EE` around a
    /// simple-typed element, for instance. Anything else means the stream and
    /// the grammar disagree, which must be a rejection rather than a guess.
    pub fn expect_event(&mut self, code: u64, width: u32) -> ExiResult<()> {
        if self.event(width)? == code { Ok(()) } else { Err(ExiError::UnknownEventCode) }
    }

    /// Enters a nested element, enforcing [`MAX_DEPTH`].
    pub fn enter(&mut self) -> ExiResult<()> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(ExiError::DepthLimitExceeded);
        }
        Ok(())
    }

    /// Leaves a nested element.
    pub fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    /// Reads an Unsigned Integer.
    pub fn uint(&mut self) -> ExiResult<u64> {
        prim::read_uint(&mut self.bits)
    }

    /// Reads a Signed Integer.
    pub fn int(&mut self) -> ExiResult<i64> {
        prim::read_int(&mut self.bits)
    }

    /// Reads an `n`-bit unsigned integer.
    pub fn nbit(&mut self, n: u32) -> ExiResult<u64> {
        prim::read_nbit_uint(&mut self.bits, n)
    }

    /// Reads a Boolean.
    pub fn boolean(&mut self) -> ExiResult<bool> {
        prim::read_bool(&mut self.bits)
    }

    /// Reads a schema-restricted integer (EXI 1.0 §7.1.9).
    ///
    /// The index is checked against the range before it is offset: a range of
    /// twenty values leaves twelve of the thirty-two five-bit encodings unused,
    /// and those are rejected rather than passed through as out-of-schema
    /// values that could not be re-encoded.
    pub fn restricted(&mut self, min: i64, max: i64) -> ExiResult<i64> {
        debug_assert!(min <= max, "empty range {min}..={max}");
        let span = u64::try_from(i128::from(max) - i128::from(min))
            .map_err(|_| ExiError::ValueOutOfRange)?;
        let index = self.nbit(prim::bit_width(span + 1))?;
        if index > span {
            return Err(ExiError::ValueOutOfRange);
        }
        i64::try_from(i128::from(min) + i128::from(index)).map_err(|_| ExiError::ValueOutOfRange)
    }

    /// Reads binary content, rejecting anything outside the schema's length
    /// facets.
    pub fn binary(&mut self, lengths: Lengths) -> ExiResult<alloc::vec::Vec<u8>> {
        let bytes = prim::read_binary(&mut self.bits, lengths.max_len())?;
        lengths.check(bytes.len())?;
        Ok(bytes)
    }

    /// Reads a Decimal.
    pub fn decimal(&mut self) -> ExiResult<prim::Decimal> {
        prim::read_decimal(&mut self.bits)
    }

    /// Reads a Float.
    pub fn float(&mut self) -> ExiResult<prim::Float> {
        prim::read_float(&mut self.bits)
    }

    /// Reads a date-time.
    pub fn datetime(&mut self) -> ExiResult<prim::DateTime> {
        prim::read_datetime(&mut self.bits)
    }

    /// Reads a string value through the string table.
    ///
    /// The length facets are checked on the literal *and* on a table hit: a
    /// partition entry is a value this same stream coded literally, so it has
    /// already passed — but the check costs nothing and a table index is
    /// attacker-chosen.
    pub fn string(&mut self, ctx: ValueCtx, lengths: Lengths) -> ExiResult<String> {
        let value = self.string_inner(ctx, lengths)?;
        lengths.check(prim::char_len(&value))?;
        Ok(value)
    }

    fn string_inner(&mut self, ctx: ValueCtx, lengths: Lengths) -> ExiResult<String> {
        let marker = self.uint()?;
        match marker {
            0 if self.opts.table_enabled() => {
                let width = self.values.local_index_width(ctx);
                let idx = self.nbit(width)?;
                self.values.local(ctx, idx).map(String::from).ok_or(ExiError::BadStringTableIndex)
            }
            1 if self.opts.table_enabled() => {
                let width = self.values.global_index_width();
                let idx = self.nbit(width)?;
                // Mirrors the encoder: a global hit does not populate the local
                // partition.
                self.values.global(idx).map(String::from).ok_or(ExiError::BadStringTableIndex)
            }
            0 | 1 => Err(ExiError::BadStringTableIndex),
            n => {
                let len = usize::try_from(n - 2).map_err(|_| ExiError::ValueTooLong)?;
                if len > lengths.max_len() {
                    return Err(ExiError::ValueTooLong);
                }
                let s = prim::read_chars(&mut self.bits, len)?;
                if self.opts.table_enabled() && self.opts.admits(len) {
                    self.values.insert(ctx, &s);
                }
                Ok(s)
            }
        }
    }

    /// Bits consumed so far.
    #[must_use]
    pub const fn bit_pos(&self) -> usize {
        self.bits.bit_pos()
    }

    /// Bits still unread.
    #[must_use]
    pub const fn bits_remaining(&self) -> usize {
        self.bits.bits_remaining()
    }

    /// Consumes the trailing pad bits and asserts the document is fully read.
    ///
    /// A stream with bytes left over after the document ended is rejected:
    /// silently ignoring them would let a peer smuggle data past the grammar.
    pub fn finish(mut self) -> ExiResult<()> {
        self.bits.skip_padding()?;
        if self.bits.bits_remaining() != 0 {
            return Err(ExiError::TrailingData);
        }
        Ok(())
    }
}

/// A message that forms a complete EXI document: header, one root element, end.
pub trait ExiDocument: Sized {
    /// Writes header, body and padding into `buf`; returns the byte length.
    fn to_slice(&self, buf: &mut [u8]) -> ExiResult<usize>;

    /// Parses a complete EXI document, rejecting trailing bytes.
    fn from_bytes(bytes: &[u8]) -> ExiResult<Self>;

    /// Encodes into a fresh vector.
    fn to_vec(&self) -> ExiResult<alloc::vec::Vec<u8>> {
        encode_growing(|buf| self.to_slice(buf))
    }
}

/// Runs a slice encoder against a buffer that doubles until the output fits.
///
/// The EXI encoders write into caller-owned slices so that a `no_std` target
/// can size its own buffer; this is the convenience wrapper for callers that
/// would rather have a `Vec`. It stops at [`MAX_EXI_PAYLOAD_LEN`], which is
/// far above any real V2G message.
///
/// [`MAX_EXI_PAYLOAD_LEN`]: crate::MAX_EXI_PAYLOAD_LEN
pub fn encode_growing(
    mut encode: impl FnMut(&mut [u8]) -> ExiResult<usize>,
) -> ExiResult<alloc::vec::Vec<u8>> {
    // ISO 15118 caps a V2GTP payload at 4 GiB but real messages are far
    // smaller; grow from a realistic size rather than guessing big.
    let mut buf = alloc::vec![0u8; 4096];
    loop {
        match encode(&mut buf) {
            Ok(n) => {
                buf.truncate(n);
                return Ok(buf);
            }
            Err(ExiError::OutputFull) if buf.len() < crate::MAX_EXI_PAYLOAD_LEN => {
                buf.resize((buf.len() * 2).min(crate::MAX_EXI_PAYLOAD_LEN), 0);
            }
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CTX_A: ValueCtx = ValueCtx(1);
    const CTX_B: ValueCtx = ValueCtx(2);

    fn roundtrip_strings(values: &[(ValueCtx, &str)]) {
        let mut buf = [0u8; 1024];
        let mut e = Encoder::new(&mut buf);
        e.write_header(Header::ISO15118).unwrap();
        for &(ctx, s) in values {
            e.string(ctx, s, Lengths::max(4096)).unwrap();
        }
        let len = e.finish().unwrap();

        let mut d = Decoder::new(&buf[..len]);
        d.read_header().unwrap();
        for &(ctx, s) in values {
            assert_eq!(d.string(ctx, Lengths::max(4096)).unwrap(), s);
        }
        d.finish().unwrap();
    }

    #[test]
    fn repeated_strings_roundtrip_through_the_table() {
        roundtrip_strings(&[
            (CTX_A, "urn:iso:15118:2:2013:MsgDef"),
            (CTX_A, "urn:iso:15118:2:2013:MsgDef"), // local hit
            (CTX_B, "urn:iso:15118:2:2013:MsgDef"), // global hit
            (CTX_B, "urn:iso:15118:2:2013:MsgDef"), // still a global hit
            (CTX_A, "something else"),
        ]);
    }

    /// A global hit must not populate the local partition.
    ///
    /// Found by round-tripping ISO 15118-2 `ServiceDiscoveryRes` against the
    /// reference implementation: `ServiceName` and `ServiceScope` both carry
    /// the same text, and treating the second element's global hit as a local
    /// insertion made every later occurrence code differently.
    #[test]
    fn a_global_hit_leaves_the_local_partition_empty() {
        let mut buf = [0u8; 256];
        let mut e = Encoder::new(&mut buf);
        e.string(CTX_A, "Sample", Lengths::max(64)).unwrap(); // literal, populates both
        let before = e.bit_len();
        e.string(CTX_B, "Sample", Lengths::max(64)).unwrap(); // global hit
        let first_global = e.bit_len() - before;
        let before = e.bit_len();
        e.string(CTX_B, "Sample", Lengths::max(64)).unwrap(); // must be another global hit
        assert_eq!(e.bit_len() - before, first_global, "the second must cost the same");
    }

    #[test]
    fn the_table_actually_saves_bits() {
        let long = "urn:iso:std:iso:15118:-20:CommonMessages";
        let mut single_buf = [0u8; 512];
        let mut e = Encoder::new(&mut single_buf);
        e.string(CTX_A, long, Lengths::max(4096)).unwrap();
        let one = e.bit_len();

        let mut repeat_buf = [0u8; 512];
        let mut e = Encoder::new(&mut repeat_buf);
        e.string(CTX_A, long, Lengths::max(4096)).unwrap();
        e.string(CTX_A, long, Lengths::max(4096)).unwrap();
        let two = e.bit_len();

        assert!(two < one + 16, "a repeat should cost a handful of bits, not {} ", two - one);
    }

    #[test]
    fn a_disabled_table_codes_every_value_literally() {
        let opts = ExiOptions { value_partition_capacity: Some(0), value_max_length: None };
        let mut buf = [0u8; 512];
        let mut e = Encoder::with_options(&mut buf, opts);
        e.string(CTX_A, "abc", Lengths::max(64)).unwrap();
        e.string(CTX_A, "abc", Lengths::max(64)).unwrap();
        let len = e.finish().unwrap();

        let mut d = Decoder::with_options(&buf[..len], opts);
        assert_eq!(d.string(CTX_A, Lengths::max(64)).unwrap(), "abc");
        assert_eq!(d.string(CTX_A, Lengths::max(64)).unwrap(), "abc");
        d.finish().unwrap();
    }

    /// `xs:length` is not `xs:maxLength`, and the types that have one are the
    /// ones where a short value is a broken value rather than a small one.
    #[test]
    fn an_exact_length_refuses_a_short_value_both_ways() {
        const CHALLENGE: Lengths = Lengths::exact(16);
        let mut buf = [0u8; 128];

        let mut e = Encoder::new(&mut buf);
        assert_eq!(e.binary(&[0xA5; 15], CHALLENGE), Err(ExiError::ValueTooShort));
        assert_eq!(e.binary(&[0xA5; 17], CHALLENGE), Err(ExiError::ValueTooLong));
        e.binary(&[0xA5; 16], CHALLENGE).unwrap();

        // ...and a peer that puts a short one on the wire is refused too, which
        // is the direction that matters: the alternative is decoding it and
        // re-encoding a message no conforming implementation will take.
        let mut e = Encoder::new(&mut buf);
        e.binary(&[0xA5; 15], Lengths::max(16)).unwrap();
        let len = e.finish().unwrap();
        let mut d = Decoder::new(&buf[..len]);
        assert_eq!(d.binary(CHALLENGE), Err(ExiError::ValueTooShort));
    }

    #[test]
    fn a_minimum_length_applies_to_strings_as_well() {
        const EMAID: Lengths = Lengths::new(14, 15);
        let mut buf = [0u8; 128];

        let mut e = Encoder::new(&mut buf);
        assert_eq!(e.string(CTX_A, "DE123", EMAID), Err(ExiError::ValueTooShort));
        e.string(CTX_A, "DE8ACME123456A", EMAID).unwrap();
        let len = e.finish().unwrap();

        let mut d = Decoder::new(&buf[..len]);
        assert_eq!(d.string(CTX_A, EMAID).unwrap(), "DE8ACME123456A");

        // A shorter one on the wire is refused, table hit or not.
        let mut e = Encoder::new(&mut buf);
        e.string(CTX_A, "short", Lengths::max(64)).unwrap();
        let len = e.finish().unwrap();
        let mut d = Decoder::new(&buf[..len]);
        assert_eq!(d.string(CTX_A, EMAID), Err(ExiError::ValueTooShort));
    }

    #[test]
    fn over_long_strings_are_refused_both_ways() {
        let mut buf = [0u8; 128];
        let mut e = Encoder::new(&mut buf);
        assert_eq!(e.string(CTX_A, "abcdef", Lengths::max(3)), Err(ExiError::ValueTooLong));

        let mut e = Encoder::new(&mut buf);
        e.string(CTX_A, "abcdef", Lengths::max(64)).unwrap();
        let len = e.finish().unwrap();
        let mut d = Decoder::new(&buf[..len]);
        assert_eq!(d.string(CTX_A, Lengths::max(3)), Err(ExiError::ValueTooLong));
    }

    #[test]
    fn a_forged_table_index_is_rejected() {
        // Marker 0 (local hit) with an empty partition: width is 0 bits, so the
        // index is 0 and there is nothing at 0.
        let mut buf = [0u8; 16];
        let mut e = Encoder::new(&mut buf);
        e.uint(0).unwrap();
        let len = e.finish().unwrap();
        let mut d = Decoder::new(&buf[..len]);
        assert_eq!(d.string(CTX_A, Lengths::max(64)), Err(ExiError::BadStringTableIndex));
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut buf = [0u8; 16];
        let mut e = Encoder::new(&mut buf);
        e.write_header(Header::ISO15118).unwrap();
        e.uint(7).unwrap();
        let len = e.finish().unwrap();

        let mut with_junk = alloc::vec::Vec::from(&buf[..len]);
        with_junk.push(0xAA);
        let mut d = Decoder::new(&with_junk);
        d.read_header().unwrap();
        assert_eq!(d.uint().unwrap(), 7);
        assert_eq!(d.finish(), Err(ExiError::TrailingData));
    }

    #[test]
    fn restricted_integers_use_the_range_not_the_type_width() {
        let mut buf = [0u8; 16];
        let mut e = Encoder::new(&mut buf);
        // 1..=20 is twenty values, so five bits regardless of it being a byte.
        e.restricted(20, 1, 20).unwrap();
        assert_eq!(e.bit_len(), 5);
    }

    #[test]
    fn restricted_integers_roundtrip_across_their_whole_range() {
        // Ranges may straddle zero: ISO 15118-20 has `minInclusive="-3"`.
        for (min, max) in [(0i64, 255i64), (1, 20), (0, 0), (7, 9), (0, 4095), (-3, 3), (-128, 127)]
        {
            for v in [min, max, i64::midpoint(min, max)] {
                let mut buf = [0u8; 32];
                let mut e = Encoder::new(&mut buf);
                e.restricted(v, min, max).unwrap();
                let len = e.finish().unwrap();
                let mut d = Decoder::new(&buf[..len]);
                assert_eq!(d.restricted(min, max).unwrap(), v, "range {min}..={max}");
            }
        }
    }

    #[test]
    fn encoding_out_of_range_is_refused() {
        let mut buf = [0u8; 16];
        let mut e = Encoder::new(&mut buf);
        assert_eq!(e.restricted(21, 1, 20), Err(ExiError::ValueOutOfRange));
        assert_eq!(e.restricted(0, 1, 20), Err(ExiError::ValueOutOfRange));
    }

    #[test]
    fn a_range_straddling_zero_roundtrips() {
        let mut buf = [0u8; 16];
        let mut e = Encoder::new(&mut buf);
        e.restricted(-3, -3, 3).unwrap();
        assert_eq!(e.bit_len(), 3, "seven values need three bits");
        e.restricted(3, -3, 3).unwrap();
        let len = e.finish().unwrap();
        let mut d = Decoder::new(&buf[..len]);
        assert_eq!(d.restricted(-3, 3).unwrap(), -3);
        assert_eq!(d.restricted(-3, 3).unwrap(), 3);
    }

    #[test]
    fn decoding_an_unused_index_is_refused() {
        // 1..=20 needs five bits; indices 20..=31 have no schema value.
        for index in 20u64..32 {
            let mut buf = [0u8; 16];
            let mut e = Encoder::new(&mut buf);
            e.nbit(index, 5).unwrap();
            let len = e.finish().unwrap();
            let mut d = Decoder::new(&buf[..len]);
            assert_eq!(d.restricted(1, 20), Err(ExiError::ValueOutOfRange), "index {index}");
        }
    }

    #[test]
    fn a_single_valued_range_costs_no_bits() {
        let mut buf = [0u8; 16];
        let mut e = Encoder::new(&mut buf);
        e.restricted(5, 5, 5).unwrap();
        assert_eq!(e.bit_len(), 0);
        let mut d = Decoder::new(&[]);
        assert_eq!(d.restricted(5, 5).unwrap(), 5);
    }

    #[test]
    fn depth_is_bounded() {
        let mut buf = [0u8; 16];
        let mut e = Encoder::new(&mut buf);
        for _ in 0..MAX_DEPTH {
            e.enter().unwrap();
        }
        assert_eq!(e.enter(), Err(ExiError::DepthLimitExceeded));
    }
}
