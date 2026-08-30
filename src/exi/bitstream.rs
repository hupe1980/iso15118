//! Bit-level reader and writer for EXI's `bit-packed` alignment.
//!
//! ISO 15118 mandates the EXI *bit-packed* coding mode, so nothing in a V2G
//! message is byte-aligned except the 1-byte EXI header. Every primitive in
//! [`super::primitives`] is built on these two types.
//!
//! Both operate over caller-provided slices — no allocation, no growth, and a
//! hard bound that a malformed or hostile stream cannot exceed.

use super::{ExiError, ExiResult};

/// Writes individual bits, most-significant-bit first, into a byte slice.
///
/// The writer owns the bits it has written: it zeroes each byte the first time
/// it touches it, so the destination buffer does not need to be pre-cleared.
#[derive(Debug)]
pub struct BitWriter<'a> {
    buf: &'a mut [u8],
    /// Absolute bit position of the next bit to write.
    pos: usize,
}

impl<'a> BitWriter<'a> {
    /// Creates a writer that fills `buf`.
    #[must_use]
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Number of bits written so far.
    #[must_use]
    pub const fn bit_len(&self) -> usize {
        self.pos
    }

    /// Number of whole bytes the stream occupies, including a partially filled
    /// trailing byte (EXI pads the final byte with zero bits).
    #[must_use]
    pub const fn byte_len(&self) -> usize {
        self.pos.div_ceil(8)
    }

    /// True when the next write starts on a byte boundary.
    #[must_use]
    pub const fn is_aligned(&self) -> bool {
        self.pos.is_multiple_of(8)
    }

    /// Writes a single bit.
    pub fn write_bit(&mut self, bit: bool) -> ExiResult<()> {
        let byte = self.pos / 8;
        let off = self.pos % 8;
        let slot = self.buf.get_mut(byte).ok_or(ExiError::OutputFull)?;
        if off == 0 {
            *slot = 0;
        }
        if bit {
            *slot |= 1 << (7 - off);
        }
        self.pos += 1;
        Ok(())
    }

    /// Writes the low `n` bits of `value`, most-significant first.
    ///
    /// `n` must be in `0..=64`; the bits above `n` in `value` must be zero.
    pub fn write_bits(&mut self, value: u64, n: u32) -> ExiResult<()> {
        debug_assert!(n <= 64, "bit width {n} out of range");
        debug_assert!(n == 64 || value >> n == 0, "value {value} exceeds {n} bits");
        for i in (0..n).rev() {
            self.write_bit((value >> i) & 1 == 1)?;
        }
        Ok(())
    }

    /// Writes a whole byte (8 bits).
    pub fn write_byte(&mut self, byte: u8) -> ExiResult<()> {
        self.write_bits(u64::from(byte), 8)
    }

    /// Writes a slice of bytes.
    pub fn write_bytes(&mut self, bytes: &[u8]) -> ExiResult<()> {
        for &b in bytes {
            self.write_byte(b)?;
        }
        Ok(())
    }

    /// Pads the stream with zero bits up to the next byte boundary.
    ///
    /// EXI streams are always a whole number of bytes; call this once at the
    /// end of a document.
    pub fn pad_to_byte(&mut self) -> ExiResult<()> {
        while !self.is_aligned() {
            self.write_bit(false)?;
        }
        Ok(())
    }

    /// Finishes the stream, padding the final byte, and returns its length in
    /// bytes.
    pub fn finish(mut self) -> ExiResult<usize> {
        self.pad_to_byte()?;
        Ok(self.byte_len())
    }
}

/// Reads individual bits, most-significant-bit first, from a byte slice.
#[derive(Debug, Clone)]
pub struct BitReader<'a> {
    buf: &'a [u8],
    /// Absolute bit position of the next bit to read.
    pos: usize,
}

impl<'a> BitReader<'a> {
    /// Creates a reader over `buf`.
    #[must_use]
    pub const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Number of bits consumed so far.
    #[must_use]
    pub const fn bit_pos(&self) -> usize {
        self.pos
    }

    /// Number of bits still available.
    #[must_use]
    pub const fn bits_remaining(&self) -> usize {
        self.buf.len() * 8 - self.pos
    }

    /// True when the next read starts on a byte boundary.
    #[must_use]
    pub const fn is_aligned(&self) -> bool {
        self.pos.is_multiple_of(8)
    }

    /// Reads a single bit.
    pub fn read_bit(&mut self) -> ExiResult<bool> {
        let byte = self.pos / 8;
        let off = self.pos % 8;
        let slot = *self.buf.get(byte).ok_or(ExiError::UnexpectedEnd)?;
        self.pos += 1;
        Ok((slot >> (7 - off)) & 1 == 1)
    }

    /// Reads `n` bits into the low bits of a `u64`, most-significant first.
    pub fn read_bits(&mut self, n: u32) -> ExiResult<u64> {
        debug_assert!(n <= 64, "bit width {n} out of range");
        // Reject up front so a truncated stream cannot be read bit-by-bit into a
        // partially-filled value.
        if usize::try_from(n).unwrap_or(usize::MAX) > self.bits_remaining() {
            return Err(ExiError::UnexpectedEnd);
        }
        let mut acc = 0u64;
        for _ in 0..n {
            acc = (acc << 1) | u64::from(self.read_bit()?);
        }
        Ok(acc)
    }

    /// Reads a whole byte (8 bits).
    pub fn read_byte(&mut self) -> ExiResult<u8> {
        // 8 bits always fit in a u8.
        #[allow(clippy::cast_possible_truncation)]
        Ok(self.read_bits(8)? as u8)
    }

    /// Fills `out` with bytes read from the stream.
    pub fn read_bytes(&mut self, out: &mut [u8]) -> ExiResult<()> {
        if out.len().saturating_mul(8) > self.bits_remaining() {
            return Err(ExiError::UnexpectedEnd);
        }
        for slot in out.iter_mut() {
            *slot = self.read_byte()?;
        }
        Ok(())
    }

    /// Skips zero-padding to the next byte boundary, verifying the padding bits
    /// really are zero.
    ///
    /// A non-zero pad bit means the stream is not a well-formed EXI document
    /// (or that the grammar and the stream disagree about where the document
    /// ended), which is worth rejecting rather than ignoring.
    pub fn skip_padding(&mut self) -> ExiResult<()> {
        while !self.is_aligned() {
            if self.read_bit()? {
                return Err(ExiError::NonZeroPadding);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn writes_msb_first() {
        let mut buf = [0xFFu8; 2];
        let mut w = BitWriter::new(&mut buf);
        w.write_bits(0b101, 3).unwrap();
        w.write_bits(0b11, 2).unwrap();
        let len = w.finish().unwrap();
        assert_eq!(len, 1);
        // 101 11 000 — note the pre-existing 0xFF must have been cleared.
        assert_eq!(buf[0], 0b1011_1000);
    }

    #[test]
    fn write_past_end_is_an_error() {
        let mut buf = [0u8; 1];
        let mut w = BitWriter::new(&mut buf);
        w.write_bits(0, 8).unwrap();
        assert_eq!(w.write_bit(false), Err(ExiError::OutputFull));
    }

    #[test]
    fn read_past_end_is_an_error() {
        let mut r = BitReader::new(&[0xAB]);
        assert_eq!(r.read_bits(8).unwrap(), 0xAB);
        assert_eq!(r.read_bit(), Err(ExiError::UnexpectedEnd));
    }

    #[test]
    fn truncated_multi_bit_read_does_not_consume() {
        let mut r = BitReader::new(&[0xAB]);
        assert_eq!(r.read_bits(9), Err(ExiError::UnexpectedEnd));
        assert_eq!(r.bit_pos(), 0, "a failed read must not advance the cursor");
    }

    #[test]
    fn non_zero_padding_is_rejected() {
        let mut r = BitReader::new(&[0b0000_0001]);
        r.read_bits(4).unwrap();
        assert_eq!(r.skip_padding(), Err(ExiError::NonZeroPadding));
    }

    proptest! {
        /// Whatever we write, we read back — the fundamental duality the whole
        /// codec rests on.
        #[test]
        fn bit_roundtrip(chunks in prop::collection::vec((0u64..u64::MAX, 1u32..=64), 1..40)) {
            let mut buf = [0u8; 512];
            let mut w = BitWriter::new(&mut buf);
            let mut written = alloc::vec::Vec::new();
            for &(v, n) in &chunks {
                let v = if n == 64 { v } else { v & ((1u64 << n) - 1) };
                if w.write_bits(v, n).is_err() { break; }
                written.push((v, n));
            }
            let len = w.finish().unwrap();

            let mut r = BitReader::new(&buf[..len]);
            for (v, n) in written {
                prop_assert_eq!(r.read_bits(n).unwrap(), v);
            }
            r.skip_padding().unwrap();
        }
    }
}
