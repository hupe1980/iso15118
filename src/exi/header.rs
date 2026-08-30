//! The EXI header (EXI 1.0 §5.1).
//!
//! ISO 15118 pins every degree of freedom the header offers, so in practice a
//! V2G stream begins with the single byte `0x80` and the body starts,
//! byte-aligned, right after it. We still parse the header properly rather than
//! comparing against `0x80`, so that a stream which merely *looks* close is
//! rejected with a reason instead of silently mis-decoded.

use super::{BitReader, BitWriter, ExiError, ExiResult};

/// The optional `$EXI` cookie. ISO 15118 never emits it; we accept it on input
/// because doing so costs nothing and helps when debugging against generic EXI
/// tooling.
const COOKIE: [u8; 4] = *b"$EXI";

/// The only EXI format version this codec speaks.
const VERSION: u8 = 1;

/// A parsed EXI header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Whether the `$EXI` cookie preceded the header.
    pub cookie: bool,
    /// EXI format version (always 1 in practice).
    pub version: u8,
    /// Whether the version was flagged as a preview/draft version.
    pub preview: bool,
}

impl Default for Header {
    fn default() -> Self {
        Self { cookie: false, version: VERSION, preview: false }
    }
}

impl Header {
    /// The header every ISO 15118 message carries: no cookie, no options,
    /// final version 1 — the single byte `0x80`.
    pub const ISO15118: Self = Self { cookie: false, version: VERSION, preview: false };
}

/// Writes an EXI header.
///
/// An options document is never written: ISO 15118 requires the grammar and
/// coding options to be agreed out of band.
pub fn write_header(w: &mut BitWriter<'_>, header: Header) -> ExiResult<()> {
    debug_assert!(w.is_aligned(), "the EXI header must start byte-aligned");
    if header.cookie {
        w.write_bytes(&COOKIE)?;
    }
    w.write_bits(0b10, 2)?; // distinguishing bits
    w.write_bit(false)?; // no options document
    w.write_bit(header.preview)?;
    if header.version == 0 {
        return Err(ExiError::BadHeader);
    }
    // Versions are encoded as 4-bit groups biased by one, with 15 meaning
    // "add 15 and read another group". Version 1 is a single `0000`.
    let mut remaining = u32::from(header.version) - 1;
    while remaining >= 15 {
        w.write_bits(15, 4)?;
        remaining -= 15;
    }
    w.write_bits(u64::from(remaining), 4)
}

/// Reads and validates an EXI header.
pub fn read_header(r: &mut BitReader<'_>) -> ExiResult<Header> {
    let mut cookie = false;
    // The cookie is four whole bytes, so it can only be there if we are aligned
    // and at least four bytes remain.
    if r.is_aligned() && r.bits_remaining() >= 32 {
        let mut probe = r.clone();
        let mut buf = [0u8; 4];
        if probe.read_bytes(&mut buf).is_ok() && buf == COOKIE {
            *r = probe;
            cookie = true;
        }
    }

    if r.read_bits(2)? != 0b10 {
        return Err(ExiError::BadHeader);
    }
    if r.read_bit()? {
        // An options document would tell us to use a different alignment,
        // grammar or fidelity; we would have to honour it, and ISO 15118 never
        // sends one. Refuse rather than guess.
        return Err(ExiError::BadHeader);
    }
    let preview = r.read_bit()?;

    let mut version: u32 = 1;
    loop {
        let group = r.read_bits(4)?;
        version += u32::try_from(group).map_err(|_| ExiError::BadHeader)?;
        if group != 15 {
            break;
        }
        if version > u32::from(u8::MAX) {
            return Err(ExiError::BadHeader);
        }
    }
    let version = u8::try_from(version).map_err(|_| ExiError::BadHeader)?;
    if version != VERSION {
        return Err(ExiError::BadHeader);
    }
    Ok(Header { cookie, version, preview })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso15118_header_is_a_single_0x80_byte() {
        let mut buf = [0u8; 8];
        let mut w = BitWriter::new(&mut buf);
        write_header(&mut w, Header::ISO15118).unwrap();
        assert_eq!(w.bit_len(), 8);
        let len = w.finish().unwrap();
        assert_eq!(&buf[..len], &[0x80]);
    }

    #[test]
    fn roundtrips() {
        let mut buf = [0u8; 8];
        let mut w = BitWriter::new(&mut buf);
        write_header(&mut w, Header::ISO15118).unwrap();
        let len = w.finish().unwrap();
        let mut r = BitReader::new(&buf[..len]);
        assert_eq!(read_header(&mut r).unwrap(), Header::ISO15118);
    }

    #[test]
    fn cookie_is_accepted_on_input() {
        let bytes = [b'$', b'E', b'X', b'I', 0x80];
        let mut r = BitReader::new(&bytes);
        let h = read_header(&mut r).unwrap();
        assert!(h.cookie);
        assert_eq!(r.bit_pos(), 40);
    }

    #[test]
    fn wrong_distinguishing_bits_are_rejected() {
        let mut r = BitReader::new(&[0x00]);
        assert_eq!(read_header(&mut r), Err(ExiError::BadHeader));
    }

    #[test]
    fn an_options_document_is_rejected() {
        // '10' + presence=1 + ...
        let mut r = BitReader::new(&[0b1010_0000]);
        assert_eq!(read_header(&mut r), Err(ExiError::BadHeader));
    }

    #[test]
    fn unknown_version_is_rejected() {
        // '10' + '0' + preview '0' + version group 0001 => version 2
        let mut r = BitReader::new(&[0b1000_0001]);
        assert_eq!(read_header(&mut r), Err(ExiError::BadHeader));
    }

    #[test]
    fn empty_input_is_rejected() {
        let mut r = BitReader::new(&[]);
        assert_eq!(read_header(&mut r), Err(ExiError::UnexpectedEnd));
    }
}
