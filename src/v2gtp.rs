//! V2G Transfer Protocol framing (ISO 15118-2 §7.8.3, ISO 15118-20 §9.3).
//!
//! Every byte that crosses the charging cable above TCP or UDP is wrapped in
//! the same eight-byte header:
//!
//! ```text
//! 0        1        2        3        4        5        6        7        8
//! +--------+--------+--------+--------+--------+--------+--------+--------+
//! |  0x01  |  0xFE  |   payload type  |            payload length         |
//! +--------+--------+--------+--------+--------+--------+--------+--------+
//!  version  ~version     big-endian              big-endian, in bytes
//! ```
//!
//! The payload length arrives before, and is not covered by, any
//! authentication. It is the first hostile number a charging station reads, so
//! [`Header::decode`] never allocates on the strength of it — the caller
//! compares it against its own limit and decides.

use core::fmt;

/// Length of the V2GTP header in bytes.
pub const HEADER_LEN: usize = 8;

/// The only protocol version defined for V2GTP.
pub const PROTOCOL_VERSION: u8 = 0x01;

/// UDP port the SECC Discovery Protocol listens on.
pub const SDP_PORT: u16 = 15118;

/// What the payload after the header contains.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum PayloadType {
    /// `0x8001` — an EXI-encoded V2G message.
    ///
    /// Shared by three schemas: the `supportedAppProtocol` handshake (all
    /// protocol generations), every DIN SPEC 70121 message, and every
    /// ISO 15118-2 message. Which grammar applies is session state, not
    /// something the frame tells you — one of the reasons the handshake has to
    /// be tracked rather than sniffed.
    ExiEncodedV2gMessage,
    /// `0x8002` — ISO 15118-20 mainstream (`CommonMessages`).
    Part20Main,
    /// `0x8003` — ISO 15118-20 AC mainstream.
    Part20Ac,
    /// `0x8004` — ISO 15118-20 DC mainstream.
    Part20Dc,
    /// `0x8005` — ISO 15118-20 ACDP (pantograph) mainstream.
    Part20Acdp,
    /// `0x8006` — ISO 15118-20 WPT (wireless) mainstream.
    Part20Wpt,
    /// `0x9000` — SDP request.
    SdpRequest,
    /// `0x9001` — SDP response.
    SdpResponse,
    /// `0x9002` — SDP request over a wireless link (ISO 15118-20).
    SdpWirelessRequest,
    /// `0x9003` — SDP response over a wireless link (ISO 15118-20).
    SdpWirelessResponse,
    /// `0xA000..=0xFFFF` — reserved for manufacturer use.
    ManufacturerSpecific(u16),
}

impl PayloadType {
    /// The on-the-wire code.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        match self {
            Self::ExiEncodedV2gMessage => 0x8001,
            Self::Part20Main => 0x8002,
            Self::Part20Ac => 0x8003,
            Self::Part20Dc => 0x8004,
            Self::Part20Acdp => 0x8005,
            Self::Part20Wpt => 0x8006,
            Self::SdpRequest => 0x9000,
            Self::SdpResponse => 0x9001,
            Self::SdpWirelessRequest => 0x9002,
            Self::SdpWirelessResponse => 0x9003,
            Self::ManufacturerSpecific(v) => v,
        }
    }

    /// Parses a payload type code, rejecting the reserved ranges.
    pub const fn from_u16(value: u16) -> Result<Self, V2gtpError> {
        Ok(match value {
            0x8001 => Self::ExiEncodedV2gMessage,
            0x8002 => Self::Part20Main,
            0x8003 => Self::Part20Ac,
            0x8004 => Self::Part20Dc,
            0x8005 => Self::Part20Acdp,
            0x8006 => Self::Part20Wpt,
            0x9000 => Self::SdpRequest,
            0x9001 => Self::SdpResponse,
            0x9002 => Self::SdpWirelessRequest,
            0x9003 => Self::SdpWirelessResponse,
            0xA000..=0xFFFF => Self::ManufacturerSpecific(value),
            _ => return Err(V2gtpError::UnknownPayloadType(value)),
        })
    }

    /// True for the payload types that carry an EXI-encoded V2G message, as
    /// opposed to the fixed-layout SDP datagrams.
    #[must_use]
    pub const fn is_exi(self) -> bool {
        matches!(
            self,
            Self::ExiEncodedV2gMessage
                | Self::Part20Main
                | Self::Part20Ac
                | Self::Part20Dc
                | Self::Part20Acdp
                | Self::Part20Wpt
        )
    }

    /// True for the two SDP request types.
    #[must_use]
    pub const fn is_sdp_request(self) -> bool {
        matches!(self, Self::SdpRequest | Self::SdpWirelessRequest)
    }

    /// True for the two SDP response types.
    #[must_use]
    pub const fn is_sdp_response(self) -> bool {
        matches!(self, Self::SdpResponse | Self::SdpWirelessResponse)
    }
}

/// A decoded V2GTP header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Header {
    /// What the payload holds.
    pub payload_type: PayloadType,
    /// Declared payload length in bytes — **not yet validated against any
    /// buffer**.
    pub payload_len: u32,
}

impl Header {
    /// Builds a header for a payload of `payload_len` bytes.
    #[must_use]
    pub const fn new(payload_type: PayloadType, payload_len: u32) -> Self {
        Self { payload_type, payload_len }
    }

    /// Serialises the header into eight bytes.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; HEADER_LEN] {
        let ty = self.payload_type.as_u16().to_be_bytes();
        let len = self.payload_len.to_be_bytes();
        [PROTOCOL_VERSION, !PROTOCOL_VERSION, ty[0], ty[1], len[0], len[1], len[2], len[3]]
    }

    /// Writes the header into `out`, which must be at least [`HEADER_LEN`].
    pub fn write_to(self, out: &mut [u8]) -> Result<(), V2gtpError> {
        let bytes = self.to_bytes();
        out.get_mut(..HEADER_LEN).ok_or(V2gtpError::BufferTooSmall)?.copy_from_slice(&bytes);
        Ok(())
    }

    /// Parses a header from the first eight bytes of `input`.
    ///
    /// Succeeds even when `input` is shorter than the declared payload — that
    /// is the normal case while a TCP reader is still accumulating bytes.
    pub fn decode(input: &[u8]) -> Result<Self, V2gtpError> {
        let head: &[u8; HEADER_LEN] =
            input.get(..HEADER_LEN).ok_or(V2gtpError::Incomplete)?.try_into().unwrap();

        if head[0] != PROTOCOL_VERSION {
            return Err(V2gtpError::UnsupportedVersion(head[0]));
        }
        // The inverse byte is the spec's own framing check; a mismatch means we
        // are not looking at a V2GTP header at all.
        if head[1] != !PROTOCOL_VERSION {
            return Err(V2gtpError::VersionMismatch { version: head[0], inverse: head[1] });
        }

        let payload_type = PayloadType::from_u16(u16::from_be_bytes([head[2], head[3]]))?;
        let payload_len = u32::from_be_bytes([head[4], head[5], head[6], head[7]]);

        Ok(Self { payload_type, payload_len })
    }
}

/// Splits one complete V2GTP frame off the front of `input`.
///
/// Returns the header, the payload, and the unconsumed remainder — the shape a
/// stream reader wants. `max_payload_len` is the caller's policy limit;
/// anything larger is refused before the payload is touched.
pub fn split_frame(
    input: &[u8],
    max_payload_len: usize,
) -> Result<(Header, &[u8], &[u8]), V2gtpError> {
    let header = Header::decode(input)?;
    let len = usize::try_from(header.payload_len).map_err(|_| V2gtpError::PayloadTooLarge {
        declared: header.payload_len,
        limit: max_payload_len,
    })?;
    if len > max_payload_len {
        return Err(V2gtpError::PayloadTooLarge {
            declared: header.payload_len,
            limit: max_payload_len,
        });
    }
    let end = HEADER_LEN.checked_add(len).ok_or(V2gtpError::Incomplete)?;
    if input.len() < end {
        return Err(V2gtpError::Incomplete);
    }
    Ok((header, &input[HEADER_LEN..end], &input[end..]))
}

/// Writes header and payload into `out`, returning the total frame length.
pub fn write_frame(
    payload_type: PayloadType,
    payload: &[u8],
    out: &mut [u8],
) -> Result<usize, V2gtpError> {
    // The length field is 32 bits wide, so a payload that does not fit one is
    // not a frame at all. `declared` is what the caller asked for, capped at the
    // field's width; `limit` is the width itself.
    let len = u32::try_from(payload.len()).map_err(|_| V2gtpError::PayloadTooLarge {
        declared: u32::MAX,
        limit: u32::MAX as usize,
    })?;
    let total = HEADER_LEN + payload.len();
    if out.len() < total {
        return Err(V2gtpError::BufferTooSmall);
    }
    Header::new(payload_type, len).write_to(out)?;
    out[HEADER_LEN..total].copy_from_slice(payload);
    Ok(total)
}

/// Errors from V2GTP framing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum V2gtpError {
    /// Fewer bytes are available than the frame needs; read more and retry.
    Incomplete,
    /// The destination buffer is too small.
    BufferTooSmall,
    /// The protocol version byte is not `0x01`.
    UnsupportedVersion(u8),
    /// The version byte and its inverse do not agree.
    VersionMismatch {
        /// The version byte as received.
        version: u8,
        /// The inverse-version byte as received.
        inverse: u8,
    },
    /// The payload type is in a reserved range.
    UnknownPayloadType(u16),
    /// The declared payload exceeds the caller's limit.
    PayloadTooLarge {
        /// Length the header declared.
        declared: u32,
        /// Limit the caller allows.
        limit: usize,
    },
}

impl fmt::Display for V2gtpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Incomplete => f.write_str("incomplete V2GTP frame"),
            Self::BufferTooSmall => f.write_str("output buffer too small for V2GTP frame"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported V2GTP protocol version {v:#04x}"),
            Self::VersionMismatch { version, inverse } => {
                write!(f, "V2GTP version {version:#04x} does not match its inverse {inverse:#04x}")
            }
            Self::UnknownPayloadType(t) => write!(f, "unknown V2GTP payload type {t:#06x}"),
            Self::PayloadTooLarge { declared, limit } => {
                write!(f, "V2GTP payload of {declared} bytes exceeds the {limit} byte limit")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for V2gtpError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_bytes_match_the_spec_layout() {
        let h = Header::new(PayloadType::ExiEncodedV2gMessage, 0x1234);
        assert_eq!(h.to_bytes(), [0x01, 0xFE, 0x80, 0x01, 0x00, 0x00, 0x12, 0x34]);
    }

    #[test]
    fn header_roundtrips() {
        for ty in [
            PayloadType::ExiEncodedV2gMessage,
            PayloadType::Part20Main,
            PayloadType::Part20Ac,
            PayloadType::Part20Dc,
            PayloadType::Part20Acdp,
            PayloadType::Part20Wpt,
            PayloadType::SdpRequest,
            PayloadType::SdpResponse,
            PayloadType::SdpWirelessRequest,
            PayloadType::SdpWirelessResponse,
            PayloadType::ManufacturerSpecific(0xA123),
        ] {
            let h = Header::new(ty, 42);
            assert_eq!(Header::decode(&h.to_bytes()).unwrap(), h);
            assert_eq!(PayloadType::from_u16(ty.as_u16()).unwrap(), ty);
        }
    }

    #[test]
    fn a_bad_inverse_version_is_rejected() {
        let bytes = [0x01, 0x00, 0x80, 0x01, 0, 0, 0, 0];
        assert_eq!(
            Header::decode(&bytes),
            Err(V2gtpError::VersionMismatch { version: 0x01, inverse: 0x00 })
        );
    }

    #[test]
    fn reserved_payload_types_are_rejected() {
        assert_eq!(PayloadType::from_u16(0x0000), Err(V2gtpError::UnknownPayloadType(0x0000)));
        assert_eq!(PayloadType::from_u16(0x8007), Err(V2gtpError::UnknownPayloadType(0x8007)));
        assert_eq!(PayloadType::from_u16(0x9004), Err(V2gtpError::UnknownPayloadType(0x9004)));
    }

    #[test]
    fn a_short_buffer_is_incomplete_not_invalid() {
        assert_eq!(Header::decode(&[0x01, 0xFE, 0x80]), Err(V2gtpError::Incomplete));
    }

    #[test]
    fn split_frame_returns_payload_and_remainder() {
        let mut buf = [0u8; 32];
        let n = write_frame(PayloadType::Part20Main, &[1, 2, 3, 4], &mut buf).unwrap();
        assert_eq!(n, HEADER_LEN + 4);
        buf[n] = 0xFF; // a second frame starting

        let (h, payload, rest) = split_frame(&buf[..=n], 1024).unwrap();
        assert_eq!(h.payload_type, PayloadType::Part20Main);
        assert_eq!(payload, &[1, 2, 3, 4]);
        assert_eq!(rest, &[0xFF]);
    }

    #[test]
    fn an_oversized_declared_payload_is_refused_before_reading() {
        // Header claims 4 GiB; only the header itself is present.
        let bytes = [0x01, 0xFE, 0x80, 0x01, 0xFF, 0xFF, 0xFF, 0xFF];
        assert_eq!(
            split_frame(&bytes, 65536),
            Err(V2gtpError::PayloadTooLarge { declared: u32::MAX, limit: 65536 })
        );
    }

    #[test]
    fn a_truncated_payload_is_incomplete() {
        let bytes = [0x01, 0xFE, 0x80, 0x01, 0x00, 0x00, 0x00, 0x10, 0xAA];
        assert_eq!(split_frame(&bytes, 65536), Err(V2gtpError::Incomplete));
    }

    #[test]
    fn payload_type_classification() {
        assert!(PayloadType::Part20Dc.is_exi());
        assert!(!PayloadType::SdpRequest.is_exi());
        assert!(PayloadType::SdpWirelessRequest.is_sdp_request());
        assert!(PayloadType::SdpResponse.is_sdp_response());
        assert!(!PayloadType::SdpResponse.is_sdp_request());
    }
}
