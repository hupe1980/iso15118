//! SLAC — Signal Level Attenuation Characterization (ISO 15118-3).
//!
//! Before there is an IP link to run [`sdp`](crate::sdp) over, the vehicle and
//! the charger have to work out *which* of the possibly many stations sharing
//! the powerline medium are actually plugged into each other. They do it by
//! measuring signal attenuation: the vehicle sends a burst of sounding packets,
//! every charger in earshot measures how loud they arrive, and the quietest
//! link loses. The winner hands over a network key and the two form a private
//! `HomePlug` Green PHY network.
//!
//! These messages are `HomePlug` AV management messages (MMEs) carried directly
//! in Ethernet frames with `EtherType` `0x88E1` — below IP, so a raw socket
//! (`AF_PACKET`, or BPF) is required. This module is the codec and the timing
//! constants; the socket is the caller's, like every other transport here.
//!
//! # Message flow
//!
//! ```text
//!   EV                                                     EVSE
//!    |------------------ CM_SLAC_PARM.REQ ------------------>|
//!    |<----------------- CM_SLAC_PARM.CNF -------------------|
//!    |-------------- CM_START_ATTEN_CHAR.IND --------------->|  (x3)
//!    |----------------- CM_MNBC_SOUND.IND ------------------>|  (x10, sounding)
//!    |<---------------- CM_ATTEN_CHAR.IND -------------------|  (measurement)
//!    |----------------- CM_ATTEN_CHAR.RSP ------------------>|
//!    |----------------- CM_SLAC_MATCH.REQ ------------------>|
//!    |<---------------- CM_SLAC_MATCH.CNF -------------------|  (carries NMK + NID)
//!    |------------------ CM_SET_KEY.REQ ------------------->[modem]
//! ```
//!
//! # Scope
//!
//! [`matching`] is the state machine on top of this codec — one engine per side
//! of the plug, sans I/O like everything else here. It is also where the run is
//! held together: nothing in ISO 15118-3 authenticates these frames, and the run
//! id travels in the clear in a broadcast, so both engines bind every frame to
//! the run it claims to belong to rather than taking its word for it.
//!
//! `security_type` is fixed at `0x00` ("no security"), which is what
//! ISO 15118-3 prescribes and every deployment uses; the cipher-suite fields
//! that only appear under other security types are therefore not modelled.

pub mod matching;
mod message;

use core::fmt;

pub use message::{
    AttenCharInd, AttenCharRsp, AttenProfile, AttenProfileInd, MnbcSoundInd, RunId, SetKeyCnf,
    SetKeyReq, SlacMatchCnf, SlacMatchReq, SlacParmCnf, SlacParmReq, StartAttenCharInd, StationId,
    ValidateCnf, ValidateReq,
};

/// `EtherType` for `HomePlug` Green PHY / `HomePlug` AV management messages.
pub const ETHERTYPE_HOMEPLUG_AV: u16 = 0x88E1;

/// Length of an Ethernet header (destination, source, `EtherType`).
pub const ETHERNET_HEADER_LEN: usize = 14;

/// Minimum length of an Ethernet frame excluding the FCS.
///
/// MMEs shorter than this are zero-padded; a receiver must therefore never
/// infer a message's length from the frame's.
pub const MIN_FRAME_LEN: usize = 60;

/// Length of a station identifier (the vehicle's VIN, or an EVSE id).
pub const STATION_ID_LEN: usize = 17;

/// Length of a matching-run identifier.
pub const RUN_ID_LEN: usize = 8;

/// Length of a Network Membership Key.
pub const NMK_LEN: usize = 16;

/// Length of a Network Identifier.
pub const NID_LEN: usize = 7;

/// Number of OFDM carrier groups in an attenuation profile.
pub const AAG_LEN: usize = 58;

/// An Ethernet MAC address.
pub type MacAddr = [u8; 6];

/// The Ethernet broadcast address, used for the initial SLAC messages.
pub const BROADCAST: MacAddr = [0xFF; 6];

/// `application_type` for PEV-EVSE matching — the only value ISO 15118-3 uses.
pub const APPLICATION_TYPE_PEV_EVSE: u8 = 0x00;

/// `security_type` for "no security" — the only value ISO 15118-3 uses.
pub const SECURITY_TYPE_NONE: u8 = 0x00;

/// `HomePlug` management message version.
///
/// The version decides whether a two-byte fragmentation field sits between the
/// header and the payload, so reading it wrong shifts every subsequent field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Mmv {
    /// `HomePlug` AV 1.0 — no fragmentation field.
    Av1_0,
    /// `HomePlug` AV 1.1 — the version SLAC uses.
    Av1_1,
    /// `HomePlug` AV 2.0.
    Av2_0,
}

impl Mmv {
    /// The on-the-wire byte.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Av1_0 => 0x00,
            Self::Av1_1 => 0x01,
            Self::Av2_0 => 0x02,
        }
    }

    /// Parses the version byte.
    pub const fn from_u8(value: u8) -> Result<Self, SlacError> {
        match value {
            0x00 => Ok(Self::Av1_0),
            0x01 => Ok(Self::Av1_1),
            0x02 => Ok(Self::Av2_0),
            other => Err(SlacError::UnknownMmv(other)),
        }
    }

    /// Length of the fragmentation field that follows the header.
    #[must_use]
    pub const fn fragmentation_len(self) -> usize {
        match self {
            Self::Av1_0 => 0,
            Self::Av1_1 | Self::Av2_0 => 2,
        }
    }
}

/// Management message type.
///
/// `HomePlug` encodes the variant in the low two bits: `REQ` 0, `CNF` 1, `IND`
/// 2, `RSP` 3, with base values four apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum Mmtype {
    /// `CM_SET_KEY.REQ` — install a network key in the local modem.
    SetKeyReq,
    /// `CM_SET_KEY.CNF`.
    SetKeyCnf,
    /// `CM_SLAC_PARM.REQ` — start a matching run.
    SlacParmReq,
    /// `CM_SLAC_PARM.CNF`.
    SlacParmCnf,
    /// `CM_START_ATTEN_CHAR.IND` — announce the sounding burst.
    StartAttenCharInd,
    /// `CM_ATTEN_CHAR.IND` — report the measured attenuation profile.
    AttenCharInd,
    /// `CM_ATTEN_CHAR.RSP`.
    AttenCharRsp,
    /// `CM_MNBC_SOUND.IND` — one sounding packet.
    MnbcSoundInd,
    /// `CM_VALIDATE.REQ` — control-pilot toggle validation.
    ValidateReq,
    /// `CM_VALIDATE.CNF`.
    ValidateCnf,
    /// `CM_SLAC_MATCH.REQ` — request the network key.
    SlacMatchReq,
    /// `CM_SLAC_MATCH.CNF` — deliver NMK and NID.
    SlacMatchCnf,
    /// `CM_ATTEN_PROFILE.IND` — modem-internal attenuation report.
    AttenProfileInd,
    /// A message type this crate does not model.
    Other(u16),
}

impl Mmtype {
    /// The on-the-wire code.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        match self {
            Self::SetKeyReq => 0x6008,
            Self::SetKeyCnf => 0x6009,
            Self::SlacParmReq => 0x6064,
            Self::SlacParmCnf => 0x6065,
            Self::StartAttenCharInd => 0x606A,
            Self::AttenCharInd => 0x606E,
            Self::AttenCharRsp => 0x606F,
            Self::MnbcSoundInd => 0x6076,
            Self::ValidateReq => 0x6078,
            Self::ValidateCnf => 0x6079,
            Self::SlacMatchReq => 0x607C,
            Self::SlacMatchCnf => 0x607D,
            Self::AttenProfileInd => 0x6086,
            Self::Other(v) => v,
        }
    }

    /// Parses a management message type.
    #[must_use]
    pub const fn from_u16(value: u16) -> Self {
        match value {
            0x6008 => Self::SetKeyReq,
            0x6009 => Self::SetKeyCnf,
            0x6064 => Self::SlacParmReq,
            0x6065 => Self::SlacParmCnf,
            0x606A => Self::StartAttenCharInd,
            0x606E => Self::AttenCharInd,
            0x606F => Self::AttenCharRsp,
            0x6076 => Self::MnbcSoundInd,
            0x6078 => Self::ValidateReq,
            0x6079 => Self::ValidateCnf,
            0x607C => Self::SlacMatchReq,
            0x607D => Self::SlacMatchCnf,
            0x6086 => Self::AttenProfileInd,
            other => Self::Other(other),
        }
    }
}

/// A parsed `HomePlug` management message frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame<'a> {
    /// Destination MAC.
    pub destination: MacAddr,
    /// Source MAC.
    pub source: MacAddr,
    /// Management message version.
    pub mmv: Mmv,
    /// Management message type.
    pub mmtype: Mmtype,
    /// The message body, still padded to the Ethernet minimum if it was short.
    pub payload: &'a [u8],
}

/// Writes an Ethernet-framed management message into `out`.
///
/// The frame is zero-padded to [`MIN_FRAME_LEN`], because a shorter Ethernet
/// frame is dropped by the hardware.
pub fn write_frame(
    out: &mut [u8],
    destination: MacAddr,
    source: MacAddr,
    mmv: Mmv,
    mmtype: Mmtype,
    payload: &[u8],
) -> Result<usize, SlacError> {
    let header_len = ETHERNET_HEADER_LEN + 3 + mmv.fragmentation_len();
    let len = (header_len + payload.len()).max(MIN_FRAME_LEN);
    if out.len() < len {
        return Err(SlacError::BufferTooSmall);
    }
    out[..len].fill(0);
    out[..6].copy_from_slice(&destination);
    out[6..12].copy_from_slice(&source);
    out[12..14].copy_from_slice(&ETHERTYPE_HOMEPLUG_AV.to_be_bytes());
    out[14] = mmv.as_u8();
    // HomePlug carries the message type little-endian, unlike the EtherType.
    out[15..17].copy_from_slice(&mmtype.as_u16().to_le_bytes());
    // The fragmentation field stays zero: SLAC messages always fit one frame.
    out[header_len..header_len + payload.len()].copy_from_slice(payload);
    Ok(len)
}

/// Parses an Ethernet-framed management message.
pub fn parse_frame(frame: &[u8]) -> Result<Frame<'_>, SlacError> {
    if frame.len() < ETHERNET_HEADER_LEN + 3 {
        return Err(SlacError::Truncated);
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if ethertype != ETHERTYPE_HOMEPLUG_AV {
        return Err(SlacError::NotHomeplug(ethertype));
    }
    let mmv = Mmv::from_u8(frame[14])?;
    let mmtype = Mmtype::from_u16(u16::from_le_bytes([frame[15], frame[16]]));
    let body_start = ETHERNET_HEADER_LEN + 3 + mmv.fragmentation_len();
    let payload = frame.get(body_start..).ok_or(SlacError::Truncated)?;

    let mut destination = [0u8; 6];
    let mut source = [0u8; 6];
    destination.copy_from_slice(&frame[..6]);
    source.copy_from_slice(&frame[6..12]);
    Ok(Frame { destination, source, mmv, mmtype, payload })
}

/// Timers and counters from ISO 15118-3, in milliseconds unless noted.
///
/// These are the values a matching run is judged against; getting one wrong
/// shows up as an intermittent failure to start charging, so they are named and
/// gathered here rather than sprinkled through the state machine.
pub mod timers {
    /// Number of `CM_START_ATTEN_CHAR.IND` messages the vehicle sends.
    pub const C_EV_START_ATTEN_CHAR_INDS: u8 = 3;
    /// Number of times the vehicle retries a whole matching run.
    pub const C_EV_MATCH_RETRY: u8 = 2;
    /// Number of `CM_MNBC_SOUND.IND` sounding packets per run.
    pub const C_EV_MATCH_MNBC: u8 = 10;

    /// Interval between messages in the sounding burst (20-50 ms).
    pub const TP_EV_BATCH_MSG_INTERVAL_MS: u32 = 40;
    /// Deadline for the vehicle to receive attenuation results.
    pub const TT_EV_ATTEN_RESULTS_MS: u32 = 1200;
    /// Charger's window for collecting sounding packets.
    pub const TT_EVSE_MATCH_MNBC_MS: u32 = 600;
    /// Deadline between consecutive messages of the matching sequence.
    pub const TT_MATCH_SEQUENCE_MS: u32 = 400;
    /// Deadline for a response to a matching request.
    pub const TT_MATCH_RESPONSE_MS: u32 = 200;
    /// Lifetime of a matching session at the charger.
    pub const TT_EVSE_MATCH_SESSION_MS: u32 = 10_000;
    /// Charger's window for a vehicle to start SLAC after plug-in (20-50 s).
    pub const TT_EVSE_SLAC_INIT_MS: u32 = 40_000;
    /// Deadline for joining the logical network after matching.
    pub const TT_MATCH_JOIN_MS: u32 = 12_000;
    /// Minimum duration of control-pilot state E/F.
    pub const T_STEP_EF_MS: u32 = 4_000;
}

/// Errors from SLAC framing and message parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SlacError {
    /// The frame ended before the message did.
    Truncated,
    /// The destination buffer is too small.
    BufferTooSmall,
    /// The `EtherType` was not `HomePlug` AV.
    NotHomeplug(u16),
    /// The management message version byte was not recognised.
    UnknownMmv(u8),
    /// The message was not the type the caller was parsing.
    UnexpectedMmtype {
        /// What the caller wanted.
        expected: Mmtype,
        /// What arrived.
        actual: Mmtype,
    },
    /// `application_type` or `security_type` held a value ISO 15118-3 does not
    /// define.
    UnsupportedProfile {
        /// The `application_type` byte.
        application_type: u8,
        /// The `security_type` byte.
        security_type: u8,
    },
    /// A length field disagreed with the message it introduced.
    BadLength {
        /// Length the field declared.
        declared: usize,
        /// Length the layout requires.
        expected: usize,
    },
    /// An attenuation profile claimed more carrier groups than exist.
    TooManyGroups(u8),
}

impl fmt::Display for SlacError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("truncated SLAC message"),
            Self::BufferTooSmall => f.write_str("output buffer too small for SLAC frame"),
            Self::NotHomeplug(t) => write!(f, "EtherType {t:#06x} is not HomePlug AV"),
            Self::UnknownMmv(v) => write!(f, "unknown HomePlug message version {v:#04x}"),
            Self::UnexpectedMmtype { expected, actual } => {
                write!(f, "expected {expected:?}, got {actual:?}")
            }
            Self::UnsupportedProfile { application_type, security_type } => write!(
                f,
                "unsupported SLAC profile: application_type {application_type:#04x}, \
                 security_type {security_type:#04x}"
            ),
            Self::BadLength { declared, expected } => {
                write!(f, "length field says {declared}, layout requires {expected}")
            }
            Self::TooManyGroups(n) => write!(f, "{n} carrier groups exceeds the {AAG_LEN} maximum"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SlacError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mmtype_variants_follow_the_homeplug_encoding() {
        // Low two bits: REQ 0, CNF 1, IND 2, RSP 3.
        assert_eq!(Mmtype::SlacParmReq.as_u16() & 0x3, 0);
        assert_eq!(Mmtype::SlacParmCnf.as_u16() & 0x3, 1);
        assert_eq!(Mmtype::StartAttenCharInd.as_u16() & 0x3, 2);
        assert_eq!(Mmtype::AttenCharRsp.as_u16() & 0x3, 3);
        // Base values four apart.
        assert_eq!(Mmtype::AttenCharInd.as_u16() & !0x3, 0x606C);
        assert_eq!(Mmtype::SlacMatchReq.as_u16() & !0x3, 0x607C);
    }

    #[test]
    fn mmtype_roundtrips() {
        for t in [
            Mmtype::SetKeyReq,
            Mmtype::SetKeyCnf,
            Mmtype::SlacParmReq,
            Mmtype::SlacParmCnf,
            Mmtype::StartAttenCharInd,
            Mmtype::AttenCharInd,
            Mmtype::AttenCharRsp,
            Mmtype::MnbcSoundInd,
            Mmtype::ValidateReq,
            Mmtype::ValidateCnf,
            Mmtype::SlacMatchReq,
            Mmtype::SlacMatchCnf,
            Mmtype::AttenProfileInd,
            Mmtype::Other(0x1234),
        ] {
            assert_eq!(Mmtype::from_u16(t.as_u16()), t);
        }
    }

    #[test]
    fn frame_roundtrips_and_pads_to_the_ethernet_minimum() {
        let mut buf = [0u8; 128];
        let src = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let n = write_frame(&mut buf, BROADCAST, src, Mmv::Av1_1, Mmtype::SlacParmReq, &[1, 2, 3])
            .unwrap();
        assert_eq!(n, MIN_FRAME_LEN, "short MMEs must be padded");

        let f = parse_frame(&buf[..n]).unwrap();
        assert_eq!(f.destination, BROADCAST);
        assert_eq!(f.source, src);
        assert_eq!(f.mmv, Mmv::Av1_1);
        assert_eq!(f.mmtype, Mmtype::SlacParmReq);
        assert_eq!(&f.payload[..3], &[1, 2, 3]);
    }

    #[test]
    fn mmtype_is_little_endian_on_the_wire() {
        let mut buf = [0u8; 128];
        write_frame(&mut buf, BROADCAST, [0; 6], Mmv::Av1_1, Mmtype::SlacParmReq, &[]).unwrap();
        // 0x6064 little-endian is 64 60, not 60 64.
        assert_eq!(&buf[15..17], &[0x64, 0x60]);
        // The EtherType, by contrast, is big-endian.
        assert_eq!(&buf[12..14], &[0x88, 0xE1]);
    }

    #[test]
    fn av_1_0_has_no_fragmentation_field() {
        let mut buf = [0u8; 128];
        write_frame(&mut buf, BROADCAST, [0; 6], Mmv::Av1_0, Mmtype::SlacParmReq, &[0xAB]).unwrap();
        assert_eq!(buf[17], 0xAB, "payload starts right after the header");

        let mut buf11 = [0u8; 128];
        write_frame(&mut buf11, BROADCAST, [0; 6], Mmv::Av1_1, Mmtype::SlacParmReq, &[0xAB])
            .unwrap();
        assert_eq!(&buf11[17..19], &[0, 0], "two bytes of fragmentation info");
        assert_eq!(buf11[19], 0xAB);
    }

    #[test]
    fn a_non_homeplug_ethertype_is_rejected() {
        let mut frame = [0u8; 64];
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        assert_eq!(parse_frame(&frame), Err(SlacError::NotHomeplug(0x0800)));
    }

    #[test]
    fn a_short_frame_is_rejected() {
        assert_eq!(parse_frame(&[0u8; 16]), Err(SlacError::Truncated));
    }

    /// The ordering between these timers is what makes the protocol work: a
    /// response deadline inside a sequence deadline, a sounding window inside
    /// the window for reporting its results, a session lifetime inside the
    /// window for joining the network. Checked at compile time so a future
    /// edit to one constant cannot silently invert a relationship.
    const _: () = {
        use timers::*;
        assert!(TT_MATCH_RESPONSE_MS < TT_MATCH_SEQUENCE_MS);
        assert!(TT_EVSE_MATCH_MNBC_MS < TT_EV_ATTEN_RESULTS_MS);
        assert!(TT_EVSE_MATCH_SESSION_MS < TT_MATCH_JOIN_MS);
    };
}
