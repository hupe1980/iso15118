//! The SLAC management messages themselves.
//!
//! Every message is a fixed-layout byte record. Multi-byte integers are
//! little-endian (`HomePlug`'s convention — note that the `EtherType` in the
//! enclosing Ethernet header is big-endian, which is an easy thing to get
//! backwards).
//!
//! Messages arrive zero-padded to the Ethernet minimum frame size, so `decode`
//! accepts a payload *at least* as long as the layout and ignores the rest.

use super::{
    AAG_LEN, APPLICATION_TYPE_PEV_EVSE, MacAddr, NID_LEN, NMK_LEN, RUN_ID_LEN, SECURITY_TYPE_NONE,
    STATION_ID_LEN, SlacError,
};

/// A matching-run identifier.
pub type RunId = [u8; RUN_ID_LEN];

/// A station identifier — the vehicle's VIN, or an EVSE id.
pub type StationId = [u8; STATION_ID_LEN];

/// A cursor that reads fixed-width fields and cannot read past its slice.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], SlacError> {
        let end = self.pos.checked_add(n).ok_or(SlacError::Truncated)?;
        let slice = self.buf.get(self.pos..end).ok_or(SlacError::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, SlacError> {
        Ok(self.take(1)?[0])
    }

    fn u16le(&mut self) -> Result<u16, SlacError> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32le(&mut self) -> Result<u32, SlacError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], SlacError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    fn skip(&mut self, n: usize) -> Result<(), SlacError> {
        self.take(n).map(|_| ())
    }

    /// Reads and checks the `application_type` / `security_type` pair that
    /// opens most SLAC messages.
    fn profile(&mut self) -> Result<(), SlacError> {
        let application_type = self.u8()?;
        let security_type = self.u8()?;
        if application_type != APPLICATION_TYPE_PEV_EVSE || security_type != SECURITY_TYPE_NONE {
            // Any other pair changes the layout of what follows (cipher-suite
            // fields appear), so parsing on would produce garbage.
            return Err(SlacError::UnsupportedProfile { application_type, security_type });
        }
        Ok(())
    }
}

/// A cursor that writes fixed-width fields into a zeroed buffer.
///
/// Bounded to the message's own length rather than to the caller's buffer, so a
/// field list that does not add up to that length cannot quietly spill into
/// whatever follows. That is not hypothetical: a `CM_ATTEN_CHAR.IND` written
/// into a buffer one byte short is a defect this project has already had once,
/// and it was invisible because the send path dropped the error.
struct Writer<'a> {
    /// Exactly the message's bytes — never the whole destination.
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> Writer<'a> {
    fn new(buf: &'a mut [u8], len: usize) -> Result<Self, SlacError> {
        let buf = buf.get_mut(..len).ok_or(SlacError::BufferTooSmall)?;
        buf.fill(0);
        Ok(Self { buf, pos: 0 })
    }

    /// Finishes the message and returns its length.
    ///
    /// # Panics
    ///
    /// In debug builds, if the fields written do not add up to the length the
    /// message declared — which is a mistake in this file, not in any input.
    fn finish(&self) -> usize {
        debug_assert_eq!(
            self.pos,
            self.buf.len(),
            "wrote {} of {} declared bytes",
            self.pos,
            self.buf.len()
        );
        self.buf.len()
    }

    fn bytes(&mut self, src: &[u8]) -> &mut Self {
        self.buf[self.pos..self.pos + src.len()].copy_from_slice(src);
        self.pos += src.len();
        self
    }

    fn u8(&mut self, v: u8) -> &mut Self {
        self.bytes(&[v])
    }

    fn u16le(&mut self, v: u16) -> &mut Self {
        self.bytes(&v.to_le_bytes())
    }

    fn u32le(&mut self, v: u32) -> &mut Self {
        self.bytes(&v.to_le_bytes())
    }

    fn skip(&mut self, n: usize) -> &mut Self {
        self.pos += n; // already zeroed
        self
    }

    fn profile(&mut self) -> &mut Self {
        self.u8(APPLICATION_TYPE_PEV_EVSE).u8(SECURITY_TYPE_NONE)
    }
}

/// `CM_SLAC_PARM.REQ` — the vehicle opens a matching run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SlacParmReq {
    /// Identifier the whole run is tagged with.
    pub run_id: RunId,
}

impl SlacParmReq {
    /// Encoded length.
    pub const LEN: usize = 10;

    /// Encodes the message, returning its length.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, SlacError> {
        Ok(Writer::new(out, Self::LEN)?.profile().bytes(&self.run_id).finish())
    }

    /// Decodes the message.
    pub fn decode(payload: &[u8]) -> Result<Self, SlacError> {
        let mut r = Reader::new(payload);
        r.profile()?;
        Ok(Self { run_id: r.array()? })
    }
}

/// `CM_SLAC_PARM.CNF` — the charger accepts the run and states its parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SlacParmCnf {
    /// Destination for the sounding packets; always broadcast in practice.
    pub m_sound_target: MacAddr,
    /// How many sounding packets the charger expects.
    pub num_sounds: u8,
    /// Sounding window, in units of 100 ms.
    pub timeout: u8,
    /// Response type; fixed at `0x01`, "other GP station".
    pub resp_type: u8,
    /// MAC of the vehicle, echoed back.
    pub forwarding_sta: MacAddr,
    /// The run this confirms.
    pub run_id: RunId,
}

impl SlacParmCnf {
    /// Encoded length.
    pub const LEN: usize = 25;

    /// Encodes the message, returning its length.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, SlacError> {
        Ok(Writer::new(out, Self::LEN)?
            .bytes(&self.m_sound_target)
            .u8(self.num_sounds)
            .u8(self.timeout)
            .u8(self.resp_type)
            .bytes(&self.forwarding_sta)
            .profile()
            .bytes(&self.run_id)
            .finish())
    }

    /// Decodes the message.
    pub fn decode(payload: &[u8]) -> Result<Self, SlacError> {
        let mut r = Reader::new(payload);
        let m_sound_target = r.array()?;
        let num_sounds = r.u8()?;
        let timeout = r.u8()?;
        let resp_type = r.u8()?;
        let forwarding_sta = r.array()?;
        r.profile()?;
        Ok(Self {
            m_sound_target,
            num_sounds,
            timeout,
            resp_type,
            forwarding_sta,
            run_id: r.array()?,
        })
    }
}

/// `CM_START_ATTEN_CHAR.IND` — the vehicle announces the sounding burst.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct StartAttenCharInd {
    /// How many sounding packets will follow.
    pub num_sounds: u8,
    /// Sounding window, in units of 100 ms.
    pub timeout: u8,
    /// Response type; fixed at `0x01`.
    pub resp_type: u8,
    /// MAC of the vehicle.
    pub forwarding_sta: MacAddr,
    /// The run this belongs to.
    pub run_id: RunId,
}

impl StartAttenCharInd {
    /// Encoded length.
    pub const LEN: usize = 19;

    /// Encodes the message, returning its length.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, SlacError> {
        Ok(Writer::new(out, Self::LEN)?
            .profile()
            .u8(self.num_sounds)
            .u8(self.timeout)
            .u8(self.resp_type)
            .bytes(&self.forwarding_sta)
            .bytes(&self.run_id)
            .finish())
    }

    /// Decodes the message.
    pub fn decode(payload: &[u8]) -> Result<Self, SlacError> {
        let mut r = Reader::new(payload);
        r.profile()?;
        Ok(Self {
            num_sounds: r.u8()?,
            timeout: r.u8()?,
            resp_type: r.u8()?,
            forwarding_sta: r.array()?,
            run_id: r.array()?,
        })
    }
}

/// `CM_MNBC_SOUND.IND` — one sounding packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MnbcSoundInd {
    /// Sender identity — the vehicle's VIN when `application_type` is 0.
    pub sender_id: StationId,
    /// How many sounding packets remain after this one.
    pub remaining_sound_count: u8,
    /// The run this belongs to.
    pub run_id: RunId,
    /// Random payload the receiver measures the attenuation of.
    pub random: [u8; 16],
}

impl MnbcSoundInd {
    /// Encoded length.
    pub const LEN: usize = 52;

    /// Encodes the message, returning its length.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, SlacError> {
        Ok(Writer::new(out, Self::LEN)?
            .profile()
            .bytes(&self.sender_id)
            .u8(self.remaining_sound_count)
            .bytes(&self.run_id)
            // The run id field is 16 bytes wide here; the upper half is unused.
            .skip(8)
            .bytes(&self.random)
            .finish())
    }

    /// Decodes the message.
    pub fn decode(payload: &[u8]) -> Result<Self, SlacError> {
        let mut r = Reader::new(payload);
        r.profile()?;
        let sender_id = r.array()?;
        let remaining_sound_count = r.u8()?;
        let run_id = r.array()?;
        r.skip(8)?;
        Ok(Self { sender_id, remaining_sound_count, run_id, random: r.array()? })
    }
}

/// An attenuation profile: the average attenuation per OFDM carrier group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AttenProfile {
    /// Number of groups that carry a measurement.
    pub num_groups: u8,
    /// Per-group attenuation in dB; only the first `num_groups` are meaningful.
    #[cfg_attr(feature = "serde", serde(with = "serde_aag"))]
    pub aag: [u8; AAG_LEN],
}

#[cfg(feature = "serde")]
mod serde_aag {
    //! Serde support for the fixed 58-byte group array, which is longer than
    //! the arities serde implements by default.
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serializer};

    use super::AAG_LEN;

    pub(super) fn serialize<S: Serializer>(value: &[u8; AAG_LEN], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(value)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; AAG_LEN], D::Error> {
        let v = alloc::vec::Vec::<u8>::deserialize(d)?;
        <[u8; AAG_LEN]>::try_from(v.as_slice())
            .map_err(|_| D::Error::invalid_length(v.len(), &"58 attenuation groups"))
    }
}

impl Default for AttenProfile {
    fn default() -> Self {
        Self { num_groups: 0, aag: [0; AAG_LEN] }
    }
}

impl AttenProfile {
    /// The meaningful part of the measurement.
    ///
    /// Clamped to the 58 groups that exist, rather than indexed by
    /// `num_groups` directly. The two fields are public — as they are on every
    /// wire record in this module — so nothing stops a caller building a
    /// profile with a count larger than the array, and `Evse::observe` takes a
    /// caller-built one. Indexing on it would panic there, which on an ECU is a
    /// reset, on a value the codec never saw: `decode` and `encode` both refuse
    /// a count above [`AAG_LEN`] \([`SlacError::TooManyGroups`]\), so the only
    /// way to reach it is by hand or through `serde`.
    ///
    /// Clamping rather than refusing because this is an accessor: there is no
    /// caller to return an error to, and a mean over the groups that do exist
    /// is the honest answer to a question about a malformed value.
    #[must_use]
    pub fn groups(&self) -> &[u8] {
        &self.aag[..(self.num_groups as usize).min(AAG_LEN)]
    }

    /// Mean attenuation across the reported groups, in dB.
    ///
    /// This is the number the charger ranks candidate links by: the vehicle is
    /// plugged into whichever charger heard it loudest.
    #[must_use]
    pub fn mean_attenuation(&self) -> Option<u8> {
        let groups = self.groups();
        if groups.is_empty() {
            return None;
        }
        let sum: u32 = groups.iter().map(|&v| u32::from(v)).sum();
        #[allow(clippy::cast_possible_truncation)]
        Some((sum / groups.len() as u32) as u8)
    }

    fn validate(num_groups: u8) -> Result<(), SlacError> {
        if num_groups as usize > AAG_LEN {
            return Err(SlacError::TooManyGroups(num_groups));
        }
        Ok(())
    }
}

#[cfg(test)]
mod atten_profile_tests {
    use super::{AAG_LEN, AttenProfile};

    /// `num_groups` is a public field with an invariant only the codec
    /// enforces, and `Evse::observe` takes a caller-built profile — so the
    /// accessors have to be total on a value the codec never saw.
    #[test]
    fn an_impossible_group_count_does_not_panic() {
        let profile = AttenProfile { num_groups: 200, aag: [30; AAG_LEN] };
        assert_eq!(profile.groups().len(), AAG_LEN, "clamped to the groups that exist");
        assert_eq!(profile.mean_attenuation(), Some(30));
    }

    #[test]
    fn no_groups_is_no_measurement_rather_than_zero_decibels() {
        let profile = AttenProfile::default();
        assert!(profile.groups().is_empty());
        assert_eq!(profile.mean_attenuation(), None, "silence is not a loud link");
    }
}

/// `CM_ATTEN_CHAR.IND` — the charger reports what it measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AttenCharInd {
    /// MAC of the vehicle that started the run.
    pub source_address: MacAddr,
    /// The run this belongs to.
    pub run_id: RunId,
    /// Identity of the station that sent the sounding packets.
    pub source_id: StationId,
    /// Identity of the station sending this report.
    pub resp_id: StationId,
    /// How many sounding packets the profile is averaged over.
    pub num_sounds: u8,
    /// The measurement.
    pub profile: AttenProfile,
}

impl AttenCharInd {
    /// Encoded length.
    pub const LEN: usize = 110;

    /// Encodes the message, returning its length.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, SlacError> {
        AttenProfile::validate(self.profile.num_groups)?;
        Ok(Writer::new(out, Self::LEN)?
            .profile()
            .bytes(&self.source_address)
            .bytes(&self.run_id)
            .bytes(&self.source_id)
            .bytes(&self.resp_id)
            .u8(self.num_sounds)
            .u8(self.profile.num_groups)
            .bytes(&self.profile.aag)
            .finish())
    }

    /// Decodes the message.
    pub fn decode(payload: &[u8]) -> Result<Self, SlacError> {
        let mut r = Reader::new(payload);
        r.profile()?;
        let source_address = r.array()?;
        let run_id = r.array()?;
        let source_id = r.array()?;
        let resp_id = r.array()?;
        let num_sounds = r.u8()?;
        let num_groups = r.u8()?;
        AttenProfile::validate(num_groups)?;
        Ok(Self {
            source_address,
            run_id,
            source_id,
            resp_id,
            num_sounds,
            profile: AttenProfile { num_groups, aag: r.array()? },
        })
    }
}

/// `CM_ATTEN_CHAR.RSP` — the vehicle acknowledges the measurement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AttenCharRsp {
    /// MAC of the vehicle.
    pub source_address: MacAddr,
    /// The run this belongs to.
    pub run_id: RunId,
    /// Identity of the station that sent the sounding packets.
    pub source_id: StationId,
    /// Identity of the station that sent the report.
    pub resp_id: StationId,
    /// `0x00` on success.
    pub result: u8,
}

impl AttenCharRsp {
    /// Encoded length.
    pub const LEN: usize = 51;

    /// Encodes the message, returning its length.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, SlacError> {
        Ok(Writer::new(out, Self::LEN)?
            .profile()
            .bytes(&self.source_address)
            .bytes(&self.run_id)
            .bytes(&self.source_id)
            .bytes(&self.resp_id)
            .u8(self.result)
            .finish())
    }

    /// Decodes the message.
    pub fn decode(payload: &[u8]) -> Result<Self, SlacError> {
        let mut r = Reader::new(payload);
        r.profile()?;
        Ok(Self {
            source_address: r.array()?,
            run_id: r.array()?,
            source_id: r.array()?,
            resp_id: r.array()?,
            result: r.u8()?,
        })
    }
}

/// `CM_ATTEN_PROFILE.IND` — a modem-internal attenuation report.
///
/// Emitted by some Green PHY modems towards the host rather than over the
/// cable; the charger's host software uses it instead of computing the profile
/// itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AttenProfileInd {
    /// MAC of the vehicle that was sounded.
    pub pev_mac: MacAddr,
    /// The measurement.
    pub profile: AttenProfile,
}

impl AttenProfileInd {
    /// Encoded length.
    pub const LEN: usize = 66;

    /// Encodes the message, returning its length.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, SlacError> {
        AttenProfile::validate(self.profile.num_groups)?;
        Ok(Writer::new(out, Self::LEN)?
            .bytes(&self.pev_mac)
            .u8(self.profile.num_groups)
            .skip(1)
            .bytes(&self.profile.aag)
            .finish())
    }

    /// Decodes the message.
    pub fn decode(payload: &[u8]) -> Result<Self, SlacError> {
        let mut r = Reader::new(payload);
        let pev_mac = r.array()?;
        let num_groups = r.u8()?;
        r.skip(1)?;
        AttenProfile::validate(num_groups)?;
        Ok(Self { pev_mac, profile: AttenProfile { num_groups, aag: r.array()? } })
    }
}

/// `CM_SLAC_MATCH.REQ` — the vehicle picks its charger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SlacMatchReq {
    /// Vehicle identity (VIN).
    pub pev_id: StationId,
    /// Vehicle MAC.
    pub pev_mac: MacAddr,
    /// Charger identity.
    pub evse_id: StationId,
    /// Charger MAC.
    pub evse_mac: MacAddr,
    /// The run this concludes.
    pub run_id: RunId,
}

/// `mvf_length` for [`SlacMatchReq`] — the 62 bytes that follow the field.
const MATCH_REQ_MVF_LENGTH: u16 = 0x3E;
/// `mvf_length` for [`SlacMatchCnf`] — the 86 bytes that follow the field.
const MATCH_CNF_MVF_LENGTH: u16 = 0x56;

impl SlacMatchReq {
    /// Encoded length.
    pub const LEN: usize = 66;

    /// Encodes the message, returning its length.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, SlacError> {
        Ok(Writer::new(out, Self::LEN)?
            .profile()
            .u16le(MATCH_REQ_MVF_LENGTH)
            .bytes(&self.pev_id)
            .bytes(&self.pev_mac)
            .bytes(&self.evse_id)
            .bytes(&self.evse_mac)
            .bytes(&self.run_id)
            .skip(8)
            .finish())
    }

    /// Decodes the message.
    pub fn decode(payload: &[u8]) -> Result<Self, SlacError> {
        let mut r = Reader::new(payload);
        r.profile()?;
        let mvf = r.u16le()?;
        if mvf != MATCH_REQ_MVF_LENGTH {
            return Err(SlacError::BadLength {
                declared: mvf as usize,
                expected: MATCH_REQ_MVF_LENGTH as usize,
            });
        }
        Ok(Self {
            pev_id: r.array()?,
            pev_mac: r.array()?,
            evse_id: r.array()?,
            evse_mac: r.array()?,
            run_id: r.array()?,
        })
    }
}

/// `CM_SLAC_MATCH.CNF` — the charger hands over the network key.
///
/// This message carries the NMK in the clear over the powerline, which is why
/// ISO 15118-3 relies on the attenuation measurement having already established
/// that only the intended vehicle is close enough to hear it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SlacMatchCnf {
    /// Vehicle identity.
    pub pev_id: StationId,
    /// Vehicle MAC.
    pub pev_mac: MacAddr,
    /// Charger identity.
    pub evse_id: StationId,
    /// Charger MAC.
    pub evse_mac: MacAddr,
    /// The run this concludes.
    pub run_id: RunId,
    /// Network identifier derived from the NMK.
    pub nid: [u8; NID_LEN],
    /// Network Membership Key for the private logical network.
    pub nmk: [u8; NMK_LEN],
}

impl SlacMatchCnf {
    /// Encoded length.
    pub const LEN: usize = 90;

    /// Encodes the message, returning its length.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, SlacError> {
        Ok(Writer::new(out, Self::LEN)?
            .profile()
            .u16le(MATCH_CNF_MVF_LENGTH)
            .bytes(&self.pev_id)
            .bytes(&self.pev_mac)
            .bytes(&self.evse_id)
            .bytes(&self.evse_mac)
            .bytes(&self.run_id)
            .skip(8)
            .bytes(&self.nid)
            .skip(1)
            .bytes(&self.nmk)
            .finish())
    }

    /// Decodes the message.
    pub fn decode(payload: &[u8]) -> Result<Self, SlacError> {
        let mut r = Reader::new(payload);
        r.profile()?;
        let mvf = r.u16le()?;
        if mvf != MATCH_CNF_MVF_LENGTH {
            return Err(SlacError::BadLength {
                declared: mvf as usize,
                expected: MATCH_CNF_MVF_LENGTH as usize,
            });
        }
        let pev_id = r.array()?;
        let pev_mac = r.array()?;
        let evse_id = r.array()?;
        let evse_mac = r.array()?;
        let run_id = r.array()?;
        r.skip(8)?;
        let nid = r.array()?;
        r.skip(1)?;
        Ok(Self { pev_id, pev_mac, evse_id, evse_mac, run_id, nid, nmk: r.array()? })
    }
}

/// `CM_VALIDATE.REQ` — control-pilot toggle validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ValidateReq {
    /// Fixed at `0x00`: the vehicle toggles S2 on the control pilot.
    pub signal_type: u8,
    /// `0x00` for 100 ms, `0x01` for 200 ms in the second exchange.
    pub timer: u8,
    /// `0x01` when ready.
    pub result: u8,
}

impl ValidateReq {
    /// Encoded length.
    pub const LEN: usize = 3;

    /// Encodes the message, returning its length.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, SlacError> {
        Ok(Writer::new(out, Self::LEN)?
            .u8(self.signal_type)
            .u8(self.timer)
            .u8(self.result)
            .finish())
    }

    /// Decodes the message.
    pub fn decode(payload: &[u8]) -> Result<Self, SlacError> {
        let mut r = Reader::new(payload);
        Ok(Self { signal_type: r.u8()?, timer: r.u8()?, result: r.u8()? })
    }
}

/// `CM_VALIDATE.CNF`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ValidateCnf {
    /// Fixed at `0x00`.
    pub signal_type: u8,
    /// Number of detected control-pilot edges.
    pub toggle_num: u8,
    /// `0x00` not ready, `0x01` ready, `0x02` success, `0x03` failure,
    /// `0x04` not required.
    pub result: u8,
}

impl ValidateCnf {
    /// Encoded length.
    pub const LEN: usize = 3;

    /// Encodes the message, returning its length.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, SlacError> {
        Ok(Writer::new(out, Self::LEN)?
            .u8(self.signal_type)
            .u8(self.toggle_num)
            .u8(self.result)
            .finish())
    }

    /// Decodes the message.
    pub fn decode(payload: &[u8]) -> Result<Self, SlacError> {
        let mut r = Reader::new(payload);
        Ok(Self { signal_type: r.u8()?, toggle_num: r.u8()?, result: r.u8()? })
    }
}

/// `CM_SET_KEY.REQ` — install a network key in the local modem.
///
/// Sent from the host to its own Green PHY modem over the host interface, not
/// across the charging cable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SetKeyReq {
    /// `0x01` for an NMK.
    pub key_type: u8,
    /// Unused when the payload is not encrypted.
    pub my_nonce: u32,
    /// Unused when the payload is not encrypted.
    pub your_nonce: u32,
    /// Protocol id; `0x04` for HLE.
    pub pid: u8,
    /// Protocol run number; unused.
    pub prn: u16,
    /// Protocol message number; unused.
    pub pmn: u8,
    /// `CCo` capability for this station's role.
    pub cco_capability: u8,
    /// Network identifier.
    pub nid: [u8; NID_LEN],
    /// Encryption key select; `0x01` for NMK.
    pub new_eks: u8,
    /// The key to install.
    pub new_key: [u8; NMK_LEN],
}

impl SetKeyReq {
    /// Encoded length.
    pub const LEN: usize = 38;

    /// Encodes the message, returning its length.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, SlacError> {
        Ok(Writer::new(out, Self::LEN)?
            .u8(self.key_type)
            .u32le(self.my_nonce)
            .u32le(self.your_nonce)
            .u8(self.pid)
            .u16le(self.prn)
            .u8(self.pmn)
            .u8(self.cco_capability)
            .bytes(&self.nid)
            .u8(self.new_eks)
            .bytes(&self.new_key)
            .finish())
    }

    /// Decodes the message.
    pub fn decode(payload: &[u8]) -> Result<Self, SlacError> {
        let mut r = Reader::new(payload);
        Ok(Self {
            key_type: r.u8()?,
            my_nonce: r.u32le()?,
            your_nonce: r.u32le()?,
            pid: r.u8()?,
            prn: r.u16le()?,
            pmn: r.u8()?,
            cco_capability: r.u8()?,
            nid: r.array()?,
            new_eks: r.u8()?,
            new_key: r.array()?,
        })
    }
}

/// `CM_SET_KEY.CNF`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SetKeyCnf {
    /// `0x00` on success.
    pub result: u8,
    /// Echoed nonce.
    pub my_nonce: u32,
    /// Echoed nonce.
    pub your_nonce: u32,
    /// Echoed protocol id.
    pub pid: u8,
    /// Echoed protocol run number.
    pub prn: u16,
    /// Echoed protocol message number.
    pub pmn: u8,
    /// Echoed `CCo` capability.
    pub cco_capability: u8,
}

impl SetKeyCnf {
    /// Encoded length.
    pub const LEN: usize = 14;

    /// True when the modem accepted the key.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        self.result == 0x00
    }

    /// Encodes the message, returning its length.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, SlacError> {
        Ok(Writer::new(out, Self::LEN)?
            .u8(self.result)
            .u32le(self.my_nonce)
            .u32le(self.your_nonce)
            .u8(self.pid)
            .u16le(self.prn)
            .u8(self.pmn)
            .u8(self.cco_capability)
            .finish())
    }

    /// Decodes the message.
    pub fn decode(payload: &[u8]) -> Result<Self, SlacError> {
        let mut r = Reader::new(payload);
        Ok(Self {
            result: r.u8()?,
            my_nonce: r.u32le()?,
            your_nonce: r.u32le()?,
            pid: r.u8()?,
            prn: r.u16le()?,
            pmn: r.u8()?,
            cco_capability: r.u8()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RUN: RunId = [1, 2, 3, 4, 5, 6, 7, 8];
    const PEV_MAC: MacAddr = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
    const EVSE_MAC: MacAddr = [0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];

    fn station(seed: u8) -> StationId {
        let mut id = [0u8; STATION_ID_LEN];
        for (i, b) in id.iter_mut().enumerate() {
            #[allow(clippy::cast_possible_truncation)]
            {
                *b = seed.wrapping_add(i as u8);
            }
        }
        id
    }

    /// Encode into an oversized buffer, decode back, and check the declared
    /// length is what was written.
    #[allow(clippy::needless_pass_by_value, reason = "test helper takes ownership for ergonomics")]
    fn roundtrip<T: PartialEq + core::fmt::Debug>(
        value: T,
        len: usize,
        encode: impl Fn(&T, &mut [u8]) -> Result<usize, SlacError>,
        decode: impl Fn(&[u8]) -> Result<T, SlacError>,
    ) {
        let mut buf = [0xAAu8; 256];
        let n = encode(&value, &mut buf).unwrap();
        assert_eq!(n, len, "encoded length");
        assert_eq!(decode(&buf[..n]).unwrap(), value);
        // Messages arrive padded to the Ethernet minimum; the trailing bytes
        // must not change the result.
        assert_eq!(decode(&buf).unwrap(), value, "padding must be ignored");
    }

    #[test]
    fn slac_parm_req_roundtrips() {
        roundtrip(SlacParmReq { run_id: RUN }, 10, SlacParmReq::encode, SlacParmReq::decode);
    }

    #[test]
    fn slac_parm_cnf_roundtrips() {
        roundtrip(
            SlacParmCnf {
                m_sound_target: super::super::BROADCAST,
                num_sounds: 10,
                timeout: 6,
                resp_type: 1,
                forwarding_sta: PEV_MAC,
                run_id: RUN,
            },
            25,
            SlacParmCnf::encode,
            SlacParmCnf::decode,
        );
    }

    #[test]
    fn start_atten_char_ind_roundtrips() {
        roundtrip(
            StartAttenCharInd {
                num_sounds: 10,
                timeout: 6,
                resp_type: 1,
                forwarding_sta: PEV_MAC,
                run_id: RUN,
            },
            19,
            StartAttenCharInd::encode,
            StartAttenCharInd::decode,
        );
    }

    #[test]
    fn mnbc_sound_ind_roundtrips() {
        roundtrip(
            MnbcSoundInd {
                sender_id: station(0x30),
                remaining_sound_count: 9,
                run_id: RUN,
                random: [0x5A; 16],
            },
            52,
            MnbcSoundInd::encode,
            MnbcSoundInd::decode,
        );
    }

    #[test]
    fn atten_char_ind_roundtrips() {
        let mut aag = [0u8; AAG_LEN];
        aag[..5].copy_from_slice(&[10, 20, 30, 40, 50]);
        roundtrip(
            AttenCharInd {
                source_address: PEV_MAC,
                run_id: RUN,
                source_id: station(1),
                resp_id: station(2),
                num_sounds: 10,
                profile: AttenProfile { num_groups: 5, aag },
            },
            110,
            AttenCharInd::encode,
            AttenCharInd::decode,
        );
    }

    #[test]
    fn atten_char_rsp_roundtrips() {
        roundtrip(
            AttenCharRsp {
                source_address: PEV_MAC,
                run_id: RUN,
                source_id: station(1),
                resp_id: station(2),
                result: 0,
            },
            51,
            AttenCharRsp::encode,
            AttenCharRsp::decode,
        );
    }

    #[test]
    fn atten_profile_ind_roundtrips() {
        roundtrip(
            AttenProfileInd {
                pev_mac: PEV_MAC,
                profile: AttenProfile { num_groups: 3, aag: [7; AAG_LEN] },
            },
            66,
            AttenProfileInd::encode,
            AttenProfileInd::decode,
        );
    }

    #[test]
    fn slac_match_req_roundtrips_and_declares_62_bytes() {
        let msg = SlacMatchReq {
            pev_id: station(0x40),
            pev_mac: PEV_MAC,
            evse_id: station(0x50),
            evse_mac: EVSE_MAC,
            run_id: RUN,
        };
        roundtrip(msg, 66, SlacMatchReq::encode, SlacMatchReq::decode);

        let mut buf = [0u8; 128];
        msg.encode(&mut buf).unwrap();
        assert_eq!(u16::from_le_bytes([buf[2], buf[3]]), 0x3E);
        assert_eq!(SlacMatchReq::LEN - 4, 0x3E, "mvf_length counts the bytes after itself");
    }

    #[test]
    fn slac_match_cnf_roundtrips_and_declares_86_bytes() {
        let msg = SlacMatchCnf {
            pev_id: station(0x40),
            pev_mac: PEV_MAC,
            evse_id: station(0x50),
            evse_mac: EVSE_MAC,
            run_id: RUN,
            nid: [1, 2, 3, 4, 5, 6, 7],
            nmk: [0xEE; NMK_LEN],
        };
        roundtrip(msg, 90, SlacMatchCnf::encode, SlacMatchCnf::decode);

        let mut buf = [0u8; 128];
        msg.encode(&mut buf).unwrap();
        assert_eq!(u16::from_le_bytes([buf[2], buf[3]]), 0x56);
        assert_eq!(SlacMatchCnf::LEN - 4, 0x56);
    }

    #[test]
    fn validate_messages_roundtrip() {
        roundtrip(
            ValidateReq { signal_type: 0, timer: 1, result: 1 },
            3,
            ValidateReq::encode,
            ValidateReq::decode,
        );
        roundtrip(
            ValidateCnf { signal_type: 0, toggle_num: 3, result: 2 },
            3,
            ValidateCnf::encode,
            ValidateCnf::decode,
        );
    }

    #[test]
    fn set_key_messages_roundtrip() {
        roundtrip(
            SetKeyReq {
                key_type: 1,
                my_nonce: 0xDEAD_BEEF,
                your_nonce: 0,
                pid: 4,
                prn: 0,
                pmn: 0,
                cco_capability: 0,
                nid: [9; NID_LEN],
                new_eks: 1,
                new_key: [0x11; NMK_LEN],
            },
            38,
            SetKeyReq::encode,
            SetKeyReq::decode,
        );
        roundtrip(
            SetKeyCnf {
                result: 0,
                my_nonce: 1,
                your_nonce: 2,
                pid: 4,
                prn: 5,
                pmn: 6,
                cco_capability: 7,
            },
            14,
            SetKeyCnf::encode,
            SetKeyCnf::decode,
        );
    }

    #[test]
    fn multibyte_fields_are_little_endian() {
        let mut buf = [0u8; 64];
        SetKeyReq {
            key_type: 1,
            my_nonce: 0x1122_3344,
            your_nonce: 0,
            pid: 4,
            prn: 0,
            pmn: 0,
            cco_capability: 0,
            nid: [0; NID_LEN],
            new_eks: 1,
            new_key: [0; NMK_LEN],
        }
        .encode(&mut buf)
        .unwrap();
        assert_eq!(&buf[1..5], &[0x44, 0x33, 0x22, 0x11]);
    }

    #[test]
    fn an_unsupported_profile_is_rejected_rather_than_misparsed() {
        // security_type 0x01 would add cipher-suite fields and shift the layout.
        let mut payload = [0u8; 64];
        payload[1] = 0x01;
        assert_eq!(
            SlacParmReq::decode(&payload),
            Err(SlacError::UnsupportedProfile { application_type: 0, security_type: 1 })
        );
    }

    #[test]
    fn a_wrong_mvf_length_is_rejected() {
        let mut buf = [0u8; 128];
        SlacMatchReq {
            pev_id: station(1),
            pev_mac: PEV_MAC,
            evse_id: station(2),
            evse_mac: EVSE_MAC,
            run_id: RUN,
        }
        .encode(&mut buf)
        .unwrap();
        buf[2] = 0xFF;
        assert!(matches!(SlacMatchReq::decode(&buf), Err(SlacError::BadLength { .. })));
    }

    #[test]
    fn too_many_carrier_groups_are_rejected() {
        // num_groups sits right before the 58-byte AAG array.
        const NUM_GROUPS_OFFSET: usize = AttenCharInd::LEN - AAG_LEN - 1;
        let mut payload = [0u8; 128];
        payload[NUM_GROUPS_OFFSET] = 200;
        assert_eq!(AttenCharInd::decode(&payload), Err(SlacError::TooManyGroups(200)));
    }

    #[test]
    fn truncated_payloads_are_rejected_without_panicking() {
        let full = [0u8; 128];
        for n in 0..full.len() {
            let _ = SlacParmReq::decode(&full[..n]);
            let _ = SlacMatchCnf::decode(&full[..n]);
            let _ = AttenCharInd::decode(&full[..n]);
            let _ = SetKeyReq::decode(&full[..n]);
        }
    }

    #[test]
    fn a_small_buffer_is_refused() {
        let mut tiny = [0u8; 4];
        assert_eq!(SlacParmReq { run_id: RUN }.encode(&mut tiny), Err(SlacError::BufferTooSmall));
    }

    #[test]
    fn mean_attenuation_averages_only_the_reported_groups() {
        let mut aag = [255u8; AAG_LEN];
        aag[..4].copy_from_slice(&[10, 20, 30, 40]);
        let p = AttenProfile { num_groups: 4, aag };
        assert_eq!(p.groups(), &[10, 20, 30, 40]);
        assert_eq!(p.mean_attenuation(), Some(25));
        assert_eq!(AttenProfile::default().mean_attenuation(), None);
    }
}
