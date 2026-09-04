//! The SLAC matching run, as a pair of sans-I/O state machines.
//!
//! Matching answers a physical question with a protocol: of the several
//! charging stations sharing a powerline medium, which one is this cable
//! actually plugged into? The vehicle sends a burst of sounding packets, every
//! station in earshot measures how loud they arrive, and the quietest link
//! loses. The winner hands over a network key in the clear — which is only safe
//! *because* the measurement has already established that nobody far away can
//! hear it well enough to matter.
//!
//! ```text
//!   EV                                                        EVSE
//!    |------------------ CM_SLAC_PARM.REQ --------------------->|  broadcast
//!    |<----------------- CM_SLAC_PARM.CNF ----------------------|  per station
//!    |--------------- CM_START_ATTEN_CHAR.IND ----------------->|  x3
//!    |------------------ CM_MNBC_SOUND.IND -------------------->|  x10, sounding
//!    |<----------------- CM_ATTEN_CHAR.IND ---------------------|  the measurement
//!    |------------------ CM_ATTEN_CHAR.RSP -------------------->|  to the winner
//!    |------------------ CM_SLAC_MATCH.REQ -------------------->|
//!    |<----------------- CM_SLAC_MATCH.CNF ---------------------|  NMK + NID
//! ```
//!
//! Both engines follow the crate's usual shape: frames in, frames and events
//! out, and the caller owns the clock and the raw socket. The sounding burst is
//! the one place where *sending* is time-driven rather than reply-driven —
//! [`Ev::poll_timeout`] paces it.
//!
//! # What the measurement is worth, and what it is not
//!
//! Every check below binds a frame to the run it claims to belong to. None of
//! them makes the *measurement* trustworthy, and that gap has a CVE against the
//! standard: **CVE-2025-12357**, spoofed SLAC measurements staging a
//! man-in-the-middle against any ISO 15118-2 charger. A station reporting an
//! implausibly low attenuation is claiming to be the closest thing on the
//! medium, and the quietest link is defined to win; everything a forged report
//! needs is broadcast in the clear during sounding.
//!
//! What this module can do, it does: a forged report moves the choice earlier
//! and never later, the key is taken only from the station the vehicle chose,
//! and [`EvEvent::Measurement`] surfaces *every* station's report rather than
//! only the winner — so an application that wants to refuse an ambiguous run
//! has the numbers to do it. The standard's own answer is ISO 15118-20, where
//! TLS is mandatory and the chain authenticates the station.
//!
//! # What stays outside
//!
//! The randomness. `RunId`, the sounding payloads and the NMK must all be
//! unpredictable, and nothing in this crate generates randomness; the caller
//! supplies them. On the charger side that is a real security parameter: an NMK
//! an attacker can guess is a network an attacker can join.

use alloc::vec::Vec;
use core::fmt;

use crate::session::{Instant, Millis};
use crate::trace::{trace_close, trace_event};

use super::{
    APPLICATION_TYPE_PEV_EVSE, AttenCharInd, AttenCharRsp, AttenProfile, BROADCAST, MacAddr,
    Mmtype, Mmv, MnbcSoundInd, NID_LEN, NMK_LEN, RunId, SlacError, SlacMatchCnf, SlacMatchReq,
    SlacParmCnf, SlacParmReq, StartAttenCharInd, StationId, timers,
};

/// The management message version SLAC uses.
const MMV: Mmv = Mmv::Av1_1;

/// Parses a frame, or drops it.
///
/// One of two places a frame can be discarded — see
/// [`Evse::handle_frame`](Evse::handle_frame) for why discarding is the whole
/// design and not a shortcut.
#[allow(unused_variables, reason = "`reason` is only read by the tracing macro")]
fn accept_frame(raw: &[u8]) -> Option<super::Frame<'_>> {
    match super::parse_frame(raw) {
        Ok(f) => Some(f),
        Err(reason) => {
            trace_event!(reason = %reason, "frame dropped");
            None
        }
    }
}

/// ...and the other: a frame that framed but did not decode.
#[allow(unused_variables, reason = "both are only read by the tracing macro")]
fn decoded<T>(result: Result<T, SlacError>, mmtype: Mmtype) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(reason) => {
            trace_event!(message = ?mmtype, reason = %reason, "frame dropped");
            None
        }
    }
}

/// `resp_type` — "other GP station", the only value ISO 15118-3 uses.
const RESP_TYPE: u8 = 0x01;

/// How many distinct stations one matching run will remember answering.
///
/// The source MAC of a `CM_SLAC_PARM.CNF` is an unauthenticated Ethernet header
/// field, so without a ceiling every distinct forged value costs another entry
/// for the life of the run. Bounding it is safe because the list is
/// informational and an emptiness test — the attenuation measurement decides
/// the winner — so filling it cannot keep the real station from being chosen.
pub const MAX_STATIONS: usize = 32;

/// How many unsent frames either engine will hold.
///
/// A station queues a `CM_SLAC_PARM.CNF` for every `CM_SLAC_PARM.REQ`, and that
/// request is a broadcast anything can repeat. A run never has more than a
/// handful of frames genuinely outstanding — the sounding burst is paced one
/// frame at a time — so a queue this deep is already slack.
pub const MAX_PENDING_FRAMES: usize = 16;

/// How many undrained events either engine will hold.
///
/// The caller is expected to drain these each time round its loop; the bound is
/// what happens when it does not. Terminal events — a match, a failure — are
/// never dropped, because those are the ones a caller cannot do without.
pub const MAX_PENDING_EVENTS: usize = 64;

/// Largest SLAC frame, so a caller can size one buffer and stop thinking about
/// it.
///
/// `CM_ATTEN_CHAR.IND` is the longest message at 110 bytes; with the Ethernet
/// header, the three `HomePlug` header bytes and the two-byte fragmentation
/// field an AV 1.1 frame carries, that is 129. The margin above it is for the
/// message types this crate does not model.
pub const MAX_FRAME_LEN: usize = 192;

/// A frame to put on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outgoing {
    /// Destination MAC — [`BROADCAST`] until a station is known.
    pub destination: MacAddr,
    /// The complete Ethernet frame, padded and ready to write.
    pub frame: Vec<u8>,
}

fn frame(
    destination: MacAddr,
    source: MacAddr,
    mmtype: Mmtype,
    encode: impl Fn(&mut [u8]) -> Result<usize, SlacError>,
) -> Result<Outgoing, SlacError> {
    let mut payload = [0u8; MAX_FRAME_LEN];
    let n = encode(&mut payload)?;
    let mut out = alloc::vec![0u8; MAX_FRAME_LEN];
    let len = super::write_frame(&mut out, destination, source, MMV, mmtype, &payload[..n])?;
    out.truncate(len);
    Ok(Outgoing { destination, frame: out })
}

#[cfg(test)]
mod frame_size {
    use super::{MAX_FRAME_LEN, MMV};
    use crate::slac::{AttenCharInd, ETHERNET_HEADER_LEN};

    /// A frame that does not fit is a message that is never sent, and a
    /// matching run that stalls for no visible reason. The margin is checked
    /// here rather than discovered in the field.
    #[test]
    fn the_longest_message_fits_with_room_to_spare() {
        let needed = ETHERNET_HEADER_LEN + 3 + MMV.fragmentation_len() + AttenCharInd::LEN;
        assert!(needed <= MAX_FRAME_LEN, "{needed} bytes needed, {MAX_FRAME_LEN} available");
    }
}

// ---------------------------------------------------------------------------
// The charging station
// ---------------------------------------------------------------------------

/// What the charging station's matching engine needs to know.
#[derive(Debug, Clone)]
pub struct EvseConfig {
    /// This station's MAC address.
    pub mac: MacAddr,
    /// This station's identity, `EVSEID` padded to seventeen bytes.
    pub id: StationId,
    /// The Network Membership Key to hand to the vehicle that wins.
    ///
    /// **Caller-supplied randomness, and a real secret.** It travels in the
    /// clear over the powerline, on the strength of the attenuation
    /// measurement; a predictable one is a network anyone can join.
    pub nmk: [u8; NMK_LEN],
    /// The Network Identifier derived from the NMK.
    pub nid: [u8; NID_LEN],
    /// Reject a run whose mean attenuation is above this, in dB.
    ///
    /// `None` accepts any run and leaves the choice entirely to the vehicle,
    /// which is what ISO 15118-3 describes. A station that also wants a floor
    /// of its own — because it knows its own cable — sets one.
    pub attenuation_limit: Option<u8>,
}

/// Something the station's application has to know about.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EvseEvent {
    /// A vehicle opened a matching run.
    RunStarted(RunId),
    /// The sounding burst finished and the profile was reported.
    Measured {
        /// Mean attenuation across the carrier groups, in dB.
        mean_attenuation: u8,
        /// How many sounding packets it is averaged over.
        sounds: u8,
    },
    /// The vehicle chose this station. The link is up: the modem now has to be
    /// given the key, and an IP link will follow.
    Matched {
        /// The vehicle's identity, as it gave it.
        pev_id: StationId,
        /// The vehicle's MAC.
        pev_mac: MacAddr,
        /// The key that was handed over.
        nmk: [u8; NMK_LEN],
    },
    /// The run ended without a match.
    Failed(Reason),
}

/// The charging station's half of a matching run.
#[derive(Debug)]
pub struct Evse {
    config: EvseConfig,
    state: EvseState,
    run: Option<Run>,
    /// What the modem reported hearing. Set by [`Evse::observe`].
    measured: Option<AttenProfile>,
    deadline: Option<Instant>,
    out: Vec<Outgoing>,
    events: Vec<EvseEvent>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EvseState {
    Idle,
    Sounding,
    Measured,
    Matched,
    Failed,
}

#[derive(Debug, Clone)]
struct Run {
    id: RunId,
    pev_mac: MacAddr,
    pev_id: StationId,
    sounds: u8,
    expected_sounds: u8,
}

impl Evse {
    /// A station waiting for a vehicle to start matching.
    #[must_use]
    pub fn new(config: EvseConfig) -> Self {
        Self {
            config,
            state: EvseState::Idle,
            run: None,
            measured: None,
            deadline: None,
            out: Vec::new(),
            events: Vec::new(),
        }
    }

    /// Feeds one received Ethernet frame.
    ///
    /// **This cannot fail, and that is the point.** A SLAC engine is a
    /// promiscuous listener on a shared powerline segment: every station's
    /// traffic arrives here, none of it is authenticated, and a malformed
    /// frame is ordinary weather rather than an exception. Returning an error
    /// would hand any station within earshot a one-frame kill switch for
    /// somebody else's matching run — the same shape as the stray
    /// `CM_SLAC_PARM.REQ` this engine already refuses, and worse, because the
    /// caller would be the one acting on it.
    ///
    /// So anything that is not a well-formed message of this run is dropped:
    /// another protocol, another `HomePlug` version, a message type this crate
    /// does not model, a truncated or over-long body, a profile other than
    /// PEV-EVSE, another run's id, another vehicle's MAC. With the `tracing`
    /// feature on, each drop says which.
    pub fn handle_frame(&mut self, now: Instant, raw: &[u8]) {
        let Some(f) = accept_frame(raw) else { return };
        match f.mmtype {
            Mmtype::SlacParmReq => {
                if let Some(m) = decoded(SlacParmReq::decode(f.payload), f.mmtype) {
                    self.on_parm_req(now, f.source, m);
                }
            }
            Mmtype::StartAttenCharInd => {
                if let Some(m) = decoded(StartAttenCharInd::decode(f.payload), f.mmtype) {
                    self.on_start_atten(now, f.source, &m);
                }
            }
            Mmtype::MnbcSoundInd => {
                if let Some(m) = decoded(MnbcSoundInd::decode(f.payload), f.mmtype) {
                    self.on_sound(now, f.source, &m);
                }
            }
            Mmtype::AttenCharRsp => {
                if let Some(m) = decoded(AttenCharRsp::decode(f.payload), f.mmtype) {
                    self.on_atten_rsp(f.source, &m);
                }
            }
            Mmtype::SlacMatchReq => {
                if let Some(m) = decoded(SlacMatchReq::decode(f.payload), f.mmtype) {
                    self.on_match_req(f.source, &m);
                }
            }
            // Everything else on the medium is somebody else's.
            _ => {}
        }
    }

    fn on_parm_req(&mut self, now: Instant, source: MacAddr, req: SlacParmReq) {
        // A station that has already handed over its key is not available for a
        // new run. Every station on the segment hears every frame, so without
        // this a stray — or forged — `CM_SLAC_PARM.REQ` would reopen a matched
        // station and undo the measurement that justified the handover. The
        // application says when the station is free again, with `reset`.
        if self.state == EvseState::Matched {
            return;
        }
        // Nor is a run *in progress* reopened by a third party. `CM_SLAC_PARM`
        // is broadcast and unauthenticated, so anything on the segment can send
        // one; without this check a bystander could restart — and so abort —
        // every matching run within earshot, one frame at a time, and the
        // vehicle would see nothing but a station that never finishes.
        //
        // The vehicle's own retry still gets through, because a retry is the
        // same MAC and the same run id: ISO 15118-3 has the EV repeat
        // `CM_SLAC_PARM.REQ` when the confirmation is lost, and refusing that
        // would trade one stall for another. A genuinely new vehicle waits out
        // `TT_EVSE_match_session`, which is what that timer is for.
        if let Some(run) = &self.run
            && matches!(self.state, EvseState::Sounding | EvseState::Measured)
            && (run.pev_mac != source || run.id != req.run_id)
        {
            return;
        }
        self.run = Some(Run {
            id: req.run_id,
            pev_mac: source,
            pev_id: [0; super::STATION_ID_LEN],
            sounds: 0,
            expected_sounds: timers::C_EV_MATCH_MNBC,
        });
        self.state = EvseState::Sounding;
        // A retry re-opens the same run — the sounding count goes back to zero,
        // so the application is told, every time. `note` is what keeps that
        // honest reporting from being an unbounded queue: `CM_SLAC_PARM.REQ` is
        // a broadcast anything on the segment can repeat.
        self.note(EvseEvent::RunStarted(req.run_id));
        let cnf = SlacParmCnf {
            // Sounding is broadcast so every station in earshot can measure it.
            m_sound_target: BROADCAST,
            num_sounds: timers::C_EV_MATCH_MNBC,
            timeout: u8::try_from(timers::TT_EVSE_MATCH_MNBC_MS / 100).unwrap_or(6),
            resp_type: RESP_TYPE,
            forwarding_sta: source,
            run_id: req.run_id,
        };
        self.queue(source, Mmtype::SlacParmCnf, |b| cnf.encode(b));
        // A vehicle that opens a run and then goes quiet must not hold the
        // station forever.
        self.arm(now, Millis::from_millis(u64::from(timers::TT_EVSE_MATCH_SESSION_MS)));
    }

    fn on_start_atten(&mut self, now: Instant, source: MacAddr, ind: &StartAttenCharInd) {
        let Some(run) = self.run.as_mut().filter(|r| r.id == ind.run_id && r.pev_mac == source)
        else {
            return;
        };
        run.expected_sounds = ind.num_sounds;
        // The sounding window opens now, and closes whether or not every packet
        // arrives — a lost sounding packet must not stall the run.
        self.arm(now, Millis::from_millis(u64::from(timers::TT_EVSE_MATCH_MNBC_MS)));
    }

    fn on_sound(&mut self, now: Instant, source: MacAddr, ind: &MnbcSoundInd) {
        // The count of sounding packets is what closes the window, and the
        // attenuation measured over them is what decides which station wins.
        // A run id travels in the clear in a broadcast `CM_SLAC_PARM.REQ`, so
        // anything on the segment can quote one; only frames from the vehicle
        // that opened the run may add to its burst.
        let Some(run) = self.run.as_mut().filter(|r| r.id == ind.run_id && r.pev_mac == source)
        else {
            return;
        };
        run.pev_id = ind.sender_id;
        run.sounds = run.sounds.saturating_add(1);
        if run.sounds >= run.expected_sounds {
            self.finish_sounding(now);
        }
    }

    /// Records what the modem heard.
    ///
    /// A Green PHY modem reports the attenuation it measured over the sounding
    /// burst through `CM_ATTEN_PROFILE.IND`, already averaged; this is where
    /// that goes, and the last one wins. A host that does its own measuring
    /// averages first and calls this once.
    ///
    /// Without a measurement the station has nothing to report and the run
    /// fails: a station that answered `0 dB` because it measured nothing would
    /// claim to be the closest one on the medium.
    pub fn observe(&mut self, profile: &AttenProfile) {
        self.measured = Some(*profile);
    }

    fn finish_sounding(&mut self, now: Instant) {
        if self.state != EvseState::Sounding {
            return;
        }
        let Some(run) = self.run.clone() else { return };
        let Some(profile) = self.measured else {
            self.fail(Reason::NoMeasurement);
            return;
        };
        let mean = profile.mean_attenuation().unwrap_or(u8::MAX);
        if self.config.attenuation_limit.is_some_and(|limit| mean > limit) {
            self.fail(Reason::TooFarAway);
            return;
        }
        self.state = EvseState::Measured;
        trace_event!(attenuation_db = mean, sounds = run.sounds, "sounding measured");
        self.note(EvseEvent::Measured { mean_attenuation: mean, sounds: run.sounds });
        let ind = AttenCharInd {
            source_address: run.pev_mac,
            run_id: run.id,
            source_id: run.pev_id,
            resp_id: self.config.id,
            num_sounds: run.sounds,
            profile,
        };
        self.queue(run.pev_mac, Mmtype::AttenCharInd, |b| ind.encode(b));
        self.arm(now, Millis::from_millis(u64::from(timers::TT_EVSE_MATCH_SESSION_MS)));
    }

    fn on_atten_rsp(&mut self, source: MacAddr, rsp: &AttenCharRsp) {
        if self.run.as_ref().is_none_or(|r| r.id != rsp.run_id || r.pev_mac != source) {
            return;
        }
        // `resp_id` names the station the vehicle is answering. On a shared
        // medium every station hears every frame, so "it arrived" is not
        // "it was for me".
        if rsp.resp_id != self.config.id {
            return;
        }
        if rsp.result != 0 {
            self.fail(Reason::Rejected);
        }
    }

    fn on_match_req(&mut self, source: MacAddr, req: &SlacMatchReq) {
        let Some(run) = self.run.clone().filter(|r| r.id == req.run_id && r.pev_mac == source)
        else {
            return;
        };
        // The vehicle names the station it chose. Every station on the segment
        // hears this frame, and a station that answers one addressed to its
        // neighbour hands the network key to a vehicle that did not pick it —
        // which is the whole thing the attenuation measurement exists to
        // prevent.
        if req.evse_mac != self.config.mac || req.evse_id != self.config.id {
            return;
        }
        if self.state != EvseState::Measured {
            // A key request before the measurement is a request to skip the one
            // step that makes handing the key over safe.
            self.fail(Reason::OutOfSequence);
            return;
        }
        let cnf = SlacMatchCnf {
            pev_id: req.pev_id,
            pev_mac: req.pev_mac,
            evse_id: self.config.id,
            evse_mac: self.config.mac,
            run_id: run.id,
            nid: self.config.nid,
            nmk: self.config.nmk,
        };
        self.queue(req.pev_mac, Mmtype::SlacMatchCnf, |b| cnf.encode(b));
        self.state = EvseState::Matched;
        self.deadline = None;
        self.events.push(EvseEvent::Matched {
            pev_id: req.pev_id,
            pev_mac: req.pev_mac,
            nmk: self.config.nmk,
        });
    }

    /// The earliest instant at which [`Evse::handle_timeout`] must be called.
    #[must_use]
    pub const fn poll_timeout(&self) -> Option<Instant> {
        self.deadline
    }

    /// Advances the clock.
    pub fn handle_timeout(&mut self, now: Instant) {
        if self.deadline.is_some_and(|d| d <= now) {
            self.deadline = None;
            match self.state {
                // The sounding window closed; report what did arrive.
                EvseState::Sounding if self.run.as_ref().is_some_and(|r| r.sounds > 0) => {
                    self.finish_sounding(now);
                }
                EvseState::Sounding | EvseState::Measured => self.fail(Reason::Timeout),
                EvseState::Idle | EvseState::Matched | EvseState::Failed => {}
            }
        }
    }

    /// The next frame to write, if any.
    pub fn poll_transmit(&mut self) -> Option<Outgoing> {
        if self.out.is_empty() { None } else { Some(self.out.remove(0)) }
    }

    /// The next event, if any.
    pub fn poll_event(&mut self) -> Option<EvseEvent> {
        if self.events.is_empty() { None } else { Some(self.events.remove(0)) }
    }

    /// True once a vehicle has been matched and given the key.
    #[must_use]
    pub const fn is_matched(&self) -> bool {
        matches!(self.state, EvseState::Matched)
    }

    /// Forgets the run and waits for the next vehicle.
    pub fn reset(&mut self) {
        self.state = EvseState::Idle;
        self.run = None;
        self.measured = None;
        self.deadline = None;
        self.out.clear();
    }

    fn queue(
        &mut self,
        to: MacAddr,
        mmtype: Mmtype,
        encode: impl Fn(&mut [u8]) -> Result<usize, SlacError>,
    ) {
        match frame(to, self.config.mac, mmtype, encode) {
            Ok(out) => {
                if self.out.len() < MAX_PENDING_FRAMES {
                    self.out.push(out);
                }
            }
            // A message that cannot be built is a run that will stall; saying
            // so beats going quiet and letting the peer time out.
            Err(_) => self.fail(Reason::EncodingFailed),
        }
    }

    fn arm(&mut self, now: Instant, after: Millis) {
        self.deadline = Some(now + after);
    }

    /// Queues an informational event, unless the caller has stopped draining.
    ///
    /// Terminal events do not go through here: a run has exactly one outcome,
    /// and losing it would be worse than any flood.
    fn note(&mut self, event: EvseEvent) {
        if self.events.len() < MAX_PENDING_EVENTS {
            self.events.push(event);
        }
    }

    fn fail(&mut self, reason: Reason) {
        if self.state == EvseState::Failed {
            return;
        }
        self.state = EvseState::Failed;
        self.deadline = None;
        trace_close!(reason = %reason, "matching failed");
        self.events.push(EvseEvent::Failed(reason));
    }
}

// ---------------------------------------------------------------------------
// The vehicle
// ---------------------------------------------------------------------------

/// What the vehicle's matching engine needs to know.
#[derive(Debug, Clone)]
pub struct EvConfig {
    /// This vehicle's MAC address.
    pub mac: MacAddr,
    /// This vehicle's identity — the VIN, padded to seventeen bytes.
    pub id: StationId,
    /// The identifier this matching run is tagged with.
    ///
    /// **Caller-supplied randomness.** Two vehicles that pick the same run id
    /// on one powerline segment will each answer the other's messages.
    pub run_id: RunId,
    /// Payload for the sounding packets.
    ///
    /// **Caller-supplied randomness.** The receiver measures the attenuation of
    /// this, so a predictable value lets an eavesdropper synthesise a louder
    /// one.
    pub sounding_payload: [u8; 16],
    /// Refuse a station whose measured attenuation is above this, in dB.
    ///
    /// A station far enough away to be quiet is a station that is not the one
    /// this cable is plugged into.
    pub attenuation_limit: Option<u8>,
}

/// Something the vehicle's application has to know about.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EvEvent {
    /// A station answered the run.
    StationFound(MacAddr),
    /// A station reported what it measured.
    Measurement {
        /// The station.
        evse_mac: MacAddr,
        /// Mean attenuation across the carrier groups, in dB.
        mean_attenuation: u8,
    },
    /// The run finished: this is the station, and this is its key.
    Matched {
        /// The station that won.
        evse_mac: MacAddr,
        /// The station's identity.
        evse_id: StationId,
        /// The network key it handed over.
        nmk: [u8; NMK_LEN],
        /// The network identifier.
        nid: [u8; NID_LEN],
    },
    /// The run ended without a match.
    Failed(Reason),
}

/// The vehicle's half of a matching run.
#[derive(Debug)]
pub struct Ev {
    config: EvConfig,
    state: EvState,
    /// Stations that answered, best (quietest) first once measured.
    best: Option<(MacAddr, StationId, u8)>,
    answered: Vec<MacAddr>,
    /// Sounding packets still to send.
    remaining_sounds: u8,
    /// `CM_START_ATTEN_CHAR.IND` repeats still to send.
    remaining_starts: u8,
    deadline: Option<Instant>,
    /// When the window for collecting attenuation reports must close, however
    /// many reports arrive inside it.
    ///
    /// A report shortens the wait — once one station has answered there is
    /// little point waiting the full `TT_EV_atten_results` for others — but it
    /// must never lengthen it. This is the ceiling that makes "shortens" true
    /// in one direction only; see [`Ev::on_measurement`].
    results_deadline: Option<Instant>,
    out: Vec<Outgoing>,
    events: Vec<EvEvent>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EvState {
    Idle,
    Probing,
    Sounding,
    AwaitingMeasurements,
    AwaitingKey,
    Matched,
    Failed,
}

impl Ev {
    /// A vehicle that has not yet started matching.
    #[must_use]
    pub fn new(config: EvConfig) -> Self {
        Self {
            config,
            state: EvState::Idle,
            best: None,
            answered: Vec::new(),
            remaining_sounds: 0,
            remaining_starts: 0,
            deadline: None,
            results_deadline: None,
            out: Vec::new(),
            events: Vec::new(),
        }
    }

    /// Starts the run: broadcasts `CM_SLAC_PARM.REQ`.
    ///
    /// Also *restarts* it. ISO 15118-3 gives the vehicle `C_EV_match_retry`
    /// attempts at a whole matching run, so this is called again after a
    /// failure — and everything the previous attempt learned has to go with it.
    /// A station that answered last time may be gone, and the quietest one it
    /// measured is a measurement of a sounding burst that is over: carrying
    /// either forward would let `choose` pick a station that has not answered
    /// this run and send it a `CM_SLAC_MATCH.REQ` nobody is listening for.
    pub fn start(&mut self, now: Instant) {
        self.best = None;
        self.answered.clear();
        self.remaining_sounds = 0;
        self.remaining_starts = 0;
        self.out.clear();
        self.results_deadline = None;
        let req = SlacParmReq { run_id: self.config.run_id };
        self.queue(BROADCAST, Mmtype::SlacParmReq, |b| req.encode(b));
        self.state = EvState::Probing;
        self.arm(now, Millis::from_millis(u64::from(timers::TT_MATCH_RESPONSE_MS)));
    }

    /// Feeds one received Ethernet frame.
    ///
    /// Cannot fail, for the reason given on
    /// [`Evse::handle_frame`](Evse::handle_frame): everything on the segment
    /// arrives here and none of it is authenticated, so anything that is not a
    /// well-formed message of this run is dropped rather than reported.
    pub fn handle_frame(&mut self, now: Instant, raw: &[u8]) {
        let Some(f) = accept_frame(raw) else { return };
        match f.mmtype {
            Mmtype::SlacParmCnf => {
                let Some(cnf) = decoded(SlacParmCnf::decode(f.payload), f.mmtype) else { return };
                // `forwarding_sta` is this vehicle's own MAC echoed back. A
                // confirmation that names somebody else is an answer to
                // somebody else's run that happens to quote our id.
                if cnf.run_id == self.config.run_id
                    && cnf.forwarding_sta == self.config.mac
                    && !self.answered.contains(&f.source)
                    && self.answered.len() < MAX_STATIONS
                {
                    self.answered.push(f.source);
                    self.note(EvEvent::StationFound(f.source));
                }
            }
            Mmtype::AttenCharInd => {
                let Some(ind) = decoded(AttenCharInd::decode(f.payload), f.mmtype) else { return };
                // The report has to be about *our* sounding burst: a run id is
                // broadcast in the clear, and a report about someone else's
                // burst says nothing about this cable.
                if ind.run_id == self.config.run_id
                    && ind.source_address == self.config.mac
                    && ind.source_id == self.config.id
                {
                    self.on_measurement(now, f.source, &ind);
                }
            }
            Mmtype::SlacMatchCnf => {
                if let Some(cnf) = decoded(SlacMatchCnf::decode(f.payload), f.mmtype) {
                    self.on_match_cnf(f.source, &cnf);
                }
            }
            _ => {}
        }
    }

    /// Takes the network key — but only from the station this vehicle picked.
    ///
    /// This is the frame that hands over the NMK in the clear, and the whole
    /// point of the attenuation measurement is that only the station at the
    /// other end of this cable should be in a position to send it. Everything
    /// on the powerline segment hears the run, and a run id is broadcast in the
    /// clear in `CM_SLAC_PARM.REQ`, so a `CM_SLAC_MATCH.CNF` that merely quotes
    /// the right run id proves nothing. Accepting one from any sender would let
    /// anything on the medium race the real station and put the vehicle on an
    /// attacker's logical network — which is the one outcome matching exists to
    /// prevent.
    fn on_match_cnf(&mut self, source: MacAddr, cnf: &SlacMatchCnf) {
        if self.state != EvState::AwaitingKey || cnf.run_id != self.config.run_id {
            return;
        }
        let Some((chosen_mac, chosen_id, _)) = self.best else { return };
        if source != chosen_mac || cnf.evse_mac != chosen_mac || cnf.evse_id != chosen_id {
            return;
        }
        // ...and it has to be addressed to this vehicle, not relayed from
        // another one's run.
        if cnf.pev_mac != self.config.mac || cnf.pev_id != self.config.id {
            return;
        }
        self.state = EvState::Matched;
        self.deadline = None;
        self.events.push(EvEvent::Matched {
            evse_mac: cnf.evse_mac,
            evse_id: cnf.evse_id,
            nmk: cnf.nmk,
            nid: cnf.nid,
        });
    }

    fn on_measurement(&mut self, now: Instant, source: MacAddr, ind: &AttenCharInd) {
        let Some(mean) = ind.profile.mean_attenuation() else { return };
        self.note(EvEvent::Measurement { evse_mac: source, mean_attenuation: mean });
        if self.config.attenuation_limit.is_some_and(|limit| mean > limit) {
            // Audible, but not plausibly at the other end of this cable.
            return;
        }
        // Quietest wins: the lowest attenuation is the shortest path.
        if self.best.is_none_or(|(_, _, best)| mean < best) {
            self.best = Some((source, ind.resp_id, mean));
        }
        if self.state == EvState::AwaitingMeasurements {
            // Give any other station its chance to report before choosing —
            // but never past the end of the window opened when the sounding
            // burst finished.
            //
            // Unclamped, this is a denial of service anyone on the segment can
            // mount with one frame every `TT_match_response`: the run id, this
            // vehicle's MAC and its `source_id` are all broadcast in the clear
            // during sounding, so a forged `CM_ATTEN_CHAR.IND` costs nothing to
            // make, and each one would push the choice further away. The
            // vehicle would sit in `AwaitingMeasurements` for ever and never
            // charge.
            let next =
                now.saturating_add(Millis::from_millis(u64::from(timers::TT_MATCH_RESPONSE_MS)));
            self.deadline = Some(match self.results_deadline {
                Some(end) if end < next => end,
                _ => next,
            });
        }
    }

    /// The earliest instant at which [`Ev::handle_timeout`] must be called.
    #[must_use]
    pub const fn poll_timeout(&self) -> Option<Instant> {
        self.deadline
    }

    /// Advances the clock, which is also what paces the sounding burst.
    pub fn handle_timeout(&mut self, now: Instant) {
        if self.deadline.is_none_or(|d| d > now) {
            return;
        }
        self.deadline = None;
        match self.state {
            EvState::Probing => {
                if self.answered.is_empty() {
                    self.fail(Reason::NoStation);
                } else {
                    self.begin_sounding(now);
                }
            }
            EvState::Sounding => self.send_next_sound(now),
            EvState::AwaitingMeasurements => self.choose(now),
            EvState::AwaitingKey => self.fail(Reason::Timeout),
            EvState::Idle | EvState::Matched | EvState::Failed => {}
        }
    }

    fn begin_sounding(&mut self, now: Instant) {
        self.remaining_starts = timers::C_EV_START_ATTEN_CHAR_INDS;
        self.remaining_sounds = timers::C_EV_MATCH_MNBC;
        self.state = EvState::Sounding;
        self.send_next_sound(now);
    }

    /// Sends the next message of the burst and schedules the one after it.
    ///
    /// The three `CM_START_ATTEN_CHAR.IND` repeats come first — they are
    /// broadcast and unacknowledged, so they are repeated rather than retried —
    /// and then the sounding packets themselves, spaced by
    /// `TP_EV_BATCH_MSG_INTERVAL`.
    fn send_next_sound(&mut self, now: Instant) {
        let interval = Millis::from_millis(u64::from(timers::TP_EV_BATCH_MSG_INTERVAL_MS));
        if self.remaining_starts > 0 {
            self.remaining_starts -= 1;
            let ind = StartAttenCharInd {
                num_sounds: timers::C_EV_MATCH_MNBC,
                timeout: u8::try_from(timers::TT_EVSE_MATCH_MNBC_MS / 100).unwrap_or(6),
                resp_type: RESP_TYPE,
                forwarding_sta: self.config.mac,
                run_id: self.config.run_id,
            };
            self.queue(BROADCAST, Mmtype::StartAttenCharInd, |b| ind.encode(b));
            self.arm(now, interval);
            return;
        }
        if self.remaining_sounds > 0 {
            self.remaining_sounds -= 1;
            let ind = MnbcSoundInd {
                sender_id: self.config.id,
                remaining_sound_count: self.remaining_sounds,
                run_id: self.config.run_id,
                random: self.config.sounding_payload,
            };
            self.queue(BROADCAST, Mmtype::MnbcSoundInd, |b| ind.encode(b));
            self.arm(now, interval);
            return;
        }
        // The burst is over; the stations now have their measurements to send.
        // `TT_EV_atten_results` is the whole of that window, fixed from here.
        self.state = EvState::AwaitingMeasurements;
        self.arm(now, Millis::from_millis(u64::from(timers::TT_EV_ATTEN_RESULTS_MS)));
        self.results_deadline = self.deadline;
    }

    fn choose(&mut self, now: Instant) {
        let Some((evse_mac, evse_id, _)) = self.best else {
            self.fail(Reason::TooFarAway);
            return;
        };
        let rsp = AttenCharRsp {
            source_address: self.config.mac,
            run_id: self.config.run_id,
            source_id: self.config.id,
            resp_id: evse_id,
            result: 0,
        };
        self.queue(evse_mac, Mmtype::AttenCharRsp, |b| rsp.encode(b));
        let req = SlacMatchReq {
            pev_id: self.config.id,
            pev_mac: self.config.mac,
            evse_id,
            evse_mac,
            run_id: self.config.run_id,
        };
        self.queue(evse_mac, Mmtype::SlacMatchReq, |b| req.encode(b));
        self.state = EvState::AwaitingKey;
        // `TT_match_join` bounds the whole of joining the logical network, and
        // the key is the first half of it.
        self.arm(now, Millis::from_millis(u64::from(timers::TT_MATCH_JOIN_MS)));
    }

    /// The next frame to write, if any.
    pub fn poll_transmit(&mut self) -> Option<Outgoing> {
        if self.out.is_empty() { None } else { Some(self.out.remove(0)) }
    }

    /// The next event, if any.
    pub fn poll_event(&mut self) -> Option<EvEvent> {
        if self.events.is_empty() { None } else { Some(self.events.remove(0)) }
    }

    /// True once a station has been matched and its key received.
    #[must_use]
    pub const fn is_matched(&self) -> bool {
        matches!(self.state, EvState::Matched)
    }

    /// The stations that answered this run.
    #[must_use]
    pub fn stations(&self) -> &[MacAddr] {
        &self.answered
    }

    fn queue(
        &mut self,
        to: MacAddr,
        mmtype: Mmtype,
        encode: impl Fn(&mut [u8]) -> Result<usize, SlacError>,
    ) {
        match frame(to, self.config.mac, mmtype, encode) {
            Ok(out) => {
                if self.out.len() < MAX_PENDING_FRAMES {
                    self.out.push(out);
                }
            }
            Err(_) => self.fail(Reason::EncodingFailed),
        }
    }

    fn arm(&mut self, now: Instant, after: Millis) {
        self.deadline = Some(now + after);
    }

    /// Queues an informational event, unless the caller has stopped draining.
    ///
    /// Terminal events do not go through here: a run has exactly one outcome,
    /// and losing it would be worse than any flood.
    fn note(&mut self, event: EvEvent) {
        if self.events.len() < MAX_PENDING_EVENTS {
            self.events.push(event);
        }
    }

    fn fail(&mut self, reason: Reason) {
        if self.state == EvState::Failed {
            return;
        }
        self.state = EvState::Failed;
        self.deadline = None;
        trace_close!(reason = %reason, "matching failed");
        self.events.push(EvEvent::Failed(reason));
    }
}

/// Why a matching run ended without a match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Reason {
    /// Nothing answered the broadcast.
    NoStation,
    /// Every station that answered was too quiet to be at the other end of
    /// this cable.
    TooFarAway,
    /// The peer stopped answering.
    Timeout,
    /// The peer asked for the key before the measurement that justifies giving
    /// it.
    OutOfSequence,
    /// The peer reported a failure.
    Rejected,
    /// The sounding burst finished but the modem reported no measurement, so
    /// there is nothing honest to answer with.
    NoMeasurement,
    /// A message could not be built. A bug, not a peer's fault — reported
    /// rather than swallowed, because the alternative is a run that stalls
    /// with nothing in the log.
    EncodingFailed,
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NoStation => "no charging station answered",
            Self::TooFarAway => "no station was close enough",
            Self::Timeout => "the peer stopped answering",
            Self::OutOfSequence => "the key was requested before the measurement",
            Self::Rejected => "the peer rejected the run",
            Self::NoMeasurement => "the modem reported no attenuation measurement",
            Self::EncodingFailed => "a SLAC message could not be encoded",
        })
    }
}

/// The `application_type` every ISO 15118-3 matching run uses.
pub const APPLICATION_TYPE: u8 = APPLICATION_TYPE_PEV_EVSE;
