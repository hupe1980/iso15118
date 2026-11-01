//! Session state: the clock, the spec timers, and the message-ordering rules —
//! the layer between the codecs and a working EVCC or SECC, with no I/O.
//!
//! * [`Instant`] and [`Millis`] — the caller's monotonic clock, injected.
//! * [`Connection`] — V2GTP framing over a byte stream, bounded in bytes and in
//!   frames.
//! * [`Timers`] — the V2G deadlines, each constant tied to its requirement.
//! * [`iso2::Sequencer`] and [`iso20::Sequencer`] — the ordering graphs, shared
//!   by both roles so the two cannot disagree about the flow. ISO 15118-20 also
//!   admits only the message set of the selected service
//!   ([`iso20::Sequencer::admits`]).
//! * [`iso2::schedule`] — whether a charging profile fits the offered schedule,
//!   and which `ResponseCode` says so.
//!
//! # Two kinds of deadline
//!
//! A per-message timeout ([`Timer::Message`]) bounds one answer. A *loop*
//! budget ([`Timer::Ongoing`], from [`Flow::loop_timeout`]) bounds a phase the
//! peer repeats while the answer is `..._Ongoing` — authorization, the DC
//! isolation test, schedule exchange. It starts on the first request of the
//! phase; repeats do not restart it.
//!
//! Each budget is a pair, and [`Role`] picks the half: the station's is shorter
//! (55 s against 60 \[V2G2-713\]) so it answers `FAILED` while the vehicle still
//! listens. [`LoopBudgets`] lets a deployment set the authorization and other
//! patience loops; the DC safety phases keep their bounds.
//!
//! The sequencers hold no buffers and no keys, so a session snapshot is small,
//! `Clone` and, with `serde`, serialisable — what pause and resume need.

use core::fmt;

mod clock;
mod conn;
pub mod timers;

pub use clock::{Instant, Millis};
pub use conn::{Connection, ConnectionError, MAX_PENDING_FRAMES};
pub use timers::{Timer, Timers};

#[cfg(feature = "iso2")]
#[cfg_attr(docsrs, doc(cfg(feature = "iso2")))]
pub mod iso2;

#[cfg(feature = "iso20-common")]
#[cfg_attr(docsrs, doc(cfg(feature = "iso20-common")))]
pub mod iso20;

/// Whether the transport carrying a session is secured.
///
/// A sans-I/O core cannot observe this — the socket is the caller's — and it
/// cannot be inferred from anything on the wire either. So the caller states
/// it, and it is not a formality: ISO 15118-2 makes several rules conditional
/// on it, and the sharpest is that **Plug & Charge is not available without
/// TLS**.
///
/// \[V2G2-634\] "If a V2G Communication Session without TLS is used, the SECC
/// shall not provide the `PnC` Message Sets"; \[V2G2-635\] says the same of the
/// EVCC; \[V2G2-633\] leaves such a session external identification and nothing
/// else. A contract certificate and the signature over it travelling in clear
/// is what those forbid, and it is a downgrade a peer can otherwise simply ask
/// for.
///
/// This is the same type SECC discovery negotiates
/// ([`sdp::Security`](crate::sdp::Security) is a re-export, not a twin), so the
/// value a vehicle got out of [`Response::satisfies`] is the value it hands the
/// session — rather than two enumerations that mean the same thing and can
/// disagree.
///
/// [`Response::satisfies`]: crate::sdp::Response::satisfies
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Security {
    /// TLS. Mandatory for ISO 15118-20, and for Plug & Charge under -2.
    Tls,
    /// No transport security.
    ///
    /// Permitted by DIN SPEC 70121, and by ISO 15118-2 with external
    /// identification **only** \[V2G2-633\].
    None,
}

impl Security {
    /// True when this session may use the Plug & Charge message sets.
    ///
    /// \[V2G2-634\], \[V2G2-635\].
    #[must_use]
    pub const fn permits_plug_and_charge(self) -> bool {
        matches!(self, Self::Tls)
    }
}

impl fmt::Display for Security {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Tls => "TLS",
            Self::None => "no transport security",
        })
    }
}

/// Which side of the plug a piece of session state belongs to.
///
/// The V2G timing tables are role-specific, and the two halves of a pair are
/// deliberately different numbers: ISO 15118-2 Table 109 gives the vehicle
/// `V2G_EVCC_Ongoing_Timeout` = 60 s and the station
/// `V2G_SECC_Ongoing_Performance_Time` = 55 s for the *same* loop, so that the
/// station answers `FAILED` while the vehicle is still listening \[V2G2-713\].
/// A core that used one number for both roles would give the station a deadline
/// it can never usefully reach, which is the same as having none.
///
/// So anything that reads a budget out of those tables asks for it by role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Role {
    /// The vehicle's communication controller.
    Evcc,
    /// The charging station's communication controller.
    Secc,
}

impl Role {
    /// A short name for logs.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Evcc => "EVCC",
            Self::Secc => "SECC",
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The message-ordering rules of whichever protocol generation a session
/// negotiated.
///
/// Present only when at least one protocol generation is enabled — with none,
/// there is no flow to track.
///
/// The two generations have different message sets and different graphs, but a
/// session driver needs to ask the same question of either — "is this legal
/// now?" — so this is the one place the two are joined.
#[cfg(any(feature = "iso2", feature = "iso20-common"))]
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum Flow {
    /// An ISO 15118-2 session.
    #[cfg(feature = "iso2")]
    #[cfg_attr(docsrs, doc(cfg(feature = "iso2")))]
    Iso2(iso2::Sequencer),
    /// An ISO 15118-20 session.
    #[cfg(feature = "iso20-common")]
    #[cfg_attr(docsrs, doc(cfg(feature = "iso20-common")))]
    Iso20(iso20::Sequencer),
}

#[cfg(any(feature = "iso2", feature = "iso20-common"))]
impl Flow {
    /// Whether this build has the message set and ordering graph for
    /// `protocol`.
    ///
    /// False for a generation whose feature is off, and for `Din70121`, whose
    /// message set this crate does not implement at all.
    ///
    /// The role drivers ask this *before* the handshake, not after. A station
    /// that let a generation it cannot speak win the negotiation would decline
    /// the session rather than fall back to one both sides do have, so
    /// [`SeccConfig::protocols`](crate::secc::SeccConfig::protocols) and
    /// [`EvccConfig::protocols`](crate::evcc::EvccConfig::protocols) are
    /// filtered through this before they reach the wire:
    ///
    /// ```
    /// # #[cfg(feature = "iso2")] {
    /// use iso15118::{Protocol, Protocols};
    /// use iso15118::session::Flow;
    ///
    /// let mut speakable = Protocols::ALL;
    /// speakable.retain(Flow::supports);
    /// assert!(!speakable.contains(Protocol::Din70121));
    /// # }
    /// ```
    #[must_use]
    #[allow(unused_variables, reason = "the body is entirely feature-gated")]
    pub const fn supports(protocol: crate::Protocol) -> bool {
        match protocol {
            #[cfg(feature = "iso2")]
            crate::Protocol::Iso2 => true,
            #[cfg(feature = "iso20-common")]
            crate::Protocol::Iso20 => true,
            _ => false,
        }
    }

    /// A fresh flow for `protocol`, or `None` when this build does not have
    /// that protocol enabled.
    ///
    /// Always `Some` where [`Flow::supports`] is true, and always `None` where
    /// it is not.
    ///
    /// `security` is what the transport underneath actually is. It decides one
    /// thing and it is not a small one: a session that is not secured may not
    /// use the Plug & Charge message sets \[V2G2-634\], \[V2G2-635\], so the
    /// -2 graph refuses `PaymentServiceSelectionReq` with
    /// `SelectedPaymentOption = Contract`. ISO 15118-20 mandates TLS outright,
    /// so its graph has nothing to condition.
    #[must_use]
    #[allow(unused_variables, reason = "every arm is behind a feature")]
    pub fn new(protocol: crate::Protocol, security: Security) -> Option<Self> {
        match protocol {
            #[cfg(feature = "iso2")]
            crate::Protocol::Iso2 => Some(Self::Iso2(iso2::Sequencer::new(security))),
            #[cfg(feature = "iso20-common")]
            crate::Protocol::Iso20 => Some(Self::Iso20(iso20::Sequencer::new())),
            _ => None,
        }
    }

    /// Records that `message` arrived.
    ///
    /// A response, or an element that is not a message at all, is not
    /// sequenced: the ordering rules constrain requests.
    #[allow(unused_variables, reason = "every arm is behind a feature")]
    pub fn accept(&mut self, message: &crate::message::Message) -> Result<(), FlowError> {
        match self {
            #[cfg(feature = "iso2")]
            Self::Iso2(s) => {
                let request = iso2::Request::of(message).ok_or(FlowError::NotARequest)?;
                s.accept(request)?;
            }
            #[cfg(feature = "iso20-common")]
            Self::Iso20(s) => {
                let request = iso20::Request::of(message).ok_or(FlowError::NotARequest)?;
                // A request from a message set the session did not select is out
                // of sequence however legal the same request would be in the
                // right set — an AC charge loop in a DC session.
                if !s.admits(message.payload_type()) {
                    return Err(FlowError::Sequence(s.refusal(request)));
                }
                s.accept(request)?;
            }
        }
        Ok(())
    }

    /// Whether `message` would be accepted right now, without accepting it.
    ///
    /// The dry run [`Flow::accept`] is the committing version of. A sender uses
    /// it to check a request *before* anything else about sending it can fail,
    /// so that a message which never reached the wire never advanced the flow
    /// either.
    #[allow(unused_variables, reason = "every arm is behind a feature")]
    pub fn permits(&self, message: &crate::message::Message) -> Result<(), FlowError> {
        match self {
            #[cfg(feature = "iso2")]
            Self::Iso2(s) => {
                let request = iso2::Request::of(message).ok_or(FlowError::NotARequest)?;
                if !s.permits(request) {
                    return Err(FlowError::Sequence(s.refusal(request)));
                }
            }
            #[cfg(feature = "iso20-common")]
            Self::Iso20(s) => {
                let request = iso20::Request::of(message).ok_or(FlowError::NotARequest)?;
                if !s.admits(message.payload_type()) || !s.permits(request) {
                    return Err(FlowError::Sequence(s.refusal(request)));
                }
            }
        }
        Ok(())
    }

    /// True when the session has reached its terminal phase — stopped or
    /// paused.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        match self {
            #[cfg(feature = "iso2")]
            Self::Iso2(s) => s.is_finished(),
            #[cfg(feature = "iso20-common")]
            Self::Iso20(s) => s.is_finished(),
        }
    }

    /// True when the session was paused rather than terminated.
    ///
    /// A paused session keeps its session id, its authorization and (in -20)
    /// its selected service and agreed schedule, and the vehicle may resume it.
    #[must_use]
    pub fn is_paused(&self) -> bool {
        match self {
            #[cfg(feature = "iso2")]
            Self::Iso2(s) => s.is_paused(),
            #[cfg(feature = "iso20-common")]
            Self::Iso20(s) => s.is_paused(),
        }
    }

    /// Records that a `FAILED_*` response has gone past, after which the only
    /// request either side may still send is `SessionStopReq`.
    ///
    /// The session drivers call this for you; it is public because a caller
    /// driving the sequencers directly needs it too.
    pub fn failed(&mut self) {
        match self {
            #[cfg(feature = "iso2")]
            Self::Iso2(s) => s.failed(),
            #[cfg(feature = "iso20-common")]
            Self::Iso20(s) => s.failed(),
        }
    }

    /// True once a failure response has ended the session's forward progress.
    #[must_use]
    pub fn is_failed(&self) -> bool {
        match self {
            #[cfg(feature = "iso2")]
            Self::Iso2(s) => s.is_failed(),
            #[cfg(feature = "iso20-common")]
            Self::Iso20(s) => s.is_failed(),
        }
    }

    /// Picks up a paused ISO 15118-20 session from just after `SessionSetup`.
    ///
    /// Returns `false` for an ISO 15118-2 flow, which has no negotiated state
    /// to skip: a resumed -2 session repeats service discovery and
    /// authorization, and only the session id carries over.
    ///
    /// The argument is the whole [`EnergyTransfer`], not just the flow, because
    /// a paused session resumes with the service it selected — and whether that
    /// service was bidirectional is part of what survived the pause.
    ///
    /// [`EnergyTransfer`]: iso20::EnergyTransfer
    #[cfg(feature = "iso20-common")]
    #[cfg_attr(docsrs, doc(cfg(feature = "iso20-common")))]
    pub fn resume(&mut self, energy_transfer: iso20::EnergyTransfer) -> Result<(), ResumeError> {
        match self {
            #[cfg(feature = "iso2")]
            Self::Iso2(_) => Err(ResumeError::NotIso20),
            Self::Iso20(s) => {
                s.resume(energy_transfer);
                Ok(())
            }
        }
    }

    /// How long the session may stay in the phase it is in, as `role` bounds
    /// it.
    ///
    /// Several phases of both generations are loops the peer repeats while the
    /// answer is `..._Ongoing` — authorization, parameter discovery, the DC
    /// isolation test. Each has a bound separate from the per-message response
    /// timeout; this is that bound, and `None` for a phase that is not a loop.
    /// The role drivers arm [`Timer::Ongoing`] from it.
    ///
    /// The answer depends on `role` because the standard's does: see [`Role`].
    /// `budgets` is the deployment's override — see [`LoopBudgets`] for which
    /// loops it reaches and which it deliberately does not.
    #[must_use]
    pub const fn loop_timeout(&self, role: Role, budgets: LoopBudgets) -> Option<Millis> {
        let (default, authorizing) = match self {
            #[cfg(feature = "iso2")]
            Self::Iso2(s) => (s.loop_timeout(role), matches!(s.phase(), iso2::Phase::Authorized)),
            #[cfg(feature = "iso20-common")]
            Self::Iso20(s) => (s.loop_timeout(role), matches!(s.phase(), iso20::Phase::Authorized)),
        };
        let Some(default) = default else { return None };
        let overridden = if authorizing {
            budgets.authorization
        } else if self.is_dc_safety_phase() {
            None
        } else {
            budgets.ongoing
        };
        Some(match overridden {
            Some(budget) => budget,
            None => default,
        })
    }

    /// The isolation test and the pre-charge: loops whose budget is a safety
    /// bound rather than a patience bound, and which no override reaches.
    const fn is_dc_safety_phase(&self) -> bool {
        match self {
            #[cfg(feature = "iso2")]
            Self::Iso2(s) => matches!(s.phase(), iso2::Phase::CableCheck | iso2::Phase::PreCharge),
            #[cfg(feature = "iso20-common")]
            Self::Iso20(s) => {
                matches!(s.phase(), iso20::Phase::CableCheck | iso20::Phase::PreCharge)
            }
        }
    }

    /// The name of the phase the session is in, for logs.
    #[must_use]
    pub const fn phase_name(&self) -> &'static str {
        match self {
            #[cfg(feature = "iso2")]
            Self::Iso2(s) => s.phase_name(),
            #[cfg(feature = "iso20-common")]
            Self::Iso20(s) => s.phase_name(),
        }
    }
}

/// A deployment's own bounds for the loops a peer repeats while the answer is
/// `..._Ongoing`.
///
/// `None` keeps the generation's figure: Table 109 for ISO 15118-2, this
/// crate's labelled policy for ISO 15118-20 (see [`timers`]).
///
/// * **`authorization`** — while a driver presents a card or confirms in an
///   app. `ChargeX`'s *Timeouts Best Practices* (March 2025) found drivers
///   needing more than 140 s where ISO 15118-2 gives 60.
/// * **`ongoing`** — every other `Ongoing` loop: parameter discovery, schedule
///   exchange, welding detection.
///
/// The DC isolation test and pre-charge are safety bounds and not reachable
/// from here. On the station, keep each value shorter than the vehicle's — the
/// station cannot see the vehicle's configuration, so this is not checked.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LoopBudgets {
    /// The authorization loop.
    pub authorization: Option<Millis>,
    /// Every other `..._Ongoing` loop except the DC safety phases.
    pub ongoing: Option<Millis>,
}

/// Why a paused session could not be picked back up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResumeError {
    /// The `supportedAppProtocol` handshake has not settled, so there is no
    /// flow to resume yet.
    NotNegotiated,
    /// The negotiated generation is ISO 15118-2, which keeps only the session
    /// id across a pause; there is no flow state to restore.
    NotIso20,
}

impl fmt::Display for ResumeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotNegotiated => "no protocol has been negotiated yet",
            Self::NotIso20 => "only an ISO 15118-20 flow can be resumed",
        })
    }
}

impl core::error::Error for ResumeError {}

/// Why a message was not accepted into the flow.
#[cfg(any(feature = "iso2", feature = "iso20-common"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FlowError {
    /// The message was out of sequence.
    Sequence(SequenceError),
    /// The message was a response, or an element that is not a message, where a
    /// request was expected.
    NotARequest,
}

#[cfg(any(feature = "iso2", feature = "iso20-common"))]
impl From<SequenceError> for FlowError {
    fn from(e: SequenceError) -> Self {
        Self::Sequence(e)
    }
}

#[cfg(any(feature = "iso2", feature = "iso20-common"))]
impl fmt::Display for FlowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sequence(e) => write!(f, "{e}"),
            Self::NotARequest => f.write_str("expected a request"),
        }
    }
}

#[cfg(all(feature = "std", any(feature = "iso2", feature = "iso20-common")))]
impl std::error::Error for FlowError {}

/// A peer sent a request that its position in the flow does not allow.
///
/// ISO 15118 prescribes the reaction: answer with `FAILED_SequenceError` and
/// end the session. [`SequenceError::response_code`] is that code as its EXI
/// enumeration index, so the caller can put it in the response without knowing
/// which protocol generation raised it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SequenceError {
    /// The request that arrived, by element name.
    pub got: &'static str,
    /// The phase the session was in.
    pub phase: &'static str,
    /// `FAILED_SequenceError` as its EXI enumeration index in the protocol
    /// generation that raised it.
    pub response_code: u8,
}

impl fmt::Display for SequenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} is out of sequence in phase {}", self.got, self.phase)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SequenceError {}

/// A V2G session identifier.
///
/// Eight bytes on the wire in both protocol generations, and the value a paused
/// session is resumed under. All-zero means "no session yet": an EVCC opening a
/// fresh session sends [`SessionId::NONE`], and the SECC answers with the one it
/// assigned.
///
/// The bytes must be unpredictable — a session id is what a resumed session is
/// recognised by — so the caller supplies them from its own randomness. This
/// crate has no RNG.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SessionId([u8; Self::LEN]);

impl SessionId {
    /// Length of a session id in bytes.
    pub const LEN: usize = 8;

    /// The all-zero id, meaning "no session yet".
    pub const NONE: Self = Self([0; Self::LEN]);

    /// Wraps eight caller-supplied random bytes.
    #[must_use]
    pub const fn new(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    /// The bytes, as they travel.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }

    /// True for [`SessionId::NONE`].
    #[must_use]
    pub fn is_none(&self) -> bool {
        self.0 == [0; Self::LEN]
    }

    /// Reads an id off the wire.
    ///
    /// The two generations do not agree on the length, and the difference is
    /// real: ISO 15118-2 types `SessionID` as `hexBinary` with `maxLength = 8`,
    /// so a shorter one is legal and is zero-extended here — which is how it
    /// compares equal to what the SECC assigned. ISO 15118-20 types it as
    /// `length = 8`, exactly, and the codec refuses a short one before it ever
    /// reaches this function.
    ///
    /// Anything longer than eight bytes is a schema violation in either
    /// generation and is refused.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, SessionIdError> {
        if bytes.len() > Self::LEN {
            return Err(SessionIdError { len: bytes.len() });
        }
        let mut out = [0u8; Self::LEN];
        out[..bytes.len()].copy_from_slice(bytes);
        Ok(Self(out))
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02X}")?;
        }
        Ok(())
    }
}

/// A `SessionID` longer than the schema allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionIdError {
    /// The length that arrived.
    pub len: usize,
}

impl fmt::Display for SessionIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SessionID is {} bytes, the schema allows at most {}", self.len, SessionId::LEN)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SessionIdError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// The deployment's budgets reach the authorization loop and the other
    /// patience loops, and never the DC safety phases.
    #[cfg(feature = "iso2")]
    #[test]
    fn a_configured_loop_budget_is_the_one_enforced() {
        use crate::iso2::{EnergyTransferMode, PaymentOption};
        use iso2::Request as R;
        let budgets = LoopBudgets {
            authorization: Some(Millis::from_secs(140)),
            ongoing: Some(Millis::from_secs(90)),
        };
        let mut flow = Flow::new(crate::Protocol::Iso2, Security::None).unwrap();
        let Flow::Iso2(s) = &mut flow else { unreachable!() };
        for r in [
            R::SessionSetup,
            R::ServiceDiscovery,
            R::PaymentServiceSelection(PaymentOption::ExternalPayment),
            R::Authorization,
        ] {
            s.accept(r).unwrap();
        }
        // Table 109's 60 s by default; ChargeX's 140 s when the deployment says so.
        assert_eq!(
            flow.loop_timeout(Role::Evcc, LoopBudgets::default()),
            Some(Millis::from_secs(60))
        );
        assert_eq!(flow.loop_timeout(Role::Evcc, budgets), Some(Millis::from_secs(140)));
        assert_eq!(flow.loop_timeout(Role::Secc, budgets), Some(Millis::from_secs(140)));

        let Flow::Iso2(s) = &mut flow else { unreachable!() };
        s.accept(R::ChargeParameterDiscovery(EnergyTransferMode::DCExtended)).unwrap();
        assert_eq!(flow.loop_timeout(Role::Evcc, budgets), Some(Millis::from_secs(90)));

        // The isolation test keeps its 40 s whatever the deployment asks for.
        let Flow::Iso2(s) = &mut flow else { unreachable!() };
        s.accept(R::CableCheck).unwrap();
        assert_eq!(flow.loop_timeout(Role::Evcc, budgets), Some(Millis::from_secs(40)));
        assert_eq!(
            flow.loop_timeout(Role::Evcc, LoopBudgets::default()),
            Some(Millis::from_secs(40))
        );
    }

    /// The same for ISO 15118-20, where the authorization loop's default is this
    /// crate's three-minute policy rather than a quoted figure.
    #[cfg(feature = "iso20-common")]
    #[test]
    fn a_configured_loop_budget_reaches_the_iso20_loops_too() {
        use iso20::Request as R;
        let budgets = LoopBudgets {
            authorization: Some(Millis::from_secs(240)),
            ongoing: Some(Millis::from_secs(90)),
        };
        let mut flow = Flow::new(crate::Protocol::Iso20, Security::Tls).unwrap();
        let Flow::Iso20(s) = &mut flow else { unreachable!() };
        for r in [R::SessionSetup, R::AuthorizationSetup, R::Authorization] {
            s.accept(r).unwrap();
        }
        assert_eq!(
            flow.loop_timeout(Role::Evcc, LoopBudgets::default()),
            Some(Millis::from_secs(180))
        );
        assert_eq!(flow.loop_timeout(Role::Evcc, budgets), Some(Millis::from_secs(240)));

        let Flow::Iso20(s) = &mut flow else { unreachable!() };
        for r in [
            R::ServiceDiscovery,
            R::ServiceSelection(iso20::EnergyTransfer::unidirectional(iso20::Service::Dc)),
            R::ChargeParameterDiscovery,
        ] {
            s.accept(r).unwrap();
        }
        assert_eq!(flow.loop_timeout(Role::Secc, budgets), Some(Millis::from_secs(90)));

        let Flow::Iso20(s) = &mut flow else { unreachable!() };
        s.accept(R::ScheduleExchange).unwrap();
        s.accept(R::CableCheck).unwrap();
        assert_eq!(
            flow.loop_timeout(Role::Evcc, budgets),
            flow.loop_timeout(Role::Evcc, LoopBudgets::default()),
            "the isolation test keeps its own bound"
        );
    }

    /// ISO 15118-2 keeps only the session id across a pause; asking it to
    /// resume a flow is a mistake the caller hears about.
    #[cfg(all(feature = "iso2", feature = "iso20-common"))]
    #[test]
    fn a_two_flow_cannot_be_resumed_and_says_so() {
        let mut flow = Flow::new(crate::Protocol::Iso2, Security::None).unwrap();
        assert_eq!(
            flow.resume(iso20::EnergyTransfer::unidirectional(iso20::Service::Dc)),
            Err(ResumeError::NotIso20)
        );
    }

    #[test]
    fn a_fresh_session_has_no_id() {
        assert!(SessionId::NONE.is_none());
        assert!(!SessionId::new([1, 0, 0, 0, 0, 0, 0, 0]).is_none());
    }

    /// ISO 15118-2 permits a short `SessionID`; ISO 15118-20 does not, and the
    /// codec refuses one there before it reaches this type.
    #[test]
    fn a_short_session_id_is_zero_extended() {
        let short = SessionId::from_slice(&[0xAB, 0xCD]).unwrap();
        assert_eq!(short.as_bytes(), &[0xAB, 0xCD, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn an_over_long_session_id_is_refused() {
        assert_eq!(SessionId::from_slice(&[0; 9]), Err(SessionIdError { len: 9 }));
    }

    /// The pause/resume story rests on a session snapshot being storable, and
    /// a claim in three documents is worth exactly one test.
    ///
    /// Every *field* type already derived `serde` — the phase, the transfer
    /// mode, the payment option, the service — so the gap was invisible from
    /// anywhere except a call that tried it. That is the shape to watch for: a
    /// container whose parts are all serialisable and which is not.
    #[cfg(all(feature = "serde", feature = "iso2", feature = "iso20-common"))]
    #[test]
    fn a_session_snapshot_survives_a_power_cycle() {
        use crate::iso2::{EnergyTransferMode, PaymentOption};

        let mut flow = Flow::new(crate::Protocol::Iso2, Security::Tls).unwrap();
        for request in [
            iso2::Request::SessionSetup,
            iso2::Request::ServiceDiscovery,
            iso2::Request::PaymentServiceSelection(PaymentOption::Contract),
            iso2::Request::PaymentDetails,
            iso2::Request::Authorization,
            iso2::Request::ChargeParameterDiscovery(EnergyTransferMode::DCExtended),
        ] {
            let Flow::Iso2(s) = &mut flow else { unreachable!() };
            s.accept(request).unwrap();
        }

        let stored = serde_json::to_string(&flow).unwrap();
        let restored: Flow = serde_json::from_str(&stored).unwrap();

        // The phase and both facts the graph branches on come back, which is
        // the whole of what a resumed session needs to keep deciding.
        let (Flow::Iso2(before), Flow::Iso2(after)) = (&flow, &restored) else { unreachable!() };
        assert_eq!(after.phase(), before.phase());
        assert_eq!(after.transfer(), before.transfer());
        assert_eq!(after.payment(), before.payment());
        // ...and it decides the same way. A snapshot that restores the fields
        // and not the behaviour would pass the three assertions above.
        assert!(after.permits(iso2::Request::CableCheck));
        assert!(!after.permits(iso2::Request::PowerDelivery(crate::iso2::ChargeProgress::Start)));

        // The -20 flow too, where a paused session keeps the most state.
        let mut flow = Flow::new(crate::Protocol::Iso20, Security::Tls).unwrap();
        flow.resume(iso20::EnergyTransfer::unidirectional(iso20::Service::Dc)).unwrap();
        let restored: Flow = serde_json::from_str(&serde_json::to_string(&flow).unwrap()).unwrap();
        let Flow::Iso20(after) = &restored else { unreachable!() };
        assert_eq!(after.service(), Some(iso20::Service::Dc));
        assert!(after.permits(iso20::Request::ChargeParameterDiscovery));
    }

    #[test]
    fn session_ids_display_as_hex() {
        extern crate alloc;
        use alloc::string::ToString;
        assert_eq!(
            SessionId::new([0x3D, 0x4C, 0xBF, 0x93, 0x37, 0x4E, 0xD8, 0x9B]).to_string(),
            "3D4CBF93374ED89B"
        );
    }
}
