//! The charging station's side of a session — sans I/O.
//!
//! [`Secc`] owns everything about a V2G session that is *protocol*: framing,
//! decoding, the `supportedAppProtocol` handshake, session-id checking, the
//! message-ordering rules and the spec's timers. It owns nothing that is
//! *policy*: whether to authorize a vehicle, which schedule to offer, how much
//! current to deliver. Those arrive as [`Event::Request`] and are answered with
//! [`Secc::respond`].
//!
//! That line is where it is because everything above it is a decision a
//! charging station operator makes, and everything below it is a decision ISO
//! made. Only the second kind belongs in a library.
//!
//! # One request at a time
//!
//! V2G is half-duplex: the vehicle may not send again until it has been
//! answered. So [`Secc`] surfaces one [`Event::Request`] and reads nothing
//! further until [`Secc::respond`] has been called — anything the vehicle sent
//! early waits, bounded by
//! [`MAX_PENDING_FRAMES`](crate::session::MAX_PENDING_FRAMES). That is the
//! protocol, and it is also what stops one unauthenticated peer from queueing
//! work without bound: several requests are legal over and over — a charge loop
//! turns, an authorization retries — so an engine that decoded everything
//! already framed would build an event queue as large as the peer cared to make
//! it.
//!
//! The rule runs the other way too, which is why [`Secc::respond`] knows what
//! it is answering: a response with no request outstanding, or one that does
//! not pair with the request that is, is the station's own bug and is refused
//! here rather than sent. And because there is exactly one session, its id is
//! stamped into every response rather than rebuilt in thirty places by the
//! application.
//!
//! # The loop
//!
//! ```no_run
//! use iso15118::secc::{Event, Secc, SeccConfig};
//! use iso15118::session::{Instant, SessionId};
//! use iso15118::Protocols;
//!
//! # fn read(_: &mut [u8]) -> usize { 0 }
//! # fn write(_: &[u8]) {}
//! # fn now() -> Instant { Instant::ZERO }
//! # fn answer(_: &iso15118::message::Message) -> iso15118::message::Message { unimplemented!() }
//! let mut secc = Secc::new(SeccConfig {
//!     protocols: Protocols::ISO,
//!     session_id: SessionId::new(*b"\x11\x22\x33\x44\x55\x66\x77\x88"),
//!     ..SeccConfig::default()
//! });
//!
//! let mut buf = [0u8; 4096];
//! loop {
//!     let n = read(&mut buf);
//!     secc.handle_input(now(), &buf[..n])?;
//!     while let Some(event) = secc.poll_event() {
//!         match event {
//!             Event::ProtocolAgreed(p) => println!("speaking {p}"),
//!             Event::Request(req) => secc.respond(now(), answer(&req))?,
//!             Event::Refused { .. } => break,
//!             Event::Closed(why) => return Ok(println!("session over: {why}")),
//!             _ => {}
//!         }
//!     }
//!     write(&secc.take_transmit());
//! }
//! # Ok::<_, iso15118::secc::SeccError>(())
//! ```
//!
//! The caller also arms its own timer for [`Secc::poll_timeout`] and calls
//! [`Secc::handle_timeout`] when it fires. Nothing else is required.
//!
//! # One check the engine cannot make for you
//!
//! ISO 15118-2 obliges a station to check the `ChargingProfile` in
//! `PowerDeliveryReq` against the `SAScheduleList` it offered, and prescribes
//! the response code either way \[V2G2-224\], \[V2G2-225\]. That is protocol,
//! so it is in this crate — as
//! [`session::iso2::schedule`](crate::session::iso2::schedule) — but not in
//! this engine: keeping the schedule would hold up to three tuples of a
//! thousand entries for the life of every session, costing the session state
//! the property that makes pause and resume cheap. Your application built the
//! list, so it already has it; one call at `PowerDeliveryReq` closes it.

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::fmt;

use crate::app_protocol::SupportedAppProtocolRes;
use crate::message::Message;
use crate::session::{
    Connection, ConnectionError, Flow, FlowError, Instant, Millis, SequenceError, SessionId, Timer,
    Timers,
};
use crate::trace::{trace_close, trace_event};
use crate::{MAX_EXI_PAYLOAD_LEN, Protocol, Protocols};

/// What a charging station needs to know before the first byte arrives.
#[derive(Debug, Clone)]
pub struct SeccConfig {
    /// Protocol generations this station speaks.
    ///
    /// A set rather than a list, because the order here means nothing: the
    /// vehicle's stated priority decides which of the ones in common is used,
    /// and the standard requires the station to honour it.
    ///
    /// A generation this build has no message set for — `Din70121`, or `Iso2`
    /// without the `iso2` feature — is dropped from the set before the
    /// handshake sees it, so the station never agrees to something it cannot
    /// then speak, *and* still falls back to a generation both sides do have.
    /// See [`Flow::supports`].
    pub protocols: Protocols,
    /// The session id to assign.
    ///
    /// It has to be unpredictable — it is what a paused session is resumed
    /// under — and this crate has no RNG, so the caller supplies it.
    pub session_id: SessionId,
    /// Ceiling on one V2GTP payload.
    pub max_payload_len: usize,
    /// How long to wait for the vehicle's next request before giving up.
    ///
    /// Defaults to `V2G_SECC_Sequence_Timeout`, 60 s in both generations.
    pub sequence_timeout: Millis,
    /// How long from the connection opening to a `SessionSetupReq`.
    ///
    /// The vehicle's own budget from plug-in to `SessionSetupRes` is 20 s and
    /// includes SLAC, SDP and TLS, so a station that waits much longer than
    /// this is holding a socket for a vehicle that has already given up.
    pub setup_timeout: Millis,
}

impl Default for SeccConfig {
    fn default() -> Self {
        Self {
            protocols: Protocols::ISO,
            session_id: SessionId::NONE,
            max_payload_len: MAX_EXI_PAYLOAD_LEN,
            sequence_timeout: crate::session::timers::iso2::SECC_SEQUENCE_TIMEOUT,
            setup_timeout: crate::session::timers::iso2::EVCC_COMMUNICATION_SETUP_TIMEOUT,
        }
    }
}

/// Something the application has to know about, or act on.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Event {
    /// The `supportedAppProtocol` handshake settled. The response is already
    /// queued for the wire; nothing is required of the application.
    ProtocolAgreed(Protocol),
    /// A request arrived and is legal. Answer it with [`Secc::respond`].
    ///
    /// "Legal" here means the ordering rules and the session id — what the
    /// engine can check without knowing anything about charging. One rule sits
    /// just outside that line because it needs a message the *application*
    /// built: a `PowerDeliveryReq` has to be checked against the
    /// `SAScheduleList` this station offered in `ChargeParameterDiscoveryRes`,
    /// and the engine does not keep that list — see
    /// [`session::iso2::schedule`](crate::session::iso2::schedule), which is
    /// one call and gives you the `ResponseCode` to answer with.
    Request(Box<Message>),
    /// A request arrived that the protocol does not allow here.
    ///
    /// The spec's reaction is fixed: answer with `response_code` and end the
    /// session. The response still has to be built by the application, because
    /// which of the thirty-odd response types to use depends on the request.
    Refused {
        /// The request, so the right response type can be built for it.
        message: Box<Message>,
        /// `FAILED_SequenceError` (or `FAILED_UnknownSession`) as its EXI
        /// enumeration index in the negotiated generation.
        response_code: u8,
        /// What was wrong.
        reason: Refusal,
    },
    /// The session is over. Nothing further will be read or written.
    Closed(Close),
}

/// Why a request was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Refusal {
    /// The request is not one the current phase allows.
    Sequence(SequenceError),
    /// The request carried a session id this station did not assign.
    UnknownSession,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sequence(e) => write!(f, "{e}"),
            Self::UnknownSession => f.write_str("unknown session id"),
        }
    }
}

/// Why a session ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Close {
    /// The vehicle sent `SessionStopReq` and was answered.
    Normal,
    /// The vehicle paused the session — `SessionStopReq` with
    /// `ChargingSession = Pause` — and was answered.
    ///
    /// The station is expected to keep the session's state: its id, its
    /// authorization, and in ISO 15118-20 the selected service and the agreed
    /// schedule. The next session that arrives with the same id is this one,
    /// and [`Secc::resume`] picks it up.
    Paused,
    /// A timer expired.
    Timeout(Timer),
    /// The vehicle broke the message-ordering rules; the refusal has been
    /// reported and answered.
    Refused,
    /// The vehicle offered no protocol this station speaks.
    NoCommonProtocol,
}

impl fmt::Display for Close {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Normal => f.write_str("stopped by the vehicle"),
            Self::Paused => f.write_str("paused by the vehicle"),
            Self::Timeout(t) => write!(f, "{} timer expired", t.name()),
            Self::Refused => f.write_str("the vehicle broke the message ordering rules"),
            Self::NoCommonProtocol => f.write_str("no protocol in common"),
        }
    }
}

/// The charging station's half of a V2G session.
#[derive(Debug)]
pub struct Secc {
    config: SeccConfig,
    conn: Connection,
    timers: Timers,
    flow: Option<Flow>,
    events: VecDeque<Event>,
    /// True once `SessionSetupReq` has been answered, after which every request
    /// must carry the assigned session id.
    established: bool,
    /// The request that has been surfaced and not yet answered.
    ///
    /// V2G is strictly half-duplex, so nothing further is read until the
    /// application has answered. Without this the station would decode and
    /// queue every frame a peer pushed at it, and a repeatable request — a
    /// charge loop turning — would let one peer queue as many events as it
    /// could send bytes.
    ///
    /// It holds the request's *name* rather than a flag because
    /// [`Secc::respond`] has to check that the answer answers it.
    outstanding: Option<Outstanding>,
    /// The flow phase the last accepted request left the session in, so that
    /// entering a new one can start (or stop) that phase's loop budget.
    phase: Option<&'static str>,
    closed: bool,
}

impl Secc {
    /// A station waiting for a vehicle to connect.
    ///
    /// Call [`Secc::opened`] when the TCP or TLS connection comes up, so the
    /// setup timer starts.
    #[must_use]
    pub fn new(config: SeccConfig) -> Self {
        let conn = Connection::with_limit(config.max_payload_len);
        Self {
            config,
            conn,
            timers: Timers::new(),
            flow: None,
            events: VecDeque::new(),
            established: false,
            outstanding: None,
            phase: None,
            closed: false,
        }
    }

    /// Records that the transport connection is up, starting the setup timer.
    pub fn opened(&mut self, now: Instant) {
        self.timers.arm(Timer::CommunicationSetup, now, self.config.setup_timeout);
    }

    /// The protocol generation the handshake settled on, once it has.
    #[must_use]
    pub const fn protocol(&self) -> Option<Protocol> {
        self.conn.protocol()
    }

    /// The message-ordering state, once a protocol has been agreed.
    #[must_use]
    pub const fn flow(&self) -> Option<&Flow> {
        self.flow.as_ref()
    }

    /// True once the session has ended.
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        self.closed
    }

    /// Feeds bytes read from the transport.
    ///
    /// Frames are reassembled, decoded, checked against the session id and the
    /// ordering rules, and turned into events. Errors here are fatal to the
    /// session: the stream is not something this side can go on parsing.
    pub fn handle_input(&mut self, now: Instant, data: &[u8]) -> Result<(), SeccError> {
        if self.closed {
            return Ok(());
        }
        self.conn.receive(data)?;
        self.pump(now)
    }

    /// Decodes and dispatches buffered frames until one needs answering.
    ///
    /// Stopping at the outstanding request is the half-duplex rule made
    /// structural: a peer may not send again before it is answered, so anything
    /// already framed behind that request waits — bounded by
    /// [`MAX_PENDING_FRAMES`](crate::session::MAX_PENDING_FRAMES) — rather than
    /// being decoded into events nobody asked for.
    fn pump(&mut self, now: Instant) -> Result<(), SeccError> {
        while !self.closed && self.outstanding.is_none() {
            let Some(message) = self.conn.next_message()? else { break };
            self.dispatch(now, message)?;
        }
        Ok(())
    }

    fn dispatch(&mut self, now: Instant, message: Message) -> Result<(), SeccError> {
        // The vehicle just spoke, so it is not the one that has gone quiet.
        self.timers.arm(Timer::Sequence, now, self.config.sequence_timeout);

        if let Message::AppProtocolReq(req) = &message {
            self.timers.disarm(Timer::CommunicationSetup);
            // A generation whose message set this build does not have is not a
            // protocol in common, whatever the configuration says. Agreeing to
            // one and then failing on its first message would be worse than
            // declining it here.
            //
            // The narrowing happens *before* negotiation and not after. A
            // vehicle that prefers DIN SPEC 70121 and offers ISO 15118-2 as its
            // fallback would otherwise win the negotiation with a protocol this
            // station cannot speak, and the fallback both sides do have would
            // never be considered.
            let mut speakable = self.config.protocols;
            speakable.retain(Flow::supports);
            let agreed =
                req.negotiate(speakable).and_then(|a| Flow::new(a.protocol).map(|flow| (a, flow)));
            let Some((agreed, flow)) = agreed else {
                self.conn
                    .send(&Message::AppProtocolRes(Box::new(SupportedAppProtocolRes::reject())))?;
                self.close(Close::NoCommonProtocol);
                return Ok(());
            };
            self.conn.send(&Message::AppProtocolRes(Box::new(SupportedAppProtocolRes::accept(
                agreed,
            ))))?;
            self.conn.set_protocol(agreed.protocol);
            self.flow = Some(flow);
            trace_event!(protocol = %agreed.protocol, "protocol agreed");
            self.events.push_back(Event::ProtocolAgreed(agreed.protocol));
            return Ok(());
        }

        if !message.is_request() {
            return Err(SeccError::NotARequest(message.name()));
        }
        let Some(flow) = self.flow.as_mut() else {
            return Err(SeccError::BeforeHandshake(message.name()));
        };

        // Every request after `SessionSetupReq` must carry the id this station
        // assigned. \[V2G2-460\] — the answer is `FAILED_UnknownSession`.
        // A request with *no* id is refused for the same reason: an
        // unidentified request in an established session is not this session's.
        if self.established && message.session_id() != Some(self.config.session_id) {
            let response_code = unknown_session_code(self.conn.protocol());
            self.outstanding = Some(Outstanding { name: message.name(), refused: true });
            self.events.push_back(Event::Refused {
                message: Box::new(message),
                response_code,
                reason: Refusal::UnknownSession,
            });
            self.close_after_refusal();
            return Ok(());
        }

        match flow.accept(&message) {
            Ok(()) => {
                // From the request after `SessionSetupReq` on, the session id is
                // the station's own and every message must carry it.
                self.established |= message.name() == "SessionSetupReq";
                trace_event!(
                    message = message.name(),
                    phase = self.flow.as_ref().map(Flow::phase_name),
                    "request"
                );
                self.enter_phase(now);
                self.outstanding = Some(Outstanding { name: message.name(), refused: false });
                self.events.push_back(Event::Request(Box::new(message)));
            }
            Err(FlowError::Sequence(e)) => {
                trace_close!(message = e.got, phase = e.phase, "out of sequence");
                self.outstanding = Some(Outstanding { name: message.name(), refused: true });
                self.events.push_back(Event::Refused {
                    message: Box::new(message),
                    response_code: e.response_code,
                    reason: Refusal::Sequence(e),
                });
                self.close_after_refusal();
            }
            Err(FlowError::NotARequest) => return Err(SeccError::NotARequest(message.name())),
        }
        Ok(())
    }

    /// The session id this station is checking every request against.
    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.config.session_id
    }

    /// Adopts the vehicle's session id instead of the one this station
    /// assigned.
    ///
    /// Call from the [`Event::Request`] carrying `SessionSetupReq`, when
    /// [`Message::session_id`] names a session this station paused and whose
    /// state it still holds — then answer with `OK_OldSessionJoined`. Every
    /// later request is checked against the adopted id.
    ///
    /// Whether an id names a resumable session is stored state — a schedule, an
    /// authorization, an energy reading — that the protocol core does not hold,
    /// which is why this is the application's call and not the core's.
    ///
    /// For ISO 15118-2 this is the whole of resumption; ISO 15118-20 also keeps
    /// negotiated state, so use [`Secc::resume`] there.
    ///
    /// [`Message::session_id`]: crate::message::Message::session_id
    pub const fn join_session(&mut self, session_id: SessionId) {
        self.config.session_id = session_id;
    }

    /// Picks up a paused ISO 15118-20 session under the vehicle's own id.
    ///
    /// [`Secc::join_session`] plus the part that is -20's: the flow restarts at
    /// parameter discovery, because authorization and the selected service
    /// survived the pause and re-running them would be out of sequence.
    #[cfg(feature = "iso20-common")]
    #[cfg_attr(docsrs, doc(cfg(feature = "iso20-common")))]
    pub fn resume(&mut self, session_id: SessionId, service: crate::session::iso20::Service) {
        self.join_session(session_id);
        if let Some(flow) = self.flow.as_mut() {
            flow.resume(service);
        }
    }

    /// Answers the outstanding request.
    ///
    /// The response is framed and queued; take it with [`Secc::take_transmit`].
    /// When the request was `SessionStopReq`, or was refused, the session ends
    /// as soon as the answer is queued — which is the order the spec wants:
    /// the vehicle gets its response code before the socket goes away.
    ///
    /// The answer has to be an answer: there must be a request outstanding, and
    /// the response must be the one that pairs with it. A station that answers
    /// `AuthorizationReq` with `ChargingStatusRes` has a bug the vehicle will
    /// find, and finding it here instead costs one string comparison. The one
    /// exception is a refused request: ISO 15118 asks for the *corresponding*
    /// response there too, but a station cannot always build one for a message
    /// it does not implement, and turning a clean refusal into a dropped socket
    /// would leave the vehicle worse off than a mismatched response code does.
    ///
    /// The session id is stamped in rather than taken from the message. The
    /// station assigned it and every message of the session carries it
    /// \[V2G2-752\], so it is not a per-response decision, and an application
    /// that has to remember it in thirty places will eventually not.
    pub fn respond(&mut self, now: Instant, mut response: Message) -> Result<(), SeccError> {
        if response.is_request() {
            return Err(SeccError::NotAResponse(response.name()));
        }
        let Some(outstanding) = self.outstanding else {
            return Err(SeccError::NothingToAnswer(response.name()));
        };
        if !outstanding.refused && !response.answers(outstanding.name) {
            return Err(SeccError::WrongResponse {
                expected: outstanding.name,
                got: response.name(),
            });
        }
        response.set_session_id(self.config.session_id);
        // A `FAILED_*` code ends the session: ISO 15118 leaves the vehicle
        // nothing to send but `SessionStopReq`, and the flow is told so before
        // the next request is read. This is what stops a peer from carrying on
        // down the flow as though the failure had not happened — and the
        // sequence timer below bounds how long the station waits for the stop.
        if response.outcome().is_some_and(crate::message::Outcome::is_failure)
            && let Some(flow) = self.flow.as_mut()
        {
            trace_close!(message = response.name(), "failure response; awaiting SessionStopReq");
            flow.failed();
        }
        self.conn.send(&response)?;
        self.outstanding = None;

        match self.flow.as_ref() {
            Some(flow) if flow.is_paused() => self.close(Close::Paused),
            Some(flow) if flow.is_finished() => self.close(Close::Normal),
            _ if self.closed => {}
            _ => {
                // Still going: the vehicle owes the next request — the next one
                // in the flow, or `SessionStopReq` if this answer was a
                // failure. Either way the sequence timer bounds the wait.
                self.timers.arm(Timer::Sequence, now, self.config.sequence_timeout);
            }
        }
        // The vehicle's next request may already be framed and waiting; now
        // that this one is answered it can be read.
        self.pump(now)
    }

    /// True while a request has been surfaced and not yet answered.
    #[must_use]
    pub const fn awaiting_response(&self) -> bool {
        self.outstanding.is_some()
    }

    /// The request waiting for an answer, by element name.
    #[must_use]
    pub const fn outstanding(&self) -> Option<&'static str> {
        match self.outstanding {
            Some(Outstanding { name, .. }) => Some(name),
            None => None,
        }
    }

    /// Starts, keeps or stops the loop budget of the phase the flow is now in.
    ///
    /// A phase like `Authorized` is not one exchange but a loop the station may
    /// keep answering `..._Ongoing` — waiting on a clearing house, or on a
    /// driver tapping a card. The budget bounds the station's own indecision,
    /// runs from the *first* request of the phase, and is not restarted by the
    /// repeats: restarting it would make it unbounded.
    fn enter_phase(&mut self, now: Instant) {
        let Some(flow) = self.flow.as_ref() else { return };
        let phase = flow.phase_name();
        if self.phase == Some(phase) {
            return;
        }
        self.phase = Some(phase);
        match flow.loop_timeout() {
            Some(budget) => self.timers.arm(Timer::Ongoing, now, budget),
            None => self.timers.disarm(Timer::Ongoing),
        }
    }

    /// The next event, if any.
    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// The earliest instant at which [`Secc::handle_timeout`] must be called.
    #[must_use]
    pub fn poll_timeout(&self) -> Option<Instant> {
        self.timers.next_deadline()
    }

    /// Advances the clock, expiring any timer that has come due.
    pub fn handle_timeout(&mut self, now: Instant) {
        while let Some(timer) = self.timers.expired(now) {
            self.close(Close::Timeout(timer));
        }
    }

    /// Bytes to write to the transport.
    #[must_use]
    pub fn take_transmit(&mut self) -> Vec<u8> {
        self.conn.take_transmit()
    }

    /// True when there is nothing queued for the wire.
    #[must_use]
    pub fn transmit_is_empty(&self) -> bool {
        self.conn.transmit_is_empty()
    }

    fn close(&mut self, why: Close) {
        if self.closed {
            return;
        }
        self.closed = true;
        self.timers.disarm_all();
        trace_close!(reason = %why, "session closed");
        self.events.push_back(Event::Closed(why));
    }

    /// Ends the session, but leaves the transmit queue alone so the refusal the
    /// application is about to build still reaches the vehicle.
    fn close_after_refusal(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        self.timers.disarm_all();
        self.events.push_back(Event::Closed(Close::Refused));
    }
}

/// The request [`Secc::respond`] is owed an answer for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Outstanding {
    /// Element name of the request.
    name: &'static str,
    /// True when it was surfaced as [`Event::Refused`] rather than
    /// [`Event::Request`], in which case the response type is not checked
    /// against it — see [`Secc::respond`].
    refused: bool,
}

/// `FAILED_UnknownSession` as its EXI enumeration index in each generation.
///
/// The two schemas list their response codes in different orders, so the index
/// is not the same number in both — which is exactly the kind of thing that is
/// wrong in the field and right here.
const fn unknown_session_code(protocol: Option<Protocol>) -> u8 {
    match protocol {
        #[cfg(feature = "iso2")]
        Some(Protocol::Iso2) => crate::iso2::ResponseCode::FAILEDUnknownSession as u8,
        #[cfg(feature = "iso20-common")]
        Some(Protocol::Iso20) => crate::iso20::common::ResponseCode::FAILEDUnknownSession as u8,
        // Without a negotiated protocol there is no response code space to
        // name; the caller will not get here, because nothing is `established`.
        _ => 0,
    }
}

/// A failure that ends the session rather than being answered on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SeccError {
    /// The byte stream was not a well-formed sequence of V2G messages.
    Connection(ConnectionError),
    /// A response arrived where only requests are legal.
    NotARequest(&'static str),
    /// The application tried to answer with a request.
    NotAResponse(&'static str),
    /// A session message arrived before the protocol handshake.
    BeforeHandshake(&'static str),
    /// The application answered when no request was waiting for one.
    NothingToAnswer(&'static str),
    /// The application answered the outstanding request with the wrong
    /// response type.
    WrongResponse {
        /// The request that is waiting for an answer.
        expected: &'static str,
        /// The response that was offered.
        got: &'static str,
    },
}

impl From<ConnectionError> for SeccError {
    fn from(e: ConnectionError) -> Self {
        Self::Connection(e)
    }
}

impl fmt::Display for SeccError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connection(e) => write!(f, "{e}"),
            Self::NotARequest(name) => write!(f, "{name} is a response; the SECC expects requests"),
            Self::NotAResponse(name) => write!(f, "{name} is a request, not a response"),
            Self::BeforeHandshake(name) => {
                write!(f, "{name} arrived before supportedAppProtocol")
            }
            Self::NothingToAnswer(name) => {
                write!(f, "{name} was sent with no request outstanding")
            }
            Self::WrongResponse { expected, got } => {
                write!(f, "{got} does not answer {expected}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SeccError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Connection(e) => Some(e),
            _ => None,
        }
    }
}
