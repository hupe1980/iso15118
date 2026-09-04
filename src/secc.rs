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
//! # Two ways a request is refused, and they are not the same fault
//!
//! [`Event::Refused`] is the vehicle's fault: it sent a request the flow does
//! not allow, and `FAILED_SequenceError` says so. [`Event::Overdue`] is the
//! *station's*: a phase it kept answering `..._Ongoing` ran past
//! `V2G_SECC_Ongoing_Performance_Time`, and \[V2G2-713\] has it answer plain
//! `FAILED` and stop. Both hand over a request to answer and end the session on
//! the answer; they differ in what the response code tells the vehicle about
//! whose problem this was.
//!
//! The station's budgets are deliberately shorter than the vehicle's for the
//! same loop — 55 s against 60, 38 against 40 for the DC isolation test — and
//! that gap is what makes the second event possible at all. A station carrying
//! the vehicle's number would reach its deadline only after the vehicle had
//! given up, which is the same as having none.
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
    Connection, ConnectionError, Flow, FlowError, Instant, Millis, Role, Security, SequenceError,
    SessionId, Timer, Timers,
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
    ///
    /// There is no usable default: \[V2G2-750\] requires the station to return
    /// an id *different from zero*, so the all-zero
    /// [`SessionId::NONE`](crate::session::SessionId::NONE) that
    /// [`SeccConfig::default`] leaves here is a placeholder and not a value.
    /// Answering `SessionSetupReq` while it is still set fails with
    /// [`SeccError::NoSessionId`] rather than putting it on the wire — a
    /// station that assigns nothing leaves the session with no identity, and
    /// every later message would be adopted instead of checked.
    pub session_id: SessionId,
    /// What the transport underneath this session actually is.
    ///
    /// Not something the core can observe — the socket is the caller's — and it
    /// decides one rule that matters: **Plug & Charge is not available without
    /// TLS** \[V2G2-634\], \[V2G2-635\], so a contract selection over a
    /// plaintext connection is refused with `FAILED_SequenceError` rather than
    /// carrying a certificate chain and a signature in clear.
    ///
    /// Defaults to [`Security::None`], because the safe default for a security
    /// decision is the restrictive one: a session that has not said it is
    /// secured is treated as though it is not. A deployment doing Plug & Charge
    /// sets this to [`Security::Tls`] — which is the same value SECC discovery
    /// already produced, so it is a value being passed along rather than a new
    /// judgement.
    pub security: Security,
    /// Ceiling on one V2GTP payload.
    pub max_payload_len: usize,
    /// How many complete-but-unanswered V2GTP frames to hold.
    ///
    /// The second half of the reassembly bound, and the half that is easy to
    /// leave out: `max_payload_len` bounds *one* frame, and bounding only that
    /// moves the problem, because a peer sending whole small frames without
    /// waiting grows the decoded queue instead. V2G is strictly half-duplex, so
    /// anything past one frame in hand is already outside the protocol.
    ///
    /// Defaults to [`MAX_PENDING_FRAMES`](crate::session::MAX_PENDING_FRAMES).
    /// Lower it with `max_payload_len` on a target that cannot hold the crate's
    /// ceilings; a value of 0 is read as 1, because a connection that can hold
    /// no frame can receive nothing.
    pub max_pending_frames: usize,

    /// How long to wait for the vehicle's next request before giving up.
    ///
    /// Defaults to `V2G_SECC_Sequence_Timeout`, 60 s in both generations.
    pub sequence_timeout: Millis,
    /// How long from the connection opening to a `SessionSetupReq`.
    ///
    /// Defaults to the station's own parameter,
    /// `V2G_SECC_CommunicationSetup_Performance_Time` — 18 s \[V2G2-716\], two
    /// under the vehicle's 20 s timeout, so the station gives up while the
    /// vehicle is still listening rather than the other way round.
    pub setup_timeout: Millis,
}

impl Default for SeccConfig {
    fn default() -> Self {
        Self {
            protocols: Protocols::ISO,
            session_id: SessionId::NONE,
            security: Security::None,
            max_payload_len: MAX_EXI_PAYLOAD_LEN,
            max_pending_frames: crate::session::MAX_PENDING_FRAMES,
            sequence_timeout: crate::session::timers::iso2::SECC_SEQUENCE_TIMEOUT,
            setup_timeout: crate::session::timers::iso2::SECC_COMMUNICATION_SETUP_PERFORMANCE_TIME,
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
    /// The station's own budget for this phase ran out, and here is the
    /// request that has to carry the bad news.
    ///
    /// A phase answered `..._Ongoing` is a loop, and
    /// `V2G_SECC_Ongoing_Performance_Time` bounds how long the station may keep
    /// answering that way — 55 s in ISO 15118-2, five seconds under the
    /// vehicle's own timeout, and 38 s against 40 for the DC isolation test.
    /// \[V2G2-713\] says what to do when it expires, and it is not to go quiet:
    /// answer with `response_code` and stop the session. That gap is exactly
    /// the room the answer fits in.
    ///
    /// It arrives on a *request* rather than the moment the timer fires,
    /// because that is when the station has something to answer. A loop budget
    /// almost always expires between exchanges: the vehicle asks about once a
    /// second and the station answers within its performance time, so the
    /// instant the budget runs out there is usually nothing outstanding. The
    /// engine remembers, and hands over the next request to be refused.
    ///
    /// This replaces [`Event::Refused`] for that request, and the difference is
    /// not cosmetic: the vehicle did nothing wrong, so `FAILED_SequenceError`
    /// would be a lie about whose fault it was.
    ///
    /// Answer it with [`Secc::respond`]; the session ends as the answer is
    /// queued.
    Overdue {
        /// The request, so the right response type can be built for it.
        message: Box<Message>,
        /// `FAILED` as its EXI enumeration index in the negotiated generation.
        ///
        /// The plain code, not a specific one: \[V2G2-713\] asks for `FAILED`,
        /// and a station that could not decide has not established *why*.
        response_code: u8,
        /// The phase whose budget ran out.
        phase: &'static str,
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
    /// The byte stream stopped being a V2G session, and there is nothing to
    /// answer.
    ///
    /// A framing fault, a payload this session's own grammar will not decode, a
    /// peer pipelining past the half-duplex rule, a response where only
    /// requests are legal, or a second `supportedAppProtocol` handshake. None
    /// of those can be resynchronised — V2GTP has no delimiter to scan for and
    /// the negotiated grammar is the only reading of the bytes — so the session
    /// ends where it stands.
    ///
    /// [`Secc::handle_input`] still returns the [`SeccError`] that says which,
    /// for the log. The close is not conditional on the caller acting on it.
    Fatal,
}

impl fmt::Display for Close {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Normal => f.write_str("stopped by the vehicle"),
            Self::Paused => f.write_str("paused by the vehicle"),
            Self::Timeout(t) => write!(f, "{} timer expired", t.name()),
            Self::Refused => f.write_str("the vehicle broke the message ordering rules"),
            Self::NoCommonProtocol => f.write_str("no protocol in common"),
            Self::Fatal => f.write_str("the byte stream is not a V2G session"),
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
    /// The phase whose loop budget ran out, until the next request carries the
    /// `FAILED` that \[V2G2-713\] owes the vehicle. See [`Event::Overdue`].
    overdue: Option<&'static str>,
    closed: bool,
}

impl Secc {
    /// A station waiting for a vehicle to connect.
    ///
    /// Call [`Secc::opened`] when the TCP or TLS connection comes up, so the
    /// setup timer starts.
    #[must_use]
    pub fn new(config: SeccConfig) -> Self {
        let conn = Connection::with_limits(config.max_payload_len, config.max_pending_frames);
        Self {
            config,
            conn,
            timers: Timers::new(),
            flow: None,
            events: VecDeque::new(),
            established: false,
            outstanding: None,
            phase: None,
            overdue: None,
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
    /// ordering rules, and turned into events.
    ///
    /// **An error here closes the session**, and that is the point rather than
    /// a side effect. The stream is not something this side can go on parsing —
    /// V2GTP has no delimiter to resynchronise to, and after the handshake the
    /// negotiated grammar is the only reading of the bytes there is — so
    /// carrying on would mean parsing frames whose boundaries the peer alone
    /// decides. [`Event::Closed`]`(`[`Close::Fatal`]`)` is queued before this
    /// returns, [`Secc::is_closed`] is true, the timers are disarmed and the
    /// buffers are dropped, so an application that logs the error and calls
    /// again gets the same session-is-over answer rather than a live one.
    ///
    /// That the enforcement is not the caller's is deliberate, and it is the
    /// same rule [`Secc::respond`] keeps for a refusal: a correctly detected
    /// fault that the application is free to ignore is
    /// `EVerest`'s MEDIUM-14, not a diagnostic.
    pub fn handle_input(&mut self, now: Instant, data: &[u8]) -> Result<(), SeccError> {
        if self.closed {
            return Ok(());
        }
        let outcome =
            self.conn.receive(data).map_err(SeccError::from).and_then(|()| self.pump(now));
        if outcome.is_err() {
            self.close_fatal();
        }
        outcome
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
            // The handshake happens once: \[V2G2-536\] has the station wait
            // for one `supportedAppProtocolReq` and \[V2G2-541\] leaves
            // `SessionSetupReq` as the only request legal after it.
            //
            // Re-running this arm would replace `self.flow` with a fresh
            // `Sequencer` at `Phase::Start`, discarding the payment option, the
            // transfer mode and the failure latch — so a peer just answered
            // `FAILED_*` would be back at the top of the graph. `Connection`
            // makes it unreachable (D12); this makes it local (D26).
            if self.flow.is_some() {
                return Err(SeccError::HandshakeRepeated);
            }
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
            let agreed = req
                .negotiate(speakable)
                .and_then(|a| Flow::new(a.protocol, self.config.security).map(|flow| (a, flow)));
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
        // Every request after `SessionSetupReq` must carry the id this station
        // assigned. \[V2G2-460\] — the answer is `FAILED_UnknownSession`.
        // A request with *no* id is refused for the same reason: an
        // unidentified request in an established session is not this session's.
        //
        // Checked before the flow is borrowed, and ahead of the handshake test:
        // `established` can only be true once a flow has accepted a
        // `SessionSetupReq`, so the order changes nothing except which borrow
        // is live.
        if self.established && !self.carries_the_session_id(&message) {
            let response_code = unknown_session_code(self.conn.protocol());
            self.outstanding = Some(Outstanding {
                name: message.name(),
                refused: true,
                due: now.saturating_add(performance_time(&message)),
            });
            self.events.push_back(Event::Refused {
                message: Box::new(message),
                response_code,
                reason: Refusal::UnknownSession,
            });
            self.close_after_refusal();
            return Ok(());
        }

        let Some(flow) = self.flow.as_mut() else {
            return Err(SeccError::BeforeHandshake(message.name()));
        };

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
                self.outstanding = Some(Outstanding {
                    name: message.name(),
                    refused: false,
                    due: now.saturating_add(performance_time(&message)),
                });
                self.events.push_back(Event::Request(Box::new(message)));
            }
            Err(FlowError::Sequence(e)) => {
                self.outstanding = Some(Outstanding {
                    name: message.name(),
                    refused: true,
                    due: now.saturating_add(performance_time(&message)),
                });
                // A request refused because *this station* ran out of time is
                // not out of sequence, and saying so would blame the vehicle
                // for the station's own indecision.
                if let Some(phase) = self.overdue.take() {
                    self.events.push_back(Event::Overdue {
                        message: Box::new(message),
                        response_code: failed_code(self.conn.protocol()),
                        phase,
                    });
                } else {
                    trace_close!(message = e.got, phase = e.phase, "out of sequence");
                    self.events.push_back(Event::Refused {
                        message: Box::new(message),
                        response_code: e.response_code,
                        reason: Refusal::Sequence(e),
                    });
                }
                self.close_after_refusal();
            }
            Err(FlowError::NotARequest) => return Err(SeccError::NotARequest(message.name())),
        }
        Ok(())
    }

    /// Whether `message` carries the id this station actually assigned.
    ///
    /// The all-zero id never matches, whatever is configured — and that is a
    /// separate clause rather than a redundant one. \[V2G2-460\] is a
    /// *comparison*, and comparing against a default is how CVE-2025-68140
    /// happened in `EVerest`'s `EvseV2G`: with no session registered the stored
    /// id was zero, so a request carrying zero compared equal and was admitted
    /// to an established session.
    ///
    /// [`Secc::respond`] already refuses to assign the placeholder
    /// \[V2G2-750\], so the two cannot both be zero here. But that argument
    /// runs through three other pieces of this file, and an invariant that
    /// holds because of what a different method does is one a later edit can
    /// take away without touching this line. One comparison makes it local.
    fn carries_the_session_id(&self, message: &Message) -> bool {
        let assigned = self.config.session_id;
        !assigned.is_none() && message.session_id() == Some(assigned)
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
        // \[V2G2-750\]: the id the station returns must differ from zero.
        //
        // Checked here rather than in `Secc::new` because `join_session` may
        // still supply one while `SessionSetupReq` is being answered, and
        // checked at all because the failure is otherwise silent on this side
        // and fatal on the other: the vehicle would have nothing to check later
        // messages against, and a well-behaved one ends the session without
        // ever saying why.
        //
        // `set_session_id` reports whether the message has a header to stamp at
        // all, which is the exact set of responses the requirement covers — the
        // `supportedAppProtocol` handshake predates the session and has none.
        // Nothing has been queued yet, so refusing here leaves the wire clean.
        let stamped = response.set_session_id(self.config.session_id);
        if stamped && self.config.session_id.is_none() {
            return Err(SeccError::NoSessionId);
        }
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
        // that this one is answered it can be read — and a fault in what was
        // already framed ends the session here for the same reason it does in
        // `handle_input`.
        let outcome = self.pump(now);
        if outcome.is_err() {
            self.close_fatal();
        }
        outcome
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

    /// When the outstanding request's answer is due — its arrival instant plus
    /// `V2G_SECC_Msg_Performance_Time`.
    ///
    /// The station's half of ISO 15118-2 Table 109, and **advice rather than a
    /// deadline**: nothing here enforces it and no timer is armed from it.
    /// Missing a performance time is not a fault this side can observe — what
    /// happens is the *vehicle's* `V2G_EVCC_Msg_Timeout` running out half a
    /// second later, with nothing in this station's log to say why.
    ///
    /// The values are citations, and the tight one is not close:
    /// `CurrentDemandReq` allows **25 ms**, which constrains where the answer
    /// may come from rather than how fast the code is. `None` when nothing is
    /// outstanding.
    #[must_use]
    pub const fn response_due(&self) -> Option<Instant> {
        match self.outstanding {
            Some(Outstanding { due, .. }) => Some(due),
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
    ///
    /// It is the station's half of the pair — `V2G_SECC_*_Performance_Time`,
    /// five seconds under the vehicle's timeout for the general loop and two
    /// under it for the DC safety phases. Arming the vehicle's number here
    /// would give the station a deadline it could only reach after the vehicle
    /// had already abandoned the session. See [`Role`].
    fn enter_phase(&mut self, now: Instant) {
        let Some(flow) = self.flow.as_ref() else { return };
        let phase = flow.phase_name();
        if self.phase == Some(phase) {
            return;
        }
        self.phase = Some(phase);
        match flow.loop_timeout(Role::Secc) {
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
    ///
    /// Every timer but one ends the session. The exception is the loop budget:
    /// \[V2G2-713\] has the station *answer* `FAILED` when it runs out, so that
    /// expiry surfaces as [`Event::Overdue`] and the session stays answerable
    /// for exactly that one response. See [`Event::Overdue`].
    pub fn handle_timeout(&mut self, now: Instant) {
        while let Some(timer) = self.timers.expired(now) {
            // Every timer but the loop budget ends the session where it stands.
            // That one is a deadline the station can *answer*, so it is
            // remembered rather than acted on: the vehicle's next request in
            // this phase becomes [`Event::Overdue`] and carries the `FAILED`.
            // Should the vehicle instead go quiet, the sequence timer closes
            // the session in the ordinary way.
            if timer == Timer::Ongoing && !self.closed {
                let phase = self.flow.as_ref().map_or("unknown", Flow::phase_name);
                trace_close!(phase = phase, "loop budget expired; the next request gets FAILED");
                self.overdue = Some(phase);
                // Recorded now rather than when the answer goes out, so the
                // flow refuses everything but `SessionStopReq` from here — the
                // same rule a `FAILED` response earns when the application
                // chooses one.
                if let Some(flow) = self.flow.as_mut() {
                    flow.failed();
                }
                continue;
            }
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

    /// Ends the session because the stream stopped being one.
    ///
    /// Unlike [`Secc::close_after_refusal`] there is nothing left to answer, so
    /// the outstanding request is dropped and the buffers go with it: whatever
    /// the peer framed behind the fault was framed by the same peer, and this
    /// side has no way to tell where the next real message would have started.
    /// Anything already queued for the wire is left alone — it was built before
    /// the fault and the caller may still flush it.
    fn close_fatal(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        self.timers.disarm_all();
        self.conn.reset_input();
        self.outstanding = None;
        trace_close!("the byte stream is not a V2G session");
        self.events.push_back(Event::Closed(Close::Fatal));
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
    /// When the answer is due — the arrival instant plus this request's
    /// `V2G_SECC_Msg_Performance_Time`. Advice, never enforced: see
    /// [`Secc::response_due`].
    due: Instant,
}

/// The station's own budget for answering `request` — the other half of
/// Table 109.
///
/// Each generation's sequencer owns its table; see
/// [`iso2::Request::performance_time`] and [`iso20::Request::performance_time`].
///
/// [`iso2::Request::performance_time`]: crate::session::iso2::Request::performance_time
/// [`iso20::Request::performance_time`]: crate::session::iso20::Request::performance_time
fn performance_time(request: &Message) -> Millis {
    #[cfg(feature = "iso2")]
    if let Some(r) = crate::session::iso2::Request::of(request) {
        return r.performance_time();
    }
    #[cfg(feature = "iso20-common")]
    if let Some(r) = crate::session::iso20::Request::of(request) {
        return r.performance_time();
    }
    let _ = request;
    crate::session::timers::iso2::SECC_MSG_PERFORMANCE_DEFAULT
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
        // name, and the caller cannot get here: nothing is `established` until
        // a flow has accepted a `SessionSetupReq`, and there is no flow without
        // a protocol. `u8::MAX` rather than `0` all the same, because `0` is
        // `OK` in both schemas — an unreachable branch that fails *open* is one
        // edit away from being a reachable one that says the request was fine.
        _ => u8::MAX,
    }
}

/// Plain `FAILED` as its EXI enumeration index in each generation.
///
/// As with [`unknown_session_code`], the two schemas order their response codes
/// differently, so this is not the same number in both.
const fn failed_code(protocol: Option<Protocol>) -> u8 {
    match protocol {
        #[cfg(feature = "iso2")]
        Some(Protocol::Iso2) => crate::iso2::ResponseCode::FAILED as u8,
        #[cfg(feature = "iso20-common")]
        Some(Protocol::Iso20) => crate::iso20::common::ResponseCode::FAILED as u8,
        // Unreachable in practice: a loop budget is only ever armed for a phase
        // of a negotiated flow. `u8::MAX` for the reason
        // [`unknown_session_code`] gives — `0` is `OK`.
        _ => u8::MAX,
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
    /// A second `supportedAppProtocolReq` arrived in a session that had already
    /// negotiated one.
    ///
    /// \[V2G2-541\] leaves `SessionSetupReq` as the only legal request after
    /// the handshake, and accepting a second one would restart the ordering
    /// graph — failure latch included. Fatal: the session closes.
    HandshakeRepeated,
    /// The application answered when no request was waiting for one.
    NothingToAnswer(&'static str),
    /// No session id was configured, so there is none to assign.
    ///
    /// [`SeccConfig::session_id`] was left at the all-zero placeholder, and
    /// \[V2G2-750\] requires the station to return an id different from zero.
    /// Supply eight unpredictable bytes in [`SeccConfig`], or adopt the
    /// vehicle's own with [`Secc::join_session`] when it is rejoining a session
    /// this station paused.
    NoSessionId,
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
            Self::HandshakeRepeated => {
                f.write_str("a second supportedAppProtocolReq arrived after the handshake")
            }
            Self::NothingToAnswer(name) => {
                write!(f, "{name} was sent with no request outstanding")
            }
            Self::NoSessionId => f.write_str(
                "SeccConfig::session_id is the all-zero placeholder; a station must assign \
                 an unpredictable non-zero session id",
            ),
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
