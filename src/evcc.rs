//! The vehicle's side of a session — sans I/O.
//!
//! [`Evcc`] is the mirror of [`Secc`](crate::secc::Secc), and the asymmetry
//! between them is the protocol's, not this crate's: the vehicle *drives*. It
//! chooses which request to send and when, and the charger only ever answers.
//! So where the SECC surfaces requests to be answered, the EVCC accepts
//! requests to be sent and surfaces the answers.
//!
//! What it does for you:
//!
//! * runs the `supportedAppProtocol` handshake and remembers the outcome, so
//!   payload type `0x8001` is read as the right message set afterwards;
//! * refuses to send a request the current phase does not allow, *before* it
//!   reaches the wire — a charger would answer `FAILED_SequenceError` and drop
//!   the session, and finding out locally is better;
//! * refuses to send a *second* request while the first is unanswered, because
//!   V2G is half-duplex and the ordering graph does not say so on its own: a
//!   charge loop's request is legal over and over, and what makes the second
//!   one wrong is only that the first has not come back;
//! * refuses a response that does not answer the outstanding request — the
//!   ordering graph constrains requests, so this is the only thing standing
//!   between a charger and an answer to a question nobody asked;
//! * stamps the session id the charger assigned into every request it sends,
//!   so the application never has to carry it — and checks the id on every
//!   response, so a charger cannot change it mid-session;
//! * arms the per-message response timeout, which is 250 ms for a charge loop
//!   and seconds for everything else, *and* the budget for a whole phase the
//!   charger keeps answering `..._Ongoing` — a cable check that never finishes
//!   has to end the session, and the per-message timeout will not do it,
//!   because a prompt `Ongoing` restarts it every time;
//! * refuses to carry on after a `FAILED_*` response, and after a pause or a
//!   stop, because ISO 15118 says the session is over;
//! * bounds the whole of communication setup, from the connection opening to
//!   `SessionSetupRes`, at `V2G_EVCC_CommunicationSetup_Timeout`.
//!
//! Note the asymmetry in the API too: [`Evcc::handle_input`] takes no
//! timestamp, because nothing a *response* triggers starts a deadline — the
//! vehicle's timers all start when it sends.
//!
//! What it does not do is decide anything: which services to select, what
//! current to ask for, when to stop. That is the vehicle's business.

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::fmt;

use crate::app_protocol::SupportedAppProtocolReq;
use crate::message::Message;
use crate::session::{
    Connection, ConnectionError, Flow, FlowError, Instant, Millis, SequenceError, SessionId, Timer,
    Timers,
};
use crate::trace::{trace_close, trace_event};
use crate::{MAX_EXI_PAYLOAD_LEN, Protocol};

/// What a vehicle needs to know before it opens a session.
#[derive(Debug, Clone)]
pub struct EvccConfig {
    /// Protocol generations this vehicle speaks, **most preferred first**.
    ///
    /// The order is the vehicle's priority, and the charger is required to
    /// honour it, so it is a real choice and not a formality. Offering a
    /// generation this build has no message set for — `Din70121`, or `Iso20`
    /// without the `iso20` feature — ends the session if the charger picks it.
    pub protocols: &'static [Protocol],
    /// Ceiling on one V2GTP payload.
    pub max_payload_len: usize,
    /// From the connection opening to `SessionSetupRes`.
    pub setup_timeout: Millis,
    /// Overrides the per-message response timeout. `None` uses the value the
    /// negotiated generation's sequencer gives for each message.
    pub message_timeout: Option<Millis>,
    /// The paused session to rejoin, if this is not a new one.
    ///
    /// `None` opens a fresh session, which travels as the all-zero id. `Some`
    /// names a session the vehicle paused earlier and expects the station to
    /// still hold; the station answers `OK_OldSessionJoined` if it does, and
    /// assigns a new id if it does not — either way [`Evcc::session_id`] is the
    /// truth afterwards.
    ///
    /// It lives here rather than in the `SessionSetupReq` the application
    /// builds because it is the *only* message whose session id is the
    /// vehicle's to choose. Leaving it to the application meant one message out
    /// of thirty needed a field the other twenty-nine must not have — and
    /// needed it differently per generation, since ISO 15118-2 tolerates a
    /// short or absent id and ISO 15118-20 requires exactly eight bytes.
    ///
    /// This names *which* session; [`Evcc::resume`] picks the flow back up once
    /// the station has agreed to it, which is a separate step and an
    /// ISO 15118-20 one.
    pub rejoin: Option<SessionId>,
}

impl Default for EvccConfig {
    fn default() -> Self {
        Self {
            protocols: &[Protocol::Iso20, Protocol::Iso2],
            max_payload_len: MAX_EXI_PAYLOAD_LEN,
            setup_timeout: crate::session::timers::iso2::EVCC_COMMUNICATION_SETUP_TIMEOUT,
            message_timeout: None,
            rejoin: None,
        }
    }
}

/// Something the application has to know about.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Event {
    /// The handshake settled. From here on, requests may be sent.
    ProtocolAgreed(Protocol),
    /// The charger answered the outstanding request.
    Response(Box<Message>),
    /// The response that just arrived carried a `FAILED_*` code.
    ///
    /// Follows the [`Event::Response`] it refers to. The session is over bar
    /// the formalities: send `SessionStopReq` — the ordering rules will refuse
    /// anything else — and the charger's answer closes it.
    Failed,
    /// The session is over.
    Closed(Close),
}

/// Why a session ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Close {
    /// `SessionStopRes` arrived.
    Normal,
    /// The session was paused rather than terminated, and may be resumed under
    /// the same session id — [`Evcc::session_id`].
    Paused,
    /// A timer expired.
    Timeout(Timer),
    /// The charger offered nothing in common.
    NoCommonProtocol,
}

impl fmt::Display for Close {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Normal => f.write_str("stopped normally"),
            Self::Paused => f.write_str("paused"),
            Self::Timeout(t) => write!(f, "{} timer expired", t.name()),
            Self::NoCommonProtocol => f.write_str("no protocol in common"),
        }
    }
}

/// The vehicle's half of a V2G session.
#[derive(Debug)]
pub struct Evcc {
    config: EvccConfig,
    conn: Connection,
    timers: Timers,
    flow: Option<Flow>,
    events: VecDeque<Event>,
    session_id: SessionId,
    /// The request that is waiting for an answer, by element name.
    outstanding: Option<&'static str>,
    /// True once `SessionSetupRes` has assigned the session id, after which
    /// every message must carry that same id.
    ///
    /// Not `!session_id.is_none()`: a station that answered with an all-zero
    /// id would leave that test false for ever, and every later message would
    /// be adopted rather than checked.
    established: bool,
    /// The flow phase the last request left the session in, so that entering a
    /// new one can start (or stop) that phase's loop budget.
    phase: Option<&'static str>,
    closed: bool,
}

impl Evcc {
    /// A vehicle that has not yet opened a session.
    #[must_use]
    pub fn new(config: EvccConfig) -> Self {
        let conn = Connection::with_limit(config.max_payload_len);
        let session_id = config.rejoin.unwrap_or(SessionId::NONE);
        Self {
            config,
            conn,
            timers: Timers::new(),
            flow: None,
            events: VecDeque::new(),
            session_id,
            outstanding: None,
            established: false,
            phase: None,
            closed: false,
        }
    }

    /// Opens the session: queues `supportedAppProtocolReq` and starts the
    /// communication-setup timer.
    pub fn start(&mut self, now: Instant) -> Result<(), EvccError> {
        let req = SupportedAppProtocolReq::advertising(self.config.protocols);
        self.conn.send(&Message::AppProtocolReq(Box::new(req)))?;
        self.timers.arm(Timer::CommunicationSetup, now, self.config.setup_timeout);
        self.timers.arm(
            Timer::Message,
            now,
            self.config
                .message_timeout
                .unwrap_or(crate::session::timers::iso2::MSG_TIMEOUT_DEFAULT),
        );
        self.outstanding = Some("supportedAppProtocolReq");
        Ok(())
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

    /// The session id the charger assigned, once `SessionSetupRes` has arrived.
    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// True once the session has ended.
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        self.closed
    }

    /// Picks the flow back up after the station agreed to rejoin a paused
    /// session.
    ///
    /// Call once `SessionSetupRes` arrives with `OK_OldSessionJoined`, having
    /// named the session in [`EvccConfig::rejoin`]. An ISO 15118-20 flow then
    /// restarts at parameter discovery, because authorization and the selected
    /// service survived the pause; ISO 15118-2 keeps only the id, so `service`
    /// is ignored there.
    #[cfg(feature = "iso20-common")]
    #[cfg_attr(docsrs, doc(cfg(feature = "iso20-common")))]
    pub fn resume(&mut self, service: crate::session::iso20::Service) {
        if let Some(flow) = self.flow.as_mut() {
            flow.resume(service);
        }
    }

    /// Sends a request.
    ///
    /// Three things are checked before anything reaches the wire, and each is a
    /// rule the vehicle would otherwise break by accident:
    ///
    /// * **Nothing else is outstanding.** V2G is half-duplex — the vehicle may
    ///   not ask a second question before the first is answered — and the
    ///   ordering graph does not catch this on its own, because several
    ///   requests are legal repeatedly. A charge loop that ran a request per
    ///   tick rather than per response would pipeline without ever leaving the
    ///   graph.
    /// * **The ordering rules allow it here.** A charger would answer
    ///   `FAILED_SequenceError` and drop the session; finding out locally is
    ///   better, and it is the same graph the charger will check against.
    /// * **It encodes.** The flow is advanced and the timers armed only once
    ///   the bytes exist, so a request that never reached the wire has not
    ///   moved the session either.
    ///
    /// The session id is stamped into **every** request, so the application
    /// never writes one. Before `SessionSetupRes` that is the all-zero id, or
    /// the paused session named by [`EvccConfig::rejoin`]; afterwards it is the
    /// one the charger assigned. There is no message for which it is the
    /// application's to choose, which is why there is no message in which
    /// getting it wrong is possible.
    pub fn request(&mut self, now: Instant, mut request: Message) -> Result<(), EvccError> {
        if self.closed {
            return Err(EvccError::Closed);
        }
        if !request.is_request() {
            return Err(EvccError::NotARequest(request.name()));
        }
        if let Some(outstanding) = self.outstanding {
            return Err(EvccError::AwaitingResponse { outstanding, got: request.name() });
        }
        let Some(flow) = self.flow.as_ref() else {
            return Err(EvccError::BeforeHandshake(request.name()));
        };
        flow.permits(&request).map_err(EvccError::Flow)?;
        request.set_session_id(self.session_id);

        let timeout = self.config.message_timeout.unwrap_or_else(|| response_timeout(&request));
        let name = request.name();
        // Everything that can fail has now failed or not; from here the session
        // moves, and it moves all at once.
        self.conn.send(&request)?;
        if let Some(flow) = self.flow.as_mut() {
            // Cannot fail: `permits` asked the same graph the same question a
            // moment ago, and nothing since could have changed the answer.
            flow.accept(&request).map_err(EvccError::Flow)?;
        }
        self.enter_phase(now);
        trace_event!(message = name, timeout = %timeout, "request sent");
        self.timers.arm(Timer::Message, now, timeout);
        self.outstanding = Some(name);
        Ok(())
    }

    /// Starts, keeps or stops the loop budget of the phase the flow is now in.
    ///
    /// A phase like `CableCheck` is not one request but a loop the vehicle
    /// repeats while the answer is `..._Ongoing`, and the per-message timeout
    /// says nothing about how long that may go on. The budget therefore runs
    /// from the *first* request of the phase and is not restarted by the
    /// repeats — restarting it would make it unbounded, which is the bug it
    /// exists to prevent.
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

    /// Feeds bytes read from the transport.
    ///
    /// Every response disarms the message timer, so the caller does not have to
    /// pass a timestamp: nothing here starts a deadline, and the one that ends
    /// is the one that was already running.
    pub fn handle_input(&mut self, data: &[u8]) -> Result<(), EvccError> {
        if self.closed {
            return Ok(());
        }
        self.conn.receive(data)?;
        while let Some(message) = self.conn.next_message()? {
            self.dispatch(message)?;
            if self.closed {
                break;
            }
        }
        Ok(())
    }

    fn dispatch(&mut self, message: Message) -> Result<(), EvccError> {
        if message.is_request() {
            return Err(EvccError::NotAResponse(message.name()));
        }
        // A response answers *the* outstanding request, or it answers nothing.
        // The flow graph only constrains requests, so without this check a
        // charger could answer `AuthorizationReq` with `ChargingStatusRes` — or
        // volunteer responses nobody asked for — and every layer above would
        // take it at face value.
        let Some(expected) = self.outstanding else {
            return Err(EvccError::UnexpectedResponse { expected: None, got: message.name() });
        };
        if !message.answers(expected) {
            return Err(EvccError::UnexpectedResponse {
                expected: Some(expected),
                got: message.name(),
            });
        }
        self.timers.disarm(Timer::Message);
        self.outstanding = None;

        if let Message::AppProtocolRes(res) = &message {
            let Some(schema_id) = res.schema_id.filter(|_| res.response_code.is_ok()) else {
                self.close(Close::NoCommonProtocol);
                return Ok(());
            };
            // The charger echoes the schema id, not the namespace, so the
            // vehicle has to remember which id it gave to which protocol.
            let Some(protocol) =
                self.config.protocols.get(usize::from(schema_id).wrapping_sub(1)).copied()
            else {
                return Err(EvccError::UnknownSchemaId(schema_id));
            };
            let Some(flow) = Flow::new(protocol) else {
                // The charger chose a generation this build cannot speak. It
                // was offered, so this is a configuration mistake rather than a
                // hostile answer — but the session still cannot continue.
                self.close(Close::NoCommonProtocol);
                return Ok(());
            };
            self.conn.set_protocol(protocol);
            self.flow = Some(flow);
            trace_event!(protocol = ?protocol, "protocol agreed");
            self.events.push_back(Event::ProtocolAgreed(protocol));
            return Ok(());
        }

        // The charger assigns the session id in `SessionSetupRes`; every later
        // message must carry that same id, and the setup budget stops there.
        // A charger that changes it mid-session is either confused or is not
        // the charger the session started with. \[V2G2-390\]
        //
        // "Has one been assigned yet" is its own flag rather than
        // `session_id.is_none()`, because the two are not the same question: a
        // charger that answered `SessionSetupRes` with the all-zero id would
        // leave the second one saying "no" for ever, and every later message
        // would then be *adopted* instead of *checked* — which is the whole
        // point of the field.
        match message.session_id() {
            Some(id) if !self.established => {
                // Zero means "no session" in a request; a station answering
                // with it has assigned nothing, and there would be no id to
                // check anything against afterwards.
                if id.is_none() {
                    return Err(EvccError::NoSessionAssigned);
                }
                self.session_id = id;
                self.established = true;
                self.timers.disarm(Timer::CommunicationSetup);
            }
            Some(id) if id != self.session_id => {
                return Err(EvccError::WrongSession { expected: self.session_id, got: id });
            }
            _ => {}
        }

        // A `FAILED_*` code ends the session: the only request left is
        // `SessionStopReq`, and the flow is told so before the application can
        // try to send anything else.
        let failed = message.outcome().is_some_and(crate::message::Outcome::is_failure);
        if failed && let Some(flow) = self.flow.as_mut() {
            flow.failed();
        }

        let close = self.flow.as_ref().and_then(|flow| {
            if flow.is_paused() {
                Some(Close::Paused)
            } else if flow.is_finished() {
                Some(Close::Normal)
            } else {
                None
            }
        });
        trace_event!(message = message.name(), "response");
        self.events.push_back(Event::Response(Box::new(message)));
        if let Some(why) = close {
            self.close(why);
        } else if failed {
            // Not closed: the vehicle still owes a `SessionStopReq`, and
            // `request` will refuse anything else. The event says so now so the
            // application does not have to inspect thirty response types.
            trace_close!("failure response; only SessionStopReq is left");
            self.events.push_back(Event::Failed);
        }
        Ok(())
    }

    /// The next event, if any.
    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// The earliest instant at which [`Evcc::handle_timeout`] must be called.
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

    /// The request still waiting for an answer, by element name.
    #[must_use]
    pub const fn outstanding(&self) -> Option<&'static str> {
        self.outstanding
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
}

/// The response timeout for a request.
///
/// Each generation's sequencer owns its own table; see
/// [`iso2::Request::response_timeout`] and [`iso20::Request::response_timeout`]
/// for the values and, for -20, for what is a citation and what is a judgement.
///
/// [`iso2::Request::response_timeout`]: crate::session::iso2::Request::response_timeout
/// [`iso20::Request::response_timeout`]: crate::session::iso20::Request::response_timeout
fn response_timeout(request: &Message) -> Millis {
    #[cfg(feature = "iso2")]
    if let Some(r) = crate::session::iso2::Request::of(request) {
        return r.response_timeout();
    }
    #[cfg(feature = "iso20-common")]
    if let Some(r) = crate::session::iso20::Request::of(request) {
        return r.response_timeout();
    }
    let _ = request;
    crate::session::timers::iso2::MSG_TIMEOUT_DEFAULT
}

/// A failure that ends the session rather than being answered on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EvccError {
    /// The byte stream was not a well-formed sequence of V2G messages.
    Connection(ConnectionError),
    /// The request is not one the current phase allows.
    Flow(FlowError),
    /// A request arrived where only responses are legal.
    NotAResponse(&'static str),
    /// The application tried to send a response.
    NotARequest(&'static str),
    /// A session message was sent before the protocol handshake finished.
    BeforeHandshake(&'static str),
    /// A second request was offered while the first is still unanswered.
    ///
    /// V2G is half-duplex, so the vehicle has exactly one question outstanding
    /// at a time. Sending anyway would be outside the protocol even where the
    /// ordering graph allows the request — a charge loop, an authorization
    /// retry — because the graph constrains *which* request, not *when*.
    AwaitingResponse {
        /// The request that is still waiting for an answer.
        outstanding: &'static str,
        /// The request that was offered anyway.
        got: &'static str,
    },
    /// The charger accepted a schema id the vehicle never offered.
    UnknownSchemaId(u8),
    /// The charger answered something other than the outstanding request, or
    /// answered when nothing was outstanding.
    UnexpectedResponse {
        /// The request that is waiting for an answer, if any.
        expected: Option<&'static str>,
        /// The response that arrived.
        got: &'static str,
    },
    /// `SessionSetupRes` carried the all-zero session id, which names no
    /// session.
    ///
    /// The id is what every later message is checked against and what a paused
    /// session is resumed under, so a station that assigns nothing has left the
    /// session with no identity at all.
    NoSessionAssigned,
    /// A response carried a session id other than the one the charger assigned.
    WrongSession {
        /// The id `SessionSetupRes` assigned.
        expected: SessionId,
        /// The id that arrived.
        got: SessionId,
    },
    /// The session has already ended.
    Closed,
}

impl From<ConnectionError> for EvccError {
    fn from(e: ConnectionError) -> Self {
        Self::Connection(e)
    }
}

impl From<SequenceError> for EvccError {
    fn from(e: SequenceError) -> Self {
        Self::Flow(FlowError::Sequence(e))
    }
}

impl fmt::Display for EvccError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connection(e) => write!(f, "{e}"),
            Self::Flow(e) => write!(f, "{e}"),
            Self::NotAResponse(name) => {
                write!(f, "{name} is a request; the EVCC expects responses")
            }
            Self::NotARequest(name) => write!(f, "{name} is a response, not a request"),
            Self::BeforeHandshake(name) => {
                write!(f, "{name} cannot be sent before supportedAppProtocol")
            }
            Self::AwaitingResponse { outstanding, got } => {
                write!(f, "{got} cannot be sent while {outstanding} is still unanswered")
            }
            Self::UnknownSchemaId(id) => {
                write!(f, "the charger chose schema id {id}, which was never offered")
            }
            Self::UnexpectedResponse { expected: Some(req), got } => {
                write!(f, "{got} arrived while {req} was outstanding")
            }
            Self::UnexpectedResponse { expected: None, got } => {
                write!(f, "{got} arrived with no request outstanding")
            }
            Self::NoSessionAssigned => {
                f.write_str("the charger assigned the all-zero session id, which names no session")
            }
            Self::WrongSession { expected, got } => {
                write!(f, "a response carried session id {got}, not the assigned {expected}")
            }
            Self::Closed => f.write_str("the session has ended"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for EvccError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Connection(e) => Some(e),
            Self::Flow(e) => Some(e),
            _ => None,
        }
    }
}
