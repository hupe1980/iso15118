//! SECC Discovery Protocol (ISO 15118-2 §7.9, ISO 15118-20 §9.4).
//!
//! Once the data link is up, the vehicle still has to find the charger's TCP
//! endpoint. It multicasts a two-byte SDP request to `ff02::1` port 15118
//! saying which security and transport it wants; the charger answers with the
//! address and port to connect to.
//!
//! Both datagrams are fixed-layout payloads inside a [`crate::v2gtp`] frame, so
//! this module is pure byte shuffling — no EXI involved.
//!
//! The negotiation is a *request*, not a command: a charger that requires TLS
//! answers a `NoTransportSecurity` request with a TLS response, and it is the
//! vehicle's job to notice. [`Response::satisfies`] makes that check explicit
//! rather than leaving it to be forgotten.

use core::fmt;

use crate::v2gtp::{self, PayloadType, V2gtpError};

/// Length of an SDP request payload.
pub const REQUEST_LEN: usize = 2;

/// Length of an SDP response payload.
pub const RESPONSE_LEN: usize = 20;

/// The link-local multicast address SDP requests go to.
pub const MULTICAST_ADDR: [u8; 16] = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];

pub use crate::session::Security;

/// The SDP wire encoding of [`Security`].
///
/// The *type* is [`crate::session::Security`] rather than one of this module's
/// own, so the answer a vehicle accepts here is the same value it hands the
/// session — where it decides whether Plug & Charge is available at all
/// \[V2G2-634\]. Two enumerations meaning "TLS or not" could disagree; one
/// cannot.
impl Security {
    /// The on-the-wire byte.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Tls => 0x00,
            Self::None => 0x10,
        }
    }

    /// Parses the security byte.
    pub const fn from_u8(value: u8) -> Result<Self, SdpError> {
        match value {
            0x00 => Ok(Self::Tls),
            0x10 => Ok(Self::None),
            other => Err(SdpError::UnknownSecurity(other)),
        }
    }
}

/// Transport protocol the session will use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum TransportProtocol {
    /// TCP — the only value in use.
    Tcp,
    /// UDP. Reserved by the spec; no profile selects it.
    Udp,
}

impl TransportProtocol {
    /// The on-the-wire byte.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Tcp => 0x00,
            Self::Udp => 0x10,
        }
    }

    /// Parses the transport-protocol byte.
    pub const fn from_u8(value: u8) -> Result<Self, SdpError> {
        match value {
            0x00 => Ok(Self::Tcp),
            0x10 => Ok(Self::Udp),
            other => Err(SdpError::UnknownTransport(other)),
        }
    }
}

/// What a station will do about transport security.
///
/// The station's half of the negotiation is not a preference — ISO 15118-2
/// determines the answer from this and the request, in three requirements — so
/// this is the only input [`Response::answering`] needs beyond the endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum TlsPolicy {
    /// This station cannot do TLS.
    ///
    /// A TLS request is answered "No transport layer security" \[V2G2-627\].
    /// That is a *conforming* answer and not a downgrade attack, though it
    /// looks identical to one from the vehicle's side — which is why the
    /// vehicle decides what to do about it \[V2G2-628\] and this crate's
    /// [`Discovery`] refuses it by default.
    Unsupported,
    /// This station can do TLS, and offers it when asked \[V2G2-626\].
    ///
    /// A plaintext request is answered plaintext: the vehicle asked for what it
    /// wanted, and ISO 15118-2 permits an EIM session without TLS.
    Supported,
    /// This station requires TLS, so even a plaintext request is answered with
    /// TLS.
    ///
    /// Not a case the -2 text spells out, and not an invention either: -20
    /// mandates TLS outright, and -2 requires it for Plug & Charge. A station in
    /// either position has nothing to offer a plaintext request *but* an
    /// upgrade, and upgrading is the one direction
    /// [`Response::satisfies`] accepts — so the vehicle can act on the answer
    /// rather than being cut off without one.
    Required,
}

/// An SDP request: what the vehicle would like to speak.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Request {
    /// Requested transport security.
    pub security: Security,
    /// Requested transport protocol.
    pub transport: TransportProtocol,
}

impl Request {
    /// A request for a TLS-protected TCP session.
    pub const TLS: Self = Self { security: Security::Tls, transport: TransportProtocol::Tcp };

    /// A request for a plain TCP session.
    pub const PLAIN: Self = Self { security: Security::None, transport: TransportProtocol::Tcp };

    /// Serialises the two payload bytes.
    #[must_use]
    pub const fn to_payload(self) -> [u8; REQUEST_LEN] {
        [self.security.as_u8(), self.transport.as_u8()]
    }

    /// Parses a request payload.
    pub const fn from_payload(payload: &[u8]) -> Result<Self, SdpError> {
        if payload.len() != REQUEST_LEN {
            return Err(SdpError::BadLength { expected: REQUEST_LEN, actual: payload.len() });
        }
        Ok(Self {
            security: match Security::from_u8(payload[0]) {
                Ok(s) => s,
                Err(e) => return Err(e),
            },
            transport: match TransportProtocol::from_u8(payload[1]) {
                Ok(t) => t,
                Err(e) => return Err(e),
            },
        })
    }

    /// Wraps the request in a V2GTP frame, returning the frame length.
    pub fn write_frame(self, out: &mut [u8], wireless: bool) -> Result<usize, SdpError> {
        let ty = if wireless { PayloadType::SdpWirelessRequest } else { PayloadType::SdpRequest };
        Ok(v2gtp::write_frame(ty, &self.to_payload(), out)?)
    }

    /// Parses a request out of a complete V2GTP frame.
    pub fn from_frame(frame: &[u8]) -> Result<Self, SdpError> {
        // Bounded by the larger of the two SDP payloads, not by a request's own
        // two bytes, so that a *response* frame fed here is reported as the
        // wrong payload type rather than as an oversized one. The length check
        // that matters happens in `from_payload` either way.
        let (header, payload, rest) = v2gtp::split_frame(frame, RESPONSE_LEN.max(REQUEST_LEN))?;
        if !header.payload_type.is_sdp_request() {
            return Err(SdpError::WrongPayloadType(header.payload_type));
        }
        if !rest.is_empty() {
            return Err(SdpError::TrailingData);
        }
        Self::from_payload(payload)
    }
}

/// An SDP response: where and how to connect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Response {
    /// SECC IPv6 address, usually link-local.
    pub address: [u8; 16],
    /// SECC TCP port.
    pub port: u16,
    /// Security the charger will actually use.
    pub security: Security,
    /// Transport the charger will actually use.
    pub transport: TransportProtocol,
}

impl Response {
    /// Serialises the twenty payload bytes.
    #[must_use]
    pub const fn to_payload(self) -> [u8; RESPONSE_LEN] {
        let mut out = [0u8; RESPONSE_LEN];
        let mut i = 0;
        while i < 16 {
            out[i] = self.address[i];
            i += 1;
        }
        let port = self.port.to_be_bytes();
        out[16] = port[0];
        out[17] = port[1];
        out[18] = self.security.as_u8();
        out[19] = self.transport.as_u8();
        out
    }

    /// Parses a response payload.
    pub fn from_payload(payload: &[u8]) -> Result<Self, SdpError> {
        let payload: &[u8; RESPONSE_LEN] = payload
            .try_into()
            .map_err(|_| SdpError::BadLength { expected: RESPONSE_LEN, actual: payload.len() })?;
        let mut address = [0u8; 16];
        address.copy_from_slice(&payload[..16]);
        let port = u16::from_be_bytes([payload[16], payload[17]]);
        if port == 0 {
            return Err(SdpError::InvalidPort);
        }
        // The same reasoning as port zero, applied to the other half of the
        // endpoint: the unspecified address names nothing and a multicast
        // group cannot be the far end of a TCP connection. Neither is a
        // station that answered wrongly — it is a station that answered with
        // something no caller could act on, and the codec is where that stops.
        if address == [0u8; 16] || address[0] == 0xff {
            return Err(SdpError::InvalidAddress(address));
        }
        Ok(Self {
            address,
            port,
            security: Security::from_u8(payload[18])?,
            transport: TransportProtocol::from_u8(payload[19])?,
        })
    }

    /// Wraps the response in a V2GTP frame, returning the frame length.
    pub fn write_frame(self, out: &mut [u8], wireless: bool) -> Result<usize, SdpError> {
        let ty = if wireless { PayloadType::SdpWirelessResponse } else { PayloadType::SdpResponse };
        Ok(v2gtp::write_frame(ty, &self.to_payload(), out)?)
    }

    /// Parses a response out of a complete V2GTP frame.
    pub fn from_frame(frame: &[u8]) -> Result<Self, SdpError> {
        let (header, payload, rest) = v2gtp::split_frame(frame, RESPONSE_LEN)?;
        if !header.payload_type.is_sdp_response() {
            return Err(SdpError::WrongPayloadType(header.payload_type));
        }
        if !rest.is_empty() {
            return Err(SdpError::TrailingData);
        }
        Self::from_payload(payload)
    }

    /// Whether this response gives the vehicle what it asked for.
    ///
    /// A charger may answer with *more* security than requested, and the
    /// vehicle must then use TLS.
    ///
    /// An answer with **less** is not, by itself, an attack: \[V2G2-627\]
    /// *obliges* a station that does not support TLS to answer a TLS request
    /// with "No transport layer security". A conforming station downgrades. So
    /// what this returns is not "somebody is attacking you" but the question
    /// \[V2G2-628\] puts to the vehicle — use what was offered, or stop — and
    /// the answer depends on the vehicle, not on the station: under Plug &
    /// Charge, or under ISO 15118-20, it must stop.
    ///
    /// Which is exactly why it is a returned `bool` rather than a silent
    /// acceptance. The failure this prevents is a vehicle that asked for TLS,
    /// was answered plaintext, and never noticed — whether the answer came from
    /// an honest station or from anything else on an unauthenticated multicast
    /// segment.
    #[must_use]
    pub const fn satisfies(&self, request: &Request) -> bool {
        if self.transport as u8 != request.transport as u8 {
            return false;
        }
        // A TLS request must be answered with TLS; a plaintext request may be
        // upgraded. Only the downgrade direction is refused.
        !matches!((request.security, self.security), (Security::Tls, Security::None))
    }

    /// The answer ISO 15118-2 obliges a station to give.
    ///
    /// The station's side of discovery is one of the few places where the
    /// standard leaves *no* discretion, and it says so in three requirements —
    /// which means a station has nothing to decide here beyond its own TLS
    /// policy, and every station that re-derives this from prose is re-deriving
    /// the same table:
    ///
    /// | Request | [`TlsPolicy::Unsupported`] | [`TlsPolicy::Supported`] | [`TlsPolicy::Required`] |
    /// |---|---|---|---|
    /// | TLS | plaintext \[V2G2-627\] | TLS \[V2G2-626\] | TLS |
    /// | plaintext | plaintext | plaintext | TLS |
    ///
    /// The transport is echoed \[V2G2-625\]: a TCP request is answered TCP.
    /// Table 16 defines UDP and no profile selects it, so echoing is the
    /// generalisation rather than a second rule — and a station that cannot
    /// serve the transport asked for should not answer at all.
    ///
    /// `address` and `port` are where the vehicle will open its TCP connection,
    /// so they are this station's own — link-local on a CCS link, which is what
    /// [`Response::is_link_local`] checks and what a vehicle refuses without.
    ///
    /// ```
    /// use iso15118::sdp::{Request, Response, Security, TlsPolicy};
    ///
    /// let station = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    ///
    /// // A station with no TLS is *obliged* to answer a TLS request in plain
    /// // [V2G2-627] — and the vehicle is then obliged to notice.
    /// let answer = Response::answering(Request::TLS, station, 15118, TlsPolicy::Unsupported);
    /// assert_eq!(answer.security, Security::None);
    /// assert!(!answer.satisfies(&Request::TLS), "the vehicle has a decision to make");
    ///
    /// // A station that requires it upgrades a plaintext request instead.
    /// let answer = Response::answering(Request::PLAIN, station, 15118, TlsPolicy::Required);
    /// assert_eq!(answer.security, Security::Tls);
    /// assert!(answer.satisfies(&Request::PLAIN), "an upgrade is one the vehicle may act on");
    /// ```
    #[must_use]
    #[allow(
        clippy::match_same_arms,
        reason = "one arm per requirement; \\[V2G2-627\\]'s obligatory downgrade \
                  and an ordinary plaintext answer produce the same byte for \
                  entirely different reasons, and merging them would lose the \
                  citation that says so"
    )]
    pub const fn answering(request: Request, address: [u8; 16], port: u16, tls: TlsPolicy) -> Self {
        let security = match (request.security, tls) {
            // \[V2G2-626\] and the -20 / Plug & Charge case.
            (Security::Tls, TlsPolicy::Supported | TlsPolicy::Required)
            | (Security::None, TlsPolicy::Required) => Security::Tls,
            // \[V2G2-627\]: asked for TLS, cannot do it, must say so.
            (Security::Tls, TlsPolicy::Unsupported) => Security::None,
            // Asked for plaintext by a station that does not insist otherwise.
            (Security::None, TlsPolicy::Unsupported | TlsPolicy::Supported) => Security::None,
        };
        // \[V2G2-625\]: the transport is the one that was asked for.
        Self { address, port, security, transport: request.transport }
    }

    /// True when the advertised address is IPv6 link-local (`fe80::/10`), which
    /// is what a charger on the CCS link is expected to advertise.
    #[must_use]
    pub const fn is_link_local(&self) -> bool {
        self.address[0] == 0xfe && (self.address[1] & 0xc0) == 0x80
    }
}

#[cfg(feature = "std")]
impl Response {
    /// The SECC address as a [`std::net::Ipv6Addr`].
    #[must_use]
    pub const fn ipv6(&self) -> std::net::Ipv6Addr {
        std::net::Ipv6Addr::new(
            u16::from_be_bytes([self.address[0], self.address[1]]),
            u16::from_be_bytes([self.address[2], self.address[3]]),
            u16::from_be_bytes([self.address[4], self.address[5]]),
            u16::from_be_bytes([self.address[6], self.address[7]]),
            u16::from_be_bytes([self.address[8], self.address[9]]),
            u16::from_be_bytes([self.address[10], self.address[11]]),
            u16::from_be_bytes([self.address[12], self.address[13]]),
            u16::from_be_bytes([self.address[14], self.address[15]]),
        )
    }

    /// Builds a response from a standard IPv6 socket address.
    #[must_use]
    pub const fn from_ipv6(
        addr: std::net::Ipv6Addr,
        port: u16,
        security: Security,
        transport: TransportProtocol,
    ) -> Self {
        Self { address: addr.octets(), port, security, transport }
    }
}

/// The vehicle's side of discovery, as a sans-I/O state machine.
///
/// The codec above is the easy half. The part that is actually specified, and
/// that every implementation has to get right the same way, is the retry
/// policy: a `SECCDiscoveryReq` is a UDP multicast to `ff02::1`, it is not
/// acknowledged, and ISO 15118-2 §7.9 bounds both how often it may be repeated
/// \[V2G2-159\] and how many times \[V2G2-161\] before the vehicle gives
/// up. Those two numbers are the difference between a vehicle that finds a
/// charger through one dropped packet and a vehicle that floods the link.
///
/// Same shape as every other engine here — bytes in, bytes, events and
/// deadlines out — so the caller owns the socket and the clock.
///
/// ```
/// use iso15118::sdp::{Discovery, Event, Request, Response, Security, TransportProtocol};
/// use iso15118::session::{Instant, Millis};
///
/// let mut d = Discovery::new(Request::TLS);
/// let mut now = Instant::ZERO;
/// d.start(now);
///
/// // One request goes out immediately; nothing answers, so it is repeated.
/// assert!(d.poll_transmit().is_some());
/// now = d.poll_timeout().unwrap();
/// d.handle_timeout(now);
/// assert!(d.poll_transmit().is_some());
/// assert_eq!(d.attempts(), 2);
///
/// // The charger answers with more security than was asked for, which is
/// // allowed; less would not be.
/// let res = Response {
///     address: [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
///     port: 15118,
///     security: Security::Tls,
///     transport: TransportProtocol::Tcp,
/// };
/// let mut frame = [0u8; 32];
/// let n = res.write_frame(&mut frame, false)?;
/// d.handle_datagram(now, &frame[..n])?;
/// assert_eq!(d.poll_event(), Some(Event::Found(res)));
/// # Ok::<_, iso15118::sdp::SdpError>(())
/// ```
#[derive(Debug, Clone)]
pub struct Discovery {
    request: Request,
    wireless: bool,
    allow_off_link: bool,
    interval: crate::session::Millis,
    max_attempts: u32,
    attempts: u32,
    deadline: Option<crate::session::Instant>,
    pending: Option<[u8; v2gtp::HEADER_LEN + REQUEST_LEN]>,
    /// The run's one outcome: [`Event::Found`] or [`Event::GaveUp`].
    outcome: Option<Event>,
    /// The most recent thing worth reporting that is *not* the outcome — a
    /// refusal or a conflict.
    ///
    /// Its own slot rather than sharing the outcome's, because the two answer
    /// different questions and the interesting runs produce both: an answer
    /// that had to be refused, and then a usable one. One slot meant the
    /// outcome overwrote the refusal, which is exactly the signal a caller
    /// wants when deciding whether the segment has something else on it.
    /// Bounded at one, so a flood cannot grow anything or push the outcome out.
    notice: Option<Event>,
    /// What [`Event::Found`] reported, kept so a later answer can be compared
    /// against it.
    accepted: Option<Response>,
    done: bool,
}

/// What discovery produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Event {
    /// A charger answered, and its answer gives the vehicle at least what it
    /// asked for. Connect to [`Response::ipv6`] and [`Response::port`].
    ///
    /// Terminal: discovery is finished.
    Found(Response),
    /// A well-formed answer arrived that the vehicle must not act on.
    ///
    /// Surfaced as its own event rather than as a `Found` the caller might not
    /// inspect. **Not terminal** — see [`Discovery::handle_datagram`].
    Refused {
        /// The answer, so a log line can say who sent what.
        response: Response,
        /// What was wrong with it.
        reason: Refusal,
    },
    /// No usable answer arrived within the permitted number of attempts.
    ///
    /// Terminal.
    GaveUp {
        /// How many requests went out.
        attempts: u32,
    },
    /// A *second*, different, perfectly usable answer arrived.
    ///
    /// One V2G link has one SECC on it, answering from one address
    /// \[V2G2-144\]. Two different endpoints is somebody else on the segment
    /// answering as well.
    ///
    /// This is the half of SDP spoofing [`Refused`](Event::Refused) cannot
    /// cover. A downgrade or an off-link redirect is refused because the vehicle
    /// can *tell*; an answer that is well-formed, link-local and offers the
    /// requested security is indistinguishable from the real station's, so
    /// whichever arrives first wins and an attacker need only be quicker
    /// (arXiv 2512.15966 §3.2).
    ///
    /// The engine therefore keeps listening after it has an answer, and reports
    /// a second that disagrees. It does not decide: `accepted` has already been
    /// reported as [`Event::Found`] and may have a TCP connection on it, and the
    /// crate cannot tell a spoofer from a misconfigured second station.
    ///
    /// Not terminal, and does not displace the outcome — both are delivered.
    Conflict {
        /// The answer that was accepted, and reported as [`Event::Found`].
        accepted: Response,
        /// The one that arrived afterwards and named somewhere else.
        other: Response,
    },
}

/// Why a well-formed SDP answer is one the vehicle must not act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum Refusal {
    /// The answer offered *less* security than the request asked for.
    ///
    /// ISO 15118-20 mandates TLS outright; under -2 a vehicle doing Plug &
    /// Charge must refuse this, and one doing EIM may choose not to — by
    /// starting a new run with [`Request::PLAIN`], not by using this answer.
    SecurityDowngrade,
    /// The answer named a different transport protocol than the request.
    TransportMismatch,
    /// The answer pointed off the V2G link.
    ///
    /// ISO 15118 runs over an IPv6 link-local segment brought up by SLAAC on
    /// the charging cable, with no router on it, so a station's own address is
    /// link-local (`fe80::/10`). An answer naming anything else is naming
    /// somewhere this vehicle has no protocol reason to connect to — and SDP
    /// is an unauthenticated multicast, so *anything on the segment* can send
    /// one.
    ///
    /// A test rig on an ordinary LAN is the legitimate exception:
    /// [`Discovery::allow_off_link`] turns this refusal off, deliberately and
    /// visibly.
    OffLink,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SecurityDowngrade => f.write_str("less transport security than requested"),
            Self::TransportMismatch => f.write_str("a different transport protocol"),
            Self::OffLink => f.write_str("an address that is not link-local"),
        }
    }
}

impl Discovery {
    /// A discovery run that will ask for `request`.
    #[must_use]
    pub const fn new(request: Request) -> Self {
        Self {
            request,
            wireless: false,
            allow_off_link: false,
            interval: crate::session::timers::sdp::RESPONSE_TIMEOUT,
            max_attempts: crate::session::timers::sdp::MAX_REQUESTS,
            attempts: 0,
            deadline: None,
            pending: None,
            outcome: None,
            notice: None,
            accepted: None,
            done: false,
        }
    }

    /// Uses the wireless payload types (`0x9002`/`0x9003`) — ISO 15118-20 over
    /// WLAN rather than over the powerline.
    #[must_use]
    pub const fn wireless(mut self, wireless: bool) -> Self {
        self.wireless = wireless;
        self
    }

    /// Accepts an answer whose address is not link-local.
    ///
    /// Off by default, and the default is the one to keep on a vehicle: the
    /// V2G link is an IPv6 link-local segment with no router, so a station's
    /// own address is link-local, and SDP is an unauthenticated multicast that
    /// anything on the segment can answer. An off-link address in an answer is
    /// therefore either a misconfigured station or somebody redirecting the
    /// session somewhere the cable does not go.
    ///
    /// Turn it on for a test rig on an ordinary LAN, where the address really
    /// is global or unique-local and there is no powerline segment for anyone
    /// to sit on.
    #[must_use]
    pub const fn allow_off_link(mut self, allow: bool) -> Self {
        self.allow_off_link = allow;
        self
    }

    /// Overrides the retry interval. The default is `V2G2-159`\'s 250 ms,
    /// which is a *minimum*: sending faster is out of spec.
    #[must_use]
    pub const fn with_interval(mut self, interval: crate::session::Millis) -> Self {
        self.interval = interval;
        self
    }

    /// Overrides the attempt ceiling. The default is `V2G2-161`\'s 50.
    #[must_use]
    pub const fn with_max_attempts(mut self, max_attempts: u32) -> Self {
        self.max_attempts = max_attempts;
        self
    }

    /// Sends the first request.
    pub fn start(&mut self, now: crate::session::Instant) {
        self.attempts = 0;
        self.done = false;
        self.outcome = None;
        self.notice = None;
        self.accepted = None;
        self.send(now);
    }

    /// Number of requests sent so far.
    #[must_use]
    pub const fn attempts(&self) -> u32 {
        self.attempts
    }

    /// True once discovery has finished, either way.
    #[must_use]
    pub const fn is_finished(&self) -> bool {
        self.done
    }

    /// The datagram to multicast to [`MULTICAST_ADDR`] port
    /// [`v2gtp::SDP_PORT`], if one is due.
    #[must_use]
    pub fn poll_transmit(&mut self) -> Option<alloc::vec::Vec<u8>> {
        self.pending.take().map(|frame| frame.to_vec())
    }

    /// When [`Discovery::handle_timeout`] must next be called.
    #[must_use]
    pub const fn poll_timeout(&self) -> Option<crate::session::Instant> {
        self.deadline
    }

    /// Repeats the request, or gives up once the attempt ceiling is reached.
    pub fn handle_timeout(&mut self, now: crate::session::Instant) {
        if self.done || self.deadline.is_none_or(|d| d > now) {
            return;
        }
        self.deadline = None;
        if self.attempts >= self.max_attempts {
            self.done = true;
            self.outcome = Some(Event::GaveUp { attempts: self.attempts });
            return;
        }
        self.send(now);
    }

    /// Feeds a datagram received on the discovery port.
    ///
    /// **Only a usable answer ends discovery, and even that does not stop the
    /// listening.** The request went to a multicast group on a shared segment,
    /// so anything can answer and nothing authenticates who did. Three cases,
    /// and none of them lets one datagram decide the run:
    ///
    /// * **Malformed** — an `Err` from here. The run is untouched: same
    ///   deadline, same attempt count, as if it had never arrived.
    /// * **Well-formed but unusable** — [`Event::Refused`]. Reported, and the
    ///   run carries on armed and retrying. Otherwise one spoofed downgrade
    ///   would stop the vehicle ever hearing the station it is plugged into.
    /// * **Usable** — [`Event::Found`], and the run is finished. But keep
    ///   feeding datagrams until the connection is up: a *second* usable answer
    ///   naming somewhere else is [`Event::Conflict`], and it is the only
    ///   evidence a vehicle gets that something on the segment answered as well.
    ///
    /// The third case is the one worth understanding. A refusal is a *judgement*
    /// the vehicle can make about a single datagram; a race is not. Two
    /// well-formed, link-local, correctly-secured answers are indistinguishable
    /// one at a time, and the attacker's whole job is to be first. Comparing
    /// them to each other is the only check there is.
    ///
    /// Poll for events *inside* the receive loop rather than only after it. The
    /// engine holds the outcome in one slot and the latest notice in another,
    /// so a flood grows nothing and cannot push either out.
    pub fn handle_datagram(
        &mut self,
        _now: crate::session::Instant,
        frame: &[u8],
    ) -> Result<(), SdpError> {
        let response = Response::from_frame(frame)?;
        // Already answered: the only thing left worth saying about a datagram
        // is that it disagrees with the answer taken.
        if let Some(accepted) = self.accepted {
            if response != accepted && self.refusal(&response).is_none() {
                self.notice = Some(Event::Conflict { accepted, other: response });
            }
            return Ok(());
        }
        // Finished without one — the attempt ceiling ran out. A datagram after
        // that does not un-give-up: `GaveUp` may already have been polled and
        // acted on, and a run that quietly acquires an answer after reporting it
        // had none is worse than a slow charger.
        if self.done {
            return Ok(());
        }
        if let Some(reason) = self.refusal(&response) {
            // Report it and keep listening. The deadline and the attempt
            // counter are untouched: as far as the run is concerned, this
            // datagram did not happen.
            self.notice = Some(Event::Refused { response, reason });
            return Ok(());
        }
        self.done = true;
        self.deadline = None;
        self.pending = None;
        self.accepted = Some(response);
        self.outcome = Some(Event::Found(response));
        Ok(())
    }

    /// Why `response` is not one to act on, if it is not.
    fn refusal(&self, response: &Response) -> Option<Refusal> {
        if response.transport as u8 != self.request.transport as u8 {
            return Some(Refusal::TransportMismatch);
        }
        // A charger may answer with *more* security than requested and the
        // vehicle must then use TLS. Less is a conforming answer from a station
        // without TLS \[V2G2-627\]; whether to accept it is the vehicle's
        // decision \[V2G2-628\], and this engine's default is not to.
        if matches!((self.request.security, response.security), (Security::Tls, Security::None)) {
            return Some(Refusal::SecurityDowngrade);
        }
        if !self.allow_off_link && !response.is_link_local() {
            return Some(Refusal::OffLink);
        }
        None
    }

    /// The next event, if any.
    ///
    /// A refusal or a conflict comes out before the outcome, because the
    /// outcome is the one that will still be true next time round and the
    /// notice is not.
    pub const fn poll_event(&mut self) -> Option<Event> {
        match self.notice.take() {
            Some(notice) => Some(notice),
            None => self.outcome.take(),
        }
    }

    fn send(&mut self, now: crate::session::Instant) {
        let mut frame = [0u8; v2gtp::HEADER_LEN + REQUEST_LEN];
        // Infallible: the buffer is exactly the frame's size.
        if self.request.write_frame(&mut frame, self.wireless).is_ok() {
            self.pending = Some(frame);
        }
        self.attempts += 1;
        self.deadline = Some(now.saturating_add(self.interval));
    }
}

/// Errors from SDP encoding and decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SdpError {
    /// The payload was not the length its type requires.
    BadLength {
        /// Length the type requires.
        expected: usize,
        /// Length received.
        actual: usize,
    },
    /// The security byte was neither `0x00` nor `0x10`.
    UnknownSecurity(u8),
    /// The transport byte was neither `0x00` nor `0x10`.
    UnknownTransport(u8),
    /// Port zero cannot be connected to.
    InvalidPort,
    /// The address names no connectable endpoint: the unspecified address
    /// (`::`) or a multicast group (`ff00::/8`).
    InvalidAddress([u8; 16]),
    /// The V2GTP frame did not hold the SDP message we were parsing.
    WrongPayloadType(PayloadType),
    /// Bytes remained after the datagram.
    TrailingData,
    /// The enclosing V2GTP frame was malformed.
    Framing(V2gtpError),
}

impl From<V2gtpError> for SdpError {
    fn from(e: V2gtpError) -> Self {
        Self::Framing(e)
    }
}

impl fmt::Display for SdpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadLength { expected, actual } => {
                write!(f, "SDP payload is {actual} bytes, expected {expected}")
            }
            Self::UnknownSecurity(v) => write!(f, "unknown SDP security value {v:#04x}"),
            Self::UnknownTransport(v) => write!(f, "unknown SDP transport value {v:#04x}"),
            Self::InvalidPort => f.write_str("SDP response advertises port 0"),
            Self::InvalidAddress(a) if *a == [0u8; 16] => {
                f.write_str("SDP response advertises the unspecified address")
            }
            Self::InvalidAddress(_) => f.write_str("SDP response advertises a multicast address"),
            Self::WrongPayloadType(t) => write!(f, "unexpected payload type {t:?} for SDP message"),
            Self::TrailingData => f.write_str("trailing data after SDP datagram"),
            Self::Framing(e) => write!(f, "V2GTP framing: {e}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SdpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Framing(e) => Some(e),
            _ => None,
        }
    }
}

#[cfg(test)]
mod answering_tests {
    use super::{Request, Response, Security, TlsPolicy, TransportProtocol};

    const STATION: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

    /// The whole of \[V2G2-625\]..\[V2G2-627\] as one table, because it is one
    /// table — and because a station that gets it wrong is a station a vehicle
    /// either cannot reach or reaches unencrypted.
    #[test]
    fn the_answer_is_determined_by_the_request_and_the_policy() {
        use Security::{None as Plain, Tls};
        use TlsPolicy::{Required, Supported, Unsupported};

        for (asked, policy, expected) in [
            // \[V2G2-627\]: no TLS available, so say so rather than not answer.
            (Tls, Unsupported, Plain),
            // \[V2G2-626\]: asked for and available.
            (Tls, Supported, Tls),
            (Tls, Required, Tls),
            // A plaintext request stands unless the station insists.
            (Plain, Unsupported, Plain),
            (Plain, Supported, Plain),
            // -20, and -2 under Plug & Charge: nothing else is on offer.
            (Plain, Required, Tls),
        ] {
            let request = Request { security: asked, transport: TransportProtocol::Tcp };
            let answer = Response::answering(request, STATION, 15118, policy);
            assert_eq!(answer.security, expected, "{asked:?} + {policy:?}");
            assert_eq!(answer.transport, TransportProtocol::Tcp, "\\[V2G2-625\\]");
            assert_eq!(answer.address, STATION);
            assert_eq!(answer.port, 15118);
        }
    }

    /// The two halves have to agree about which answers a vehicle may act on,
    /// or a conforming station and this crate's own vehicle cannot charge.
    #[test]
    fn what_a_station_answers_is_what_a_vehicle_accepts_except_the_one_case() {
        for policy in [TlsPolicy::Supported, TlsPolicy::Required] {
            for request in [Request::TLS, Request::PLAIN] {
                let answer = Response::answering(request, STATION, 15118, policy);
                assert!(answer.satisfies(&request), "{request:?} + {policy:?}");
            }
        }
        // The exception, and it is the standard's rather than this crate's: a
        // station with no TLS answers a TLS request in plain \[V2G2-627\], and
        // the vehicle then decides \[V2G2-628\].
        let answer = Response::answering(Request::TLS, STATION, 15118, TlsPolicy::Unsupported);
        assert!(!answer.satisfies(&Request::TLS));
        // ...and a plaintext request to that same station is fine.
        let answer = Response::answering(Request::PLAIN, STATION, 15118, TlsPolicy::Unsupported);
        assert!(answer.satisfies(&Request::PLAIN));
    }

    /// A station answers on the link it is on, and a vehicle refuses anything
    /// else by default — so the constructor has to make the common case right.
    #[test]
    fn a_station_answering_with_its_link_local_address_is_accepted() {
        let answer = Response::answering(Request::TLS, STATION, 15118, TlsPolicy::Supported);
        assert!(answer.is_link_local());
    }

    /// The answer round-trips the wire, which is the only thing that makes it
    /// an answer.
    #[test]
    fn the_answer_survives_a_v2gtp_frame() {
        let answer = Response::answering(Request::TLS, STATION, 15118, TlsPolicy::Supported);
        let mut frame = [0u8; 64];
        let n = answer.write_frame(&mut frame, false).unwrap();
        assert_eq!(Response::from_frame(&frame[..n]).unwrap(), answer);
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;

    const LINK_LOCAL: [u8; 16] =
        [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x1a, 0x2b, 0xff, 0xfe, 0x3c, 0x4d, 0x5e];

    #[test]
    fn request_frame_matches_the_spec_layout() {
        let mut buf = [0u8; 16];
        let n = Request::TLS.write_frame(&mut buf, false).unwrap();
        assert_eq!(n, 10);
        assert_eq!(&buf[..n], &[0x01, 0xFE, 0x90, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00]);
    }

    #[test]
    fn plain_request_frame() {
        let mut buf = [0u8; 16];
        let n = Request::PLAIN.write_frame(&mut buf, false).unwrap();
        assert_eq!(&buf[8..n], &[0x10, 0x00]);
    }

    #[test]
    fn request_roundtrips_through_a_frame() {
        for req in [Request::TLS, Request::PLAIN] {
            let mut buf = [0u8; 16];
            let n = req.write_frame(&mut buf, false).unwrap();
            assert_eq!(Request::from_frame(&buf[..n]).unwrap(), req);
        }
    }

    #[test]
    fn wireless_request_uses_its_own_payload_type() {
        let mut buf = [0u8; 16];
        let n = Request::TLS.write_frame(&mut buf, true).unwrap();
        assert_eq!(&buf[2..4], &[0x90, 0x02]);
        assert_eq!(Request::from_frame(&buf[..n]).unwrap(), Request::TLS);
    }

    #[test]
    fn response_roundtrips_through_a_frame() {
        let res = Response {
            address: LINK_LOCAL,
            port: 49152,
            security: Security::Tls,
            transport: TransportProtocol::Tcp,
        };
        let mut buf = [0u8; 64];
        let n = res.write_frame(&mut buf, false).unwrap();
        assert_eq!(n, 28);
        assert_eq!(Response::from_frame(&buf[..n]).unwrap(), res);
        assert!(res.is_link_local());
    }

    #[test]
    fn a_response_may_not_downgrade_a_tls_request() {
        let res = Response {
            address: LINK_LOCAL,
            port: 15118,
            security: Security::None,
            transport: TransportProtocol::Tcp,
        };
        assert!(!res.satisfies(&Request::TLS), "TLS request answered without TLS must be refused");
        assert!(res.satisfies(&Request::PLAIN));
    }

    #[test]
    fn a_response_may_upgrade_a_plaintext_request() {
        let res = Response {
            address: LINK_LOCAL,
            port: 15118,
            security: Security::Tls,
            transport: TransportProtocol::Tcp,
        };
        assert!(res.satisfies(&Request::PLAIN));
        assert!(res.satisfies(&Request::TLS));
    }

    #[test]
    fn a_transport_mismatch_never_satisfies() {
        let res = Response {
            address: LINK_LOCAL,
            port: 15118,
            security: Security::Tls,
            transport: TransportProtocol::Udp,
        };
        assert!(!res.satisfies(&Request::TLS));
    }

    #[test]
    fn port_zero_is_rejected() {
        let mut payload = [0u8; RESPONSE_LEN];
        payload[..16].copy_from_slice(&LINK_LOCAL);
        assert_eq!(Response::from_payload(&payload), Err(SdpError::InvalidPort));
    }

    #[test]
    fn unknown_enum_bytes_are_rejected() {
        assert_eq!(Security::from_u8(0x01), Err(SdpError::UnknownSecurity(0x01)));
        assert_eq!(TransportProtocol::from_u8(0xFF), Err(SdpError::UnknownTransport(0xFF)));
    }

    #[test]
    fn a_response_frame_is_not_a_request() {
        let mut buf = [0u8; 64];
        let n = Response {
            address: LINK_LOCAL,
            port: 15118,
            security: Security::Tls,
            transport: TransportProtocol::Tcp,
        }
        .write_frame(&mut buf, false)
        .unwrap();
        assert!(matches!(Request::from_frame(&buf[..n]), Err(SdpError::WrongPayloadType(_))));
    }

    #[test]
    fn short_payloads_are_rejected() {
        assert_eq!(
            Request::from_payload(&[0x00]),
            Err(SdpError::BadLength { expected: 2, actual: 1 })
        );
        assert_eq!(
            Response::from_payload(&[0x00; 19]),
            Err(SdpError::BadLength { expected: 20, actual: 19 })
        );
    }

    #[test]
    fn discovery_repeats_until_the_attempt_ceiling() {
        use crate::session::Instant;

        let mut d = Discovery::new(Request::TLS).with_max_attempts(3);
        let mut now = Instant::ZERO;
        d.start(now);
        assert!(d.poll_transmit().is_some());

        for expected in 2..=3 {
            now = d.poll_timeout().expect("a retry deadline");
            d.handle_timeout(now);
            assert!(d.poll_transmit().is_some(), "attempt {expected}");
            assert_eq!(d.attempts(), expected);
        }

        now = d.poll_timeout().expect("one last deadline");
        d.handle_timeout(now);
        assert_eq!(d.poll_transmit(), None, "the ceiling is a ceiling");
        assert_eq!(d.poll_event(), Some(Event::GaveUp { attempts: 3 }));
        assert!(d.is_finished());
        assert_eq!(d.poll_timeout(), None, "nothing more is pending");
    }

    #[test]
    fn discovery_waits_the_specified_interval() {
        use crate::session::Instant;

        let mut d = Discovery::new(Request::PLAIN);
        d.start(Instant::ZERO);
        assert_eq!(
            d.poll_timeout(),
            Some(Instant::ZERO + crate::session::timers::sdp::RESPONSE_TIMEOUT)
        );
        // Early is not due: \[V2G2-159\] is a minimum, and sending faster is
        // out of spec.
        d.handle_timeout(Instant::from_millis(1));
        assert_eq!(d.attempts(), 1);
    }

    /// A well-formed answer on the wire, for feeding to a `Discovery`.
    fn answer(address: [u8; 16], security: Security, transport: TransportProtocol) -> Vec<u8> {
        let res = Response { address, port: 15118, security, transport };
        let mut frame = [0u8; 64];
        let n = res.write_frame(&mut frame, false).unwrap();
        frame[..n].to_vec()
    }

    #[test]
    fn a_downgrade_is_surfaced_as_a_refusal_not_a_find() {
        use crate::session::Instant;

        let mut d = Discovery::new(Request::TLS);
        d.start(Instant::ZERO);
        let wire = answer(LINK_LOCAL, Security::None, TransportProtocol::Tcp);
        d.handle_datagram(Instant::ZERO, &wire).unwrap();
        assert_eq!(
            d.poll_event(),
            Some(Event::Refused {
                response: Response::from_frame(&wire).unwrap(),
                reason: Refusal::SecurityDowngrade,
            })
        );
    }

    /// The one that matters: SDP is unauthenticated multicast on a shared
    /// segment, so if any answer could end the run, one spoofed datagram would
    /// stop the vehicle hearing the station it is plugged into.
    #[test]
    fn a_refused_answer_does_not_end_discovery() {
        use crate::session::Instant;

        let mut d = Discovery::new(Request::TLS);
        d.start(Instant::ZERO);
        let _ = d.poll_transmit();

        // Somebody on the segment answers first, without TLS.
        d.handle_datagram(
            Instant::ZERO,
            &answer(LINK_LOCAL, Security::None, TransportProtocol::Tcp),
        )
        .unwrap();
        assert!(matches!(d.poll_event(), Some(Event::Refused { .. })));
        assert!(!d.is_finished(), "one spoofed packet must not end the run");
        assert!(d.poll_timeout().is_some(), "the retry is still armed");
        assert_eq!(d.attempts(), 1, "a refused answer does not consume an attempt");

        // ...and the real station is still heard.
        let good = answer(LINK_LOCAL, Security::Tls, TransportProtocol::Tcp);
        d.handle_datagram(Instant::ZERO, &good).unwrap();
        assert_eq!(d.poll_event(), Some(Event::Found(Response::from_frame(&good).unwrap())));
        assert!(d.is_finished());
    }

    /// A terminal outcome displaces an unread refusal; a refusal displaces
    /// nothing. So a flood of refusals cannot push the real answer out of the
    /// single event slot before the caller reads it.
    #[test]
    fn a_flood_of_refusals_cannot_hide_the_outcome() {
        use crate::session::Instant;

        let mut d = Discovery::new(Request::TLS);
        d.start(Instant::ZERO);
        let bad = answer(LINK_LOCAL, Security::None, TransportProtocol::Tcp);
        for _ in 0..100 {
            d.handle_datagram(Instant::ZERO, &bad).unwrap();
        }
        let good = answer(LINK_LOCAL, Security::Tls, TransportProtocol::Tcp);
        d.handle_datagram(Instant::ZERO, &good).unwrap();

        // A hundred refusals collapse to one — the queue is two slots, not a
        // buffer — and the refusal is delivered *and* the outcome survives it.
        // Both matter: the outcome is the run's answer, and the refusal is the
        // only sign the vehicle gets that something else on the segment is
        // answering. One slot each is what lets a flood cost nothing without
        // either half being lost.
        assert!(matches!(d.poll_event(), Some(Event::Refused { .. })));
        assert_eq!(d.poll_event(), Some(Event::Found(Response::from_frame(&good).unwrap())));
        assert_eq!(d.poll_event(), None, "two unread events, not a hundred and one");
    }

    /// Listening on past the answer must not also mean listening on past the
    /// *giving up*: `GaveUp` may already have been polled and acted on.
    #[test]
    fn an_answer_after_the_attempt_ceiling_does_not_undo_giving_up() {
        use crate::session::Instant;

        let mut d = Discovery::new(Request::TLS).with_max_attempts(1);
        let mut now = Instant::ZERO;
        d.start(now);
        now = d.poll_timeout().unwrap();
        d.handle_timeout(now);
        assert_eq!(d.poll_event(), Some(Event::GaveUp { attempts: 1 }));

        d.handle_datagram(now, &answer(LINK_LOCAL, Security::Tls, TransportProtocol::Tcp)).unwrap();
        assert_eq!(d.poll_event(), None);
        assert!(d.is_finished());
    }

    /// The attack a refusal cannot catch: a well-formed, link-local, correctly
    /// secured answer that simply arrives first.
    ///
    /// Nothing about one such datagram distinguishes it from the real station's
    /// — that is the point of the attack (arXiv 2512.15966 §3.2) — so the only
    /// check available is against the *other* answer, and the only way to have
    /// one is to go on listening after the run is finished.
    #[test]
    fn a_second_station_answering_is_reported_rather_than_ignored() {
        use crate::session::Instant;

        const OTHER: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9];

        let mut d = Discovery::new(Request::TLS);
        d.start(Instant::ZERO);

        let first = answer(LINK_LOCAL, Security::Tls, TransportProtocol::Tcp);
        d.handle_datagram(Instant::ZERO, &first).unwrap();
        let accepted = Response::from_frame(&first).unwrap();
        assert_eq!(d.poll_event(), Some(Event::Found(accepted)));
        assert!(d.is_finished());

        // The station the cable is actually plugged into, answering second.
        let second = answer(OTHER, Security::Tls, TransportProtocol::Tcp);
        d.handle_datagram(Instant::ZERO, &second).unwrap();
        assert_eq!(
            d.poll_event(),
            Some(Event::Conflict { accepted, other: Response::from_frame(&second).unwrap() }),
        );

        // A retransmission of the answer already taken is not a conflict — an
        // SDP server may legitimately answer twice, and calling that an attack
        // would make the check useless.
        d.handle_datagram(Instant::ZERO, &first).unwrap();
        assert_eq!(d.poll_event(), None);

        // Nor is an answer that would have been refused on its own merits: it
        // is already reported as what it is, and the vehicle is not acting on
        // it either way.
        d.handle_datagram(Instant::ZERO, &answer(OTHER, Security::None, TransportProtocol::Tcp))
            .unwrap();
        assert_eq!(d.poll_event(), None);
    }

    /// The V2G link is link-local and has no router, so an answer pointing
    /// anywhere else is pointing somewhere the cable does not go.
    #[test]
    fn an_off_link_address_is_refused_by_default() {
        use crate::session::Instant;

        const GLOBAL: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let wire = answer(GLOBAL, Security::Tls, TransportProtocol::Tcp);

        let mut d = Discovery::new(Request::TLS);
        d.start(Instant::ZERO);
        d.handle_datagram(Instant::ZERO, &wire).unwrap();
        assert_eq!(
            d.poll_event(),
            Some(Event::Refused {
                response: Response::from_frame(&wire).unwrap(),
                reason: Refusal::OffLink,
            })
        );
        assert!(!d.is_finished());

        // ...and a test rig on an ordinary LAN can say so, visibly.
        let mut d = Discovery::new(Request::TLS).allow_off_link(true);
        d.start(Instant::ZERO);
        d.handle_datagram(Instant::ZERO, &wire).unwrap();
        assert!(matches!(d.poll_event(), Some(Event::Found(_))));
    }

    #[test]
    fn a_transport_mismatch_is_named_as_one() {
        use crate::session::Instant;

        let mut d = Discovery::new(Request::TLS);
        d.start(Instant::ZERO);
        d.handle_datagram(
            Instant::ZERO,
            &answer(LINK_LOCAL, Security::Tls, TransportProtocol::Udp),
        )
        .unwrap();
        assert!(matches!(
            d.poll_event(),
            Some(Event::Refused { reason: Refusal::TransportMismatch, .. })
        ));
    }

    /// Port zero has always been refused by the codec. An address that names
    /// no endpoint is the same defect on the other half of the pair.
    #[test]
    fn an_address_that_is_not_an_endpoint_is_refused_by_the_codec() {
        let mut payload = [0u8; RESPONSE_LEN];
        payload[16] = 0x3B; // port 15118
        payload[17] = 0x0E;
        assert_eq!(
            Response::from_payload(&payload),
            Err(SdpError::InvalidAddress([0u8; 16])),
            "the unspecified address"
        );

        payload[0] = 0xff;
        payload[15] = 0x01; // ff00::1, a multicast group
        assert!(matches!(Response::from_payload(&payload), Err(SdpError::InvalidAddress(_))));

        payload[0] = 0xfe;
        payload[1] = 0x80;
        assert!(Response::from_payload(&payload).is_ok(), "a link-local address is fine");
    }

    /// The request goes to a multicast group, so anything on the link can
    /// answer. One bad answer must not end the run.
    #[test]
    fn a_malformed_answer_does_not_end_discovery() {
        use crate::session::Instant;

        let mut d = Discovery::new(Request::TLS);
        d.start(Instant::ZERO);
        let _ = d.poll_transmit();
        assert!(d.handle_datagram(Instant::ZERO, &[0xDE, 0xAD]).is_err());
        assert!(!d.is_finished());
        assert!(d.poll_timeout().is_some(), "the retry is still armed");
    }

    #[cfg(feature = "std")]
    #[test]
    fn ipv6_conversion_roundtrips() {
        let addr: std::net::Ipv6Addr = "fe80::21a:2bff:fe3c:4d5e".parse().unwrap();
        let res = Response::from_ipv6(addr, 15118, Security::Tls, TransportProtocol::Tcp);
        assert_eq!(res.ipv6(), addr);
        assert_eq!(res.address, LINK_LOCAL);
    }
}
