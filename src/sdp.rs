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

/// Transport-layer security the session will use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Security {
    /// TLS. Mandatory for ISO 15118-20 and for Plug & Charge under -2.
    Tls,
    /// No transport security. Permitted by DIN SPEC 70121 and by ISO 15118-2
    /// with external identification (EIM) only.
    None,
}

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
    /// vehicle must then use TLS; it may never answer with less. Downgrade is
    /// the attack this check exists to stop.
    #[must_use]
    pub const fn satisfies(&self, request: &Request) -> bool {
        if self.transport as u8 != request.transport as u8 {
            return false;
        }
        // A TLS request must be answered with TLS; a plaintext request may be
        // upgraded. Only the downgrade direction is refused.
        !matches!((request.security, self.security), (Security::Tls, Security::None))
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
    interval: crate::session::Millis,
    max_attempts: u32,
    attempts: u32,
    deadline: Option<crate::session::Instant>,
    pending: Option<[u8; v2gtp::HEADER_LEN + REQUEST_LEN]>,
    event: Option<Event>,
    done: bool,
}

/// What discovery produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Event {
    /// A charger answered, and its answer gives the vehicle at least what it
    /// asked for. Connect to [`Response::ipv6`] and [`Response::port`].
    Found(Response),
    /// A charger answered, but with *less* security than was requested.
    ///
    /// This is the downgrade the check exists to catch, so it is surfaced as
    /// its own event rather than as a `Found` the caller might not inspect.
    /// ISO 15118-20 mandates TLS outright; under -2 a vehicle doing Plug &
    /// Charge must refuse this, and one doing EIM may choose not to.
    Refused(Response),
    /// No charger answered within the permitted number of attempts.
    GaveUp {
        /// How many requests went out.
        attempts: u32,
    },
}

impl Discovery {
    /// A discovery run that will ask for `request`.
    #[must_use]
    pub const fn new(request: Request) -> Self {
        Self {
            request,
            wireless: false,
            interval: crate::session::timers::sdp::RESPONSE_TIMEOUT,
            max_attempts: crate::session::timers::sdp::MAX_REQUESTS,
            attempts: 0,
            deadline: None,
            pending: None,
            event: None,
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
        self.event = None;
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
            self.event = Some(Event::GaveUp { attempts: self.attempts });
            return;
        }
        self.send(now);
    }

    /// Feeds a datagram received on the discovery port.
    ///
    /// A datagram that is not a well-formed `SECCDiscoveryRes` is an error but
    /// **not** the end of discovery: the request went to a multicast group, so
    /// anything on the link can answer, and one bad answer must not stop the
    /// vehicle waiting for a good one. Retrying continues either way.
    pub fn handle_datagram(
        &mut self,
        _now: crate::session::Instant,
        frame: &[u8],
    ) -> Result<(), SdpError> {
        if self.done {
            return Ok(());
        }
        let response = Response::from_frame(frame)?;
        self.done = true;
        self.deadline = None;
        self.pending = None;
        self.event = Some(if response.satisfies(&self.request) {
            Event::Found(response)
        } else {
            Event::Refused(response)
        });
        Ok(())
    }

    /// The outcome, once there is one.
    pub const fn poll_event(&mut self) -> Option<Event> {
        self.event.take()
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
mod tests {
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

    #[test]
    fn a_downgrade_is_surfaced_as_a_refusal_not_a_find() {
        use crate::session::Instant;

        let mut d = Discovery::new(Request::TLS);
        d.start(Instant::ZERO);
        let res = Response {
            address: LINK_LOCAL,
            port: 15118,
            security: Security::None,
            transport: TransportProtocol::Tcp,
        };
        let mut frame = [0u8; 64];
        let n = res.write_frame(&mut frame, false).unwrap();
        d.handle_datagram(Instant::ZERO, &frame[..n]).unwrap();
        assert_eq!(d.poll_event(), Some(Event::Refused(res)));
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
