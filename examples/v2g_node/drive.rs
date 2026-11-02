//! The loops around the engines: the twenty lines of I/O `examples/evcc_tcp.rs`
//! and `examples/secc_tcp.rs` show, with a deadline and a log.
//!
//! What to send next and what to answer are the vehicle's and the station's
//! decisions, so they come from a [`VehicleScript`] or a [`StationScript`]; the
//! loops only move bytes, read the clock and record what happened.

use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant as StdInstant};

use iso15118::Protocol;
use iso15118::evcc::{self, Evcc, EvccConfig};
use iso15118::message::Message;
use iso15118::secc::{self, Secc, SeccConfig};

use crate::net::{Clock, Deadline};

/// Which generation a session speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Generation {
    Iso2,
    Iso20,
}

/// Which energy service a session negotiates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Service {
    Ac,
    Dc,
}

impl Generation {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Iso2 => "iso2",
            Self::Iso20 => "iso20",
        }
    }
}

impl Service {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Ac => "ac",
            Self::Dc => "dc",
        }
    }
}

impl std::str::FromStr for Generation {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "iso2" => Ok(Self::Iso2),
            "iso20" => Ok(Self::Iso20),
            other => Err(format!("unknown generation {other}")),
        }
    }
}

impl std::str::FromStr for Service {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "ac" => Ok(Self::Ac),
            "dc" => Ok(Self::Dc),
            other => Err(format!("unknown service {other}")),
        }
    }
}

/// What a vehicle does next.
#[derive(Debug)]
pub(crate) enum Next {
    /// Send this request after the pause: a vehicle repeating an `Ongoing`
    /// phase does not hammer the station.
    Send(Message, Duration),
    /// Nothing more to send: `SessionStopRes` has arrived.
    Done,
}

/// The vehicle's decisions.
pub(crate) trait VehicleScript {
    /// The first request once the handshake has settled.
    fn first(&mut self, protocol: Protocol) -> Message;
    /// The next request, given the station's last answer.
    fn next(&mut self, response: &Message) -> Next;
    /// `SessionStopReq` — the only request left after a `FAILED_*` answer.
    fn stop(&self) -> Message;
    /// Why the vehicle gave the session up, if it did: a session it stopped
    /// before power flowed closes normally and is still not a pass.
    fn abandoned(&self) -> Option<&str> {
        None
    }
}

/// The station's decisions.
pub(crate) trait StationScript {
    fn answer(&mut self, request: &Message) -> Message;
}

/// What one session did, from our side.
#[derive(Debug, Default, Clone)]
pub(crate) struct Ran {
    /// The driver's own close reason, as it prints.
    pub(crate) close: Option<String>,
    /// Closed normally after `SessionStop`, nothing refused, nothing failed.
    pub(crate) normal: bool,
    pub(crate) messages: u32,
    pub(crate) last_request: Option<String>,
    /// The first thing that went wrong, if anything did.
    pub(crate) error: Option<String>,
}

impl Ran {
    fn note(&mut self, error: String) {
        eprintln!("  !! {error}");
        self.error.get_or_insert(error);
    }
}

fn prepare(stream: &TcpStream) {
    // A short read timeout turns the blocking socket into the poll loop a
    // sans-I/O engine wants.
    let _ = stream.set_read_timeout(Some(Duration::from_millis(20)));
    let _ = stream.set_nodelay(true);
}

/// Runs a whole session as the vehicle.
#[allow(clippy::too_many_lines, reason = "one loop: write, read, time, events, answer")]
pub(crate) fn evcc(
    stream: &mut TcpStream,
    config: EvccConfig,
    script: &mut dyn VehicleScript,
    deadline: Deadline,
) -> Ran {
    prepare(stream);
    let clock = Clock::start();
    let mut ran = Ran::default();
    let mut evcc = Evcc::new(config);
    if let Err(e) = evcc.start(clock.now()) {
        ran.note(format!("start: {e}"));
        return ran;
    }

    let mut pending: Option<(Message, StdInstant)> = None;
    let mut failed = false;
    let mut close = None;
    let mut buf = vec![0u8; 16 * 1024];

    loop {
        let out = evcc.take_transmit();
        if !out.is_empty()
            && let Err(e) = stream.write_all(&out)
        {
            ran.note(format!("write: {e}"));
            break;
        }
        if evcc.is_closed() {
            break;
        }
        if deadline.passed() {
            ran.note("deadline passed".into());
            break;
        }

        if let Some((request, at)) = pending.take() {
            if StdInstant::now() >= at {
                eprintln!("  -> {}", request.name());
                ran.last_request = Some(request.name().into());
                if let Err(e) = evcc.request(clock.now(), request) {
                    ran.note(format!("our vehicle refused to send: {e}"));
                    break;
                }
                continue;
            }
            pending = Some((request, at));
        }

        match stream.read(&mut buf) {
            Ok(0) => {
                if close.is_none() {
                    ran.note("the station hung up".into());
                }
                break;
            }
            Ok(n) => {
                if let Err(e) = evcc.handle_input(clock.now(), &buf[..n]) {
                    ran.note(format!("from the station: {e}"));
                }
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(e) => {
                ran.note(format!("read: {e}"));
                break;
            }
        }
        if evcc.poll_timeout().is_some_and(|t| t <= clock.now()) {
            evcc.handle_timeout(clock.now());
        }

        let mut answer = None;
        while let Some(event) = evcc.poll_event() {
            match event {
                evcc::Event::ProtocolAgreed(p) => {
                    eprintln!("  speaking {p}");
                    pending = Some((script.first(p), StdInstant::now()));
                }
                evcc::Event::Response(m) => {
                    eprintln!("  <- {}", m.name());
                    ran.messages += 1;
                    answer = Some(*m);
                }
                evcc::Event::Failed => {
                    ran.note(format!(
                        "the station answered {} with FAILED",
                        ran.last_request.as_deref().unwrap_or("?")
                    ));
                    failed = true;
                }
                evcc::Event::Closed(why) => {
                    eprintln!("  --- {why}");
                    close = Some(why);
                }
                _ => {}
            }
        }
        if let Some(m) = answer {
            if failed {
                if m.name() != "SessionStopRes" {
                    pending = Some((script.stop(), StdInstant::now()));
                }
            } else if let Next::Send(request, pause) = script.next(&m) {
                pending = Some((request, StdInstant::now() + pause));
            }
        }
    }

    if let Some(why) = script.abandoned() {
        ran.note(why.into());
    }
    ran.close = close.map(|c| c.to_string());
    ran.normal = close == Some(evcc::Close::Normal) && !failed && ran.error.is_none();
    ran
}

fn hex_string(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// Serves one whole session as the station.
pub(crate) fn secc(
    stream: &mut TcpStream,
    config: SeccConfig,
    script: &mut dyn StationScript,
    deadline: Deadline,
) -> Ran {
    prepare(stream);
    let clock = Clock::start();
    let mut ran = Ran::default();
    let mut secc = Secc::new(config);
    secc.opened(clock.now());
    // `V2G_NODE_HEX=1` prints every chunk read, for reading a disagreement
    // back to the bytes.
    let hex = std::env::var_os("V2G_NODE_HEX").is_some();
    let mut close = None;
    let mut buf = vec![0u8; 16 * 1024];

    loop {
        if deadline.passed() {
            ran.note("deadline passed".into());
            break;
        }
        match stream.read(&mut buf) {
            Ok(0) => {
                if close.is_none() {
                    ran.note("the vehicle hung up".into());
                }
                break;
            }
            Ok(n) => {
                if hex {
                    eprintln!("  .. {}", hex_string(&buf[..n]));
                }
                if let Err(e) = secc.handle_input(clock.now(), &buf[..n]) {
                    ran.note(format!("from the vehicle: {e}"));
                }
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(e) => {
                ran.note(format!("read: {e}"));
                break;
            }
        }
        if secc.poll_timeout().is_some_and(|t| t <= clock.now()) {
            secc.handle_timeout(clock.now());
        }

        while let Some(event) = secc.poll_event() {
            match event {
                secc::Event::ProtocolAgreed(p) => eprintln!("  speaking {p}"),
                secc::Event::Request(req) => {
                    eprintln!("  <- {}", req.name());
                    ran.messages += 1;
                    ran.last_request = Some(req.name().into());
                    let res = script.answer(&req);
                    eprintln!("  -> {}", res.name());
                    if let Err(e) = secc.respond(clock.now(), res) {
                        ran.note(format!("our station could not answer {}: {e}", req.name()));
                    }
                }
                secc::Event::Refused { message, response_code, reason } => {
                    ran.last_request = Some(message.name().into());
                    ran.note(format!("we refused {}: {reason}", message.name()));
                    // The evidence for the disagreement: what we decoded.
                    eprintln!("  !! as we decoded it: {message:?}");
                    if let Some(refusal) = message.refusal(response_code) {
                        let _ = secc.respond(clock.now(), refusal);
                    }
                }
                secc::Event::Overdue { message, response_code, phase } => {
                    ran.note(format!("our station ran out of time in {phase}"));
                    if let Some(refusal) = message.refusal(response_code) {
                        let _ = secc.respond(clock.now(), refusal);
                    }
                }
                secc::Event::Closed(why) => {
                    eprintln!("  --- {why}");
                    close = Some(why);
                }
                _ => {}
            }
        }

        let out = secc.take_transmit();
        if !out.is_empty()
            && let Err(e) = stream.write_all(&out)
        {
            ran.note(format!("write: {e}"));
            break;
        }
        if secc.is_closed() {
            break;
        }
    }

    ran.close = close.map(|c| c.to_string());
    ran.normal = close == Some(secc::Close::Normal) && ran.error.is_none();
    ran
}
