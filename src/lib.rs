//! ISO 15118 — vehicle-to-grid communication in pure Rust.
//!
//! The protocol an electric vehicle and a charging station speak over the CCS
//! charging cable while deciding whether to move 350 kW between them:
//! `HomePlug` link setup, SECC discovery, V2GTP framing, a schema-informed EXI
//! codec generated from the official schemas, the ISO 15118-2 and ISO 15118-20
//! message sets, the message-ordering rules and timers of both, session engines
//! for either role, and the Plug & Charge signature profile.
//!
//! The two sides are named throughout as the standard names them: the **EVCC**
//! is the vehicle's communication controller and the **SECC** is the charging
//! station's.
//!
//! Narrative documentation, including the exact EXI profile and how the wire
//! format is verified, is at <https://hupe1980.github.io/iso15118/>.
//!
//! # Sans-I/O
//!
//! Nothing here opens a socket, reads a clock, or blocks. Protocol engines take
//! bytes and a timestamp and hand back bytes, events and deadlines; the caller
//! owns the transport, the clock, the randomness and the crypto. That is what
//! lets the same code drive a Tokio-based charge point back end and a
//! bare-metal EVCC on a microcontroller — and it is why a whole DC charging
//! session runs as a unit test in microseconds, with time as a variable.
//!
//! Every engine — [`secc::Secc`], [`evcc::Evcc`], [`sdp::Discovery`],
//! [`slac::matching::Ev`] and [`slac::matching::Evse`] — is driven the same
//! way. The names differ only where the job does:
//!
//! | Step | Session engines | Discovery and SLAC |
//! |---|---|---|
//! | Bytes from the wire | `handle_input(now, &bytes)` | `handle_datagram` / `handle_frame` |
//! | What happened | `poll_event()` | `poll_event()` |
//! | Your answer | `respond` (SECC) / `request` (EVCC) | — the engine decides |
//! | Bytes for the wire | `take_transmit()` | `poll_transmit()` |
//! | The next deadline | `poll_timeout()`, then `handle_timeout(now)` | same |
//!
//! A session engine consumes a *stream* and reassembles it; discovery and SLAC
//! consume whole datagrams and frames, one at a time. The vehicle drives — it
//! chooses each request — and the charger only answers.
//!
//! **An error from `handle_input` has already ended the session.** The engine
//! closes itself — timers disarmed, buffers dropped, `Event::Closed` queued —
//! before returning it: V2GTP has no delimiter to resynchronise on, so the
//! error is for the log, not for a decision.
//!
//! # Whose key, and which session
//!
//! [`pnc`] answers "is this signature about *this* session" — the
//! `GenChallenge` binding, checked in the same call as the signature.
//! [`pnc::pki`] answers "is this key one to trust" — RFC 5280 path validation
//! under ISO 15118's Annex F profiles. Neither answers whether a certificate was
//! **revoked**; [`pnc::pki`] says why.
//!
//! # Protocol, not policy
//!
//! The engines own framing, decoding, the handshake, session-id checking,
//! message ordering and the spec timers. Whether to authorize, which schedule
//! to offer and how much current to deliver arrive as events, answered with a
//! message the application builds. Ordering includes stopping, pausing and
//! renegotiating — see [`session`].
//!
//! # Plug & Charge needs TLS
//!
//! ISO 15118-2 forbids the Plug & Charge message sets on an unsecured session
//! \[V2G2-634\], \[V2G2-635\]. A sans-I/O core cannot observe the transport, so
//! [`secc::SeccConfig::security`] and [`evcc::EvccConfig::security`] state it.
//! The default, [`session::Security::None`], refuses a contract selection rather
//! than put a certificate chain on a plaintext wire.
//!
//! # Half-duplex, both ways
//!
//! [`secc::Secc`] surfaces one request and reads nothing further until
//! [`secc::Secc::respond`]; [`evcc::Evcc::request`] refuses a second request
//! while the first is unanswered, and [`secc::Secc::respond`] refuses a response
//! that answers nothing or the wrong question. Besides being the protocol's
//! rule, this stops an unauthenticated peer from queueing work without bound.
//!
//! # You never write a session id
//!
//! [`secc::Secc::respond`] and [`evcc::Evcc::request`] stamp it into every
//! message — the all-zero id before setup, the assigned one after. The one case
//! where the vehicle picks it, rejoining a paused session, is
//! [`evcc::EvccConfig::rejoin`].
//!
//! # Layering
//!
//! Each layer is usable on its own — [`v2gtp`] and [`sdp`] are plain byte
//! codecs, and [`exi`] is a standalone schema-informed EXI implementation.
//!
//! ```text
//! evcc / secc      role drivers: sessions, timers, decisions
//! session          clock, spec timers and loop budgets, ordering graphs
//! message          V2GTP payload type + negotiated protocol -> typed message
//! iso2 / iso20     generated message types and codecs
//! exi              schema-informed EXI: documents and fragments
//! v2gtp  framing   sdp  discovery
//! slac             HomePlug link setup + matching state machines
//!                  protocol — which generation, cross-cutting
//!                  pnc — Plug & Charge signatures, cross-cutting
//! ```
//!
//! # Feature flags
//!
//! Everything is additive — every combination compiles, and every flag gates
//! real code.
//!
//! | Group | Flags |
//! |---|---|
//! | Environment | `std` (default; the core is `no_std` + `alloc`) |
//! | Roles | `evcc`, `secc` |
//! | Protocols | `iso2`, `iso20` (= `iso20-ac`, `iso20-dc`, `iso20-wpt`, `iso20-acdp`, `iso20-ac-der-iec`, `iso20-ac-der-sae`; each implies `iso20-common`) |
//! | Link | `sdp`, `slac` |
//! | Security | `pnc`, `pnc-rustcrypto` |
//! | Integration | `serde`, `tracing` |
//!
//! `alloc` is a requirement rather than a feature: in bit-packed EXI a string is
//! a run of bit-shifted code points, so a decoded value can never borrow from
//! the input. A role driver needs a protocol to drive, so `secc` or `evcc` on
//! their own compile and gate nothing.
//!
//! # Which generation, and how to say so
//!
//! "ISO 15118" names two incompatible protocols. [`Protocol`] is the one a
//! session settled on; [`Protocols`] is the set a piece of equipment
//! implements, which is a different question and the one a datasheet or a
//! regulatory feed asks.
//!
//! [`Protocol::as_str`] gives a short stable name — `"din70121"`,
//! `"iso15118-2"`, `"iso15118-20"` — and `FromStr` reads it back, for a record,
//! a metric label or a database column. A bare `"iso15118"` is refused: it names
//! neither generation. See [`protocol`].
//!
//! ```
//! use iso15118::{Protocol, Protocols};
//!
//! assert_eq!(Protocol::Iso20.as_str(), "iso15118-20");
//! assert_eq!("iso15118-2".parse(), Ok(Protocol::Iso2));
//!
//! // A whole set round-trips too — a configuration file's worth.
//! let station: Protocols = "iso15118-20,iso15118-2".parse()?;
//! assert_eq!(station, Protocols::ISO);
//! assert_eq!(station.best(), Some(Protocol::Iso20));
//! # Ok::<_, iso15118::ParseProtocolError>(())
//! ```
//!
//! # Example: the protocol handshake
//!
//! The vehicle offers the protocols it speaks — ISO 15118-20 as one entry per
//! message set — and the charger picks one. [`secc::Secc`] and [`evcc::Evcc`]
//! run this for you.
//!
//! ```
//! use iso15118::Protocol;
//! use iso15118::app_protocol::{SupportedAppProtocolReq, SupportedAppProtocolRes};
//! use iso15118::exi::ExiDocument;
//!
//! // EVCC: advertise -20 first, then -2 as a fallback.
//! let req = SupportedAppProtocolReq::advertising([Protocol::Iso20, Protocol::Iso2]);
//! let on_the_wire = req.to_vec()?;
//!
//! // SECC: this charger only does ISO 15118-2.
//! let req = SupportedAppProtocolReq::from_bytes(&on_the_wire)?;
//! let agreed = req.negotiate(Protocol::Iso2).expect("a protocol in common");
//! assert_eq!(agreed.protocol, Protocol::Iso2);
//!
//! let res = SupportedAppProtocolRes::accept(agreed);
//! assert!(res.response_code.is_ok());
//! # Ok::<_, iso15118::exi::ExiError>(())
//! ```

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod exi;
pub mod v2gtp;

#[cfg(feature = "sdp")]
#[cfg_attr(docsrs, doc(cfg(feature = "sdp")))]
pub mod sdp;

#[cfg(feature = "slac")]
#[cfg_attr(docsrs, doc(cfg(feature = "slac")))]
pub mod slac;

pub mod app_protocol;

pub mod message;
pub mod session;

// A role driver needs a protocol to drive: with neither `iso2` nor `iso20`
// enabled there is no message set and no flow, so the module would be an empty
// shell. Features stay additive — this only decides when the module appears.
#[cfg(all(feature = "secc", any(feature = "iso2", feature = "iso20-common")))]
#[cfg_attr(docsrs, doc(cfg(feature = "secc")))]
pub mod secc;

#[cfg(all(feature = "evcc", any(feature = "iso2", feature = "iso20-common")))]
#[cfg_attr(docsrs, doc(cfg(feature = "evcc")))]
pub mod evcc;

#[cfg(feature = "pnc")]
#[cfg_attr(docsrs, doc(cfg(feature = "pnc")))]
pub mod pnc;

mod generated;

#[cfg(feature = "iso2")]
#[cfg_attr(docsrs, doc(cfg(feature = "iso2")))]
pub use generated::iso2;

#[cfg(feature = "iso20-common")]
#[cfg_attr(docsrs, doc(cfg(feature = "iso20-common")))]
pub use generated::iso20;

mod error;
pub use error::{Error, Result};

pub mod protocol;
pub use protocol::{Iso20Set, ParseProtocolError, Protocol, Protocols};

#[macro_use]
mod trace;

/// The README, compiled as a doctest so its examples cannot rot. Checked only
/// with the default features, which is how a reader meets the crate; a doctest
/// cannot be gated block by block.
#[cfg(all(
    doctest,
    feature = "std",
    feature = "iso2",
    feature = "iso20",
    feature = "sdp",
    feature = "slac",
    feature = "evcc",
    feature = "secc",
    feature = "pnc"
))]
#[doc = include_str!("../README.md")]
mod readme {}

/// Default ceiling on the EXI payload of a single V2GTP frame.
///
/// The V2GTP length field is 32 bits wide and arrives before anything has been
/// authenticated, so some limit has to be imposed. One mebibyte is far above
/// the largest real message — an ISO 15118-20 `ScheduleExchangeRes` carrying a
/// full price schedule runs to tens of kilobytes — and far below what would
/// let a peer exhaust memory.
///
/// Session cores accept an override; this is only the default policy.
pub const MAX_EXI_PAYLOAD_LEN: usize = 1024 * 1024;
