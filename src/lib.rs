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
//! The two column headings are a distinction worth keeping: a session engine
//! consumes a *stream* and has to reassemble it, so it takes whatever bytes
//! arrived and returns everything queued. Discovery and SLAC consume complete
//! datagrams and Ethernet frames, where a boundary is meaningful, so they take
//! one and hand back one at a time.
//!
//! The answering step differs because the protocol does. The vehicle *drives*:
//! it chooses the next request, and the charger only ever answers.
//!
//! # Protocol, not policy
//!
//! The engines own framing, decoding, the protocol handshake, session-id
//! checking, message ordering and the spec timers. They own nothing about
//! charging: whether to authorize a vehicle, which schedule to offer, how much
//! current to deliver. Those arrive as events and are answered with a message
//! the application builds. Everything above that line is a decision a charge
//! point operator makes; everything below it is a decision ISO made.
//!
//! Ordering includes what the standard says about *stopping*: a `FAILED_*`
//! response ends the session and leaves only `SessionStopReq`, a vehicle may
//! stop from any established phase, and `Pause` and -20's
//! `ServiceRenegotiation` are not `Terminate`. It also includes *renegotiating*:
//! revising the schedule mid-charge keeps the service, the authorization and the
//! power flow, and does not send a DC session back through its isolation test.
//! See [`session`].
//!
//! # Half-duplex, and what that is worth
//!
//! Neither side of a V2G session may send again before the other has answered,
//! so the engines do not read ahead: [`secc::Secc`] surfaces one request and
//! reads nothing further until [`secc::Secc::respond`] has been called, and
//! [`evcc::Evcc`] accepts a response only if it answers the request that is
//! outstanding. Both are protocol rules, and both are also what stops one
//! unauthenticated peer from queueing work without bound — several requests are
//! legal repeatedly, and the ordering graph constrains requests only.
//!
//! The rule is symmetric, so the enforcement is too, and this is the half that
//! is easy to leave out: [`evcc::Evcc::request`] refuses a second request while
//! the first is unanswered, and [`secc::Secc::respond`] refuses a response that
//! answers nothing or answers the wrong question. The ordering graph cannot
//! catch either — it constrains *which* request, not *when*.
//!
//! # You never write a session id
//!
//! The charger assigns one in `SessionSetupRes` and every message of the session
//! repeats it, so it is not a per-message decision. [`secc::Secc::respond`]
//! stamps it into every response and [`evcc::Evcc::request`] into every request
//! — the all-zero id before setup, the assigned one after. Leave the field
//! empty and the driver fills it.
//!
//! Rejoining a paused session is the one case where the vehicle picks the id,
//! and it says so once in [`evcc::EvccConfig::rejoin`]. That is worth more than
//! it looks: ISO 15118-2 tolerates a short or absent `SessionID` and
//! ISO 15118-20 requires exactly eight bytes, so a field left to the application
//! is a field that is right in one generation and wrong in the other.
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
//! | Protocols | `iso2`, `iso20` (= `iso20-ac`+`iso20-dc`+`iso20-wpt`+`iso20-acdp`) |
//! | Link | `sdp`, `slac` |
//! | Security | `pnc`, `pnc-rustcrypto` |
//! | Integration | `serde`, `tracing` |
//!
//! `alloc` is a requirement rather than a feature: in bit-packed EXI a string is
//! a run of bit-shifted code points, so a decoded value can never borrow from
//! the input. A role driver needs a protocol to drive, so `secc` or `evcc` on
//! their own compile and gate nothing.
//!
//! # Example: the protocol handshake
//!
//! The vehicle offers the protocols it speaks; the charger picks one. This is
//! the first EXI-encoded exchange of every session, whichever generation wins —
//! and [`secc::Secc`] runs it for you, because it is pure protocol.
//!
//! ```
//! use iso15118::Protocol;
//! use iso15118::app_protocol::{SupportedAppProtocolReq, SupportedAppProtocolRes};
//! use iso15118::exi::ExiDocument;
//!
//! // EVCC: advertise -20 first, then -2 as a fallback.
//! let req = SupportedAppProtocolReq::advertising(&[Protocol::Iso20, Protocol::Iso2]);
//! let on_the_wire = req.to_vec()?;
//!
//! // SECC: this charger only does ISO 15118-2.
//! let req = SupportedAppProtocolReq::from_bytes(&on_the_wire)?;
//! let agreed = req.negotiate(&[Protocol::Iso2]).expect("a protocol in common");
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

#[macro_use]
mod trace;

/// The README, compiled as a doctest so its examples cannot rot.
///
/// A README example that no longer builds is worse than no example: it is the
/// first thing a reader tries and the last thing anyone re-checks.
///
/// The examples show the crate as a reader meets it — default features — and a
/// doctest cannot be feature-gated block by block, so the whole file is checked
/// only when those features are on. A stripped build compiling the README would
/// prove nothing about it anyway.
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

/// Which generation of the protocol a session is speaking.
///
/// The `supportedAppProtocol` handshake picks one of these, and it determines
/// every grammar, payload type and state machine used afterwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum Protocol {
    /// DIN SPEC 70121 — legacy DC charging, EIM only, no TLS.
    ///
    /// Recognised in the handshake so a charger can decline it explicitly
    /// rather than by silence, but its message set is **not implemented**: the
    /// DIN schemas are not freely available, and hand-transcribing them would
    /// produce a codec with no reference to check against.
    Din70121,
    /// ISO 15118-2:2014.
    Iso2,
    /// ISO 15118-20:2022.
    Iso20,
}

impl Protocol {
    /// The XML namespace that identifies this protocol in the
    /// `supportedAppProtocol` handshake.
    #[must_use]
    pub const fn namespace(self) -> &'static str {
        match self {
            Self::Din70121 => "urn:din:70121:2012:MsgDef",
            Self::Iso2 => "urn:iso:15118:2:2013:MsgDef",
            Self::Iso20 => "urn:iso:std:iso:15118:-20:CommonMessages",
        }
    }

    /// Major/minor version numbers advertised alongside the namespace.
    #[must_use]
    #[allow(clippy::match_same_arms, reason = "one arm per protocol reads as a table")]
    pub const fn version(self) -> (u32, u32) {
        match self {
            Self::Din70121 => (2, 0),
            Self::Iso2 => (2, 0),
            Self::Iso20 => (1, 0),
        }
    }

    /// Recognises a protocol from its handshake namespace.
    #[must_use]
    pub fn from_namespace(ns: &str) -> Option<Self> {
        [Self::Din70121, Self::Iso2, Self::Iso20].into_iter().find(|p| p.namespace() == ns)
    }

    /// Whether this protocol requires TLS unconditionally.
    #[must_use]
    pub const fn requires_tls(self) -> bool {
        matches!(self, Self::Iso20)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespaces_round_trip() {
        for p in [Protocol::Din70121, Protocol::Iso2, Protocol::Iso20] {
            assert_eq!(Protocol::from_namespace(p.namespace()), Some(p));
        }
        assert_eq!(Protocol::from_namespace("urn:nope"), None);
    }

    #[test]
    fn only_dash_20_mandates_tls() {
        assert!(Protocol::Iso20.requires_tls());
        assert!(!Protocol::Iso2.requires_tls());
        assert!(!Protocol::Din70121.requires_tls());
    }

    #[test]
    fn newer_protocols_sort_higher() {
        // The SECC picks the most capable protocol both sides support, so the
        // ordering here is load-bearing.
        assert!(Protocol::Iso20 > Protocol::Iso2);
        assert!(Protocol::Iso2 > Protocol::Din70121);
    }
}
