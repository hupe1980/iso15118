# Changelog

Notable changes, newest first. This project is pre-1.0: the minor version is the
breaking one, and it is bumped whenever the public API changes.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
versioning follows [Cargo's pre-1.0 semver](https://doc.rust-lang.org/cargo/reference/semver.html).

## [0.3.0] — unreleased

Protocol identity gets a stable name, six defects are fixed — four of them things
an unauthenticated peer on the segment could exploit — and the ISO 15118-2
charging-profile rule is implemented.

### Added

- `Protocol::as_str` — a short stable name (`"din70121"`, `"iso15118-2"`,
  `"iso15118-20"`) for a charge-detail record, a log line or a database column,
  with `Display` and `FromStr` round-tripping it. `FromStr` also accepts a
  handshake namespace, and refuses a bare `"iso15118"` with an error that says
  which generation is missing (`ParseProtocolError::generation_omitted`).
- `Protocol::title` for what a person reads, `Protocol::ALL` and
  `Protocol::COUNT`.
- `Protocols` — an ordered, `Copy`, allocation-free, `const`-constructible set of
  generations. What an EVCC offers, what an SECC accepts, and what a piece of
  equipment implements. `Display`/`FromStr` as one comma-separated token, so a
  supported set can live in a configuration file.
- `session::Flow::supports` — whether this build has the message set for a
  generation.
- `session::iso2::schedule` — the ISO 15118-2 rule that a `ChargingProfile` must
  fit the `SAScheduleTuple` it names \[V2G2-224\], \[V2G2-225\], \[V2G2-479\],
  with `ProfileError::response_code` giving the code the standard prescribes.
  Comparison is in exact integer milliwatts and the unit is checked, not assumed.
- `session::Connection::next_frame` / `send_frame` — the crate's V2GTP framing
  and its bounds, with the decode left to the caller. The seam for a message set
  this crate does not have; see the DIN SPEC 70121 answer in the documentation.
- `SupportedAppProtocolReq::protocol_for_schema_id`.
- `sdp::Discovery::allow_off_link`, `sdp::Refusal`.
- `EvccError::NothingToOffer` and `SdpError::InvalidAddress`.
- `slac::matching::{MAX_STATIONS, MAX_PENDING_EVENTS, MAX_PENDING_FRAMES}`.

### Changed

**Breaking.**

- `SeccConfig::protocols` and `EvccConfig::protocols` are `Protocols`, not
  `&'static [Protocol]`. A supported set read from a configuration file no
  longer has to be leaked to get a `'static` lifetime.
- `Protocol`'s `serde` representation is the stable short name (`"iso15118-20"`)
  rather than the Rust variant name (`"Iso20"`), so serde, `Display` and a
  hand-written `match` all produce one spelling. The variant name no longer
  deserialises.
- `SupportedAppProtocolReq::advertising` and `negotiate` take
  `impl Into<Protocols>`.
- `sdp::Event::Refused` is a struct variant carrying a `Refusal` reason.
- `Protocol` moved to the `protocol` module; it is still re-exported at the crate
  root.

### Fixed

- **An SECC declined sessions it could have served.** Generations with no message
  set were filtered *after* negotiation, so a vehicle preferring DIN SPEC 70121
  with ISO 15118-2 as its fallback let DIN win on priority and then took the
  whole session down — when both sides had a generation in common in the same
  request. The narrowing now happens before negotiation.
- **An EVCC could map a schema id onto a protocol it never offered.** The
  charger's echoed id was indexed into the *configured* list rather than the
  advertised one. A vehicle no longer advertises what it cannot speak, and
  `Evcc::start` reports `NothingToOffer` when that leaves nothing.
- **One spoofed datagram ended SDP discovery.** Any well-formed answer was
  terminal, including a refused one, so anything on the segment could answer
  first with a TLS downgrade and the real station's answer was discarded. Only a
  usable answer is terminal now; a refusal is reported and the run carries on.
- **An SDP answer could redirect a vehicle off the link.** The address it names
  is where the vehicle opens its connection, and nothing checked it. A
  non-link-local address is now `Refusal::OffLink` by default —
  `Discovery::allow_off_link(true)` for a test rig on an ordinary LAN — and the
  codec refuses the unspecified address and multicast groups outright, as it
  always did port `0`.
- **A forged `CM_ATTEN_CHAR.IND` postponed the SLAC choice for ever.** Every
  accepted report re-armed the measurement window, and everything a forgery needs
  is broadcast in the clear during sounding. A report can now move the choice
  earlier and never later.
- **Three SLAC collections grew on an unauthenticated peer's say-so** — the
  station list (keyed by an Ethernet source MAC), both event queues and the
  outgoing frame queue. All bounded; terminal events are never dropped.
- Four `[V2G2-nnn]` citations named unrelated requirements — message-set support
  and data-link pausing rather than the rules they were attached to — and one
  named the `Failed_NoNegotiation` rule for a claim about priority. Corrected
  against the standard's text. Every timing constant was checked against
  Table 109 and Table 111 and matched.

## [0.2.0] — 2026-08-30

## [0.1.0] — 2026-08-30

Earlier releases predate this file.

[0.3.0]: https://github.com/hupe1980/iso15118/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/hupe1980/iso15118/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/hupe1980/iso15118/releases/tag/v0.1.0
