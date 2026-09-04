# Changelog

Notable changes, newest first. This project is pre-1.0: the minor version is the
breaking one, and it is bumped whenever the public API changes.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
versioning follows [Cargo's pre-1.0 semver](https://doc.rust-lang.org/cargo/reference/semver.html).

## [0.4.0] — unreleased

**The V2G PKI.** Certificate chains validate against ISO 15118's own Annex F
profiles and the encrypted contract private key can be taken out of its
envelope — the crate's largest named gap, now down to revocation. The spec
timers gain the half of ISO 15118-2's Table 109 that belongs to the answering
side; a stream fault ends the session instead of merely being reported; the
session state becomes storable; and Plug & Charge is refused on an unsecured
transport.

Twenty-two defects are fixed. Among them: an ISO 15118-20 authorization bypass,
a pause that could leave a cable live, a panic an unauthenticated peer could
trigger, and a stream fault that was reported without ending the session.

### Added

- `session::Role` — which side of the plug a budget belongs to. The V2G timing
  tables give the two roles *different* numbers for the same loop, so every loop
  budget is now asked for by role.
- The station's half of the timing tables, which was missing entirely:
  `SECC_COMMUNICATION_SETUP_PERFORMANCE_TIME` (18 s, \[V2G2-716\]),
  `SECC_ONGOING_PERFORMANCE_TIME` (55 s, \[V2G2-713\]),
  `SECC_CABLE_CHECK_PERFORMANCE_TIME` (38 s) and
  `SECC_PRE_CHARGE_PERFORMANCE_TIME` (5 s), all from Table 109 and Table 111,
  plus the -20 counterparts derived from them. The ordering within each pair is
  asserted at compile time.
- `secc::Event::Overdue` — the station ran out of deciding time and owes the
  vehicle a plain `FAILED` \[V2G2-713\]. Carries the request to answer. It
  replaces `Event::Refused` for that one request, because the vehicle did
  nothing wrong and `FAILED_SequenceError` would say otherwise.
- `secc::SeccError::NoSessionId` — refuses to answer `SessionSetupReq` with the
  all-zero placeholder, which \[V2G2-750\] forbids.
- `SupportedAppProtocolReq::advertised_protocol` — the inverse of the schema-id
  numbering `advertising` assigns, so the two directions cannot drift apart.
- `session::iso2::Phase::CertificateInstalled`.
- `PayloadType::Reserved`, `PayloadType::is_ignorable`, `PayloadType::belongs_to`
  and `Connection::ignored_frames` — the vocabulary \[V2G2-800\] needs.
- `session::Security`, `SeccConfig::security` and `EvccConfig::security` — the
  transport a session runs over, which the core cannot observe and which decides
  one rule that matters. It is the same type SDP negotiates (`sdp::Security` is
  now a re-export, not a twin), so the value flows from discovery into the
  session unchanged.
- `sdp::Response::answering` and `sdp::TlsPolicy` — the **station's** side of
  discovery, which ISO 15118-2 determines rather than leaves open:
  \[V2G2-625\] echoes the transport, \[V2G2-626\] answers a TLS request with TLS
  where it is supported, and \[V2G2-627\] *obliges* a station without TLS to
  answer one in plain. Only the vehicle's half existed, so every station on this
  crate was re-deriving a six-cell table from prose. `TlsPolicy::Required` is the
  row -2 does not spell out and -20 mandates.
- `tests/concepts.rs` — a guard over the maintainers' internal architecture
  notes: contiguous stable identifiers, no dangling citation or link, and the
  counts the prose states matching the entries there are. Skips when the
  gitignored `concepts/` directory is absent, which is what CI and every
  contributor see.
- `Message::ev_energy_status()` and `message::{EvEnergyStatus, MilliwattHours}` —
  the vehicle's state of charge, battery capacity, energy request and departure
  time read out of **either** generation into one small view, so a consumer above
  the protocol never names an EXI type. ISO 15118-2 hides a state of charge in
  `DC_EVStatus` across six requests and its energy figures in
  `ChargeParameterDiscoveryReq`; ISO 15118-20 puts one in `DisplayParameters` on
  every charge-loop message and the other in `ScheduleExchangeReq` or a dynamic
  control mode. Energy is exact integer milliwatt-hours — these numbers decide
  what a vehicle is sold — and a value in a unit that is not watt-hours is
  dropped rather than converted. Asked for by the `hems` workspace.
- Both halves of ISO 15118-2 Table 109's per-message timing, where only the
  vehicle's had existed: `SECC_MSG_PERFORMANCE_DEFAULT` (1,5 s),
  `SECC_MSG_PERFORMANCE_BACKEND` (4,5 s) and
  `SECC_MSG_PERFORMANCE_CURRENT_DEMAND` (**25 ms**), with
  `iso2::Request::performance_time` / `iso20::Request::performance_time` and
  `Secc::response_due()` to reach them. Performance times are not enforced and
  cannot be — missing one is the *peer* timing out, later, with nothing in this
  side's log — so what the engine owes the application is the number against the
  session clock. The 25 ms row is a constraint on where a DC charge loop's answer
  may come from, not on how tight the handler is.
- `Evcc::next_request_due()` and `iso20::EVCC_SEQUENCE_PERFORMANCE_TIME` — the
  vehicle's half of the same pair. \[V2G2-485\] and the thirty-odd clauses
  beside it give the EVCC 40 s from a response to have the next request out, and
  the station's `V2G_SECC_Sequence_Timeout` is twenty seconds behind that. The
  constant existed and nothing read it.
- `SeccConfig::max_pending_frames` and `EvccConfig::max_pending_frames` — the
  second reassembly ceiling, which the documentation had been telling constrained
  targets to lower while it was reachable only from `Connection::with_limits`.
- `secc::Close::Fatal` and `evcc::Close::Fatal` — the session ended because the
  byte stream stopped being one.
- `secc::SeccError::HandshakeRepeated` and `evcc::EvccError::AlreadyStarted` —
  the `supportedAppProtocol` handshake happens once \[V2G2-536\],
  \[V2G2-541\].
- `sdp::Event::Conflict` — a second, different, perfectly usable SDP answer. The
  refusals cover the answers a vehicle can *judge*; this covers the one it
  cannot, because a well-formed link-local answer offering exactly the requested
  security is indistinguishable from the real station's and the attacker's only
  job is to be first (arXiv 2512.15966 §3.2). The engine keeps listening after it
  has an answer and reports a second that disagrees; it deliberately does not
  decide.
- `session::Connection::reset_input` — drop what has arrived without discarding
  what is queued for the wire.
- **`pnc::pki` — the V2G PKI.** An allocation-free DER reader and X.509v3 parser
  over caller-owned bytes, RFC 5280 §6.1 basic path validation \[V2G2-885\],
  and the ISO 15118 Annex F certificate profiles:
  - `pki::validate` walks a chain to a configured trust anchor, checking every
    signature, every validity window, `BasicConstraints`, `pathLenConstraint`
    and `keyCertSign`, chaining issuer to subject by DER equality, and refusing
    a critical extension it cannot process — which RFC 5280 requires and Annex F
    quotes verbatim.
  - `pki::Profile` selects the Annex F table: `SeccCertificate`,
    `ContractCertificate`, `OemProvisioningCertificate`, or `Unchecked`. The
    profile is a *parameter* because \[V2G2-925\] makes it a validity
    condition — a chain that validates to the wrong root is exactly the failure
    that requirement names, and nothing in a certificate says which use it was
    issued for.
  - `MAX_PATH_LEN` = 3 \[V2G2-009\], counted over what arrived rather than
    over what is reached.
  - `pki::VerifyWith`, a sibling of `Verify` for a key that arrives *inside* the
    DER rather than in configuration, with `rustcrypto::Backend` implementing
    it. X.509's DER `ECDSA-Sig-Value` is converted to the raw `r ‖ s` pair
    inside the parser, so a backend implements one signature format for both a
    message and a certificate.
  - Time is seconds since the Unix epoch, supplied by the caller —
    deliberately not `session::Instant`, which is monotonic and cannot express a
    validity period.
  - **No revocation.** No OCSP, no CRL; the standard makes OCSP a recommendation
    because a charging vehicle cannot be assumed to reach a responder, and the
    answer belongs in the back end a station already talks to.
- **`pnc::envelope` — the contract private key, and the envelope it travels in.**
  `CertificateInstallationRes` and `CertificateUpdateRes` deliver a contract
  certificate *and its private key*, which is the one place in ISO 15118 where a
  secret crosses the wire:
  - `envelope::open` and `envelope::seal` do the one-pass ECDH of NIST
    SP 800-56A §6.2.2.2 \[V2G2-818\], the concatenation KDF with SHA-256 over
    the `OtherInfo` ISO 15118 pins, and AES-128-CBC with no padding
    \[V2G2-815\], \[V2G2-817\] — a private key is already a multiple of the
    block size, so \[V2G2-815\] NOTE 7 says there is none.
  - **\[V2G2-823\] is not optional.** `open` takes the contract certificate's
    public key and checks that the delivered scalar generates it, and there is
    no call that skips the check. A vehicle that installs an unchecked key has a
    contract it can never use and cannot diagnose: every signature it makes is
    valid, over the wrong key, and every station refuses it.
  - `envelope::KeyAgreement` and `envelope::Aes128Cbc` are traits, so the
    contract key can stay inside a secure element. `KeyAgreement` sits beside
    `Sign` rather than on it because \[V2G2-822\] makes key agreement a
    different capability on a different set of certificates —
    `rustcrypto::AgreementKey` is a separate type from `SigningKey` for that
    reason, and `rustcrypto::Aes128` is the cipher.
  - The randomness stays the caller's: sealing takes the ephemeral key and the
    IV, which \[V2G2-815\] requires to be random and never reused.
- `scripts/make-test-envelope.sh` — has **OpenSSL** do the ECDH, the KDF and the
  cipher, so `tests/envelope.rs` opens a `ContractSignatureEncryptedPrivateKey` a
  third implementation sealed. Every mistake that matters there is invisible to a
  crate testing itself: a counter left out of the KDF, `OtherInfo` in the wrong
  order, the digest truncated from the wrong end, the IV read off the tail.
- `PncError::{BadEnvelope, KeyMismatch}`.
- `scripts/make-test-pki.sh` — mints the V2G chains `tests/pki.rs` validates,
  with **OpenSSL**, so the certificates are DER a third implementation encoded.
  It found a defect on its first run. Validity windows are absolute dates, so the
  fixtures do not rot.
- A tenth fuzz target, `certificate`, over the crate's only hand-written parser.
  It asserts that every borrowed field lies inside the input, not merely that
  nothing panicked.
- `pnc::MAX_SIGNED_ELEMENTS` — \[V2G2-909\]'s limit of four signed elements,
  which the xmldsig schema ISO 15118 imports does not carry.
- `PncError::{TooManyReferences, ForbiddenField}`.
- `scripts/verify-citations.sh` — fetches the text of ISO 15118-2:2014(E) from
  the US FHWA rulemaking docket that publishes it in full, and checks that every
  one of the 101 `[V2G2-nnn]` this repository cites names a requirement the
  standard actually defines (of its 852). The evidence standard's third item — "a
  citation somebody actually read" — was the only one nothing checked.

### Changed

**Breaking.**

- `Flow::new` and `session::iso2::Sequencer::new` take a `Security`. The -2
  sequencer has no `Default` any more: the safe value is the restrictive one, and
  a `Default` would pick a side of a security decision for the caller.
- `PayloadType::from_u16` is infallible and returns `PayloadType` rather than a
  `Result`: a code outside Table 10's assignments is not a malformed *header*,
  and refusing to parse it discards the length field that makes the message
  skippable. `V2gtpError::UnknownPayloadType` is gone.
- `MessageError::Unsupported` splits into `NotForThisSession` (ignored) and
  `NoCodec` (reported). They were one variant covering two different faults.
- `Flow::loop_timeout`, `iso2::Phase::loop_timeout`, `iso20::Phase::loop_timeout`
  and both `Sequencer::loop_timeout` take a `session::Role`. There is no single
  right answer to return without one.
- `SeccConfig::setup_timeout` defaults to the station's own 18 s
  \[V2G2-716\] rather than the vehicle's 20 s.
- **`Evcc::handle_input` now takes a timestamp**, like `Secc::handle_input`. The
  old signature came with a documented reason — "nothing a *response* triggers
  starts a deadline" — and \[V2G2-485\] is a response starting one. The engines
  are symmetric because the standard is.
- **An error from `handle_input` now closes the session**, on both sides, before
  the error is returned: timers disarmed, input buffers dropped,
  `Event::Closed(Close::Fatal)` queued. A caller that logs and reads again — the
  ordinary shape of a server loop — used to be talking to a live engine.
- `pnc::iso2::build_signed_info` and `pnc::iso20::build_signed_info` return a
  `Result`: more than four signed elements is \[V2G2-909\] and is refused on
  the way out as well as on the way in.
- `sdp::Discovery` holds two unread events rather than one: the outcome, and the
  latest refusal or conflict. A refusal used to be displaced by the answer that
  followed it, which threw away the only sign a vehicle gets that something else
  on the segment is answering.

### Fixed

- **A fatal stream fault was reported and not acted on.** A framing error, a
  payload the negotiated grammar would not decode, or a peer pipelining past the
  frame ceiling returned an `Err` from `handle_input` and left the engine open:
  `is_closed()` false, every timer still armed, no `Event::Closed`, and the
  frames the peer had queued *behind* the fault still waiting to be decoded on
  the next call. The engine now closes itself first. This is the same shape as
  the finding that made refusal-handling non-configurable — a correctly detected
  fault an application is free to ignore is not enforcement — and the session
  fuzz target now asserts it against arbitrary bytes at arbitrary read
  boundaries.
- **A second `supportedAppProtocolReq` would have reset the ordering graph**,
  discarding the payment option, the energy transfer mode and the failure latch,
  so a peer with nothing left but `SessionStopReq` would have been back at the
  top of the flow. Not reachable — `Connection` remembers the negotiated
  generation, so payload type `0x8001` no longer decodes as the handshake — but
  the argument ran through another file, which is the state the null-session-id
  CVE was in. Refused locally now, as \[V2G2-536\] and \[V2G2-541\] require.
  `Evcc::start` refuses a second call for the same reason.
- **`max_pending_frames` was unreachable from the role drivers.** Three documents
  told a constrained target to lower it; only `Connection::with_limits` took it,
  and `Secc::new`/`Evcc::new` called `Connection::with_limit`.
- **The first usable SDP answer won silently**, and every later one was dropped
  without a word — including the real station's, when a spoofer answered first.
- **A signature could name more elements than \[V2G2-909\] allows.** The bound
  looked covered because `verify` compares the reference count against the
  element count the caller supplied — which makes it a property of the call site
  rather than of the profile. It is a clause of its own now, in both directions.
- **Three fields \[V2G2-771\] forbids were ignored rather than refused**:
  `SignedInfo/@Id`, `Reference/@Type` and `SignatureValue/@Id`. They are ordinary
  optional attributes the schema carries, so nothing refused them by accident.
  `HMACOutputLength` from the same list was already refused on the argument that
  a signature using a field the profile excludes is not a signature this profile
  describes; that argument applies unchanged.
- **The documented reason for accepting non-minimal EXI integers was wrong.**
  Three documents said signatures are computed over the bytes as received, so a
  re-encoding never has to match. ISO 15118-2 Annex J.4 says the opposite: the
  digest check de-references the signed element and *re-encodes* it as a
  fragment, and `SignedInfo` is canonicalised the same way. The leniency stands —
  canonical EXI requires the minimal form, so a peer that signs non-canonical
  bytes has produced a signature nothing reproduces — but its scope is now
  stated: interoperability on unsigned content, and nothing on signed content.
- The fallback response code in `Secc`'s unreachable "no negotiated generation"
  branches was `0`, which is `OK` in both schemas. An unreachable branch that
  fails open is one edit from a reachable one that says the request was fine.
- **An ISO 15118-20 peer could charge without ever authorizing.**
  `SessionStopReq` with `ChargingSession = ServiceRenegotiation` returns the flow
  to the phase from which `ServiceDiscoveryReq` is legal — which in -20 is the
  phase *after* authorization — and it was accepted from any established phase.
  From `SessionSetup` it was therefore not a shortcut but an authorization
  bypass: a session that never sent an `AuthorizationReq` reached
  `PowerDeliveryReq(Start)` with every request legal on the way. It is now
  accepted only once a service has been selected, which is also the only point
  at which the word means anything.
- **A vehicle could pause a session with the power still flowing.** A pause takes
  the transport connection down with it \[V2G2-739\], and §8.4.1 permits one only
  after `PowerDeliveryReq` with `ChargeProgress = Stop`. Accepted from the charge
  loop it ended the conversation with the contactors closed and the link at
  battery voltage. `Pause` is now refused in the phases where the cable is live —
  the charge loop, and in DC the cable check and pre-charge — in both
  generations. `Terminate` is unchanged and still legal from any established
  phase, because an abort is exactly the case where the vehicle cannot tidy up
  first.
- **The station's loop budgets were the vehicle's numbers, so they could never
  fire in time to say anything.** Table 109 and Table 111 give the SECC 55 s
  against the EVCC's 60 for the same `..._Ongoing` loop, and 38 against 40 for
  the DC isolation test, precisely so the station can answer `FAILED` while the
  vehicle is still listening \[V2G2-713\]. Armed with the vehicle's figure the
  station's timer only ever expired after the vehicle had abandoned the session.
  Budgets are now per role, and the expiry surfaces as `Event::Overdue` rather
  than dropping the socket.
- **A DC vehicle that stopped power delivery could not renegotiate.**
  \[V2G2-601\] makes `ChargeParameterDiscoveryReq` a legal next request after
  `PowerDeliveryRes` for `ChargeProgress = Stop`, alongside welding detection and
  the session stop, and \[V2G2-797\] allows the same out of the charge loop after
  a metering receipt. Both were refused with `FAILED_SequenceError`. Any return
  to parameter discovery from a charge already under way now counts as a
  renegotiation, so the way back up does not demand an isolation test on a cable
  that was never disconnected.
- **A peer with no credentials could keep a certificate pool busy indefinitely.**
  `CertificateInstallationReq` returned the flow to its own phase, leaving a
  second one legal — and each request restarts the sequence timer, so the loop
  had no end. \[V2G2-554\], \[V2G2-557\] and \[V2G2-558\] leave
  `PaymentDetailsReq` as the only legal next request either way, which is now
  what the graph says.
- **A station could assign the all-zero session id.** `SeccConfig::session_id`
  has no usable default — the crate has no RNG — and the placeholder it starts at
  is the one value \[V2G2-750\] forbids. Left unset it went on the wire, leaving
  the vehicle nothing to check later messages against. `Secc::respond` now
  refuses, on the side that can still fix it.
- **The session state was not `serde`-serialisable, and three documents said it
  was.** Pause and resume across a power cycle rests on storing a session
  snapshot. Every *field* of `Sequencer` derived `Serialize`/`Deserialize` — the
  phase, the transfer mode, the payment option, the service — and the two structs
  and `Flow` did not, so the gap was invisible from anywhere except a call that
  tried it. The test that pins it asserts the restored flow **decides** the same
  way, not merely that the fields round-trip.
- **Plug & Charge was permitted over a plaintext session.** ISO 15118-2 forbids
  it outright — \[V2G2-634\] to the station, \[V2G2-635\] to the vehicle, with
  \[V2G2-633\] leaving such a session external identification and nothing else —
  and the ordering graph had no way to know, so a contract selection was accepted
  and the certificate chain, the authorization signature and the EMAID would all
  have travelled in clear. The graph now refuses
  `PaymentServiceSelectionReq(Contract)` unless the caller has said the transport
  is secured. The default is the restrictive one.
- **A doc comment said a station "may never answer with less security" than
  requested.** \[V2G2-627\] says the opposite: a station without TLS *shall*
  answer a TLS request with "No transport layer security". The behaviour was
  right — the vehicle refuses it by default — but the stated reason was wrong in
  a way that would mislead anyone implementing the station side, which is now
  `Response::answering`. What `satisfies` reports is the choice \[V2G2-628\]
  gives the vehicle, not an accusation.
- **An unsupported V2GTP payload type ended the session, where \[V2G2-800\] says
  to ignore the message.** A manufacturer-specific frame — `0xA000..=0xFFFF`,
  which Table 10 reserves for exactly that — killed a charge, as did a reserved
  code and a payload type from a generation the session had not negotiated. All
  three arrive in a header that is otherwise intact, so the frame boundary is
  trustworthy and the frame is skippable; `Connection::next_message` now skips
  them and counts them in `ignored_frames()`. The security property is
  unchanged: a peer still cannot get a -20 message processed in a -2 session, it
  just cannot end the session by trying either. A payload type that *does*
  belong to the session and has no codec — `0x8001` under DIN SPEC 70121 — is
  still reported, because silently dropping it would look like a peer that had
  gone quiet.
- **`AttenProfile::groups` panicked on a group count larger than the array.**
  Both fields are public, as on every wire record in that module, and
  `Evse::observe` takes a caller-built profile — so a count above the 58 groups
  that exist reached a slice index. The codec refuses one in both directions, so
  the only way in was by hand or through `serde`, but on an ECU a panic is a
  reset. The accessor now clamps, which makes `mean_attenuation` total, and the
  SLAC fuzz target drives `observe` with an arbitrary count.
- **The session-id check compared against a configured default.** With an
  all-zero id configured, a request carrying all zeroes would compare equal and
  be admitted to an established session — the shape of CVE-2025-68140 in
  `EVerest`'s `EvseV2G`. It was unreachable here, but only via a three-step
  argument through `Secc::respond` and the outstanding-request gate. The check
  now refuses the all-zero id as its own clause, so the property is local.
- **A SLAC retry inherited the failed run's stations and measurements.**
  ISO 15118-3 gives the vehicle `C_EV_match_retry` attempts, and `Ev::start`
  carried the previous attempt's station list and best measurement into the next
  one — so a retry could address `CM_SLAC_MATCH.REQ` to a station that had not
  answered it. A retry now starts from nothing.
- `Encoder::restricted` / `Decoder::restricted` coded a value in *zero* bits
  rather than sixty-four for a range spanning the whole of `i64`, where the
  "+1 for the count of values" wrapped. No V2G schema has such a range — the
  widest is `12..=1024` — but the facets are data.

## [0.3.0] — 2026-09-01

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

[0.4.0]: https://github.com/hupe1980/iso15118/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/hupe1980/iso15118/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/hupe1980/iso15118/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/hupe1980/iso15118/releases/tag/v0.1.0
