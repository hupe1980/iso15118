<h1 align="center">⚡ iso15118</h1>

<p align="center">
  <strong>ISO 15118 vehicle-to-grid communication in pure Rust.</strong><br>
  Sans-I/O, <code>no_std</code>-capable, both sides of the plug.
</p>

<p align="center">
  <a href="https://github.com/hupe1980/iso15118/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/hupe1980/iso15118/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://crates.io/crates/iso15118"><img alt="crates.io" src="https://img.shields.io/crates/v/iso15118.svg"></a>
  <a href="https://docs.rs/iso15118"><img alt="docs.rs" src="https://img.shields.io/docsrs/iso15118"></a>
  <a href="#-license"><img alt="License" src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue"></a>
</p>

<p align="center">
  <a href="https://hupe1980.github.io/iso15118/"><strong>Documentation</strong></a> ·
  <a href="https://hupe1980.github.io/iso15118/docs/getting-started/">Getting started</a> ·
  <a href="https://docs.rs/iso15118">API reference</a>
</p>

---

ISO 15118 is the protocol your car and a DC fast charger speak while deciding
whether to move 350 kW between them. This crate is the whole of it that runs on a
CPU: a schema-informed EXI codec generated from the official schemas, the
ISO 15118-2 and -20 message sets, HomePlug link setup, SECC discovery, V2GTP
framing, the message-ordering rules and spec timers of both generations,
sans-I/O session engines for either role, and the Plug & Charge signature profile.

No sockets, no clock, no async runtime, no cryptography in the core — those are
the caller's, and that is the point.

> 🚧 **Status: pre-1.0, but the protocol is real.** All 121 message types round-trip
> byte-for-byte against the EXI reference implementation, as documents *and* as
> signature fragments. `examples/` completes an AC charging session over a real
> socket. What is missing is [named rather than
> implied](https://hupe1980.github.io/iso15118/docs/roadmap/) — certificate
> revocation above all.

## 💡 Why

The implementations that exist are C ([OpenV2G], unmaintained), C++
([EVerest/libiso15118], tied to its runtime) or Python ([Josev], unusable on an
ECU). None lets you run the same protocol logic on a charge-point back end and on
a bare-metal microcontroller.

1. **Sans-I/O.** Bytes and a timestamp in; bytes, events and deadlines out. The
   pattern behind `quinn-proto` and `rustls` — and why a whole DC charging session
   runs as a unit test in microseconds, with time as a variable.
2. **`no_std` + `alloc`.** The core builds for `thumbv7em-none-eabihf`. Features
   are additive and every one gates real code, grammar tables included.
3. **A wire format someone else agrees with.** Round-tripping your own encoder
   through your own decoder proves they agree with each other and nothing more.
4. **A decoder you can point at the internet.** Every length bounded by *both* its
   schema facets before anything is allocated — `xs:length` is not
   `xs:maxLength` — plus `#![forbid(unsafe_code)]` and ten fuzz targets. The
   layers above hold the same line: half-duplex enforced in both directions, a
   SLAC engine that treats a malformed frame as weather rather than an error, and
   a Plug & Charge signature that has to name the session it arrived in.

[OpenV2G]: https://sourceforge.net/projects/openv2g/
[EVerest/libiso15118]: https://github.com/EVerest/libiso15118
[Josev]: https://github.com/SwitchEV/iso15118

## 📦 Install

```sh
cargo add iso15118
```

A DC-only embedded vehicle controller, with nothing else compiled in:

```sh
cargo add iso15118 --no-default-features --features evcc,iso20-dc,pnc
```

Rust 1.88 or newer.

## 🔌 A charging station, without a socket

The engine owns framing, decoding, the handshake, session-id checking, message
ordering and every spec timer. Your code owns the charging decisions.

```rust,no_run
use iso15118::message::Message;
use iso15118::secc::{Event, Secc, SeccConfig, SeccError};
use iso15118::session::{Instant, SessionId};
use iso15118::Protocols;
# use std::io::{Read, Write};
# fn now() -> Instant { Instant::ZERO }
# fn random_session_id() -> [u8; 8] { [0; 8] }
# fn my_logic(_: &Message) -> Result<Message, SeccError> { unimplemented!() }
# fn failure(_: &Message, _: u8) -> Message { unimplemented!() }
# fn run(stream: &mut std::net::TcpStream) -> Result<(), Box<dyn std::error::Error>> {
# let mut buf = [0u8; 4096];
let mut secc = Secc::new(SeccConfig {
    protocols: Protocols::ISO,                         // -20 and -2, whichever wins
    session_id: SessionId::new(random_session_id()),   // must be unpredictable
    ..SeccConfig::default()
});
secc.opened(now());

loop {
    let n = stream.read(&mut buf)?;
    secc.handle_input(now(), &buf[..n])?;

    while let Some(event) = secc.poll_event() {
        match event {
            // The handshake is pure protocol; the answer is already queued.
            Event::ProtocolAgreed(p) => println!("speaking {p}"),   // "iso15118-20"
            // This is where your charging station lives.
            Event::Request(req) => secc.respond(now(), my_logic(&req)?)?,
            // Out of sequence: answer with `response_code`, then it is over.
            Event::Refused { message, response_code, .. } => {
                secc.respond(now(), failure(&message, response_code))?;
            }
            Event::Closed(why) => return Ok(println!("session over: {why}")),
            _ => {}
        }
    }
    stream.write_all(&secc.take_transmit())?;
}
# }
```

Arm your own timer for `secc.poll_timeout()` and call `secc.handle_timeout(now)`
when it fires. That is the whole integration surface. `evcc::Evcc` is driven the
same way from the vehicle's side — it answers with `request` rather than
`respond`, because the vehicle chooses what to send rather than replying to it.

```sh
cargo run --example secc_tcp     # a minimal charging station
cargo run --example evcc_tcp     # ...and a car that charges from it
```

## 🏷️ Which generation

"ISO 15118" names two incompatible protocols, and the vocabularies around it are
careless about which — DATEX II's `VehicleToGridCommunicationTypeEnum`, which
European operators publish for AFIR compliance, spells its literal `iso15118`,
means ISO 15118-**20** by it, and has no literal for ISO 15118-2 at all.

So every name this crate emits says the generation, and it will not parse one that
does not.

```rust
use iso15118::{Protocol, Protocols};

// A short stable name for a CDR, a log line, a metric label, a database column.
assert_eq!(Protocol::Iso20.as_str(), "iso15118-20");
assert_eq!(Protocol::Iso20.title(), "ISO 15118-20:2022");
assert_eq!("iso15118-2".parse(), Ok(Protocol::Iso2));

// ...and it round-trips, so a value written under one release parses under the next.
let speaks: Protocols = "iso15118-20,iso15118-2".parse()?;
assert_eq!(speaks, Protocols::ISO);
assert_eq!(speaks.best(), Some(Protocol::Iso20));   // the newest it implements

// A bare "iso15118" is refused rather than guessed at, and says why.
let err = "iso15118".parse::<Protocol>().unwrap_err();
assert!(err.generation_omitted());
# Ok::<_, iso15118::ParseProtocolError>(())
```

`Protocol` is what a session negotiated; `Protocols` is what a piece of equipment
*implements* — a `Copy`, allocation-free set, and also what an EVCC offers and an
SECC accepts. A regulation binds a charge point by the second, whoever plugs in.

## 📨 Messages

```rust
use iso15118::exi::ExiDocument;
use iso15118::iso20::common::MessageHeader;
use iso15118::iso20::messages::{ChargingSession, SessionStopReq};

let req = SessionStopReq {
    header: MessageHeader {
        // ISO 15118-20 types SessionID as `length = 8` — exactly eight bytes,
        // not at most eight. A shorter one is a message a conforming charger
        // must reject, and this crate will not encode one.
        session_id: vec![0x3D, 0x4C, 0xBF, 0x93, 0x37, 0x4E, 0xD8, 0x9B],
        time_stamp: 1_725_456_343,
        signature: None,
    },
    charging_session: ChargingSession::Terminate,
    ev_termination_code: None,
    ev_termination_explanation: None,
};
let bytes = req.to_vec()?;
assert_eq!(SessionStopReq::from_bytes(&bytes)?, req);
# Ok::<_, iso15118::exi::ExiError>(())
```

## ✅ What works

| Layer | State |
|---|---|
| **EXI** codec — schema-informed, bit-packed | primitives, string table, grammars, header, documents **and fragments**, every length facet enforced both ways |
| **V2GTP** framing · **SDP** discovery | all payload types, hostile-length handling, bounded reassembly, an unsupported payload type *ignored* rather than fatal \[V2G2-800\]; discovery for **both** sides — the vehicle's retry engine with TLS-downgrade and off-link rejection, and the station's answer as the table \[V2G2-625\]–\[V2G2-627\] determine |
| **SLAC** (ISO 15118-3) | frame codec with every layout pinned byte for byte, timers, and the matching state machine for both roles |
| **ISO 15118-2** message set | all 34 body messages, `ds:Signature` included |
| **ISO 15118-20** message sets | `CommonMessages`, AC, DC, WPT, ACDP |
| **Session layer** | Plug & Charge refused on an unsecured transport \[V2G2-634\]; clock, spec timers and loop budgets **per role** — the station's half of every pair is the shorter one, so it answers `FAILED` while the vehicle is still listening — ordering graphs for both generations, and the ISO 15118-2 rule that a charging profile must fit the schedule it was offered, with the `ResponseCode` the standard prescribes |
| **EVCC / SECC drivers** | handshake, sequencing, session-id stamping and checking, half-duplex in both directions, pause and resume — with a whole DC session per generation as an end-to-end test |
| **Reading the battery** | `Message::ev_energy_status()` — state of charge, capacity, energy request and departure out of *either* generation, in exact integer milliwatt-hours, without the caller naming an EXI type |
| **Protocol identity** | `Protocol` / `Protocols` with stable short names, `Display`, `FromStr` and serde that all agree on one spelling |
| **Plug & Charge signatures** | XMLDSig over EXI fragments, build and verify, algorithm restrictions enforced, and the two bindings that make a signature mean something: the `GenChallenge` for authorization and the echoed reading for metering |
| **V2G PKI** | `pnc::pki` — an allocation-free DER/X.509 reader and RFC 5280 path validation under ISO 15118's own Annex F profiles: the depth limit \[V2G2-009\], `BasicConstraints` and `pathLenConstraint`, the key-usage bits each leaf row requires, and the `Domain Component` \[V2G2-925\] makes a validity condition |
| **Contract key delivery** | `pnc::envelope` — the one place a secret crosses the wire: one-pass ECDH \[V2G2-818\], the concatenation KDF, AES-128-CBC \[V2G2-815\], and \[V2G2-823\]'s check that the delivered key belongs to the certificate it came with, with no call that skips it |

⚠️ Not here: **certificate revocation** (no OCSP, no CRL — the standard makes it
a recommendation, and the answer belongs in the back end your station already
talks to), transport bindings, and the DIN SPEC 70121 *message set* — though the
handshake, the framing and the timers below it are generation-agnostic and
public, so a DIN codec of your own can ride them. See
[what is not here](https://hupe1980.github.io/iso15118/docs/roadmap/).

## 🔬 Verification

Four passes, each asking a question the others cannot. Only the first says
anything about other implementations.

```text
scripts/verify-grammars.sh   all 2 / 80 / 54 / 42 / 48 / 38 / 34 element
                             grammars agree with the reference  (298 total)
scripts/verify-messages.sh   all 121 documents round-trip against the reference
                             all 121 fragments round-trip against the reference
```

**Differential, against `exificient`.** The scripts above prove the encoding, and
catch what no round-trip can: a dropped substitution-group head, mixed content on
the wrong side of `EE`, a string-table partition populated on a global hit. The
same principle covers the two structures that are not EXI: the certificate chains
`pnc::pki` validates and the contract-key envelope `pnc::envelope` opens are both
built by **OpenSSL**, from the requirement text.

**Read against the standards**, and against what EVerest and Josev do — because
the scripts prove the encoding and nothing above it. `xs:length` is not
`xs:maxLength` on the six types where a truncated value is a security problem, a
DC renegotiation must not deadlock, ISO 15118-20 service ids belong to particular
flows. Each rule is a test.

**Adversarial**, for the engines on a shared, unauthenticated medium: not "is this
frame well-formed" but "what can a frame nobody can authenticate make this engine
*do*". Dropping a bad frame is half of not being steered by one; the other half is
that such a frame must set neither a deadline nor a queue length. So a refused SDP
answer does not end discovery, a forged attenuation report cannot postpone a SLAC
choice, and every queue an unauthenticated peer can reach is bounded.

**Citations checked against the text**, not against memory: every `[V2G2-nnn]`
names the requirement that states the rule it is attached to, and every timing
constant matches Table 109 and Table 111 — *both halves* of Table 109, the
timeouts each side enforces and the performance times each side owes.
`scripts/verify-citations.sh` does the mechanical half, confirming that each of
the 101 requirement numbers cited here exists among the standard's 852:
ISO 15118-2:2014(E) is a paid document that a US FHWA rulemaking docket publishes
in full, so this is checkable rather than asserted.

SLAC is the one wire format with no reference implementation to differ against,
so its thirteen message layouts are pinned byte for byte instead — checked field
for field against [EVerest's libslac], because "our encoder agrees with our
decoder" is not evidence and this crate says so on every other page.

[EVerest's libslac]: https://github.com/EVerest/libslac

[The full account →](https://hupe1980.github.io/iso15118/docs/verification/)

```sh
cargo test --workspace --all-features
cargo hack check -p iso15118 --feature-powerset --depth 2 --no-dev-deps
cargo +nightly fuzz run session fuzz/corpus/session fuzz/seeds/session

scripts/generate.sh && git diff --exit-code src/generated   # codegen has not drifted
scripts/verify-grammars.sh              # every grammar vs. the reference
scripts/verify-messages.sh              # every message, as document and fragment
scripts/verify-citations.sh             # every [V2G2-nnn] vs. the standard's text
```

Three of those need a JDK and the ISO schemas, which `scripts/fetch-schemas.sh`
downloads; the last needs `pdftotext` and network access. Building or using the
crate never needs any of them — `src/generated/` is committed.

## 📚 Documentation

| | |
|---|---|
| [Getting started](https://hupe1980.github.io/iso15118/docs/getting-started/) | Install, the five steps, a session end to end |
| [Architecture](https://hupe1980.github.io/iso15118/docs/architecture/) | The layers, and why each is separate |
| [Sessions and ordering](https://hupe1980.github.io/iso15118/docs/sessions/) | Which request is legal when, and what happens when one is not |
| [The EXI profile](https://hupe1980.github.io/iso15118/docs/exi/) | Every coding option ISO 15118 pins out of band |
| [Plug & Charge](https://hupe1980.github.io/iso15118/docs/plug-and-charge/) | What gets signed, and what a valid signature does not prove |
| [SLAC](https://hupe1980.github.io/iso15118/docs/slac/) | Which station this cable is plugged into |
| [Embedded and `no_std`](https://hupe1980.github.io/iso15118/docs/embedded/) | Shipping it on a microcontroller |
| [FAQ](https://hupe1980.github.io/iso15118/docs/faq/) | Short answers to the common questions |

The API reference is on [docs.rs](https://docs.rs/iso15118), and what changed
between releases is in [CHANGELOG.md](CHANGELOG.md).

## 🤝 Contributing

Issues and pull requests welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). A
change to any wire format needs a golden vector or a spec citation; "it
round-trips with itself" is not evidence that it matches what a charger will send.

## ⚖️ License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your
option.

ISO 15118 is a standard published by the International Organization for
Standardization. This is an independent implementation, not affiliated with or
endorsed by ISO, and no part of the standard is redistributed here.
