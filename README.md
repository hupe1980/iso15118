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
> implied](https://hupe1980.github.io/iso15118/docs/roadmap/) — the V2G PKI
> above all.

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
   `xs:maxLength` — plus `#![forbid(unsafe_code)]` and nine fuzz targets. The
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
use iso15118::Protocol;
# use std::io::{Read, Write};
# fn now() -> Instant { Instant::ZERO }
# fn random_session_id() -> [u8; 8] { [0; 8] }
# fn my_logic(_: &Message) -> Result<Message, SeccError> { unimplemented!() }
# fn failure(_: &Message, _: u8) -> Message { unimplemented!() }
# fn run(stream: &mut std::net::TcpStream) -> Result<(), Box<dyn std::error::Error>> {
# let mut buf = [0u8; 4096];
let mut secc = Secc::new(SeccConfig {
    protocols: &[Protocol::Iso20, Protocol::Iso2],
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
            Event::ProtocolAgreed(p) => println!("speaking {p:?}"),
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
| **V2GTP** framing · **SDP** discovery | all payload types, hostile-length handling, bounded reassembly, TLS-downgrade rejection |
| **SLAC** (ISO 15118-3) | frame codec with every layout pinned byte for byte, timers, and the matching state machine for both roles |
| **ISO 15118-2** message set | all 34 body messages, `ds:Signature` included |
| **ISO 15118-20** message sets | `CommonMessages`, AC, DC, WPT, ACDP |
| **Session layer** | clock, spec timers and loop budgets, ordering graphs for both generations |
| **EVCC / SECC drivers** | handshake, sequencing, session-id stamping and checking, half-duplex in both directions, pause and resume — with a whole DC session per generation as an end-to-end test |
| **Plug & Charge signatures** | XMLDSig over EXI fragments, build and verify, algorithm restrictions enforced, and the two bindings that make a signature mean something: the `GenChallenge` for authorization and the echoed reading for metering |

⚠️ Not here: **V2G PKI** (X.509 path validation and the certificate flows),
transport bindings, DIN SPEC 70121. See
[what is not here](https://hupe1980.github.io/iso15118/docs/roadmap/).

## 🔬 Verification

Four layers, in increasing strength. Only the last two say anything about other
implementations.

```text
scripts/verify-grammars.sh   all 2 / 80 / 54 / 42 / 48 / 38 / 34 element
                             grammars agree with the reference  (298 total)
scripts/verify-messages.sh   all 121 documents round-trip against the reference
                             all 121 fragments round-trip against the reference
```

Between them, and the fuzzers, they have found nine defects no round-trip test
could — a dropped substitution-group head, mixed content on the wrong side of
`EE`, a string-table partition populated on a global hit, and six more.

The scripts prove the encoding and nothing above it. Reading the layers against
the standards, and against what EVerest and Josev do, found twenty-two more the
scripts cannot reach: a deadlocked DC renegotiation, a SLAC key handover any
station on the segment could forge, ISO 15118-20 service ids mapped to the wrong
flows, `xs:length` treated as `xs:maxLength` on the six types where a truncated
value is a security problem, and eighteen others. Each is a test.

Three of those found further defects on their first run — including a four-byte
ISO 15118-20 `SessionID` in this README, legal in ISO 15118-2 and not in -20,
which stopped compiling the moment the facet was enforced.

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
```

The last three need a JDK and the ISO schemas, which `scripts/fetch-schemas.sh`
downloads. Building or using the crate never needs them — `src/generated/` is
committed.

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

The API reference is on [docs.rs](https://docs.rs/iso15118).

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
