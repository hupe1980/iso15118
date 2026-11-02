+++
title = "Getting started"
description = "Install the iso15118 crate, pick your feature flags, and run a complete ISO 15118-2 charging session between a vehicle and a charging station over a real TCP socket."
weight = 10
+++

## Install

```sh
cargo add iso15118
```

The defaults give both generations, both roles, discovery, SLAC and the Plug &
Charge signature profile. On a microcontroller, narrow them — see
[Embedded and `no_std`](@/docs/embedded.md):

```sh
# A DC-only vehicle controller, with nothing else compiled in.
cargo add iso15118 --no-default-features --features evcc,iso20-dc,pnc
```

Rust 1.88 or newer. `#![forbid(unsafe_code)]` crate-wide.

## The five calls

Every engine is driven the same way:

```text
engine.handle_input(now, &bytes)?;   // bytes from the wire
engine.poll_event();                 // what happened, what is needed
engine.respond(now, message)?;       // your answer  (Evcc::request, the other way round)
engine.take_transmit();              // bytes for the wire
engine.poll_timeout();               // when to call handle_timeout
```

`Evcc` sends with `request`, because the vehicle drives. `sdp::Discovery` and
`slac::matching` take whole datagrams or frames (`handle_datagram`,
`handle_frame`) and emit them with `poll_transmit`. You own the socket, the clock
and the event loop; see the [overview](@/docs/_index.md#the-shape-of-every-engine).

## A charging station

`Secc` runs the handshake, checks every request against the session id and the
ordering rules, and hands you the legal ones. Answering is your charging logic.

<!-- pinned-to: README.md -->
```rust
use iso15118::message::Message;
use iso15118::secc::{Event, Secc, SeccConfig, SeccError};
use iso15118::session::{Instant, SessionId};
use iso15118::Protocols;

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
            Event::ProtocolAgreed(p) => println!("speaking {p}"),   // "iso15118-20"
            Event::Request(req) => secc.respond(now(), my_logic(&req)?)?,
            // Out of sequence: `refusal` builds the answer, and it always encodes.
            Event::Refused { message, response_code, .. } => {
                if let Some(no) = message.refusal(response_code) {
                    secc.respond(now(), no)?;
                }
            }
            Event::Closed(why) => return Ok(println!("session over: {why}")),
            _ => {}
        }
    }
    stream.write_all(&secc.take_transmit())?;
}
```

Arm a timer for `secc.poll_timeout()` and call `secc.handle_timeout(now)` when it
fires.

- **One request at a time.** V2G is half-duplex: the station surfaces one
  `Event::Request` and reads nothing further until `respond`. `respond` refuses an
  answer to nothing; `Evcc::request` refuses a second outstanding request.
- **You never write a session id.** `respond` and `Evcc::request` stamp it. A
  vehicle rejoining a paused session names the id once, in `EvccConfig::rejoin`.
- **The station agrees only to what it can run.** `SeccConfig::iso20_sets`
  (default: every ISO 15118-20 message set compiled in) narrows which -20 entries
  of the vehicle's offer count; `Secc::iso20_set()` reports which one won.

## A vehicle

```rust,no_run
use iso15118::evcc::{Evcc, EvccConfig, Event};
use iso15118::{Iso20Set, Protocol, Protocols};

let mut evcc = Evcc::new(EvccConfig {
    // Most preferred first — the charger is required to honour the order.
    // (`Protocols::ISO` is exactly this pair, in this order.)
    protocols: Protocols::new().with(Protocol::Iso20).with(Protocol::Iso2),
    // ISO 15118-20 is offered once per message set the vehicle can run; DC then
    // AC is the default, and what every deployed station recognises.
    iso20_sets: vec![Iso20Set::Dc, Iso20Set::Ac],
    ..EvccConfig::default()
});
evcc.start(now())?;                       // queues supportedAppProtocolReq

// ...then, once a protocol has been agreed:
evcc.request(now(), session_setup_req())?;
```

`Evcc::request` checks the ordering rules before anything reaches the wire. Both
sides drop generations and -20 message sets this build cannot speak before the
handshake; `Evcc::start` reports `NothingToOffer` if nothing is left.

## Run it

```sh
cargo run --example secc_tcp     # a minimal charging station
cargo run --example evcc_tcp     # ...and a car that charges from it
cargo run --example sdp_discovery -- eth0
```

The two TCP examples complete an AC session against each other.
`tests/session.rs` runs a whole DC session through both engines with no I/O.
`examples/v2g_node` runs either role on a real link — SDP, then TCP — and is
what [runs against Josev and EVerest](@/docs/verification.md#live-peers).

## Recording which generation you spoke

```rust
use iso15118::{Protocol, Protocols};

assert_eq!(Protocol::Iso20.as_str(), "iso15118-20");
assert_eq!(Protocol::Iso20.title(), "ISO 15118-20:2022");
assert_eq!("iso15118-2".parse(), Ok(Protocol::Iso2));   // ...and back again

// `Protocols` is the set form, printed and parsed as one comma-separated token,
// so a supported set can live in a config file or an environment variable.
let station: Protocols = "iso15118-20,iso15118-2".parse()?;
assert_eq!(station.best(), Some(Protocol::Iso20));
```

A bare `"iso15118"` does not parse: DATEX II's AFIR profile uses that literal for
ISO 15118-20 and has none for -2, so a name without a generation is ambiguous.

## Reading the battery

`Message::ev_energy_status()` reads state of charge, capacity, energy request and
departure out of either generation:

```rust
// Whatever arrived — a -2 cable check, a -20 charge loop, a schedule exchange.
if let Some(energy) = message.ev_energy_status() {
    println!("{:?}% charged", energy.present_soc);
    println!("{:?} mWh capacity", energy.energy_capacity);
    println!("leaving in {:?} s", energy.departure_in);
}
```

Every field is `Option` — `None` means "this message did not say". Energy is exact
integer milliwatt-hours; a value in a unit other than watt-hours is dropped, not
converted.

## What you bring

- **TCP, TLS, UDP** — and raw Ethernet for SLAC.
- **Randomness** — session ids, `GenChallenge`, SLAC run ids, sounding payloads,
  the NMK. Each place that needs it takes the bytes as input.
- **Cryptography** — three one-method traits; `pnc-rustcrypto` implements them.
- **A monotonic millisecond clock.**

## Next

- [Architecture](@/docs/architecture.md) — the layers.
- [Sessions and ordering](@/docs/sessions.md) — which request is legal when.
- [Feature flags](@/docs/features.md) — compiling only what you need.
