+++
title = "Getting started"
description = "Install the iso15118 crate, pick your feature flags, and run a complete ISO 15118-2 charging session between a vehicle and a charging station over a real TCP socket."
weight = 10
+++

## Install

```sh
cargo add iso15118
```

The default features give you both protocol generations, both roles, discovery,
SLAC and the Plug & Charge signature profile. That is the right starting point on
a server. On a microcontroller you will want to narrow it — see
[Embedded and `no_std`](@/docs/embedded.md).

```sh
# A DC-only vehicle controller, with nothing else compiled in.
cargo add iso15118 --no-default-features --features evcc,iso20-dc,pnc
```

The crate needs Rust 1.88 or newer, builds without `std`, and contains no
`unsafe` — `#![forbid(unsafe_code)]` is set crate-wide, so it cannot acquire any.

## The five steps

Every engine in the crate is driven the same way, and learning it once covers all
of them:

```text
engine.handle_input(now, &bytes)?;   // bytes from the wire
engine.poll_event();                 // what happened, what is needed
engine.respond(now, message)?;       // your answer  (Evcc::request, the other way round)
engine.take_transmit();              // bytes for the wire
engine.poll_timeout();               // when to call handle_timeout
```

Those are `Secc`'s names. `Evcc` answers with `request` rather than `respond`,
because the vehicle chooses what to send rather than replying to it, and the
engines below IP — `sdp::Discovery` and `slac::matching` — take one complete
datagram or frame with `handle_datagram` / `handle_frame` and return one at a
time with `poll_transmit`, because there a boundary is meaningful. `handle_frame`
also returns nothing rather than a `Result`, because on a shared powerline
segment a malformed frame is not an error. The five steps are the same; see the
[overview](@/docs/_index.md#the-shape-of-every-engine) for the table.

You own the socket, the clock and the event loop. The engine owns the protocol.

## A charging station

`Secc` is the station's half of a session. It runs the `supportedAppProtocol`
handshake for you, checks every request against the session id it assigned and
against the message-ordering rules, and hands you the requests that are legal.
Answering them is your job, because the answer is a charging decision.

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
```

<div class="note">
<span class="note-title">Checked, not transcribed</span>
That sample is pinned to the crate's own README, which is compiled as a doctest —
a test in this repository fails if a line here stops matching the code it came
from. The same is true of every fenced block on this site that carries a
<code>pinned-to</code> marker.
</div>

The one remaining obligation is the clock: arm your own timer for
`secc.poll_timeout()` and call `secc.handle_timeout(now)` when it fires. That is
the whole integration surface.

<div class="note">
<span class="note-title">One request at a time</span>
V2G is half-duplex — neither side may send again before the other has answered.
So the station surfaces one <code>Event::Request</code> and reads nothing further
until <code>respond</code> has been called. That is the protocol, and it is also
what stops one unauthenticated peer from queueing work without bound.

The rule is symmetric, so the enforcement is too: <code>respond</code> refuses a
response that answers nothing or answers the wrong question, and
<code>Evcc::request</code> refuses a second request while the first is still
outstanding. Neither is something the ordering graph can catch — it constrains
<em>which</em> request, not <em>when</em>.
</div>

<div class="note">
<span class="note-title">You never write a session id</span>
The station assigns one in <code>SessionSetupRes</code> and every message of the
session repeats it, so it is not a per-message decision. <code>respond</code>
stamps it into every response and <code>Evcc::request</code> into every request —
the all-zero id before setup, the assigned one after. Leave the field empty and
the driver fills it.

Rejoining a paused session is the one case where the vehicle picks the id, and it
says so once, in <code>EvccConfig::rejoin</code>, rather than hand-placing it in
<code>SessionSetupReq</code>. That matters more than it looks: ISO 15118-2
tolerates a short or absent id and ISO 15118-20 requires exactly eight bytes, so
a field left to the application is a field that is right in one generation and
wrong in the other.
</div>

## A vehicle

`Evcc` is the mirror, and the asymmetry between them is the protocol's rather than
this crate's: the vehicle *drives*. It chooses what to send and when; the station
only ever answers. So where the station surfaces requests to be answered, the
vehicle accepts requests to be sent and surfaces the answers.

```rust,no_run
use iso15118::evcc::{Evcc, EvccConfig, Event};
use iso15118::{Protocol, Protocols};

let mut evcc = Evcc::new(EvccConfig {
    // Most preferred first — the charger is required to honour the order.
    // (`Protocols::ISO` is exactly this pair, in this order.)
    protocols: Protocols::new().with(Protocol::Iso20).with(Protocol::Iso2),
    ..EvccConfig::default()
});
evcc.start(now())?;                       // queues supportedAppProtocolReq

// ...then, once a protocol has been agreed:
evcc.request(now(), session_setup_req())?;
```

`Evcc::request` checks the ordering rules **before** the request reaches the
wire. A charger would answer `FAILED_SequenceError` and drop the session; finding
out locally, synchronously, with the offending message in hand, is better.

<div class="note">
<span class="note-title">What you configure is not always what goes on the wire</span>
Both sides narrow their configured set to the generations this build has a message
set for, <em>before</em> the handshake rather than after it. So a station
configured for <code>[din70121, iso15118-2]</code> meeting a vehicle that prefers
DIN still agrees on ISO 15118-2, rather than letting DIN win and then finding
there is no codec for it. A vehicle never advertises what it cannot speak, and
<code>Evcc::start</code> reports <code>NothingToOffer</code> if that leaves
nothing to offer.
</div>

## Run it

Two examples in the repository complete a real AC charging session over a real
socket — the integration story as code that runs, rather than as prose:

```sh
cargo run --example secc_tcp     # a minimal charging station
cargo run --example evcc_tcp     # ...and a car that charges from it
cargo run --example sdp_discovery -- eth0
```

And `tests/session.rs` runs a complete **DC** session — handshake, setup, service
discovery, authorization, cable check, pre-charge, charge loop, welding detection,
shutdown — through both engines with no I/O at all and time as a variable.

## Recording which generation you spoke

`Event::ProtocolAgreed` carries a `Protocol`, and it has a short stable name for
the places a protocol gets written down — a charge-detail record, a log line, a
metric label, a database column:

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

Every name says which generation, and a bare `"iso15118"` does not parse. That is
not fussiness: the DATEX II profile European operators publish for AFIR
compliance spells its literal `iso15118`, means ISO 15118-**20** by it, and has no
literal for ISO 15118-2 at all — so a name without a generation is one somebody
downstream has to guess at.

## Asking the vehicle's battery one question

The layer above the protocol almost always wants the same four things — state of
charge, battery capacity, how much energy is being asked for, and when the car is
leaving — and the two generations hide them in different places. ISO 15118-2 puts
a state of charge inside `DC_EVStatus`, which rides on six different requests, and
its energy figures in `ChargeParameterDiscoveryReq`; ISO 15118-20 puts the state
of charge in `DisplayParameters` on every charge-loop message and the energy
request in `ScheduleExchangeReq` or in a dynamic control mode.

`Message::ev_energy_status()` asks it once, for either generation:

```rust
// Whatever arrived — a -2 cable check, a -20 charge loop, a schedule exchange.
if let Some(energy) = message.ev_energy_status() {
    println!("{:?}% charged", energy.present_soc);
    println!("{:?} mWh capacity", energy.energy_capacity);
    println!("leaving in {:?} s", energy.departure_in);
}
```

Two things about the shape are deliberate. Every field is `Option`, because every
one of them is optional *somewhere* — an AC ISO 15118-2 session states no charge
level at all — and `None` means "this message did not say", never "zero". And
energy is exact integer **milliwatt-hours**, not a float: these numbers decide how
much energy a vehicle is sold. A value in a unit that is not watt-hours is dropped
rather than converted, on the principle that a wrong number is worse than no
number.

## What you still have to bring

Deliberately, and permanently:

- **TCP, TLS and UDP.** A sans-I/O engine consumes bytes; where they came from is
  not its business. The protocol requirements are still enforced where they *are*
  protocol: `Protocol::Iso20::requires_tls()` is `true`, and SDP refuses a
  security downgrade.
- **Raw Ethernet**, for SLAC. `slac::matching` produces and consumes complete
  frames and lets you move them.
- **Randomness.** Session ids, SLAC run ids, sounding payloads and the network
  membership key must be unpredictable. There is no RNG here, and every place one
  is needed says so and takes the bytes as configuration.
- **Cryptography.** The Plug & Charge layer is three one-method traits. The
  optional `pnc-rustcrypto` feature is one implementation of them.
- **A clock.** A monotonic millisecond count. Nothing here reads one.

## Next

- [Architecture](@/docs/architecture.md) — what each layer does and why it is separate.
- [Sessions and ordering](@/docs/sessions.md) — which request is legal when, and what happens when one is not.
- [Feature flags](@/docs/features.md) — how to compile only what you need.
