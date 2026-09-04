+++
title = "Architecture"
description = "The layering of the iso15118 crate: bit-level EXI, generated message sets, message dispatch, the session layer, and the sans-I/O role drivers on top."
weight = 20
+++

The crate is strictly layered, and every layer is usable on its own.
[`v2gtp`](https://docs.rs/iso15118/latest/iso15118/v2gtp/) and
[`sdp`](https://docs.rs/iso15118/latest/iso15118/sdp/) are plain byte codecs;
[`exi`](https://docs.rs/iso15118/latest/iso15118/exi/) is a usable
schema-informed EXI implementation in its own right.

```text
evcc / secc      role drivers: sessions, timers, decisions
session          clock, spec timers, message-ordering graphs
message          V2GTP payload type + negotiated protocol → typed message
iso2 / iso20     generated message types and codecs
exi              schema-informed EXI: documents and fragments
v2gtp  framing   sdp  discovery
slac             HomePlug link setup + matching state machines
                 pnc — Plug & Charge signatures, cross-cutting
```

## Sans-I/O, concretely

Every engine takes bytes and a timestamp and hands back bytes, events and
deadlines. The clock is `session::Instant`, a monotonic millisecond count you
supply. Nothing reads a clock, opens a socket, or spawns a task.

The payoff is not architectural purity. It is that a whole DC charging session
runs as a unit test in microseconds with time as a variable, so every spec timer
is a plain assertion rather than a field observation — and that the same protocol
logic runs under an async runtime and on a microcontroller with neither.

### Two kinds of deadline

A **per-message timeout** bounds the answer to one request: 250 ms for a DC
charge loop, seconds for anything that reaches a back end.

A **loop budget** bounds a whole phase. Several phases are not one exchange but a
repetition the peer keeps making while the answer is `..._Ongoing` —
authorization waiting on a driver, the DC isolation test, schedule exchange
waiting on a tariff. `V2G_EVCC_CableCheck_Timeout` is that kind, and it is the
one implementations leave as a documented constant, because the per-message
timeout looks like it already covers the case and does not: it restarts on every
repeat, so a station that answers `Ongoing` promptly for ever is never late.

The budget therefore starts on the **first** request of a phase and is not
restarted by the repeats. Both drivers arm it, because the two sides bound
different things: the vehicle bounds how long it waits, the station bounds its
own indecision.

### ...and every deadline is two numbers, not one

Those two things are bounded by *different values*, and the difference is the
point of having both. ISO 15118-2 Table 109 gives the same loop
`V2G_EVCC_Ongoing_Timeout` = 60 s for the vehicle and
`V2G_SECC_Ongoing_Performance_Time` = 55 s for the station, and \[V2G2-713\] says
what the station is to do when its own runs out: answer `FAILED` and stop the
session. The gap is the room in which that answer fits. Table 111 does the same
for the rest — 18 s against 20 s for communication setup, 38 against 40 for the
DC isolation test, 5 against 7 for the pre-charge.

A core that used one number for both roles would give the station a deadline it
can only reach *after* the vehicle has already abandoned the session: a timer
that can never fire in time to say anything, which is the same as not having one.
So `session::Role` is a parameter of every budget, and the drivers pass their own:

```rust
flow.loop_timeout(Role::Secc)   // the station's half — always the shorter
flow.loop_timeout(Role::Evcc)   // the vehicle's
```

The ordering within each pair is asserted at compile time, because inverting one
would not fail any other test — it would just quietly make the station's timer
unreachable.

And once the station's timer *can* fire in time, it has something to do with the
room: \[V2G2-713\] says a station that runs out of deciding time answers plain
`FAILED` and stops the session, rather than dropping the socket and leaving the
vehicle to report a timeout five seconds later. `Secc` surfaces that as
`Event::Overdue`, carrying the request to answer — and it arrives on the
vehicle's *next* request rather than the instant the timer fires, because a loop
budget expires between exchanges, with the station idle and nothing outstanding.

It is deliberately not `Event::Refused`. That one means the vehicle sent
something the flow does not allow and earns `FAILED_SequenceError`. This one is
the station's own indecision, and blaming the vehicle for it in the response code
would send a field engineer to the wrong end of the cable.

### Half-duplex, because the protocol is

Neither side may send again before the other has answered. The engines enforce
that rather than assuming it:

- `Secc` surfaces one request and reads nothing further until `respond` has been
  called. Anything the vehicle sent early waits, bounded by a cap on undrained
  frames.
- `Evcc` accepts a response only if it answers the request that is outstanding.

Both are protocol rules. Both are also what stops one unauthenticated peer from
queueing work without bound — several requests are legal repeatedly (a charge
loop turns, an authorization retries), and the ordering graph constrains requests
only, so without these checks a peer could build an event queue as large as it
cared to.

## Where the line between protocol and policy is

The engines own framing, decoding, the protocol handshake, session-id stamping and checking,
message ordering and the timers. They own nothing about charging: whether to
authorize a vehicle, which schedule to offer, how much current to deliver. Those
arrive as events and are answered with a message the application builds.

That is where the line is because everything above it is a decision a charge
point operator makes and everything below it is a decision ISO made. Only the
second kind belongs in a library.

## The layers

### `protocol`

Which generation, and which set of them. `Protocol` is what one session
negotiated; `Protocols` is what a piece of equipment implements — an ordered,
`Copy`, allocation-free set that is also what an EVCC offers and an SECC accepts.

It is its own layer rather than a detail of the handshake because it is the one
fact that outlives the session: a charge-detail record, a metric label, a
compliance feed and a datasheet all have to name a generation, and every one of
them should name it the same way. `Protocol::as_str` is that name — `"din70121"`,
`"iso15118-2"`, `"iso15118-20"` — with `Display`, `FromStr` and `serde` agreeing
on it and refusing the ambiguous bare `"iso15118"`.

### `exi`

Bit I/O over caller-owned slices, the EXI built-in datatypes, the value string
table, the grammar runtime and the document/fragment split. This is the layer
that touches unauthenticated bytes first, and it is the one with the most
adversarial thinking in it. See [The EXI profile](@/docs/exi.md).

### `iso2` and `iso20`

Generated message types and codecs, committed to the repository so a reader can
see the codec without running the generator. The generator is still the source of
truth — see [Code generation](@/docs/codegen.md).

Generated code carries **no state tables**. A content model's whole event-code
arithmetic is five short integer slices that a shared interpreter drives. The
equivalent unrolled state machine for one `maxOccurs="2048"` particle would be
2049 states, and ISO 15118-20 has several; here each costs one extra `u32`. That
is what makes the generated code fit on an ECU.

### `message`

A V2GTP frame carries a payload type and a blob. Turning that pair into a typed
message needs a fact the frame does not contain: which protocol generation the
session agreed on. Payload type `0x8001` is the `supportedAppProtocol` handshake
before negotiation, a DIN SPEC 70121 message if DIN won, and an ISO 15118-2
message if -2 won. Sniffing is not an option; the session has to remember.
`message::Message` is that dispatch, done once, in one place.

### `session`

The clock, the spec timers, V2GTP stream framing, the message-ordering graphs —
one per protocol generation, shared by both roles — and the ISO 15118-2 rule that
a `ChargingProfile` must fit the `SAScheduleTuple` it names. The sequencers hold no
buffers and no keys, so a session snapshot is small, `Clone` and
`serde`-serialisable, which is what ISO 15118-20 pause and resume across a power
cycle needs. See [Sessions and ordering](@/docs/sessions.md).

### `secc` and `evcc`

The role drivers: they join a `Connection`, a `Timers` set and a `Flow` into
something with an event loop, and surface the decisions the application has to
make.

### `slac` and `sdp`

Below the IP link: which station this cable is plugged into, and which port to
connect to. Both are separate engines with the same shape as the session drivers.
See [SLAC](@/docs/slac.md) and [Discovery and framing](@/docs/discovery.md).

### `pnc`

Cross-cutting, because a signature covers elements from whichever message set is
in use. It computes what to hash and what to sign and checks the result; it
contains no cryptography of its own. See [Plug & Charge](@/docs/plug-and-charge.md).
