+++
title = "Architecture"
description = "The layering of the iso15118 crate: bit-level EXI, generated message sets, message dispatch, the session layer, and the sans-I/O role drivers on top."
weight = 20
+++

The crate is strictly layered, and every layer is usable on its own:
[`v2gtp`](https://docs.rs/iso15118/latest/iso15118/v2gtp/) and
[`sdp`](https://docs.rs/iso15118/latest/iso15118/sdp/) are plain byte codecs,
[`exi`](https://docs.rs/iso15118/latest/iso15118/exi/) a schema-informed EXI
implementation in its own right.

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

## Sans-I/O

Every engine takes bytes and a timestamp and returns bytes, events and deadlines.
The clock is `session::Instant`, a monotonic millisecond count you supply. So a
whole DC session runs as a unit test with time as a variable, and the same logic
runs under an async runtime and on a microcontroller.

### Two kinds of deadline

- A **per-message timeout** bounds the answer to one request: 250 ms in a DC
  charge loop, seconds for anything that reaches a back end.
- A **loop budget** bounds a whole phase the peer repeats while the answer is
  `..._Ongoing` — authorization, the DC isolation test, schedule exchange. It
  starts on the first request of the phase and the repeats do not restart it; a
  per-message timeout alone would let a station answer `Ongoing` for ever.

### Every deadline is two numbers

ISO 15118-2 gives each role its own value for the same loop, the station's
shorter: 55 s against 60 s for `Ongoing`, 18 against 20 for communication setup,
38 against 40 for the isolation test, 5 against 7 for pre-charge. The gap is where
the station's `FAILED` fits \[V2G2-713\]. So every budget takes the role, and the
ordering within each pair is asserted at compile time:

```rust,ignore
flow.loop_timeout(Role::Secc, budgets)   // the station's half — always the shorter
flow.loop_timeout(Role::Evcc, budgets)   // the vehicle's
```

`budgets` is the deployment's `LoopBudgets`, usually the default — see
[Sessions](@/docs/sessions.md#loop-budgets-a-deployment-can-set).

When the station's own budget runs out, `Secc` surfaces `Event::Overdue` with the
request to answer with plain `FAILED` — not `Event::Refused`, which means the
*vehicle* broke the flow and earns `FAILED_SequenceError`.

### Half-duplex

`Secc` surfaces one request and reads nothing further until `respond`; `Evcc`
accepts only a response to the request outstanding. Several requests are legal
repeatedly, so this — not the ordering graph — is what stops a peer queueing work
without bound.

## Protocol, not policy

The engines own framing, decoding, the handshake, session ids, ordering and
timers. Whether to authorize, which schedule to offer and how much current to
deliver arrive as events and are answered with a message the application builds.

## The layers

**`protocol`** — `Protocol` is what one session negotiated; `Protocols` what a
device implements (an ordered, `Copy`, allocation-free set). `Protocol::as_str` is
the stable name — `"din70121"`, `"iso15118-2"`, `"iso15118-20"` — shared by
`Display`, `FromStr` and `serde`. In the handshake ISO 15118-20 names a *message
set*: `Iso20Set` lists the six namespaces, all read as -20. The vehicle offers one
entry per set it can run (`EvccConfig::iso20_sets`, DC then AC by default); the
station agrees only to a set it can run (`SeccConfig::iso20_sets`, every compiled
set by default), so a usable lower-priority entry wins over an unusable first.

**`exi`** — bit I/O over caller-owned slices, built-in datatypes, the value string
table, the grammar runtime, documents and fragments. The first layer to touch
unauthenticated bytes. See [The EXI profile](@/docs/exi.md).

**`iso2` / `iso20`** — generated message types and codecs, committed. A content
model's event-code arithmetic is five short integer slices driven by a shared
interpreter, not state tables, so a `maxOccurs="2048"` particle costs one `u32`.
See [Code generation](@/docs/codegen.md).

**`message`** — turns a V2GTP payload type plus the negotiated protocol into a
typed message. `0x8001` carries the handshake and then DIN/TS 70121 or ISO 15118-2,
depending on what was negotiated, so the session has to remember.

**`session`** — clock, spec timers, stream framing, one ordering graph per
generation shared by both roles, and the ISO 15118-2 charging-profile rule. The
sequencers hold no buffers or keys, so a session snapshot is small, `Clone` and
`serde`-serialisable — what pause and resume across a power cycle need. See
[Sessions and ordering](@/docs/sessions.md).

**`secc` / `evcc`** — the role drivers: a `Connection`, `Timers` and a `Flow`
joined into an event loop.

**`slac` / `sdp`** — which station this cable is plugged into, and which port to
connect to. See [SLAC](@/docs/slac.md) and [Discovery](@/docs/discovery.md).

**`pnc`** — signatures across message sets: what to hash and sign, and checking
the result. No cryptography of its own. See
[Plug & Charge](@/docs/plug-and-charge.md).
