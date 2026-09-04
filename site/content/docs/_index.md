+++
title = "Documentation"
description = "How the iso15118 crate is put together: the EXI codec, the ISO 15118-2 and -20 message sets, session ordering, SLAC, discovery and Plug & Charge signatures."
sort_by = "weight"
template = "section.html"
page_template = "page.html"
weight = 0

[extra]
nav_title = "Overview"
+++

This crate implements the ISO 15118 communication suite — the protocol an
electric vehicle and a charging station speak over the CCS cable while deciding
whether to move 350 kW between them. It covers everything from the powerline
link coming up to the charge loop turning, and it does none of the I/O.

The documentation is written to be read in order, but each page stands alone.

## Where to start

| If you want to… | Read |
|---|---|
| Install it and run a session | [Getting started](@/docs/getting-started.md) |
| Understand the layering | [Architecture](@/docs/architecture.md) |
| Know which request is legal when | [Sessions and ordering](@/docs/sessions.md) |
| Encode or decode V2G messages yourself | [The EXI profile](@/docs/exi.md) |
| Bring the link up | [SLAC](@/docs/slac.md), then [discovery and framing](@/docs/discovery.md) |
| Sign or verify a contract credential | [Plug & Charge](@/docs/plug-and-charge.md) |
| Decide whether a key is one to trust | [Certificates](@/docs/pki.md) |
| Ship it on a microcontroller | [Embedded and `no_std`](@/docs/embedded.md) |
| Know whether to trust the wire format | [Verification](@/docs/verification.md) |

## The shape of every engine

There are five protocol engines in this crate — the charging station, the
vehicle, SECC discovery and the two halves of SLAC matching — and all of them
are driven the same way. The names differ only where the job does.

| Step | Session engines | Discovery and SLAC |
|---|---|---|
| Bytes from the wire | `handle_input(now, &bytes)` | `handle_datagram` / `handle_frame` |
| What happened | `poll_event()` | `poll_event()` |
| Your answer | `respond` (SECC) · `request` (EVCC) | — the engine decides |
| Bytes for the wire | `take_transmit()` | `poll_transmit()` |
| The next deadline | `poll_timeout()`, then `handle_timeout(now)` | same |

Three of those differences are deliberate rather than incidental. A **session
engine consumes a stream** and has to reassemble it, so it takes whatever bytes
arrived and returns everything queued; **discovery and SLAC consume complete
datagrams and Ethernet frames**, where a boundary is meaningful, so they take one
and hand back one at a time. The answering step differs because the protocol
does: the vehicle *drives*, choosing the next request, while the charger only
ever answers — and below IP there is nothing to decide, so those engines answer
for themselves.

The third is in the error types, and it is the one worth knowing before you write
the loop. `handle_input` returns a `Result`, because a TCP stream that stops
being V2GTP cannot be resynchronised and the session really is over — **and it is
already over when the error reaches you**. The engine closes itself first:
timers disarmed, buffers dropped, `Event::Closed(Close::Fatal)` queued. So the
usual shape of a server loop — log the error, read again — gets a closed session
rather than a live one, which is the point. A rule the caller may skip is not a
rule.
`handle_frame` returns **nothing at all**: a SLAC engine listens promiscuously on
a shared powerline segment where every station's unauthenticated traffic arrives,
so a malformed frame is ordinary weather — and reporting one would hand anything
within earshot a one-frame kill switch for somebody else's matching run. See
[SLAC](@/docs/slac.md).

Nothing in that table reads a clock, opens a socket or spawns a task. The clock
is a monotonic millisecond count you supply, the transport is yours, and the
randomness and the cryptography are yours. That is what lets the same protocol
logic run under Tokio on a charge-point back end and on a bare-metal vehicle
controller — and it is why a complete DC charging session runs as a unit test in
microseconds, with time as a variable the test increments.

## Terms

ISO 15118 has its own vocabulary, and the crate uses it rather than inventing a
friendlier one.

| Term | Meaning |
|---|---|
| **EVCC** | Electric Vehicle Communication Controller — the vehicle's side. |
| **SECC** | Supply Equipment Communication Controller — the charging station's side. |
| **EXI** | Efficient XML Interchange, the binary encoding every V2G message uses. |
| **V2GTP** | The eight-byte frame header that wraps every message on TCP or UDP. |
| **SDP** | SECC Discovery Protocol — how the vehicle finds the station's TCP port. |
| **SLAC** | Signal Level Attenuation Characterization — which station this cable is plugged into. |
| **PnC** | Plug & Charge — authenticating with a contract certificate instead of a card. |
| **BPT** | Bidirectional Power Transfer — the vehicle discharging back to the grid. |

One term the vocabulary is careless about is the protocol's own name. "ISO 15118"
covers two incompatible generations, and this crate never writes it without one:
`Protocol::as_str()` is `"iso15118-2"` or `"iso15118-20"`, never a bare
`"iso15118"`, and it refuses to parse one. See
[Getting started](@/docs/getting-started.md#recording-which-generation-you-spoke).

## A note on scope

The engines own **framing, decoding, the handshake, session-id stamping and checking, message
ordering and the spec timers**. They own **nothing** about charging: whether to
authorize a vehicle, which schedule to offer, how much current to deliver.

That line is where it is because everything above it is a decision a charge point
operator makes, and everything below it is a decision ISO made. Only the second
kind belongs in a library. The consequence is honest: this crate will not run a
charging station on its own, and it does not pretend to.
