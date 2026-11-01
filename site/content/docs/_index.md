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

The ISO 15118 communication suite — what a vehicle and a charging station speak
over the CCS cable — from the powerline link coming up to the charge loop turning,
with none of the I/O.

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

Five engines — station, vehicle, SECC discovery and both halves of SLAC — are
driven the same way:

| Step | Session engines | Discovery and SLAC |
|---|---|---|
| Bytes from the wire | `handle_input(now, &bytes)` | `handle_datagram` / `handle_frame` |
| What happened | `poll_event()` | `poll_event()` |
| Your answer | `respond` (SECC) · `request` (EVCC) | — the engine decides |
| Bytes for the wire | `take_transmit()` | `poll_transmit()` |
| The next deadline | `poll_timeout()`, then `handle_timeout(now)` | same |

- **Streams versus frames.** A session engine reassembles a TCP stream; discovery
  and SLAC take one complete datagram or Ethernet frame at a time.
- **Who answers.** The vehicle drives with `request`, the station answers with
  `respond`; below IP the engines answer for themselves.
- **Errors.** `handle_input` returns a `Result`, and the session is **already
  closed** when the error reaches you (`Event::Closed(Close::Fatal)` queued). SLAC's
  `handle_frame` returns nothing: on a shared medium a malformed frame is ordinary,
  and reporting one would let anyone in earshot end someone else's run.

None of it reads a clock, opens a socket or spawns a task; the clock, transport,
randomness and cryptography are yours. So the same logic runs under Tokio and on a
bare-metal controller, and a whole DC session runs as a unit test.

## Terms

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

"ISO 15118" names two incompatible generations, so `Protocol::as_str()` is
always `"iso15118-2"` or `"iso15118-20"` and a bare `"iso15118"` does not parse —
see [Getting started](@/docs/getting-started.md#recording-which-generation-you-spoke).

## Scope

The engines own framing, decoding, the handshake, session ids, ordering and the
spec timers. Whether to authorize, which schedule to offer and how much current to
deliver are the application's. What is deliberately outside the crate is listed
under [Limitations](@/docs/faq.md#limitations).
