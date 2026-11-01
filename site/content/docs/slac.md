+++
title = "SLAC"
description = "ISO 15118-3 signal level attenuation characterization in Rust: the matching state machine for both roles, every frame bound to its run, and what an unauthenticated peer cannot make it do."
weight = 60
+++

Matching decides which of the stations sharing a powerline medium this cable is
plugged into. The vehicle sends sounding packets, every station in earshot reports
how loud they arrived, and the loudest link wins. The winner hands over the network
membership key **in the clear** — safe only because the measurement established
that nobody far away can hear it.

```text
  EV                                                        EVSE
   |------------------ CM_SLAC_PARM.REQ --------------------->|  broadcast
   |<----------------- CM_SLAC_PARM.CNF ----------------------|  per station
   |--------------- CM_START_ATTEN_CHAR.IND ----------------->|  x3
   |------------------ CM_MNBC_SOUND.IND -------------------->|  x10, sounding
   |<----------------- CM_ATTEN_CHAR.IND ---------------------|  the measurement
   |------------------ CM_ATTEN_CHAR.RSP -------------------->|  to the winner
   |------------------ CM_SLAC_MATCH.REQ -------------------->|
   |<----------------- CM_SLAC_MATCH.CNF ---------------------|  NMK + NID
```

`slac::matching::{Ev, Evse}` are that run as sans-I/O state machines: frames in,
frames and events out. `Ev::poll_timeout` paces the sounding burst.

## Every frame is bound to its run

Nothing in ISO 15118-3 is authenticated, and the run id is broadcast in the clear.
So both engines check who a frame comes from:

- the vehicle takes `CM_SLAC_MATCH.CNF` — the key — only from the station it
  chose, naming that station and this vehicle;
- it takes attenuation reports and `CM_SLAC_PARM.CNF` only if they name this
  vehicle;
- the station counts sounding packets and answers `CM_ATTEN_CHAR.RSP` and
  `CM_SLAC_MATCH.REQ` only from the vehicle that opened the run, and refuses a key
  request before the measurement;
- a run in progress, or a station that has handed over its key, is not restarted by
  a stray `CM_SLAC_PARM.REQ`; the vehicle's own retry (same MAC, same run id) still
  gets through, and `reset` frees the station.

## Spoofed measurements

Binding narrows *who* is heard; it cannot make the measurement trustworthy.
**CVE-2025-12357** (CISA ICSA-25-303-01) describes spoofed measurements staging a
man-in-the-middle against ISO 15118-2: a station reporting implausibly low
attenuation claims to be closest, and everything the report needs is broadcast
during sounding. This crate:

- lets a report move the choice **earlier, never later**, so it cannot stall the
  run;
- takes the key only from the station the vehicle chose;
- surfaces every station's report in `EvEvent::Measurement`, so an application can
  refuse an ambiguous run.

ISO 15118-20's mandatory TLS authenticates the station the link was set up with.

## A bystander's frames are not errors

`handle_frame` returns nothing — not a `Result`. On a shared medium a malformed or
foreign frame is ordinary; reporting one would give anything in earshot a
one-frame kill switch for someone else's run. Frames of another protocol, version,
message type, profile, run or vehicle are dropped (with `tracing`, each says why).
`Secc::handle_input` does return errors: a TCP stream that stops being V2GTP is
over.

Nothing a bystander sends sets a deadline or a queue length:

- the attenuation window only shortens;
- the list of answering stations is bounded (`MAX_STATIONS`);
- both queues are bounded (`MAX_PENDING_EVENTS`, `MAX_PENDING_FRAMES`), and
  terminal events are never dropped.

## Layouts are pinned

SLAC has no reference implementation, so every message is encoded with a distinct
byte per field and asserted verbatim — field order, offsets, widths, reserved gaps,
both `MVFLength` constants — checked against
[EVerest's `libslac`](https://github.com/EVerest/libslac).

## Choosing a station

- The **vehicle's** attenuation limit: a station this quiet is not at the other end
  of the cable. The primary defence.
- The **station's** optional limit: a floor of its own; `None` leaves the choice to
  the vehicle.

A station that measured nothing fails the run rather than reporting 0 dB.

## What you bring

- **Randomness** — run id, sounding payloads, and the NMK, which an attacker must
  not be able to guess.
- **A raw socket** — SLAC is Ethernet (`AF_PACKET` or BPF); frames come padded and
  ready to write.
- **The control pilot** — hardware. The ISO 15118-3 constants are in
  `slac::timers`.

## Tests

The integration test puts two stations on one medium with one vehicle: the near
one wins, a far one is refused, the key never goes to a peer that skipped the
measurement or chose a neighbour, a forged key handover is ignored, and a
bystander's sounding packets do not close the window — in memory, with a mock
clock.
