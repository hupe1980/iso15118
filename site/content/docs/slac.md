+++
title = "SLAC"
description = "ISO 15118-3 signal level attenuation characterization in Rust: the matching state machine for both roles, and why every frame is bound to the run it claims to belong to."
weight = 60
+++

Matching answers a physical question with a protocol: of the several charging
stations sharing a powerline medium, which one is this cable actually plugged
into?

The vehicle sends a burst of sounding packets, every station in earshot measures
how loud they arrive, and the quietest link loses. The winner hands over a network
membership key — **in the clear**, which is only safe *because* the measurement
has already established that nobody far away can hear it well enough to matter.

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

`slac::matching::{Ev, Evse}` are that run as a pair of sans-I/O state machines:
frames in, frames and events out, with the caller owning the raw socket and the
clock. The sounding burst is the one place where *sending* is time-driven rather
than reply-driven, and `Ev::poll_timeout` paces it.

## What the measurement is worth

The whole security of a matching run rests on one thing being true: the frames
that make up a run all came from the party the run is with.

**Nothing in ISO 15118-3 authenticates them.** Every station on the segment hears
every frame, and the run id is broadcast in the clear in the first message — so
quoting one proves nothing at all. A `CM_SLAC_MATCH.CNF` that merely names the
right run id could come from anywhere on the medium, and a vehicle that took the
first one to arrive would join whatever logical network answered fastest. That is
the one outcome matching exists to prevent.

So both engines bind every frame to the run it claims:

- the vehicle accepts **`CM_SLAC_MATCH.CNF` — the frame carrying the key — only
  from the station it chose**, naming that station and naming this vehicle;
- it accepts an attenuation report only if it is about *this* vehicle's sounding
  burst, and a `CM_SLAC_PARM.CNF` only if it names this vehicle;
- the station counts sounding packets, and answers `CM_ATTEN_CHAR.RSP` and
  `CM_SLAC_MATCH.REQ`, **only from the vehicle that opened the run** — the sound
  count is what closes the measurement window, so a bystander's sounds would close
  it early over a burst that was not the vehicle's;
- the station refuses a key request that arrives before the measurement, because
  that is a request to skip the one step that makes handing the key over safe;
- a station that has already handed over its key is not reopened by a stray
  `CM_SLAC_PARM.REQ`. The application says when it is free again, with `reset`;
- and neither is a run **in progress**. `CM_SLAC_PARM.REQ` is broadcast and
  unauthenticated, so anything on the segment can send one; a station that
  restarted on every one could be made to abort every matching run within
  earshot, one frame at a time, with the vehicle seeing nothing but a station
  that never finishes. The vehicle's own retry still gets through, because a
  retry is the same MAC and the same run id — ISO 15118-3 has the vehicle repeat
  the request when the confirmation is lost, and refusing that would trade one
  stall for another. A genuinely new vehicle waits out `TT_EVSE_match_session`,
  which is what that timer is for.

### The one thing binding cannot fix

All of that narrows *who* a frame can be accepted from. It cannot make the
measurement itself trustworthy, and that gap now has a CVE against the standard:
**CVE-2025-12357** (CVSS 6.3), which describes manipulating SLAC with **spoofed
measurements** to stage a man-in-the-middle between a vehicle and any
ISO 15118-2 charger — wirelessly, at close range, by electromagnetic induction.

The mechanism is the protocol's own logic used honestly. A station that reports
an implausibly low attenuation is claiming to be the closest thing on the medium,
and the quietest link is *defined* to win. Everything a forged report needs — the
run id, the vehicle's MAC, its `source_id` — is broadcast in the clear during
sounding, so the report costs nothing to make and the binding checks above all
pass.

This crate cannot fix that, and does not pretend to. What it does is refuse to
make it worse: a forged report can move the choice **earlier and never later**,
so it cannot also be used to stall the run; the key is taken only from the
station the vehicle actually chose; and `EvEvent::Measurement` surfaces *every*
station's report rather than only the winner, so an application that wants to
refuse an ambiguous run — two stations within a few dB of each other, where there
should be one loud one — has the numbers to do it.

The standard's own answer, and CISA's recommendation, is ISO 15118-20: TLS is
mandatory there and the certificate chain authenticates the station the link was
established with. That is a reason to prefer -20, not a patch for -3.

### Nothing a bystander sends is an error

The same reasoning decides the shape of the API. `handle_frame` returns nothing
at all — not a `Result`. A SLAC engine is a promiscuous listener on a shared
segment: every station's traffic arrives, none of it is authenticated, and a
malformed frame is ordinary weather rather than an exception. Reporting one would
hand anything within earshot a one-frame kill switch for somebody else's matching
run, because the caller would be the one acting on it.

So anything that is not a well-formed message of *this* run is dropped: another
protocol, another HomePlug version, a message type this crate does not model, a
truncated body, a profile other than PEV-EVSE, another run's id, another
vehicle's MAC. With the `tracing` feature on, each drop says which.

That is the opposite of the choice one layer up: `Secc::handle_input` *does*
return a `Result`, because a TCP stream that stops being V2GTP cannot be
resynchronised and the session really is over. The difference is not style, it is
whether the medium is shared.

### The layouts are pinned, not remembered

SLAC has no reference implementation to differ against the way the EXI layer has
`exificient`, and its thirteen message layouts are hand-transcribed from
ISO 15118-3 and HomePlug GreenPHY. Round-tripping them proves the encoder and the
decoder agree with each other — which is the evidence
[Verification](@/docs/verification.md) opens by saying is not evidence.

So every message is also encoded with a distinct byte per field and asserted
verbatim, pinning field order, offsets, widths, the reserved gaps and both
`MVFLength` constants. The expected bytes were checked field for field against
[EVerest's `libslac`](https://github.com/EVerest/libslac).

None of this makes an unauthenticated protocol authenticated. It makes the engine
enforce the one assumption the design does rest on, instead of assuming it.

### Nothing a bystander sends decides how long, or how much

Dropping a bad frame is only half of not being steered by one. The other half is
that a frame nobody can authenticate must not set a deadline or a queue length.

**The measurement window closes when it opened.** After sounding, the vehicle
waits `TT_EV_atten_results` for attenuation reports and shortens that wait once
one arrives. Shortening is right; *lengthening* would be a denial of service
anyone in earshot could mount with one frame every `TT_match_response`, because
everything a forged `CM_ATTEN_CHAR.IND` needs — the run id, the vehicle's MAC,
its `source_id` — is broadcast in the clear during sounding. So a report moves
the choice earlier and never later.

**The list of stations that answered is bounded** (`MAX_STATIONS`). Its source
MAC is an unauthenticated Ethernet header field, so without a ceiling every
distinct forged value costs an entry for the life of the run. Bounding it is safe
because that list does not choose the winner — the measurement does.

**Both queues are bounded** (`MAX_PENDING_EVENTS`, `MAX_PENDING_FRAMES`): a
station queues a confirmation for every `CM_SLAC_PARM.REQ` it accepts, and that
request is a broadcast anything can repeat. Terminal events are never dropped — a
run has one outcome, and losing it would be worse than any flood.

## Choosing a station

Both sides can set an attenuation limit, and they mean different things:

- the **vehicle's** limit is "a station this quiet is not at the other end of my
  cable" — the primary defence, and the one ISO 15118-3 describes;
- the **station's** limit is optional and is a floor of its own, for a station
  that knows its own cable. `None` accepts any run and leaves the choice entirely
  to the vehicle.

A station that measured nothing fails the run rather than reporting 0 dB, because
a station answering "0 dB" because it measured nothing would be claiming to be the
closest one on the medium.

## What you bring

**The randomness.** The run id, the sounding payloads and the network membership
key must all be unpredictable, and nothing in this crate generates randomness. On
the station side that is a real security parameter: an NMK an attacker can guess
is a network an attacker can join.

**The raw socket.** SLAC runs on Ethernet, not IP, so it needs `AF_PACKET` or BPF.
`slac::matching` produces and consumes complete frames, padded and ready to write,
and lets you move them.

**The control-pilot state machine.** Whether the cable is plugged in, and what the
PWM duty cycle says, is hardware. The ISO 15118-3 constants for it are exposed as
`slac::timers` so your own state machine can cite them.

## Testing it without a powerline

The interesting case is the one the protocol exists for: two stations share the
medium and both hear the vehicle, so both answer and both report a measurement.
The integration test runs exactly that — two competing stations against one
vehicle — and checks that the near one wins, that a station too far away is
refused, that a station never hands its key to a peer that skipped the measurement
or to one that chose a neighbour, that a forged key handover is ignored while the
real one still works, and that a bystander's sounding packets do not close the
measurement window.

All of it in memory, with a mock clock, in microseconds.
