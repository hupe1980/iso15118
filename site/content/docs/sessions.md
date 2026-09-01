+++
title = "Sessions and ordering"
description = "How iso15118 models the ISO 15118-2 and -20 message flows: transition graphs shared by both roles, the failure rule, pause and resume, and renegotiation."
weight = 30

[extra]
nav_title = "Sessions & ordering"
+++

ISO 15118's ordering rules are not decoration. `FAILED_SequenceError` is a
defined response code and terminating the session is the defined reaction, so
*which requests are legal right now* is protocol logic that both sides need and
that neither should re-derive from prose.

This crate keeps it in one place per protocol generation, shared by the vehicle
and the station, so the two cannot disagree about the flow — and so each ordering
rule is a unit test rather than a field observation.

## Two questions

A sequencer answers two questions:

- *Is this request legal here, and where does it go?* — what a station needs.
- *What would be legal?* — what a vehicle, and a fuzzer, need.

```rust
use iso15118::session::iso2::{Request, Sequencer};
use iso15118::iso2::{ChargeProgress, EnergyTransferMode, PaymentOption};

let mut s = Sequencer::new();
s.accept(Request::SessionSetup)?;
s.accept(Request::ServiceDiscovery)?;
s.accept(Request::PaymentServiceSelection(PaymentOption::ExternalPayment))?;
s.accept(Request::Authorization)?;
s.accept(Request::ChargeParameterDiscovery(EnergyTransferMode::DCExtended))?;

// DC inserts cable check and pre-charge before power flows.
assert!(s.accept(Request::PowerDelivery(ChargeProgress::Start)).is_err());
s.accept(Request::CableCheck)?;
# Ok::<_, iso15118::session::SequenceError>(())
```

## The flow is a graph, not a list

Which request may follow which depends on facts established earlier in the
session, and the graph branches on exactly the facts the protocol branches on:

- the **payment option** chosen at service selection — with a contract, credentials
  and the certificate flows come before authorization; with external
  identification there is nothing to present;
- the **energy transfer mode** chosen at parameter discovery — whether the session
  is DC, and therefore has a cable check, a pre-charge and a welding detection at
  all;
- in ISO 15118-20, the **service** selected — AC, DC, WPT or ACDP, each with its
  own parameter-discovery and charge-loop messages, and the pantograph and
  wireless positioning exchanges that only two of them have.

Every branch has a test.

## Stopping is part of the graph

Three rules that are easy to leave out, and each of which produces a different
field failure.

### A `FAILED_*` response ends the session

ISO 15118 leaves no discretion: after a failure the peer may send
`SessionStopReq` and nothing else. `Sequencer::failed()` is that state, and both
role drivers enter it automatically — `Message::outcome()` classifies any
response's code using `is_ok`/`is_warning`/`is_failure`, which the generator
derives from the schemas' own `OK_`/`WARNING_`/`FAILED_` prefixes, so neither
generation's forty-odd codes are maintained by hand.

Leaving this out is the class of bug behind EVerest's
[`GHSA-9vv5-67cv-9crq`](https://github.com/EVerest/EVerest/security/advisories/GHSA-9vv5-67cv-9crq):
a peer keeps walking the flow as though the refusal had not happened. Here it is
a state, two lines of graph, and a test.

### `SessionStopReq` is legal from any established phase

Not only at the end of a completed charge. Vehicles abort — a fault, a driver
unplugging, an answer they did not like — and refusing the stop does not prevent
it. It just replaces a clean shutdown with a sixty-second timeout.

### Not every "stop" stops

`ChargingSession` is an enumeration and its values mean different things:

| Value | Effect |
|---|---|
| `Terminate` | Ends the session. |
| `Pause` | Suspends it for a later resume under the same session id. |
| `ServiceRenegotiation` (-20) | Does not end it at all — keeps the authorization and returns to service discovery to pick a different service. |

Treating all three as terminal drops a session the standard says continues. A
station that does not implement renegotiation answers
`FAILED_NoServiceRenegotiationSupported`, and the failure rule above then ends the
session — the same outcome, by the right route.

## Renegotiation is not a restart

Both generations let a session revise its terms mid-charge, and the two names for
it mean different things.

- **`PowerDeliveryReq` with `ChargeProgress = Renegotiate`** (-2) or
  **`ScheduleRenegotiation`** (-20) revises the *schedule*. It returns to
  parameter discovery with the service, the authorization and the power flow all
  standing.
- **`SessionStopReq` with `ChargingSession = ServiceRenegotiation`** (-20) reopens
  the *service*: back to service discovery, keeping the authorization.

<div class="note note-warn">
<span class="note-title">The DC trap, and its mirror image</span>

A **schedule** renegotiation does not repeat the isolation test or the pre-charge.
Those run once, on the way up; the renegotiation comes back through with the
contactors still closed and the link still at the battery's voltage. A graph that
demands a cable check there does not merely add a message — it strands every DC
vehicle that renegotiates, because the vehicle will not send one.

A **service** renegotiation is the opposite case and needs the opposite answer.
Changing the energy transfer service means power stopped and the contactors
opened, so the next `PowerDeliveryReq(Start)` is a first one again and the
isolation test is not optional. The graph therefore *forgets* the earlier
renegotiation — along with the service it happened under — rather than carrying
it across. Getting this wrong is not visible in a normal session: it only shows up
when a vehicle renegotiates its schedule and then its service, and then it closes
a DC contactor on a cable nobody has re-checked.
</div>

## Pause and resume

Pause and resume are first-class on both sides. A paused flow reports
`is_paused()` rather than only `is_finished()`, and the drivers surface
`Close::Paused`.

Coming back, `Secc::join_session` adopts the id the vehicle named — which is the
whole of resumption in ISO 15118-2 — and `Secc::resume` / `Evcc::resume` add the
part that is -20's: the flow restarts at parameter discovery, because the
authorization and the selected service survived the pause and re-running them
would be out of sequence.

Whether an arriving id names a resumable session is stored state — a schedule, an
authorization, an energy reading — that the protocol core does not hold. So that
call is the application's, and the core does not pretend otherwise.

## The charging profile has to fit the schedule

Ordering is not the only rule the standard states and both sides need. When the
vehicle sends `PowerDeliveryReq` it picks one of the `SAScheduleTuple`s the
station offered and states, as a `ChargingProfile`, the power it intends to draw
over time.

| | |
|---|---|
| \[V2G2-224\] | the SECC **shall always accept** a profile that does not exceed the `PMax` of every entry of the chosen tuple |
| \[V2G2-225\] | and **shall answer `FAILED_ChargingProfileInvalid`** to one that does |
| \[V2G2-479\] | `FAILED_TariffSelectionInvalid` if the `SAScheduleTupleID` was never offered |

The station does not *decide* whether a profile conforms — arithmetic does — so
this is protocol, and it lives in `session::iso2::schedule`. Without it,
`ResponseCode::FAILEDChargingProfileInvalid` is a value the crate can name and no
caller can know when to send.

```rust
match schedule::check_power_delivery(&offered, &req) {
    Ok(()) => { /* [V2G2-224]: this one must be accepted */ }
    // Every error names the code the standard prescribes, and `is_local_fault`
    // says whether the schedule *we* offered was the malformed one.
    Err(e) => respond(failure(e.response_code())),
}
```

Both sides measure from the same origin and are step functions over it, with
breakpoints that need not line up:

```text
offered   |<-- PMax A -->|<------ PMax B ------>|<-- PMax C -->|
          0             300                   1800           3600   (duration)

profile   |<--- P1 --->|<-------- P2 -------->|<------- P3 ------->  (open)
          0           240                    1500
```

A `PMaxScheduleEntry`'s `start` is seconds from NOW and is also the stop of the
interval before it \[V2G2-328\], \[V2G2-329\]; only the last may carry a
`duration`, which ends the coverage \[V2G2-331\]. A `ChargingProfileEntryStart`
is an offset from the same NOW, the next start is when this entry stops, and the
last runs on until the profile is replaced \[V2G2-289\]..\[V2G2-291\].

Two details decide whether the arithmetic is right. The multiplier is a power of
ten — `1100` with multiplier `1` is 11 kW — so comparison is in exact integer
milliwatts and no floating point goes near a decision that ends a session. And
the unit is checked rather than assumed: `PMax` is watts \[V2G2-832\], and 32 A
and 32 W are the same integer.

Where the schedule states no limit there is nothing to exceed and nothing fails.
A profile routinely runs past the coverage, and ISO 15118-2 handles that by having
the vehicle ask for a new schedule \[V2G2-305\]; `schedule::coverage` reports
where the edge is.

`Secc` deliberately does not do this for you. Keeping the `SAScheduleList` would
cost the session state the property that makes pause and resume cheap — that a
snapshot holds no buffers — and your application built the schedule, so it already
has it.

## Timers

Every constant cites the requirement it comes from, and where ISO 15118-2 and -20
differ both values are given rather than one being made to stand for both. The
two families fail in opposite directions and are modelled separately:

- **Performance times** bound how long *this* side may take to answer. They are a
  promise, not a deadline to watch — missing one makes the peer time out — so the
  core surfaces them as advice rather than enforcing them.
- **Timeouts** bound how long this side waits for the *peer*. Missing one is
  terminal: the session ends, and the spec says what to send.

See [Architecture](@/docs/architecture.md#two-kinds-of-deadline) for why a loop
budget is not the same thing as a per-message timeout, and why conflating them
leaves a cable-check loop unbounded.
