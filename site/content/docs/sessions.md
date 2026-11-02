+++
title = "Sessions and ordering"
description = "How iso15118 models the ISO 15118-2 and -20 message flows: transition graphs shared by both roles, the message-set rule, the failure rule, pause and resume, renegotiation and timers."
weight = 30

[extra]
nav_title = "Sessions & ordering"
+++

Which request is legal right now is protocol logic both sides need:
`FAILED_SequenceError` is a defined response code and ending the session is the
defined reaction. This crate keeps one ordering graph per generation, shared by
the vehicle and the station, so the two cannot disagree — and every rule is a
unit test.

## The sequencer

A sequencer answers *is this request legal here, and where does it go?* (the
station) and *what would be legal?* (the vehicle, and a fuzzer).

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

The graph branches on the facts the protocol branches on: the **payment option**
(a contract brings the certificate flows before authorization), the **energy
transfer mode** (DC adds cable check, pre-charge and welding detection), and in
ISO 15118-20 the **selected service**.

## Requests only

The graph is a function of requests. Where ISO 15118-2's state chart branches on
response *content*, the graph allows the union:

| Phase | Allows | The branch lives in |
|---|---|---|
| `ChargeParameters`, `CableCheck`, `PreCharge`, `Authorized`, `WeldingDetection` | a repeat, or moving on | `EVSEProcessing` \[V2G2-688\], \[V2G2-573\] |
| `Charging` (AC) | `ChargingStatusReq`, `MeteringReceiptReq`, `PowerDeliveryReq` | `ReceiptRequired` \[V2G2-575\], \[V2G2-577\] |

Everything a request decides is enforced: the payment option, the energy transfer
mode, the selected service, `ChargeProgress`, `ChargingSession`.

In ISO 15118-20 the graph also reads `EVProcessing` on `PowerDeliveryReq(Start)`.
A `Start` that says `Ongoing` is a vehicle still starting, so one more `Start`
straight after it is admitted; a `Start` after one that said `Finished`, or once
the charge loop has begun, is `FAILED_SequenceError`. The drivers read the field
themselves; driving `session::iso20::Sequencer` directly, call
`accept_processing` with `power_delivery_ongoing(&message)`.

## One service, one message set

ISO 15118-20 gives each energy transfer service its own message set and V2GTP
payload type. Before `ServiceSelectionReq` no energy-transfer message belongs to
the session; after it only the selected service's do; `CommonMessages` always
does. `Flow::accept` and `Flow::permits` check `Sequencer::admits` before the
graph and refuse anything else with `FAILED_SequenceError`.

| Service ids | `Service` | Message set and flow |
|---|---|---|
| 1, 5 | `Ac` | AC |
| 2, 6 | `Dc` | DC, with isolation test, pre-charge and weld check |
| 3 | `Wpt` | WPT |
| 4, 7 | `Acdp` | ACDP to position and connect, then DC and the DC flow |
| 8, 9 | `Mcs` | DC and the DC flow |
| 10 | `AcDerIec` | `AC_DER_IEC` (Amd 1), the AC flow |
| 11 | `AcDerSae` | `AC_DER_SAE` (Amd 1), the AC flow |

The `_BPT` ids (5, 6, 7, 9) and the two `AC_DER` services set
`EnergyTransfer::bidirectional`. For MCS, two rules of Amd 1 are the caller's: no
ISO 15118-2 fallback (configure the station with ISO 15118-20 only) and pausing
the ISO 15118-10 data link.

## Plug & Charge needs TLS

| | |
|---|---|
| \[V2G2-634\] | without TLS, the SECC **shall not provide** the PnC message sets |
| \[V2G2-635\] | the same, of the EVCC |
| \[V2G2-633\] | such a session accepts external identification only |

The core cannot see the transport, so the caller states it in
`SeccConfig::security` / `EvccConfig::security`. The -2 graph refuses
`PaymentServiceSelectionReq` with `Contract` under `Security::None` — the message
every certificate and signature of the session hangs off.

```rust
use iso15118::secc::SeccConfig;
use iso15118::session::Security;

let config = SeccConfig {
    // The value SDP already negotiated, passed along rather than re-decided.
    security: Security::Tls,
    ..SeccConfig::default()
};
```

The default is `Security::None`: a session that has not said it is secured is
treated as unsecured, and forgetting gives a loud `FAILED_SequenceError` rather
than a certificate in clear. It is the same `Security` type SDP negotiates.
ISO 15118-20 mandates TLS, so its graph has nothing to condition.

## Stopping

### A `FAILED_*` response ends the session

After a failure the peer may send `SessionStopReq` and nothing else. Both
drivers enter that state on their own; `Message::outcome()` classifies every
response code from the schemas' own `OK_`/`WARNING_`/`FAILED_` prefixes. (A peer
that keeps walking the flow after a refusal is
[`GHSA-9vv5-67cv-9crq`](https://github.com/EVerest/EVerest/security/advisories/GHSA-9vv5-67cv-9crq)
in another stack.)

`Message::refusal(response_code)` builds the response that refuses any request,
every other field at the schema's minimum, so it always encodes.

### Three kinds of stop

| `ChargingSession` | Effect | Legal |
|---|---|---|
| `Terminate` | Ends the session. | Any established phase. |
| `Pause` | Suspends it for a resume under the same id. | Only once the cable is not live — not in the charge loop, cable check or pre-charge (§8.4.1). |
| `ServiceRenegotiation` (-20) | Keeps the authorization, returns to service discovery. | Only once a service is selected; earlier it would bypass authorization. |

A station without renegotiation answers `FAILED_NoServiceRenegotiationSupported`,
which ends the session by the failure rule.

## Renegotiation

- **Schedule** — `PowerDeliveryReq` with `Renegotiate` (-2) or
  `ScheduleRenegotiation` (-20): back to parameter discovery; service,
  authorization and power flow stand.
- **Service** — `SessionStopReq` with `ServiceRenegotiation` (-20): back to service
  discovery, keeping the authorization.

<div class="note note-warn">
<span class="note-title">DC safety phases</span>
Any return to parameter discovery from a charge already started — a schedule
renegotiation, or \[V2G2-601\]/\[V2G2-797\]'s second charge — skips the isolation
test and pre-charge: the contactors are still closed, and demanding them would
strand the vehicle. A <strong>service</strong> renegotiation opens the contactors,
so the next <code>PowerDeliveryReq(Start)</code> needs the isolation test again,
and the graph forgets the earlier renegotiation.
</div>

## Pause and resume

A paused flow reports `is_paused()`, and the drivers surface `Close::Paused`.
`Secc::join_session` adopts the vehicle's id — all of resumption in ISO 15118-2.
In ISO 15118-20, `Secc::resume` / `Evcc::resume` also restart the flow at
parameter discovery, because authorization and the selected service survived.
Both return `Result<(), ResumeError>`: before the handshake, or in a -2 session,
the call is refused. Whether an id names a resumable session is the
application's stored state.

## The charging profile has to fit the schedule

| | |
|---|---|
| \[V2G2-224\] | the SECC **shall accept** a profile within the `PMax` of every entry of the chosen tuple |
| \[V2G2-225\] | and **shall answer `FAILED_ChargingProfileInvalid`** to one that is not |
| \[V2G2-479\] | `FAILED_TariffSelectionInvalid` for a tuple id never offered |

`session::iso2::schedule` does the arithmetic:

```rust
match schedule::check_power_delivery(&offered, &req) {
    Ok(()) => { /* [V2G2-224]: this one must be accepted */ }
    // Every error names the code the standard prescribes, and `is_local_fault`
    // says whether the schedule *we* offered was the malformed one.
    Err(e) => respond(failure(e.response_code())),
}
```

Both are step functions from the same origin, with breakpoints that need not
line up:

```text
offered   |<-- PMax A -->|<------ PMax B ------>|<-- PMax C -->|
          0             300                   1800           3600   (duration)

profile   |<--- P1 --->|<-------- P2 -------->|<------- P3 ------->  (open)
          0           240                    1500
```

A `PMaxScheduleEntry` starts in seconds from NOW and stops where the next starts;
only the last may carry a `duration` \[V2G2-328\]..\[V2G2-331\]. Comparison is in
exact integer milliwatts — the multiplier is a power of ten — and the unit is
checked: `PMax` is watts \[V2G2-832\]. Where the schedule states no limit nothing
fails; `schedule::coverage` reports where coverage ends \[V2G2-305\]. `Secc` does
not keep the `SAScheduleList`: your application built it, and a session snapshot
stays free of buffers.

## Timers

Every constant cites its requirement; where -2 and -20 differ, both are given.

- **Timeouts** bound how long this side waits for the peer. Missing one ends the
  session.
- **Performance times** bound how long this side may take. They are advice:
  `secc.response_due()` and `evcc.next_request_due()`.
- **Loop budgets** bound a whole `..._Ongoing` loop — see
  [Architecture](@/docs/architecture.md#two-kinds-of-deadline).

| Request | The station has | The vehicle waits |
|---|---|---|
| Most messages | 1,5 s | 2 s |
| `ServiceDetail`, `PaymentDetails`, `PowerDelivery`, the certificate flows | 4,5 s | 5 s |
| `CurrentDemand` — the DC charge loop | **25 ms** | 250 ms |

The station's 25 ms means a DC charge loop cannot wait on a database, a lock shared
with a web server, or a garbage collector.

### Loop budgets a deployment can set

The defaults are ISO 15118-2 Table 109 and, for ISO 15118-20, this crate's
labelled policy. `LoopBudgets` on `EvccConfig` and `SeccConfig` overrides two:

```rust,ignore
use iso15118::session::{LoopBudgets, Millis};

let config = EvccConfig {
    loop_budgets: LoopBudgets {
        authorization: Some(Millis::from_secs(140)),   // ChargeX, Timeouts Best Practices
        ongoing: None,                                  // keep the standard's
    },
    ..EvccConfig::default()
};
```

`authorization` is the loop while a driver presents a card or confirms in an app;
`ongoing` is every other `..._Ongoing` loop. The DC isolation test and pre-charge
keep their safety bounds. On the station, keep each value shorter than the
vehicle's.
