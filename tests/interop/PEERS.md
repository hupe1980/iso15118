# Live peers

The implementations `tests/josev.rs` and `tests/everest.rs` run this crate
against, what each is pinned to, and every disagreement a live session
has found. A disagreement is either fixed in this crate — with a test — or
recorded here as the peer's, never tolerated in the node's code.

## Josev

| | |
|---|---|
| What | The community edition of the Python ISO 15118 stack (`ecog-io/iso15118`) |
| Licence | Apache-2.0; nothing of it is in this repository — the image installs it |
| Pin | `iso15118==0.31.2` from PyPI, with `aiofile==3.9.0` |
| Codec | `EXICodec.jar`, which is `exificient` — so Josev is **session** evidence, not codec evidence |
| Rows | Both roles × ISO 15118-2 and -20 × AC and DC, EIM over TCP: 8 |
| Runs | `cargo test --test josev -- --nocapture`; CI job `interop-josev` on every pull request |
| Cost | ≈ 2 min with the image cached, one session ≈ 2–3 s |

Measured 2026-11-02: **8 of 8 rows pass**, twice in a row.

### What the sessions found

| # | Found | Whose | Resolution |
|---|---|---|---|
| J1 | Josev's -20 vehicle repeats `PowerDeliveryReq(Start)` with `EVProcessing = Ongoing` before it has started — on some runs, not others. This crate's -20 sequencer read the repeat as out of sequence and refused it with `FAILED_SequenceError` | This crate's | The sequencer admits a `Start` straight after a `Start` that said `Ongoing`, and nothing else (`a_start_that_said_ongoing_may_be_repeated`, `a_start_that_said_finished_may_not_be_repeated`). The -20 text is not read here; EVerest's -20 charge loop answers the repeat, Donar's station refuses it |
| J2 | Josev's vehicle refuses an SDP answer whose TCP port is outside 49152–65535, then crashes (`AttributeError: 'SDPResponse' object has no attribute 'ip_address'`) instead of ignoring it | The node's port; Josev's crash | The node binds a dynamic port. The crash — and the log message calling the TCP port "the mandatory UDP server port 15118" — is Josev's |
| J3 | Josev's -20 station crashes (`AttributeError: 'NoneType' object has no attribute 'departure_time'`) when a vehicle selects the Scheduled parameter set and sends a Dynamic schedule exchange, rather than answering `FAILED` | The node's selection; Josev's crash | The node selects the parameter set whose `ControlMode` it then uses. The crash is Josev's |
| J4 | Josev's -20 station rejects a `PowerDeliveryReq(Start)` without `EVPowerProfile` as a validation error and then goes silent — the vehicle sees only its own message timeout | The node's request; Josev's silence | The node sends the profile with `Start`; Donar's station requires it too. Answering nothing is Josev's |
| J5 | Josev's simulated station reports `EVSEPresentVoltage` = 1 V for the whole pre-charge, so a vehicle that waits for its battery voltage never closes its contactors; this crate's vehicle closed the session on the pre-charge timeout, as it should | Josev's simulator | The image sets the simulator's present voltage to 400 V, as a bench sets a simulated supply. The protocol stack is untouched |
| J6 | The 0.31.2 wheel does not declare `aiofile`, which the vehicle imports | Josev's packaging | Installed explicitly |
| J7 | Without `EVCC_CONFIG_PATH` the vehicle crashes building `supportedAppProtocolReq`; its -20 vehicle reads contract certificates even for EIM, which the wheel does not ship; it does not exit when its SDP retries run out | Josev's | The image passes an example configuration, runs the wheel's `create_certs.sh`, and `timeout` bounds every process |

## EVerest

| | |
|---|---|
| What | EVerest's software-in-the-loop station (`EvseManager`, `IsoMux`, `EvseV2G` for -2, `Evse15118D20` for -20), with its own car simulator (`EvManager`) driving the pilot and SLAC |
| Licence | Apache-2.0; nothing of it is in this repository — the image is pulled |
| Pin | `ghcr.io/everest/everest-demo/manager:2025.10.0-single-phase`, the tag everest-demo pins (3.96 GB compressed, 20.3 GB unpacked); EVerest's own test PKI from the image (`everest-aux`) |
| Codec | `libcbv2g` — not `exificient`, so this is codec evidence too |
| Station | `config-sil-dc-ours.yaml` (`IsoMux` in front of both generations) and `config-sil-dc-pnc-ours.yaml` (`EvseV2G` alone, for Plug & Charge): EVerest's own configurations without `PyEvJosev` |
| Rows | Our EVCC only — EVerest's EV simulator is Josev, already covered: -2 DC TCP EIM, -20 DC TCP EIM, -2 DC TLS EIM, -2 DC TLS Plug & Charge |
| Runs | `cargo test --test everest -- --nocapture`; CI job `interop-everest` on every pull request |
| Cost | ≈ 3.5 min with the base image pulled; the Plug & Charge row ≈ 44 s, the others ≈ 8 s |

Measured 2026-11-03: **4 of 4 rows pass**. In the Plug & Charge row `EvseV2G`
verifies our `AuthorizationReq` signature with `libcbv2g` unconditionally
(`check_iso2_signature`; a mismatch is `FAILED_SignatureError`) and answers
`Ongoing`, then `Finished`.

### What the sessions found

| # | Found | Whose | Resolution |
|---|---|---|---|
| V1 | Behind `IsoMux`, which terminates TLS, `EvseV2G` sees plain TCP and withdraws Contract payment ("PnC is not allowed without TLS-communication") — Plug & Charge cannot run through the multiplexer | EVerest's design (its own isomux TLS configuration disables contract payment) | The Plug & Charge row uses `EvseV2G` alone |
| V2 | `IsoMux` answers SDP from start-up, before SLAC has matched, then closes the connection, because the station enables HLC only after the match | EVerest's | The node starts SDP once SLAC has matched, as a vehicle does |
| V3 | A station with no energy budget yet answers `ChargeParameterDiscovery` with `EVSENotification = StopCharging` and fails the next `PowerDeliveryReq(Start)`; the node's vehicle ignored the notification | The node's | The vehicle honours `StopCharging` — before power flows it stops and the row fails, naming it. The bench plugs in after 20 s, once the energy manager has a budget |
| V4 | `Evse15118D20` refuses to start without a V2G certificate, even for EIM, and the image ships its certificate directories empty | The image's | The image installs EVerest's test PKI |
| V5 | EVerest's modules rename their processes (`iso_mux:IsoMux --prefix …`); a station not killed by command line keeps answering SDP into the next row | The harness's | Teardown matches the command line and waits |
| V6 | `EvseV2G` logs an `ERRO` when a TLS peer closes without `close_notify` | The node's proxy | `socat` closes the session itself when the node hangs up |
| V7 | After the signature check, the Plug & Charge authorization stays `Ongoing` for ≈ 35 s | EVerest's `Auth` | None needed; within the vehicle's budget |

## Donar

Not run: no crates.io release. Skipped by name until there is one.
