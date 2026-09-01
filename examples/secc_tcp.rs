//! A minimal ISO 15118-2 AC charging station, over a real TCP socket.
//!
//! What the crate gives you is the top half of this file: framing, EXI, the
//! `supportedAppProtocol` handshake, session-id checking, message ordering and
//! every spec timer, all in [`Secc`]. What you write is the bottom half —
//! `answer` — which is the charging station: whether to authorize, which
//! schedule to offer, how much current to allow.
//!
//! That is the whole integration surface, and it is deliberately this small.
//!
//! ```sh
//! cargo run --example secc_tcp
//! # then, in another terminal:
//! cargo run --example evcc_tcp
//! ```
//!
//! # What a real station adds
//!
//! **TLS.** Plug & Charge under -2, and everything under -20, requires it.
//! Wrap the `TcpStream` in `rustls` and hand the *decrypted* bytes to
//! `handle_input`; nothing here changes. **A real session id**, from a real
//! RNG — this one is a constant so the example is reproducible, and a
//! predictable session id is a session anyone can resume. **SDP**, so a vehicle
//! can find the port; see `examples/sdp_discovery.rs` for the other side of it.

use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant as StdInstant};

use iso15118::iso2::{
    ACEVSEStatus, Body, BodyChoice, ChargeService, EVSENotification, EVSEProcessing,
    EnergyTransferMode, MessageHeader, PMaxSchedule, PMaxScheduleEntry, PMaxScheduleEntryChoice,
    PaymentOption, PaymentOptionList, PhysicalValue, RelativeTimeInterval, ResponseCode,
    SAScheduleList, SAScheduleTuple, ServiceCategory, SupportedEnergyTransferMode, UnitSymbol,
    V2GMessage,
};
use iso15118::message::Message;
use iso15118::secc::{Close, Event, Secc, SeccConfig};
use iso15118::session::{Instant, SessionId};
use iso15118::{Protocol, Protocols, iso2};

const LISTEN: &str = "127.0.0.1:15119";

fn main() -> std::io::Result<()> {
    let listener = TcpListener::bind(LISTEN)?;
    println!("listening on {LISTEN}");
    for stream in listener.incoming() {
        let stream = stream?;
        println!("--- vehicle connected from {:?}", stream.peer_addr()?);
        if let Err(e) = serve(stream) {
            eprintln!("session ended: {e}");
        }
    }
    Ok(())
}

fn serve(mut stream: TcpStream) -> std::io::Result<()> {
    // A real station takes these eight bytes from its RNG. They have to be
    // unpredictable: the session id is what a paused session is resumed under.
    let session_id = SessionId::new([0x3D, 0x4C, 0xBF, 0x93, 0x37, 0x4E, 0xD8, 0x9B]);
    let mut secc = Secc::new(SeccConfig {
        // -20 requires TLS, and this example has none, so it offers -2 only.
        protocols: Protocols::only(Protocol::Iso2),
        session_id,
        ..SeccConfig::default()
    });

    let started = StdInstant::now();
    // A monotonic millisecond count is all the crate wants; the origin is
    // arbitrary and only differences are ever read.
    let now =
        || Instant::from_millis(u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX));

    // A short read timeout is what turns a blocking socket into the poll loop
    // a sans-I/O engine wants: read, then let the clock advance.
    stream.set_read_timeout(Some(Duration::from_millis(100)))?;
    secc.opened(now());

    let mut buf = [0u8; 4096];
    while !secc.is_closed() {
        match stream.read(&mut buf) {
            Ok(0) => break, // the vehicle hung up
            Ok(n) => {
                if let Err(e) = secc.handle_input(now(), &buf[..n]) {
                    // A framing or decode failure is fatal: the stream cannot
                    // be resynchronised, so the session is over.
                    eprintln!("bad input: {e}");
                    break;
                }
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(e) => return Err(e),
        }

        // The engine says which timer is due and when; nothing polls a clock
        // in a loop, and nothing sleeps inside the library.
        if secc.poll_timeout().is_some_and(|deadline| deadline <= now()) {
            secc.handle_timeout(now());
        }

        while let Some(event) = secc.poll_event() {
            match event {
                Event::ProtocolAgreed(p) => println!("speaking {p}"),
                Event::Request(req) => {
                    println!("  <- {}", req.name());
                    let response = answer(&req);
                    println!("  -> {}", response.name());
                    // No session id here: `respond` stamps the one this station
                    // assigned, because it is not a per-message choice.
                    secc.respond(now(), wrap(response)).expect("respond");
                }
                // The ordering rules were broken. The reaction is fixed: send
                // the code the spec names, and the session is over.
                Event::Refused { message, response_code, reason } => {
                    eprintln!("  !! {}: {reason}", message.name());
                    let refusal = refuse(&message, response_code);
                    secc.respond(now(), wrap(refusal)).expect("respond");
                }
                Event::Closed(why) => {
                    println!("--- {why}");
                    if why == Close::Paused {
                        println!("    keep the schedule and the id: this session may come back");
                    }
                }
                _ => {}
            }
        }

        let out = secc.take_transmit();
        if !out.is_empty() {
            stream.write_all(&out)?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Everything below this line is the charging station, not the protocol.
// ---------------------------------------------------------------------------

/// The station's answer to one request.
///
/// Every decision here is a charge point operator's: which payment options to
/// offer, whether this vehicle is authorized, what schedule to give it, when to
/// close the contactor. None of it is in the library, and none of it should be.
#[allow(clippy::too_many_lines, reason = "one arm per message reads as the table it is")]
fn answer(request: &Message) -> BodyChoice {
    let status = ACEVSEStatus {
        notification_max_delay: 0,
        evse_notification: EVSENotification::None,
        rcd: false,
    };

    match body(request).expect("a request body") {
        BodyChoice::SessionSetupReq(req) => {
            println!("     vehicle id {:02X?}", req.evcc_id);
            BodyChoice::SessionSetupRes(iso2::SessionSetupRes {
                response_code: ResponseCode::OKNewSessionEstablished,
                evse_id: "DE*ABC*E123*45".into(),
                evse_time_stamp: Some(1_725_456_343),
            })
        }

        // What this station sells, and how it takes payment. Plug & Charge
        // would add `PaymentOption::Contract` here — and then a contract
        // certificate to validate, which this crate does not do for you.
        BodyChoice::ServiceDiscoveryReq(_) => {
            BodyChoice::ServiceDiscoveryRes(iso2::ServiceDiscoveryRes {
                response_code: ResponseCode::OK,
                payment_option_list: PaymentOptionList {
                    payment_option: vec![PaymentOption::ExternalPayment],
                },
                charge_service: ChargeService {
                    service_id: 1,
                    service_name: Some("AC_DC_Charging".into()),
                    service_category: ServiceCategory::EVCharging,
                    service_scope: None,
                    free_service: false,
                    supported_energy_transfer_mode: SupportedEnergyTransferMode {
                        energy_transfer_mode: vec![EnergyTransferMode::ACThreePhaseCore],
                    },
                },
                service_list: None,
            })
        }

        BodyChoice::PaymentServiceSelectionReq(_) => {
            BodyChoice::PaymentServiceSelectionRes(iso2::PaymentServiceSelectionRes {
                response_code: ResponseCode::OK,
            })
        }

        // `EVSEProcessing::Ongoing` is how a station says "the driver is still
        // tapping their card"; the vehicle then repeats the request, and the
        // ordering rules already allow that.
        BodyChoice::AuthorizationReq(_) => BodyChoice::AuthorizationRes(iso2::AuthorizationRes {
            response_code: ResponseCode::OK,
            evse_processing: EVSEProcessing::Finished,
        }),

        BodyChoice::ChargeParameterDiscoveryReq(req) => {
            println!("     vehicle wants {:?}", req.requested_energy_transfer_mode);
            BodyChoice::ChargeParameterDiscoveryRes(iso2::ChargeParameterDiscoveryRes {
                response_code: ResponseCode::OK,
                evse_processing: EVSEProcessing::Finished,
                // The schedule: 22 kW, for the next twelve hours.
                choice_2: Some(iso2::ChargeParameterDiscoveryResChoice2::SAScheduleList(
                    SAScheduleList {
                        sa_schedule_tuple: vec![SAScheduleTuple {
                            sa_schedule_tuple_id: 1,
                            p_max_schedule: PMaxSchedule {
                                p_max_schedule_entry: vec![PMaxScheduleEntry {
                                    choice: PMaxScheduleEntryChoice::RelativeTimeInterval(
                                        RelativeTimeInterval { start: 0, duration: Some(43_200) },
                                    ),
                                    p_max: watts(22, 3),
                                }],
                            },
                            sales_tariff: None,
                        }],
                    },
                )),
                choice_3: iso2::ChargeParameterDiscoveryResChoice3::ACEVSEChargeParameter(
                    iso2::ACEVSEChargeParameter {
                        ac_evse_status: status,
                        evse_nominal_voltage: volts(230),
                        evse_max_current: amps(32),
                    },
                ),
            })
        }

        // The contactor. `ChargeProgress::Start` closes it, `Stop` opens it —
        // and this is the one place in the flow where a `FAILED_*` answer means
        // "the hardware said no", which ends the session by itself.
        BodyChoice::PowerDeliveryReq(req) => {
            println!("     contactor: {:?}", req.charge_progress);
            BodyChoice::PowerDeliveryRes(iso2::PowerDeliveryRes {
                response_code: ResponseCode::OK,
                choice: iso2::PowerDeliveryResChoice::ACEVSEStatus(status),
            })
        }

        BodyChoice::ChargingStatusReq(_) => {
            BodyChoice::ChargingStatusRes(iso2::ChargingStatusRes {
                response_code: ResponseCode::OK,
                evse_id: "DE*ABC*E123*45".into(),
                sa_schedule_tuple_id: 1,
                evse_max_current: Some(amps(32)),
                meter_info: None,
                receipt_required: Some(false),
                ac_evse_status: status,
            })
        }

        BodyChoice::SessionStopReq(req) => {
            println!("     {:?}", req.charging_session);
            BodyChoice::SessionStopRes(iso2::SessionStopRes { response_code: ResponseCode::OK })
        }

        other => panic!("this example has no answer for {}", other.name()),
    }
}

/// The response to a request that broke the ordering rules.
///
/// The response *code* comes from the engine — it is the same rule on both
/// sides of the plug — but which of the seventeen response types carries it
/// depends on the request, and only the application knows how to build one.
fn refuse(request: &Message, response_code: u8) -> BodyChoice {
    let code = ResponseCode::from_index(u64::from(response_code)).unwrap_or(ResponseCode::FAILED);
    match body(request) {
        Some(BodyChoice::AuthorizationReq(_)) => {
            BodyChoice::AuthorizationRes(iso2::AuthorizationRes {
                response_code: code,
                evse_processing: EVSEProcessing::Finished,
            })
        }
        // Anything else gets the one response every session can end with.
        _ => BodyChoice::SessionStopRes(iso2::SessionStopRes { response_code: code }),
    }
}

fn body(message: &Message) -> Option<BodyChoice> {
    match message {
        Message::Iso2(doc) => match &**doc {
            iso2::Document::V2GMessage(m) => m.body.choice.clone(),
            _ => None,
        },
        _ => None,
    }
}

/// Wraps a body in the `V2G_Message` envelope -2 puts every message in.
///
/// The session id is left empty on purpose: [`Secc::respond`] writes the one
/// this station assigned, so there is no copy of it here to get wrong.
fn wrap(choice: BodyChoice) -> Message {
    Message::Iso2(Box::new(iso2::Document::V2GMessage(V2GMessage {
        header: MessageHeader { session_id: Vec::new(), notification: None, signature: None },
        body: Body { choice: Some(choice) },
    })))
}

/// `PhysicalValueType` is a 16-bit value with a decimal exponent, which is how
/// 22 kW fits in a field that stops at 32767.
fn watts(value: i16, multiplier: i8) -> PhysicalValue {
    PhysicalValue { multiplier, unit: UnitSymbol::W, value }
}

fn volts(value: i16) -> PhysicalValue {
    PhysicalValue { multiplier: 0, unit: UnitSymbol::V, value }
}

fn amps(value: i16) -> PhysicalValue {
    PhysicalValue { multiplier: 0, unit: UnitSymbol::A, value }
}
