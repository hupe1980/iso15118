//! The vehicle side of `examples/secc_tcp.rs`: a complete AC charging session
//! over a real TCP socket.
//!
//! The asymmetry between this and the station is the protocol's, not the
//! crate's: the vehicle *drives*. It chooses the next request; the station only
//! ever answers. So [`Evcc`] takes requests to send and surfaces the answers,
//! where [`Secc`](iso15118::secc::Secc) does the reverse.
//!
//! ```sh
//! cargo run --example secc_tcp     # in one terminal
//! cargo run --example evcc_tcp     # in another
//! ```
//!
//! A real vehicle finds the station with SDP first — see
//! `examples/sdp_discovery.rs` — rather than hard-coding a port.

use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant as StdInstant};

use iso15118::evcc::{Close, Evcc, EvccConfig, Event};
use iso15118::iso2::{
    Body, BodyChoice, ChargeProgress, ChargingSession, EnergyTransferMode, MessageHeader,
    PaymentOption, PhysicalValue, SelectedService, SelectedServiceList, UnitSymbol, V2GMessage,
};
use iso15118::message::Message;
use iso15118::session::Instant;
use iso15118::{Protocol, Protocols, iso2};

const CONNECT: &str = "127.0.0.1:15119";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect(CONNECT)?;
    stream.set_read_timeout(Some(Duration::from_millis(100)))?;
    println!("connected to {CONNECT}");

    let mut evcc = Evcc::new(EvccConfig {
        // Most preferred first: the station is required to honour the order.
        protocols: Protocols::only(Protocol::Iso2),
        ..EvccConfig::default()
    });

    let started = StdInstant::now();
    // A monotonic millisecond count is all the crate wants; the origin is
    // arbitrary and only differences are ever read.
    let now =
        || Instant::from_millis(u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX));

    // The whole session, as the list of requests it is. Each is sent once the
    // previous answer has arrived; the ordering rules refuse anything the
    // current phase does not allow, here rather than on the wire.
    let mut plan: Vec<BodyChoice> = charging_plan();
    plan.reverse();

    evcc.start(now())?;
    let mut awaiting = true;

    while !evcc.is_closed() {
        let out = evcc.take_transmit();
        if !out.is_empty() {
            stream.write_all(&out)?;
        }

        let mut buf = [0u8; 4096];
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if let Err(e) = evcc.handle_input(&buf[..n]) {
                    eprintln!("bad input: {e}");
                    break;
                }
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(e) => return Err(e.into()),
        }

        if evcc.poll_timeout().is_some_and(|deadline| deadline <= now()) {
            evcc.handle_timeout(now());
        }

        while let Some(event) = evcc.poll_event() {
            match event {
                Event::ProtocolAgreed(p) => {
                    println!("speaking {p}");
                    awaiting = false;
                }
                Event::Response(res) => {
                    println!("  <- {}", res.name());
                    if let Some(BodyChoice::SessionSetupRes(setup)) = body(&res) {
                        println!("     station {} assigned {}", setup.evse_id, evcc.session_id());
                    }
                    awaiting = false;
                }
                // A `FAILED_*` code ends the session. The only request left is
                // `SessionStopReq`, and `request` will refuse anything else.
                Event::Failed => {
                    eprintln!("  !! the station refused; stopping");
                    plan.clear();
                    plan.push(stop(ChargingSession::Terminate));
                    awaiting = false;
                }
                Event::Closed(why) => {
                    println!("--- {why}");
                    if why == Close::Paused {
                        println!("    resume later with session id {}", evcc.session_id());
                    }
                }
                _ => {}
            }
        }

        if !awaiting
            && !evcc.is_closed()
            && let Some(next) = plan.pop()
        {
            println!("  -> {}", next.name());
            // No session id here either: before `SessionSetupRes` there is none
            // to send, and afterwards `request` stamps the one the station
            // assigned. A vehicle *resuming* a paused session is the exception,
            // and it names that session's id in its `SessionSetupReq`.
            evcc.request(now(), wrap(next))?;
            awaiting = true;
        }
    }
    Ok(())
}

/// The session this vehicle intends to have.
fn charging_plan() -> Vec<BodyChoice> {
    let mut plan = vec![
        BodyChoice::SessionSetupReq(iso2::SessionSetupReq {
            evcc_id: vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        }),
        BodyChoice::ServiceDiscoveryReq(iso2::ServiceDiscoveryReq {
            service_scope: None,
            service_category: None,
        }),
        BodyChoice::PaymentServiceSelectionReq(iso2::PaymentServiceSelectionReq {
            selected_payment_option: PaymentOption::ExternalPayment,
            selected_service_list: SelectedServiceList {
                selected_service: vec![SelectedService { service_id: 1, parameter_set_id: None }],
            },
        }),
        BodyChoice::AuthorizationReq(iso2::AuthorizationReq { id: None, gen_challenge: None }),
        BodyChoice::ChargeParameterDiscoveryReq(iso2::ChargeParameterDiscoveryReq {
            max_entries_sa_schedule_tuple: Some(1),
            requested_energy_transfer_mode: EnergyTransferMode::ACThreePhaseCore,
            choice: iso2::ChargeParameterDiscoveryReqChoice::ACEVChargeParameter(
                iso2::ACEVChargeParameter {
                    departure_time: None,
                    e_amount: watts(30, 3),
                    ev_max_voltage: volts(400),
                    ev_max_current: amps(32),
                    ev_min_current: amps(6),
                },
            ),
        }),
        BodyChoice::PowerDeliveryReq(power_delivery(ChargeProgress::Start)),
    ];
    // The charge loop. A real vehicle keeps going until the battery is full or
    // the driver unplugs; three round trips are enough to show the shape.
    for _ in 0..3 {
        plan.push(BodyChoice::ChargingStatusReq(iso2::ChargingStatusReq));
    }
    plan.push(BodyChoice::PowerDeliveryReq(power_delivery(ChargeProgress::Stop)));
    plan.push(stop(ChargingSession::Terminate));
    plan
}

fn stop(charging_session: ChargingSession) -> BodyChoice {
    BodyChoice::SessionStopReq(iso2::SessionStopReq { charging_session })
}

fn power_delivery(charge_progress: ChargeProgress) -> iso2::PowerDeliveryReq {
    iso2::PowerDeliveryReq {
        charge_progress,
        sa_schedule_tuple_id: 1,
        charging_profile: None,
        choice: None,
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
/// The session id is left empty: a fresh session has none to send, and once
/// `SessionSetupRes` has assigned one, [`Evcc::request`] stamps it.
fn wrap(choice: BodyChoice) -> Message {
    Message::Iso2(Box::new(iso2::Document::V2GMessage(V2GMessage {
        header: MessageHeader { session_id: Vec::new(), notification: None, signature: None },
        body: Body { choice: Some(choice) },
    })))
}

fn watts(value: i16, multiplier: i8) -> PhysicalValue {
    PhysicalValue { multiplier, unit: UnitSymbol::Wh, value }
}

fn volts(value: i16) -> PhysicalValue {
    PhysicalValue { multiplier: 0, unit: UnitSymbol::V, value }
}

fn amps(value: i16) -> PhysicalValue {
    PhysicalValue { multiplier: 0, unit: UnitSymbol::A, value }
}
