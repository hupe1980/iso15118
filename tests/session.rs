//! A whole ISO 15118-2 session, EVCC to SECC, with no sockets and no clock.
//!
//! This is the point of the sans-I/O design: a charging session — protocol
//! handshake, session setup, service discovery, authorization, DC cable check,
//! pre-charge, the charge loop, welding detection and shutdown — runs as a
//! plain unit test in microseconds, with time as a variable the test increments.
//!
//! The two sides talk to each other through byte vectors, so everything the
//! wire would carry is exercised: V2GTP framing, EXI, the document event codes,
//! session-id checking and the ordering rules.

#![cfg(all(feature = "iso2", feature = "evcc", feature = "secc"))]

use iso15118::Protocol;
use iso15118::evcc::{Evcc, EvccConfig};
use iso15118::iso2::{
    Body, BodyChoice, ChargeProgress, DCEVSEStatus, DCEVSEStatusCode, EnergyTransferMode,
    IsolationLevel, MessageHeader, PaymentOption, ResponseCode, V2GMessage,
};
use iso15118::message::Message;
use iso15118::secc::{self, Secc, SeccConfig};
use iso15118::session::{Instant, Millis, SessionId, Timer};
use iso15118::{evcc, iso2};

const SESSION_ID: SessionId = SessionId::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);

/// The two sides, wired to each other by byte vectors and a shared clock.
struct Link {
    evcc: Evcc,
    secc: Secc,
    now: Instant,
}

impl Link {
    fn new() -> Self {
        let evcc = Evcc::new(EvccConfig { protocols: &[Protocol::Iso2], ..Default::default() });
        let mut secc = Secc::new(SeccConfig {
            protocols: &[Protocol::Iso2],
            session_id: SESSION_ID,
            ..Default::default()
        });
        let now = Instant::ZERO;
        secc.opened(now);
        Self { evcc, secc, now }
    }

    fn advance(&mut self, by: Millis) {
        self.now = self.now + by;
        self.evcc.handle_timeout(self.now);
        self.secc.handle_timeout(self.now);
    }

    /// Moves whatever the EVCC has queued to the SECC, and back.
    fn pump(&mut self) {
        let up = self.evcc.take_transmit();
        if !up.is_empty() {
            self.secc.handle_input(self.now, &up).expect("SECC input");
        }
        let down = self.secc.take_transmit();
        if !down.is_empty() {
            self.evcc.handle_input(&down).expect("EVCC input");
        }
    }

    /// Drains the SECC's events, answering each request with `answer`.
    fn serve(&mut self, answer: impl Fn(&Message) -> Message) {
        while let Some(event) = self.secc.poll_event() {
            match event {
                secc::Event::Request(req) => {
                    let res = answer(&req);
                    self.secc.respond(self.now, res).expect("respond");
                }
                secc::Event::Refused { message, reason, .. } => {
                    panic!("SECC refused {}: {reason}", message.name())
                }
                _ => {}
            }
        }
    }

    /// Sends `request`, lets the SECC answer it, and returns the answer.
    fn exchange(&mut self, request: BodyChoice) -> BodyChoice {
        self.evcc.request(self.now, wrap(request)).expect("request");
        self.pump();
        self.serve(|req| wrap(reply_to(req)));
        self.pump();
        let mut answer = None;
        while let Some(event) = self.evcc.poll_event() {
            if let evcc::Event::Response(res) = event {
                answer = unwrap(&res);
            }
        }
        answer.expect("a response")
    }
}

fn header() -> MessageHeader {
    MessageHeader {
        session_id: SESSION_ID.as_bytes().to_vec(),
        notification: None,
        signature: None,
    }
}

fn wrap(choice: BodyChoice) -> Message {
    Message::Iso2(Box::new(iso2::Document::V2GMessage(V2GMessage {
        header: header(),
        body: Body { choice: Some(choice) },
    })))
}

fn unwrap(message: &Message) -> Option<BodyChoice> {
    match message {
        Message::Iso2(doc) => match &**doc {
            iso2::Document::V2GMessage(m) => m.body.choice.clone(),
            _ => None,
        },
        _ => None,
    }
}

/// A charging station that says yes to everything, which is all this test needs
/// it to do: the point here is the sequencing, not the policy.
#[allow(
    clippy::too_many_lines,
    clippy::match_same_arms,
    reason = "one arm per message reads as the table it is"
)]
fn reply_to(request: &Message) -> BodyChoice {
    use BodyChoice as B;
    let status = DCEVSEStatus {
        notification_max_delay: 0,
        evse_notification: iso2::EVSENotification::None,
        evse_isolation_status: Some(IsolationLevel::Valid),
        evse_status_code: DCEVSEStatusCode::EVSEReady,
    };
    match unwrap(request).expect("a body") {
        B::SessionSetupReq(_) => B::SessionSetupRes(iso2::SessionSetupRes {
            response_code: ResponseCode::OKNewSessionEstablished,
            evse_id: "DE*ABC*E123*45".into(),
            evse_time_stamp: Some(1_725_456_343),
        }),
        B::ServiceDiscoveryReq(_) => B::ServiceDiscoveryRes(iso2::ServiceDiscoveryRes {
            response_code: ResponseCode::OK,
            payment_option_list: iso2::PaymentOptionList {
                payment_option: alloc_vec(PaymentOption::ExternalPayment),
            },
            charge_service: iso2::ChargeService {
                service_id: 1,
                service_name: None,
                service_category: iso2::ServiceCategory::EVCharging,
                service_scope: None,
                free_service: false,
                supported_energy_transfer_mode: iso2::SupportedEnergyTransferMode {
                    energy_transfer_mode: alloc_vec(EnergyTransferMode::DCExtended),
                },
            },
            service_list: None,
        }),
        B::PaymentServiceSelectionReq(_) => {
            B::PaymentServiceSelectionRes(iso2::PaymentServiceSelectionRes {
                response_code: ResponseCode::OK,
            })
        }
        B::AuthorizationReq(_) => B::AuthorizationRes(iso2::AuthorizationRes {
            response_code: ResponseCode::OK,
            evse_processing: iso2::EVSEProcessing::Finished,
        }),
        B::ChargeParameterDiscoveryReq(_) => {
            B::ChargeParameterDiscoveryRes(iso2::ChargeParameterDiscoveryRes {
                response_code: ResponseCode::OK,
                evse_processing: iso2::EVSEProcessing::Finished,
                choice_2: None,
                choice_3: iso2::ChargeParameterDiscoveryResChoice3::DCEVSEChargeParameter(
                    iso2::DCEVSEChargeParameter {
                        dc_evse_status: status.clone(),
                        evse_maximum_current_limit: physical(200),
                        evse_maximum_power_limit: kilo(150),
                        evse_maximum_voltage_limit: physical(900),
                        evse_minimum_current_limit: physical(0),
                        evse_minimum_voltage_limit: physical(150),
                        evse_current_regulation_tolerance: None,
                        evse_peak_current_ripple: physical(1),
                        evse_energy_to_be_delivered: None,
                    },
                ),
            })
        }
        B::CableCheckReq(_) => B::CableCheckRes(iso2::CableCheckRes {
            response_code: ResponseCode::OK,
            dc_evse_status: status.clone(),
            evse_processing: iso2::EVSEProcessing::Finished,
        }),
        B::PreChargeReq(_) => B::PreChargeRes(iso2::PreChargeRes {
            response_code: ResponseCode::OK,
            dc_evse_status: status.clone(),
            evse_present_voltage: physical(400),
        }),
        B::PowerDeliveryReq(_) => B::PowerDeliveryRes(iso2::PowerDeliveryRes {
            response_code: ResponseCode::OK,
            choice: iso2::PowerDeliveryResChoice::DCEVSEStatus(status.clone()),
        }),
        B::CurrentDemandReq(_) => B::CurrentDemandRes(iso2::CurrentDemandRes {
            response_code: ResponseCode::OK,
            dc_evse_status: status,
            evse_present_voltage: physical(400),
            evse_present_current: physical(100),
            evse_current_limit_achieved: false,
            evse_voltage_limit_achieved: false,
            evse_power_limit_achieved: false,
            evse_maximum_voltage_limit: None,
            evse_maximum_current_limit: None,
            evse_maximum_power_limit: None,
            evse_id: "DE*ABC*E123*45".into(),
            sa_schedule_tuple_id: 1,
            meter_info: None,
            receipt_required: None,
        }),
        B::WeldingDetectionReq(_) => B::WeldingDetectionRes(iso2::WeldingDetectionRes {
            response_code: ResponseCode::OK,
            dc_evse_status: DCEVSEStatus {
                notification_max_delay: 0,
                evse_notification: iso2::EVSENotification::None,
                evse_isolation_status: Some(IsolationLevel::Valid),
                evse_status_code: DCEVSEStatusCode::EVSEShutdown,
            },
            evse_present_voltage: physical(0),
        }),
        B::SessionStopReq(_) => {
            B::SessionStopRes(iso2::SessionStopRes { response_code: ResponseCode::OK })
        }
        other => panic!("the charger has no answer for {other:?}"),
    }
}

fn physical(value: i16) -> iso2::PhysicalValue {
    iso2::PhysicalValue { multiplier: 0, unit: iso2::UnitSymbol::V, value }
}

/// `PhysicalValueType` is a 16-bit value with a decimal exponent, which is how
/// 150 kW fits in a field that stops at 32767.
fn kilo(value: i16) -> iso2::PhysicalValue {
    iso2::PhysicalValue { multiplier: 3, unit: iso2::UnitSymbol::W, value }
}

fn alloc_vec<T>(item: T) -> Vec<T> {
    vec![item]
}

/// Runs the handshake and returns once both sides agree on ISO 15118-2.
fn negotiated() -> Link {
    let mut link = Link::new();
    link.evcc.start(link.now).expect("start");
    link.pump();
    link.serve(|_| unreachable!("the handshake needs no application decision"));
    link.pump();

    let agreed = core::iter::from_fn(|| link.evcc.poll_event())
        .find_map(|e| match e {
            evcc::Event::ProtocolAgreed(p) => Some(p),
            _ => None,
        })
        .expect("a protocol");
    assert_eq!(agreed, Protocol::Iso2);
    assert_eq!(link.secc.protocol(), Some(Protocol::Iso2));
    link
}

#[test]
fn a_whole_dc_charging_session_runs_without_a_socket() {
    let mut link = negotiated();

    let res = link.exchange(BodyChoice::SessionSetupReq(iso2::SessionSetupReq {
        evcc_id: vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
    }));
    let BodyChoice::SessionSetupRes(setup) = res else { panic!("wrong response") };
    assert_eq!(setup.response_code, ResponseCode::OKNewSessionEstablished);
    assert_eq!(link.evcc.session_id(), SESSION_ID, "the charger assigned the id");

    link.exchange(BodyChoice::ServiceDiscoveryReq(iso2::ServiceDiscoveryReq {
        service_scope: None,
        service_category: None,
    }));
    link.exchange(BodyChoice::PaymentServiceSelectionReq(iso2::PaymentServiceSelectionReq {
        selected_payment_option: PaymentOption::ExternalPayment,
        selected_service_list: iso2::SelectedServiceList {
            selected_service: vec![iso2::SelectedService { service_id: 1, parameter_set_id: None }],
        },
    }));
    link.exchange(BodyChoice::AuthorizationReq(iso2::AuthorizationReq {
        id: None,
        gen_challenge: None,
    }));
    link.exchange(BodyChoice::ChargeParameterDiscoveryReq(iso2::ChargeParameterDiscoveryReq {
        max_entries_sa_schedule_tuple: None,
        requested_energy_transfer_mode: EnergyTransferMode::DCExtended,
        choice: iso2::ChargeParameterDiscoveryReqChoice::DCEVChargeParameter(
            dc_ev_charge_parameter(),
        ),
    }));

    // DC: isolation, then voltage matching, before a contactor closes.
    link.exchange(BodyChoice::CableCheckReq(iso2::CableCheckReq { dc_ev_status: ev_status() }));
    link.exchange(BodyChoice::PreChargeReq(iso2::PreChargeReq {
        dc_ev_status: ev_status(),
        ev_target_voltage: physical(400),
        ev_target_current: physical(2),
    }));
    link.exchange(BodyChoice::PowerDeliveryReq(power_delivery(ChargeProgress::Start)));

    for _ in 0..3 {
        link.exchange(BodyChoice::CurrentDemandReq(current_demand()));
        link.advance(Millis::from_millis(60));
    }

    link.exchange(BodyChoice::PowerDeliveryReq(power_delivery(ChargeProgress::Stop)));
    link.exchange(BodyChoice::WeldingDetectionReq(iso2::WeldingDetectionReq {
        dc_ev_status: ev_status(),
    }));
    link.exchange(BodyChoice::SessionStopReq(iso2::SessionStopReq {
        charging_session: iso2::ChargingSession::Terminate,
    }));

    assert!(link.secc.is_closed(), "the charger ends the session after SessionStopRes");
    assert!(link.evcc.is_closed(), "and so does the vehicle");
}

#[test]
fn the_charger_refuses_a_request_that_is_out_of_sequence() {
    let mut link = negotiated();
    // Skipping straight to authorization: no session, no services, no payment.
    let _ = link.evcc.take_transmit();
    let bad = wrap(BodyChoice::AuthorizationReq(iso2::AuthorizationReq {
        id: None,
        gen_challenge: None,
    }));
    // Bypass the EVCC's own check — a conforming vehicle would not send this,
    // and the charger must not depend on that.
    let mut raw = iso15118::session::Connection::new();
    raw.set_protocol(Protocol::Iso2);
    raw.send(&bad).unwrap();
    let wire = raw.take_transmit();
    link.secc.handle_input(link.now, &wire).unwrap();

    let mut refused = None;
    let mut closed = None;
    while let Some(event) = link.secc.poll_event() {
        match event {
            secc::Event::Refused { response_code, reason, .. } => {
                refused = Some((response_code, reason));
            }
            secc::Event::Closed(why) => closed = Some(why),
            _ => {}
        }
    }
    let (code, reason) = refused.expect("a refusal");
    assert_eq!(code, ResponseCode::FAILEDSequenceError as u8);
    assert!(matches!(reason, secc::Refusal::Sequence(_)));
    assert_eq!(closed, Some(secc::Close::Refused));
}

#[test]
fn the_vehicle_refuses_to_send_a_request_that_is_out_of_sequence() {
    let mut link = negotiated();
    let e = link
        .evcc
        .request(link.now, wrap(BodyChoice::CurrentDemandReq(current_demand())))
        .unwrap_err();
    assert!(matches!(e, evcc::EvccError::Flow(_)), "caught locally, not on the wire: {e}");
    assert!(link.evcc.transmit_is_empty(), "nothing must have reached the wire");
}

#[test]
fn a_silent_vehicle_expires_the_sequence_timer() {
    let mut link = negotiated();
    link.exchange(BodyChoice::SessionSetupReq(iso2::SessionSetupReq {
        evcc_id: vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
    }));
    while link.secc.poll_event().is_some() {}

    let deadline = link.secc.poll_timeout().expect("a deadline");
    assert_eq!(deadline - link.now, Millis::from_secs(60), "V2G_SECC_Sequence_Timeout");

    link.advance(Millis::from_secs(61));
    let closed = core::iter::from_fn(|| link.secc.poll_event()).find_map(|e| match e {
        secc::Event::Closed(why) => Some(why),
        _ => None,
    });
    assert_eq!(closed, Some(secc::Close::Timeout(Timer::Sequence)));
}

#[test]
fn a_silent_charger_expires_the_vehicles_message_timer() {
    let mut link = negotiated();
    link.evcc
        .request(
            link.now,
            wrap(BodyChoice::SessionSetupReq(iso2::SessionSetupReq { evcc_id: vec![0; 6] })),
        )
        .unwrap();
    assert_eq!(link.evcc.outstanding(), Some("SessionSetupReq"));

    // `SessionSetupRes` gets the default 2 s budget.
    let deadline = link.evcc.poll_timeout().expect("a deadline");
    assert_eq!(deadline - link.now, Millis::from_secs(2));

    link.advance(Millis::from_secs(3));
    let closed = core::iter::from_fn(|| link.evcc.poll_event()).find_map(|e| match e {
        evcc::Event::Closed(why) => Some(why),
        _ => None,
    });
    assert_eq!(closed, Some(evcc::Close::Timeout(Timer::Message)));
}

#[test]
fn a_charger_with_nothing_in_common_says_so_and_stops() {
    let mut evcc = Evcc::new(EvccConfig { protocols: &[Protocol::Iso20], ..Default::default() });
    let mut secc = Secc::new(SeccConfig {
        protocols: &[Protocol::Din70121],
        session_id: SESSION_ID,
        ..Default::default()
    });
    let now = Instant::ZERO;
    evcc.start(now).unwrap();
    secc.handle_input(now, &evcc.take_transmit()).unwrap();
    evcc.handle_input(&secc.take_transmit()).unwrap();

    assert!(secc.is_closed());
    let closed = core::iter::from_fn(|| evcc.poll_event()).find_map(|e| match e {
        evcc::Event::Closed(why) => Some(why),
        _ => None,
    });
    assert_eq!(closed, Some(evcc::Close::NoCommonProtocol));
}

fn ev_status() -> iso2::DCEVStatus {
    iso2::DCEVStatus {
        ev_ready: true,
        ev_error_code: iso2::DCEVErrorCode::NOERROR,
        ev_ress_soc: 42,
    }
}

fn dc_ev_charge_parameter() -> iso2::DCEVChargeParameter {
    iso2::DCEVChargeParameter {
        departure_time: None,
        dc_ev_status: ev_status(),
        ev_maximum_current_limit: physical(200),
        ev_maximum_power_limit: None,
        ev_maximum_voltage_limit: physical(900),
        ev_energy_capacity: None,
        ev_energy_request: None,
        full_soc: None,
        bulk_soc: None,
    }
}

fn power_delivery(progress: ChargeProgress) -> iso2::PowerDeliveryReq {
    iso2::PowerDeliveryReq {
        charge_progress: progress,
        sa_schedule_tuple_id: 1,
        charging_profile: None,
        choice: Some(iso2::PowerDeliveryReqChoice::DCEVPowerDeliveryParameter(
            iso2::DCEVPowerDeliveryParameter {
                dc_ev_status: ev_status(),
                bulk_charging_complete: None,
                charging_complete: false,
            },
        )),
    }
}

fn current_demand() -> iso2::CurrentDemandReq {
    iso2::CurrentDemandReq {
        dc_ev_status: ev_status(),
        ev_target_current: physical(100),
        ev_maximum_voltage_limit: None,
        ev_maximum_current_limit: None,
        ev_maximum_power_limit: None,
        bulk_charging_complete: None,
        charging_complete: false,
        remaining_time_to_full_soc: None,
        remaining_time_to_bulk_soc: None,
        ev_target_voltage: physical(400),
    }
}

/// ISO 15118 leaves no discretion after a `FAILED_*` response: the session is
/// over, and the only request the vehicle may still send is `SessionStopReq`.
/// A core that lets the flow carry on is the bug `EVerest`'s
/// `GHSA-9vv5-67cv-9crq` describes.
#[test]
fn a_failure_response_leaves_only_session_stop() {
    let mut link = negotiated();
    link.exchange(BodyChoice::SessionSetupReq(iso2::SessionSetupReq {
        evcc_id: vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
    }));

    // The charger declines service discovery.
    link.evcc
        .request(
            link.now,
            wrap(BodyChoice::ServiceDiscoveryReq(iso2::ServiceDiscoveryReq {
                service_scope: None,
                service_category: None,
            })),
        )
        .unwrap();
    link.pump();
    link.serve(|_| {
        wrap(BodyChoice::ServiceDiscoveryRes(iso2::ServiceDiscoveryRes {
            response_code: ResponseCode::FAILEDServiceIDInvalid,
            payment_option_list: iso2::PaymentOptionList {
                payment_option: alloc_vec(PaymentOption::ExternalPayment),
            },
            charge_service: iso2::ChargeService {
                service_id: 1,
                service_name: None,
                service_category: iso2::ServiceCategory::EVCharging,
                service_scope: None,
                free_service: false,
                supported_energy_transfer_mode: iso2::SupportedEnergyTransferMode {
                    energy_transfer_mode: alloc_vec(EnergyTransferMode::DCExtended),
                },
            },
            service_list: None,
        }))
    });
    link.pump();

    let failed =
        core::iter::from_fn(|| link.evcc.poll_event()).any(|e| matches!(e, evcc::Event::Failed));
    assert!(failed, "the vehicle is told the response was a failure");

    // Both sides now refuse to go on with anything but the stop.
    let next = wrap(BodyChoice::PaymentServiceSelectionReq(iso2::PaymentServiceSelectionReq {
        selected_payment_option: PaymentOption::ExternalPayment,
        selected_service_list: iso2::SelectedServiceList {
            selected_service: vec![iso2::SelectedService { service_id: 1, parameter_set_id: None }],
        },
    }));
    assert!(link.evcc.request(link.now, next).is_err(), "the vehicle refuses to carry on");
    assert!(!link.secc.is_closed(), "the charger still waits for SessionStopReq");

    link.exchange(BodyChoice::SessionStopReq(iso2::SessionStopReq {
        charging_session: iso2::ChargingSession::Terminate,
    }));
    assert!(link.secc.is_closed());
    assert!(link.evcc.is_closed());
}

/// A paused session is finished but not terminated: both sides keep the id, so
/// the next session under it is a resume rather than a new one.
#[test]
fn a_paused_session_is_reported_as_paused() {
    let mut link = negotiated();
    link.exchange(BodyChoice::SessionSetupReq(iso2::SessionSetupReq {
        evcc_id: vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
    }));
    link.exchange(BodyChoice::SessionStopReq(iso2::SessionStopReq {
        charging_session: iso2::ChargingSession::Pause,
    }));

    assert_eq!(link.evcc.session_id(), SESSION_ID, "the id survives, to resume under");
    assert!(link.secc.is_closed());
    assert!(link.evcc.is_closed());
}

/// The other half of a pause: the vehicle comes back with the id it was given,
/// and the station adopts it rather than assigning a new one.
///
/// Whether an id names a resumable session is stored state the core does not
/// hold — a schedule, an energy reading — so the decision is the application's
/// and `join_session` is how it says so.
#[test]
fn a_station_can_join_the_session_a_vehicle_asks_to_resume() {
    const PAUSED: SessionId = SessionId::new([0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 1]);

    // The vehicle says once, in configuration, which session it is rejoining —
    // rather than hand-placing an id in the one message out of thirty whose
    // session id is its own to choose.
    let mut link = Link::new();
    link.evcc = Evcc::new(EvccConfig {
        protocols: &[Protocol::Iso2],
        rejoin: Some(PAUSED),
        ..Default::default()
    });
    link.evcc.start(link.now).unwrap();
    link.pump();
    link.serve(|_| unreachable!("the handshake needs no application decision"));
    link.pump();
    while link.evcc.poll_event().is_some() {}

    let setup = wrap(BodyChoice::SessionSetupReq(iso2::SessionSetupReq {
        evcc_id: vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
    }));
    link.evcc.request(link.now, setup).unwrap();
    link.pump();

    while let Some(event) = link.secc.poll_event() {
        if let secc::Event::Request(req) = event {
            assert_eq!(req.session_id(), Some(PAUSED));
            link.secc.join_session(PAUSED);
            let res = wrap_with(
                PAUSED,
                BodyChoice::SessionSetupRes(iso2::SessionSetupRes {
                    response_code: ResponseCode::OKOldSessionJoined,
                    evse_id: "DE*ABC*E123*45".into(),
                    evse_time_stamp: Some(1_725_456_343),
                }),
            );
            link.secc.respond(link.now, res).unwrap();
        }
    }
    assert_eq!(link.secc.session_id(), PAUSED, "the station adopted the vehicle's id");
    link.pump();
    while link.evcc.poll_event().is_some() {}

    // The rest of the session runs under the resumed id, and the station's
    // check accepts it.
    let next = wrap_with(
        PAUSED,
        BodyChoice::ServiceDiscoveryReq(iso2::ServiceDiscoveryReq {
            service_scope: None,
            service_category: None,
        }),
    );
    link.evcc.request(link.now, next).unwrap();
    link.pump();
    link.serve(|req| wrap_with(PAUSED, reply_to(req)));
    assert!(!link.secc.is_closed(), "a resumed session is not a rejected one");
}

fn wrap_with(session_id: SessionId, choice: BodyChoice) -> Message {
    Message::Iso2(Box::new(iso2::Document::V2GMessage(V2GMessage {
        header: MessageHeader {
            session_id: session_id.as_bytes().to_vec(),
            notification: None,
            signature: None,
        },
        body: Body { choice: Some(choice) },
    })))
}

/// `Protocol::Din70121` exists so a charger can decline it by name, but this
/// crate has no DIN message set — its schemas are not freely available. A
/// charger configured for it must decline rather than agree to something it
/// cannot then speak.
#[test]
fn a_protocol_with_no_message_set_is_not_a_protocol_in_common() {
    let mut evcc = Evcc::new(EvccConfig { protocols: &[Protocol::Din70121], ..Default::default() });
    let mut secc = Secc::new(SeccConfig {
        protocols: &[Protocol::Din70121, Protocol::Iso2],
        session_id: SESSION_ID,
        ..Default::default()
    });
    let now = Instant::ZERO;
    evcc.start(now).unwrap();
    secc.handle_input(now, &evcc.take_transmit()).unwrap();

    assert!(secc.is_closed(), "the charger must decline what it cannot speak");
    assert_eq!(secc.protocol(), None);
}

/// The other half of half-duplex: the *vehicle* does not pipeline either.
///
/// The ordering graph cannot catch this on its own, because a charge loop's
/// `CurrentDemandReq` is legal over and over — what makes the second one wrong
/// is that the first has not been answered yet.
#[test]
fn the_vehicle_will_not_ask_a_second_question_before_the_first_is_answered() {
    let mut link = charging();
    link.evcc.request(link.now, wrap(BodyChoice::CurrentDemandReq(current_demand()))).unwrap();
    assert_eq!(link.evcc.outstanding(), Some("CurrentDemandReq"));

    let again = link.evcc.request(link.now, wrap(BodyChoice::CurrentDemandReq(current_demand())));
    assert!(matches!(
        again,
        Err(evcc::EvccError::AwaitingResponse {
            outstanding: "CurrentDemandReq",
            got: "CurrentDemandReq"
        })
    ));

    // ...and the refusal changed nothing: the first request is still the one
    // outstanding, and answering it still works.
    link.pump();
    link.serve(|req| wrap(reply_to(req)));
    link.pump();
    assert_eq!(link.evcc.outstanding(), None, "the one request was answered");
}

/// The session id is the station's to assign and neither side's to choose per
/// message, so the drivers stamp it rather than trusting the application to.
#[test]
fn the_session_id_is_stamped_in_rather_than_taken_from_the_message() {
    let mut link = negotiated();
    link.exchange(BodyChoice::SessionSetupReq(iso2::SessionSetupReq { evcc_id: vec![0; 6] }));
    assert_eq!(link.evcc.session_id(), SESSION_ID);

    // An application that builds a request with the wrong id — or with none —
    // still puts the right one on the wire.
    link.evcc
        .request(
            link.now,
            wrap_with(
                SessionId::new([0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0]),
                BodyChoice::ServiceDiscoveryReq(iso2::ServiceDiscoveryReq {
                    service_scope: None,
                    service_category: None,
                }),
            ),
        )
        .unwrap();
    link.pump();

    let request = core::iter::from_fn(|| link.secc.poll_event())
        .find_map(|e| match e {
            secc::Event::Request(m) => Some(m),
            _ => None,
        })
        .expect("the station accepted it");
    assert_eq!(request.session_id(), Some(SESSION_ID), "the wrong id never reached the wire");
}

/// A station that answers the wrong question has a bug the vehicle would find;
/// finding it locally costs one string comparison.
#[test]
fn the_station_cannot_answer_one_request_with_another_s_response() {
    let mut link = negotiated();
    link.evcc
        .request(
            link.now,
            wrap(BodyChoice::SessionSetupReq(iso2::SessionSetupReq { evcc_id: vec![0; 6] })),
        )
        .unwrap();
    link.pump();
    let _ = core::iter::from_fn(|| link.secc.poll_event()).count();

    let wrong = wrap(BodyChoice::ServiceDiscoveryRes(iso2::ServiceDiscoveryRes {
        response_code: ResponseCode::OK,
        payment_option_list: iso2::PaymentOptionList {
            payment_option: alloc_vec(PaymentOption::ExternalPayment),
        },
        charge_service: iso2::ChargeService {
            service_id: 1,
            service_name: None,
            service_category: iso2::ServiceCategory::EVCharging,
            service_scope: None,
            free_service: false,
            supported_energy_transfer_mode: iso2::SupportedEnergyTransferMode {
                energy_transfer_mode: alloc_vec(EnergyTransferMode::DCExtended),
            },
        },
        service_list: None,
    }));
    assert!(matches!(
        link.secc.respond(link.now, wrong),
        Err(secc::SeccError::WrongResponse { expected: "SessionSetupReq", .. })
    ));

    // The right one still works: a refusal must not consume the obligation.
    let right = wrap(reply_to(&wrap(BodyChoice::SessionSetupReq(iso2::SessionSetupReq {
        evcc_id: vec![0; 6],
    }))));
    link.secc.respond(link.now, right).unwrap();
    assert!(!link.secc.awaiting_response());
}

/// ...and answering when nothing was asked is refused too, rather than being
/// framed and sent to a vehicle that is waiting for something else.
#[test]
fn the_station_cannot_answer_a_question_nobody_asked() {
    let mut link = negotiated();
    let stray =
        wrap(BodyChoice::SessionStopRes(iso2::SessionStopRes { response_code: ResponseCode::OK }));
    assert!(matches!(
        link.secc.respond(link.now, stray),
        Err(secc::SeccError::NothingToAnswer("SessionStopRes"))
    ));
    assert!(link.secc.transmit_is_empty(), "nothing was queued");
}

/// `n` back-to-back `CurrentDemandReq` frames on one wire, as a peer that does
/// not wait to be answered would send them.
///
/// Framed straight through a [`Connection`](iso15118::session::Connection)
/// rather than through [`Evcc`], because `Evcc` refuses to pipeline — that is
/// the other half of the same rule, and it has its own test. A hostile peer is
/// not running this crate.
fn pipelined(n: usize) -> Vec<u8> {
    let mut peer = iso15118::session::Connection::new();
    peer.set_protocol(Protocol::Iso2);
    for _ in 0..n {
        peer.send(&wrap(BodyChoice::CurrentDemandReq(current_demand()))).unwrap();
    }
    peer.take_transmit()
}

/// V2G is half-duplex: the vehicle may not send again before it is answered.
/// A peer that pipelines a burst of repeatable requests — a charge loop turns,
/// and `CurrentDemandReq` is legal over and over — would otherwise have every
/// one of them decoded and queued as an event before the station answered a
/// single one, which is an unbounded queue on an unauthenticated peer's say-so.
#[test]
fn the_charger_reads_one_request_at_a_time() {
    let mut link = charging();

    link.secc.handle_input(link.now, &pipelined(4)).expect("SECC input");
    assert!(link.secc.awaiting_response(), "one request is outstanding");
    let requests = core::iter::from_fn(|| link.secc.poll_event())
        .filter(|e| matches!(e, secc::Event::Request(_)))
        .count();
    assert_eq!(requests, 1, "the other three wait until this one is answered");
}

/// More than a handful of unanswered frames is not a peer that is merely early;
/// it is one that is not following the protocol, and the receiver stops rather
/// than buffering for it.
#[test]
fn a_flood_of_pipelined_frames_ends_the_stream() {
    let mut link = charging();

    let burst = pipelined(iso15118::session::MAX_PENDING_FRAMES + 1);
    assert!(link.secc.handle_input(link.now, &burst).is_err(), "the flood is refused");
}

/// The flow graph constrains requests, so nothing but this check stops a
/// charger from answering one request with another request's response — or
/// from volunteering responses to a vehicle that asked for nothing.
#[test]
fn the_vehicle_refuses_an_answer_to_a_question_it_did_not_ask() {
    let mut link = negotiated();
    link.evcc
        .request(
            link.now,
            wrap(BodyChoice::SessionSetupReq(iso2::SessionSetupReq { evcc_id: vec![0; 6] })),
        )
        .unwrap();
    let _ = link.evcc.take_transmit();

    // A well-formed, in-session `ServiceDiscoveryRes` — for a request that was
    // never sent.
    let mut charger = iso15118::session::Connection::new();
    charger.set_protocol(Protocol::Iso2);
    charger
        .send(&wrap(reply_to(&wrap(BodyChoice::ServiceDiscoveryReq(iso2::ServiceDiscoveryReq {
            service_scope: None,
            service_category: None,
        })))))
        .unwrap();
    let wire = charger.take_transmit();

    assert!(matches!(
        link.evcc.handle_input(&wire),
        Err(evcc::EvccError::UnexpectedResponse { expected: Some("SessionSetupReq"), .. })
    ));
}

/// A cable check is a *loop*: the station answers `Ongoing` and the vehicle
/// asks again. The per-message timeout says nothing about how long that may go
/// on, so without a budget of its own a vehicle waits forever for an isolation
/// test that will never finish \[V2G2-717\].
#[test]
fn the_cable_check_loop_has_a_budget_the_repeats_do_not_extend() {
    let mut link = negotiated();
    for req in setup_through_authorization() {
        link.exchange(req);
    }
    link.exchange(BodyChoice::ChargeParameterDiscoveryReq(charge_parameter_discovery()));

    let started = link.now;
    link.evcc.request(link.now, wrap(BodyChoice::CableCheckReq(cable_check()))).unwrap();
    assert_eq!(
        link.evcc.poll_timeout(),
        Some(started + Millis::from_secs(2)),
        "the per-message budget is the nearer deadline"
    );

    // The station keeps answering `Ongoing`, so the vehicle keeps asking.
    for _ in 0..8 {
        link.pump();
        link.serve(|req| wrap(reply_to(req)));
        link.pump();
        while link.evcc.poll_event().is_some() {}
        link.advance(Millis::from_secs(5));
        if link.evcc.is_closed() {
            break;
        }
        link.evcc.request(link.now, wrap(BodyChoice::CableCheckReq(cable_check()))).unwrap();
    }

    let closed = core::iter::from_fn(|| link.evcc.poll_event()).find_map(|e| match e {
        evcc::Event::Closed(why) => Some(why),
        _ => None,
    });
    assert_eq!(
        closed,
        Some(evcc::Close::Timeout(Timer::Ongoing)),
        "the loop budget runs from the first request, not from the last"
    );
    assert!(
        link.now - started >= Millis::from_secs(40),
        "V2G_EVCC_CableCheck_Timeout is 40 s, not 40 s per repeat"
    );
}

fn cable_check() -> iso2::CableCheckReq {
    iso2::CableCheckReq { dc_ev_status: ev_status() }
}

fn charge_parameter_discovery() -> iso2::ChargeParameterDiscoveryReq {
    iso2::ChargeParameterDiscoveryReq {
        max_entries_sa_schedule_tuple: None,
        requested_energy_transfer_mode: EnergyTransferMode::DCExtended,
        choice: iso2::ChargeParameterDiscoveryReqChoice::DCEVChargeParameter(
            dc_ev_charge_parameter(),
        ),
    }
}

fn setup_through_authorization() -> Vec<BodyChoice> {
    vec![
        BodyChoice::SessionSetupReq(iso2::SessionSetupReq {
            evcc_id: vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        }),
        BodyChoice::ServiceDiscoveryReq(iso2::ServiceDiscoveryReq {
            service_scope: None,
            service_category: None,
        }),
        BodyChoice::PaymentServiceSelectionReq(iso2::PaymentServiceSelectionReq {
            selected_payment_option: PaymentOption::ExternalPayment,
            selected_service_list: iso2::SelectedServiceList {
                selected_service: alloc_vec(iso2::SelectedService {
                    service_id: 1,
                    parameter_set_id: None,
                }),
            },
        }),
        BodyChoice::AuthorizationReq(iso2::AuthorizationReq { id: None, gen_challenge: None }),
    ]
}

/// A session driven as far as the charge loop.
fn charging() -> Link {
    let mut link = negotiated();
    for req in setup_through_authorization() {
        link.exchange(req);
    }
    link.exchange(BodyChoice::ChargeParameterDiscoveryReq(charge_parameter_discovery()));
    link.exchange(BodyChoice::CableCheckReq(cable_check()));
    link.exchange(BodyChoice::PreChargeReq(iso2::PreChargeReq {
        dc_ev_status: ev_status(),
        ev_target_voltage: physical(400),
        ev_target_current: physical(2),
    }));
    link.exchange(BodyChoice::PowerDeliveryReq(power_delivery(ChargeProgress::Start)));
    link
}
