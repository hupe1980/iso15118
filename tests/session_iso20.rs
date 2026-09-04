//! A whole ISO 15118-20 DC session, EVCC to SECC, with no sockets and no clock.
//!
//! The -2 counterpart is `tests/session.rs`. This one exists because -20 is half
//! the crate and everything about it was tested one layer at a time: the
//! sequencer had unit tests, the messages round-tripped, the drivers were
//! exercised against -2. Nothing put the three together, and the seams between
//! them are where -20 differs most from -2:
//!
//! * **five payload types, not one.** `CommonMessages` travels under `0x8002`
//!   and the DC messages under `0x8004`, so a single session interleaves two
//!   V2GTP payload types and two `Message` variants, and the dispatch has to
//!   pick the right decoder for each without being told;
//! * **a header on every message** rather than one wrapper around all of them,
//!   so the session id is stamped and checked in a different place;
//! * **a different flow** — authorization before service discovery, schedule
//!   exchange as a phase of its own, and `ChargeLoop` in place of
//!   `CurrentDemand`.

#![cfg(all(feature = "iso20-dc", feature = "evcc", feature = "secc"))]

use iso15118::evcc::{self, Evcc, EvccConfig};
use iso15118::iso20::common::{MessageHeader, Processing, RationalNumber, ResponseCode};
use iso15118::iso20::{dc, messages as cm};
use iso15118::message::Message;
use iso15118::secc::{self, Secc, SeccConfig};
use iso15118::session::{Instant, Millis, SessionId};
use iso15118::{Protocol, Protocols};

const SESSION_ID: SessionId = SessionId::new([0x3D, 0x4C, 0xBF, 0x93, 0x37, 0x4E, 0xD8, 0x9B]);
const TIMESTAMP: u64 = 1_725_456_343;

/// The DC energy transfer service — id 2 in the standard's assignment.
const DC_SERVICE: u16 = 2;

/// A header with no session id: both drivers stamp the real one in.
fn header() -> MessageHeader {
    MessageHeader { session_id: Vec::new(), time_stamp: TIMESTAMP, signature: None }
}

/// `RationalNumber` is -20's physical value: a signed mantissa and a decimal
/// exponent, so 350 kW is `35 × 10^4`.
fn number(value: i16, exponent: i8) -> RationalNumber {
    RationalNumber { exponent, value }
}

struct Link {
    evcc: Evcc,
    secc: Secc,
    now: Instant,
}

impl Link {
    fn new() -> Self {
        let evcc = Evcc::new(EvccConfig {
            protocols: Protocols::only(Protocol::Iso20),
            ..Default::default()
        });
        let mut secc = Secc::new(SeccConfig {
            protocols: Protocols::only(Protocol::Iso20),
            session_id: SESSION_ID,
            ..Default::default()
        });
        let now = Instant::ZERO;
        secc.opened(now);
        Self { evcc, secc, now }
    }

    fn pump(&mut self) {
        let up = self.evcc.take_transmit();
        if !up.is_empty() {
            self.secc.handle_input(self.now, &up).expect("SECC input");
        }
        let down = self.secc.take_transmit();
        if !down.is_empty() {
            self.evcc.handle_input(self.now, &down).expect("EVCC input");
        }
    }

    /// Drains the station's events, answering each request.
    fn serve(&mut self) {
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

    /// One request/response exchange, end to end through bytes.
    fn exchange(&mut self, request: Message) -> Message {
        let name = request.name();
        self.evcc.request(self.now, request).unwrap_or_else(|e| panic!("send {name}: {e}"));
        self.pump();
        self.serve();
        self.pump();
        self.now = self.now + Millis::from_millis(10);

        core::iter::from_fn(|| self.evcc.poll_event())
            .find_map(|e| match e {
                evcc::Event::Response(m) => Some(*m),
                _ => None,
            })
            .unwrap_or_else(|| panic!("no response to {name}"))
    }

    fn negotiate(&mut self) {
        self.evcc.start(self.now).expect("start");
        self.pump();
        self.serve();
        self.pump();
        let agreed = core::iter::from_fn(|| self.evcc.poll_event()).find_map(|e| match e {
            evcc::Event::ProtocolAgreed(p) => Some(p),
            _ => None,
        });
        assert_eq!(agreed, Some(Protocol::Iso20));
    }
}

// ---------------------------------------------------------------------------
// The station's answers — the only part that is policy rather than protocol
// ---------------------------------------------------------------------------

fn answer(request: &Message) -> Message {
    match request {
        Message::Iso20(doc) => common_answer(doc),
        Message::Iso20Dc(doc) => dc_answer(doc),
        other => panic!("this station has no answer for {}", other.name()),
    }
}

fn common_answer(doc: &cm::Document) -> Message {
    use cm::Document as D;
    let body = match doc {
        D::SessionSetupReq(_) => D::SessionSetupRes(cm::SessionSetupRes {
            header: header(),
            response_code: ResponseCode::OKNewSessionEstablished,
            evse_id: "DE*ABC*E123*45".into(),
        }),
        D::AuthorizationSetupReq(_) => D::AuthorizationSetupRes(cm::AuthorizationSetupRes {
            header: header(),
            response_code: ResponseCode::OK,
            authorization_services: vec![cm::Authorization::EIM],
            certificate_installation_service: false,
            choice: cm::AuthorizationSetupResChoice::EIMASResAuthorizationMode(
                cm::EIMASResAuthorizationMode,
            ),
        }),
        D::AuthorizationReq(_) => D::AuthorizationRes(cm::AuthorizationRes {
            header: header(),
            response_code: ResponseCode::OK,
            evse_processing: Processing::Finished,
        }),
        D::ServiceDiscoveryReq(_) => D::ServiceDiscoveryRes(cm::ServiceDiscoveryRes {
            header: header(),
            response_code: ResponseCode::OK,
            service_renegotiation_supported: true,
            energy_transfer_service_list: cm::ServiceList {
                service: vec![cm::Service { service_id: DC_SERVICE, free_service: false }],
            },
            vas_list: None,
        }),
        D::ServiceSelectionReq(_) => D::ServiceSelectionRes(cm::ServiceSelectionRes {
            header: header(),
            response_code: ResponseCode::OK,
        }),
        D::ScheduleExchangeReq(_) => D::ScheduleExchangeRes(cm::ScheduleExchangeRes {
            header: header(),
            response_code: ResponseCode::OK,
            evse_processing: Processing::Finished,
            go_to_pause: None,
            choice: cm::ScheduleExchangeResChoice::DynamicSEResControlMode(
                cm::DynamicSEResControlMode {
                    departure_time: None,
                    minimum_soc: None,
                    target_soc: None,
                    choice: None,
                },
            ),
        }),
        D::PowerDeliveryReq(_) => D::PowerDeliveryRes(cm::PowerDeliveryRes {
            header: header(),
            response_code: ResponseCode::OK,
            evse_status: None,
        }),
        D::SessionStopReq(_) => D::SessionStopRes(cm::SessionStopRes {
            header: header(),
            response_code: ResponseCode::OK,
        }),
        other => panic!("no answer for {}", other.name()),
    };
    Message::Iso20(Box::new(body))
}

fn dc_answer(doc: &dc::Document) -> Message {
    use dc::Document as D;
    let body = match doc {
        D::DCChargeParameterDiscoveryReq(_) => {
            D::DCChargeParameterDiscoveryRes(dc::DCChargeParameterDiscoveryRes {
                header: header(),
                response_code: ResponseCode::OK,
                choice: dc::DCChargeParameterDiscoveryResChoice::DCCPDResEnergyTransferMode(
                    dc::DCCPDResEnergyTransferMode {
                        evse_maximum_charge_power: number(35, 4), // 350 kW
                        evse_minimum_charge_power: number(1, 3),
                        evse_maximum_charge_current: number(500, 0),
                        evse_minimum_charge_current: number(1, 0),
                        evse_maximum_voltage: number(920, 0),
                        evse_minimum_voltage: number(200, 0),
                        evse_power_ramp_limitation: None,
                    },
                ),
            })
        }
        D::DCCableCheckReq(_) => D::DCCableCheckRes(dc::DCCableCheckRes {
            header: header(),
            response_code: ResponseCode::OK,
            evse_processing: Processing::Finished,
        }),
        D::DCPreChargeReq(_) => D::DCPreChargeRes(dc::DCPreChargeRes {
            header: header(),
            response_code: ResponseCode::OK,
            evse_present_voltage: number(400, 0),
        }),
        D::DCChargeLoopReq(_) => D::DCChargeLoopRes(dc::DCChargeLoopRes {
            header: header(),
            response_code: ResponseCode::OK,
            evse_status: None,
            meter_info: None,
            receipt: None,
            evse_present_current: number(120, 0),
            evse_present_voltage: number(400, 0),
            evse_power_limit_achieved: false,
            evse_current_limit_achieved: false,
            evse_voltage_limit_achieved: false,
            choice: dc::DCChargeLoopResChoice::DynamicDCCLResControlMode(
                dc::DynamicDCCLResControlMode {
                    departure_time: None,
                    minimum_soc: None,
                    target_soc: None,
                    ack_max_delay: None,
                    evse_maximum_charge_power: number(35, 4),
                    evse_minimum_charge_power: number(1, 3),
                    evse_maximum_charge_current: number(500, 0),
                    evse_maximum_voltage: number(920, 0),
                },
            ),
        }),
        D::DCWeldingDetectionReq(_) => D::DCWeldingDetectionRes(dc::DCWeldingDetectionRes {
            header: header(),
            response_code: ResponseCode::OK,
            evse_present_voltage: number(0, 0),
        }),
        other => panic!("no answer for {}", other.name()),
    };
    Message::Iso20Dc(Box::new(body))
}

// ---------------------------------------------------------------------------
// The vehicle's requests
// ---------------------------------------------------------------------------

fn common(body: cm::Document) -> Message {
    Message::Iso20(Box::new(body))
}

fn dc_msg(body: dc::Document) -> Message {
    Message::Iso20Dc(Box::new(body))
}

fn charge_loop() -> Message {
    dc_msg(dc::Document::DCChargeLoopReq(dc::DCChargeLoopReq {
        header: header(),
        display_parameters: None,
        meter_info_requested: false,
        ev_present_voltage: number(400, 0),
        choice: dc::DCChargeLoopReqChoice::DynamicDCCLReqControlMode(
            dc::DynamicDCCLReqControlMode {
                departure_time: None,
                ev_target_energy_request: number(60, 3),
                ev_maximum_energy_request: number(80, 3),
                ev_minimum_energy_request: number(10, 3),
                ev_maximum_charge_power: number(20, 4),
                ev_minimum_charge_power: number(1, 3),
                ev_maximum_charge_current: number(300, 0),
                ev_maximum_voltage: number(900, 0),
                ev_minimum_voltage: number(200, 0),
            },
        ),
    }))
}

#[test]
#[allow(clippy::too_many_lines, reason = "one line per message; the flow is the test")]
fn a_whole_dc_session_runs_across_two_payload_types() {
    let mut link = Link::new();
    link.negotiate();

    let res = link.exchange(common(cm::Document::SessionSetupReq(cm::SessionSetupReq {
        header: header(),
        evcc_id: "WMIVIN1234567890".into(),
    })));
    assert_eq!(res.name(), "SessionSetupRes");
    assert_eq!(link.evcc.session_id(), SESSION_ID, "the station assigned it");

    // Authorization comes before service discovery in -20 — the headline
    // reordering against -2.
    link.exchange(common(cm::Document::AuthorizationSetupReq(cm::AuthorizationSetupReq {
        header: header(),
    })));
    link.exchange(common(cm::Document::AuthorizationReq(cm::AuthorizationReq {
        header: header(),
        selected_authorization_service: cm::Authorization::EIM,
        choice: cm::AuthorizationReqChoice::EIMAReqAuthorizationMode(cm::EIMAReqAuthorizationMode),
    })));
    link.exchange(common(cm::Document::ServiceDiscoveryReq(cm::ServiceDiscoveryReq {
        header: header(),
        supported_service_i_ds: None,
    })));
    link.exchange(common(cm::Document::ServiceSelectionReq(cm::ServiceSelectionReq {
        header: header(),
        selected_energy_transfer_service: cm::SelectedService {
            service_id: DC_SERVICE,
            parameter_set_id: 1,
        },
        selected_vas_list: None,
    })));

    // ...and here the session crosses into the DC schema and payload type
    // `0x8004`, without anything being told to switch.
    let res = link.exchange(dc_msg(dc::Document::DCChargeParameterDiscoveryReq(
        dc::DCChargeParameterDiscoveryReq {
            header: header(),
            choice: dc::DCChargeParameterDiscoveryReqChoice::DCCPDReqEnergyTransferMode(
                dc::DCCPDReqEnergyTransferMode {
                    ev_maximum_charge_power: number(20, 4),
                    ev_minimum_charge_power: number(1, 3),
                    ev_maximum_charge_current: number(300, 0),
                    ev_minimum_charge_current: number(1, 0),
                    ev_maximum_voltage: number(900, 0),
                    ev_minimum_voltage: number(200, 0),
                    target_soc: Some(80),
                },
            ),
        },
    )));
    assert_eq!(res.name(), "DC_ChargeParameterDiscoveryRes");
    assert_eq!(
        res.session_id(),
        Some(SESSION_ID),
        "a DC message carries the same session id as a CommonMessages one"
    );

    link.exchange(common(cm::Document::ScheduleExchangeReq(cm::ScheduleExchangeReq {
        header: header(),
        maximum_supporting_points: 12,
        choice: cm::ScheduleExchangeReqChoice::DynamicSEReqControlMode(
            cm::DynamicSEReqControlMode {
                departure_time: 3600,
                minimum_soc: Some(20),
                target_soc: Some(80),
                ev_target_energy_request: number(60, 3),
                ev_maximum_energy_request: number(80, 3),
                ev_minimum_energy_request: number(10, 3),
                ev_maximum_v2_x_energy_request: None,
                ev_minimum_v2_x_energy_request: None,
            },
        ),
    })));

    // DC safety phases, then power.
    link.exchange(dc_msg(dc::Document::DCCableCheckReq(dc::DCCableCheckReq { header: header() })));
    link.exchange(dc_msg(dc::Document::DCPreChargeReq(dc::DCPreChargeReq {
        header: header(),
        ev_processing: Processing::Finished,
        ev_present_voltage: number(0, 0),
        ev_target_voltage: number(400, 0),
    })));
    link.exchange(common(cm::Document::PowerDeliveryReq(cm::PowerDeliveryReq {
        header: header(),
        ev_processing: Processing::Finished,
        charge_progress: cm::ChargeProgress::Start,
        ev_power_profile: None,
        bpt_channel_selection: None,
    })));

    for _ in 0..3 {
        assert_eq!(link.exchange(charge_loop()).name(), "DC_ChargeLoopRes");
    }

    link.exchange(common(cm::Document::PowerDeliveryReq(cm::PowerDeliveryReq {
        header: header(),
        ev_processing: Processing::Finished,
        charge_progress: cm::ChargeProgress::Stop,
        ev_power_profile: None,
        bpt_channel_selection: None,
    })));
    link.exchange(dc_msg(dc::Document::DCWeldingDetectionReq(dc::DCWeldingDetectionReq {
        header: header(),
        ev_processing: Processing::Finished,
    })));
    link.exchange(common(cm::Document::SessionStopReq(cm::SessionStopReq {
        header: header(),
        charging_session: cm::ChargingSession::Terminate,
        ev_termination_code: None,
        ev_termination_explanation: None,
    })));

    assert!(link.evcc.is_closed(), "the vehicle saw the session end");
    assert!(link.secc.is_closed(), "and so did the station");
}

/// The -20 flow puts authorization first. A vehicle that used -2's order would
/// be refused by its own driver, before the wire.
#[test]
fn the_dash_2_order_is_refused_on_a_dash_20_session() {
    let mut link = Link::new();
    link.negotiate();
    link.exchange(common(cm::Document::SessionSetupReq(cm::SessionSetupReq {
        header: header(),
        evcc_id: "WMIVIN1234567890".into(),
    })));

    let too_early = common(cm::Document::ServiceDiscoveryReq(cm::ServiceDiscoveryReq {
        header: header(),
        supported_service_i_ds: None,
    }));
    assert!(
        matches!(link.evcc.request(link.now, too_early), Err(evcc::EvccError::Flow(_))),
        "service discovery before authorization is -2's order, not -20's"
    );
}

/// A DC message before the service is selected has no business on the wire, and
/// the station says so with `FAILED_SequenceError` rather than decoding it.
#[test]
fn a_dc_message_before_the_service_is_selected_is_refused() {
    let mut link = Link::new();
    link.negotiate();
    link.exchange(common(cm::Document::SessionSetupReq(cm::SessionSetupReq {
        header: header(),
        evcc_id: "WMIVIN1234567890".into(),
    })));

    // Framed straight past the vehicle's own check, as a peer that is not
    // running this crate would send it.
    let mut peer = iso15118::session::Connection::new();
    peer.set_protocol(Protocol::Iso20);
    let mut cable_check =
        dc_msg(dc::Document::DCCableCheckReq(dc::DCCableCheckReq { header: header() }));
    cable_check.set_session_id(SESSION_ID);
    peer.send(&cable_check).unwrap();
    let wire = peer.take_transmit();

    link.secc.handle_input(link.now, &wire).expect("it decodes; it is just not legal here");
    let refusal = core::iter::from_fn(|| link.secc.poll_event()).find_map(|e| match e {
        secc::Event::Refused { reason, .. } => Some(reason),
        _ => None,
    });
    assert!(
        matches!(refusal, Some(secc::Refusal::Sequence(_))),
        "expected a sequence refusal, got {refusal:?}"
    );
}
