//! A scripted station: says yes, offers AC and DC, and answers with what the
//! vehicle asked for — pre-charge reaches the target voltage the vehicle
//! named, the charge loop delivers the current it asked for.
//!
//! A live vehicle checks the answers it gets, so they have to be plausible:
//! a schedule the vehicle can pick an id from, the energy mode it requested,
//! a parameter set it can select. Every one of those is the operator's
//! decision, which is why none of it is in the crate.

use iso15118::iso2::{self, BodyChoice, EnergyTransferMode, PaymentOption, ResponseCode};
use iso15118::iso20::common::{self as c20, MessageHeader, Processing};
use iso15118::iso20::{ac, dc, messages as cm};
use iso15118::message::Message;

use crate::drive::StationScript;
use crate::vehicle::{iso2_body, number};

const EVSE_ID: &str = "DE*ICE*E000001";

#[derive(Debug, Default)]
pub(crate) struct Station;

impl StationScript for Station {
    fn answer(&mut self, request: &Message) -> Message {
        match request {
            Message::Iso2(_) => iso2_answer(request),
            Message::Iso20(doc) => common_answer(doc),
            Message::Iso20Dc(doc) => dc_answer(doc),
            Message::Iso20Ac(doc) => ac_answer(doc),
            // The engine hands over only the negotiated generation's requests.
            other => failed(other),
        }
    }
}

/// A request this station has no answer for gets `FAILED`, which ends the
/// session — and the row, which is the point: the script is missing an arm.
fn failed(request: &Message) -> Message {
    eprintln!("  !! the station has no answer for {}", request.name());
    let code = match request {
        Message::Iso2(_) => ResponseCode::FAILED as u8,
        _ => c20::ResponseCode::FAILED as u8,
    };
    request.refusal(code).unwrap_or_else(|| request.clone())
}

// ---------------------------------------------------------------------------
// ISO 15118-2
// ---------------------------------------------------------------------------

fn v2(choice: BodyChoice) -> Message {
    Message::Iso2(Box::new(iso2::Document::V2GMessage(iso2::V2GMessage {
        header: iso2::MessageHeader { session_id: Vec::new(), notification: None, signature: None },
        body: iso2::Body { choice: Some(choice) },
    })))
}

fn pv(value: i16, multiplier: i8, unit: iso2::UnitSymbol) -> iso2::PhysicalValue {
    iso2::PhysicalValue { multiplier, unit, value }
}

fn dc_status(code: iso2::DCEVSEStatusCode) -> iso2::DCEVSEStatus {
    iso2::DCEVSEStatus {
        notification_max_delay: 0,
        evse_notification: iso2::EVSENotification::None,
        evse_isolation_status: Some(iso2::IsolationLevel::Valid),
        evse_status_code: code,
    }
}

fn ac_status() -> iso2::ACEVSEStatus {
    iso2::ACEVSEStatus {
        notification_max_delay: 0,
        evse_notification: iso2::EVSENotification::None,
        rcd: false,
    }
}

fn schedule(kw: i16) -> iso2::ChargeParameterDiscoveryResChoice2 {
    iso2::ChargeParameterDiscoveryResChoice2::SAScheduleList(iso2::SAScheduleList {
        sa_schedule_tuple: vec![iso2::SAScheduleTuple {
            sa_schedule_tuple_id: 1,
            p_max_schedule: iso2::PMaxSchedule {
                p_max_schedule_entry: vec![iso2::PMaxScheduleEntry {
                    choice: iso2::PMaxScheduleEntryChoice::RelativeTimeInterval(
                        iso2::RelativeTimeInterval { start: 0, duration: Some(86_400) },
                    ),
                    p_max: pv(kw, 3, iso2::UnitSymbol::W),
                }],
            },
            sales_tariff: None,
        }],
    })
}

#[allow(clippy::too_many_lines, reason = "one arm per request reads as the table it is")]
fn iso2_answer(request: &Message) -> Message {
    use BodyChoice as B;
    use iso2::DCEVSEStatusCode as S;
    use iso2::UnitSymbol as U;
    let Some(body) = iso2_body(request) else {
        return failed(request);
    };
    let answer = match body {
        B::SessionSetupReq(_) => B::SessionSetupRes(iso2::SessionSetupRes {
            response_code: ResponseCode::OKNewSessionEstablished,
            evse_id: EVSE_ID.into(),
            evse_time_stamp: None,
        }),
        B::ServiceDiscoveryReq(_) => B::ServiceDiscoveryRes(iso2::ServiceDiscoveryRes {
            response_code: ResponseCode::OK,
            payment_option_list: iso2::PaymentOptionList {
                payment_option: vec![PaymentOption::ExternalPayment],
            },
            charge_service: iso2::ChargeService {
                service_id: 1,
                service_name: None,
                service_category: iso2::ServiceCategory::EVCharging,
                service_scope: None,
                free_service: false,
                supported_energy_transfer_mode: iso2::SupportedEnergyTransferMode {
                    energy_transfer_mode: vec![
                        EnergyTransferMode::DCExtended,
                        EnergyTransferMode::DCCore,
                        EnergyTransferMode::ACThreePhaseCore,
                        EnergyTransferMode::ACSinglePhaseCore,
                    ],
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
        B::ChargeParameterDiscoveryReq(req) => {
            let is_dc = matches!(
                req.choice,
                iso2::ChargeParameterDiscoveryReqChoice::DCEVChargeParameter(_)
            );
            B::ChargeParameterDiscoveryRes(iso2::ChargeParameterDiscoveryRes {
                response_code: ResponseCode::OK,
                evse_processing: iso2::EVSEProcessing::Finished,
                choice_2: Some(schedule(if is_dc { 50 } else { 11 })),
                choice_3: if is_dc {
                    iso2::ChargeParameterDiscoveryResChoice3::DCEVSEChargeParameter(
                        iso2::DCEVSEChargeParameter {
                            dc_evse_status: dc_status(S::EVSEReady),
                            evse_maximum_current_limit: pv(200, 0, U::A),
                            evse_maximum_power_limit: pv(50, 3, U::W),
                            evse_maximum_voltage_limit: pv(900, 0, U::V),
                            evse_minimum_current_limit: pv(0, 0, U::A),
                            evse_minimum_voltage_limit: pv(150, 0, U::V),
                            evse_current_regulation_tolerance: None,
                            evse_peak_current_ripple: pv(1, 0, U::A),
                            evse_energy_to_be_delivered: None,
                        },
                    )
                } else {
                    iso2::ChargeParameterDiscoveryResChoice3::ACEVSEChargeParameter(
                        iso2::ACEVSEChargeParameter {
                            ac_evse_status: ac_status(),
                            evse_nominal_voltage: pv(230, 0, U::V),
                            evse_max_current: pv(16, 0, U::A),
                        },
                    )
                },
            })
        }
        B::CableCheckReq(_) => B::CableCheckRes(iso2::CableCheckRes {
            response_code: ResponseCode::OK,
            dc_evse_status: dc_status(S::EVSEReady),
            evse_processing: iso2::EVSEProcessing::Finished,
        }),
        B::PreChargeReq(req) => B::PreChargeRes(iso2::PreChargeRes {
            response_code: ResponseCode::OK,
            dc_evse_status: dc_status(S::EVSEReady),
            evse_present_voltage: req.ev_target_voltage.clone(),
        }),
        B::PowerDeliveryReq(req) => B::PowerDeliveryRes(iso2::PowerDeliveryRes {
            response_code: ResponseCode::OK,
            choice: if req.choice.is_some() {
                iso2::PowerDeliveryResChoice::DCEVSEStatus(dc_status(S::EVSEReady))
            } else {
                iso2::PowerDeliveryResChoice::ACEVSEStatus(ac_status())
            },
        }),
        B::CurrentDemandReq(req) => B::CurrentDemandRes(iso2::CurrentDemandRes {
            response_code: ResponseCode::OK,
            dc_evse_status: dc_status(S::EVSEReady),
            evse_present_voltage: req.ev_target_voltage.clone(),
            evse_present_current: req.ev_target_current.clone(),
            evse_current_limit_achieved: false,
            evse_voltage_limit_achieved: false,
            evse_power_limit_achieved: false,
            evse_maximum_voltage_limit: None,
            evse_maximum_current_limit: None,
            evse_maximum_power_limit: None,
            evse_id: EVSE_ID.into(),
            sa_schedule_tuple_id: 1,
            meter_info: None,
            receipt_required: None,
        }),
        B::ChargingStatusReq(_) => B::ChargingStatusRes(iso2::ChargingStatusRes {
            response_code: ResponseCode::OK,
            evse_id: EVSE_ID.into(),
            sa_schedule_tuple_id: 1,
            evse_max_current: Some(pv(16, 0, U::A)),
            meter_info: None,
            receipt_required: None,
            ac_evse_status: ac_status(),
        }),
        B::WeldingDetectionReq(_) => B::WeldingDetectionRes(iso2::WeldingDetectionRes {
            response_code: ResponseCode::OK,
            dc_evse_status: dc_status(S::EVSEShutdown),
            evse_present_voltage: pv(0, 0, U::V),
        }),
        B::SessionStopReq(_) => {
            B::SessionStopRes(iso2::SessionStopRes { response_code: ResponseCode::OK })
        }
        _ => return failed(request),
    };
    v2(answer)
}

// ---------------------------------------------------------------------------
// ISO 15118-20
// ---------------------------------------------------------------------------

fn header() -> MessageHeader {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    MessageHeader { session_id: Vec::new(), time_stamp: now, signature: None }
}

fn int(name: &str, value: i32) -> cm::Parameter {
    cm::Parameter { name: name.into(), choice: cm::ParameterChoice::IntValue(value) }
}

#[allow(clippy::too_many_lines, reason = "one arm per request reads as the table it is")]
fn common_answer(doc: &cm::Document) -> Message {
    use cm::Document as D;
    let ok = c20::ResponseCode::OK;
    let body = match doc {
        D::SessionSetupReq(_) => D::SessionSetupRes(cm::SessionSetupRes {
            header: header(),
            response_code: c20::ResponseCode::OKNewSessionEstablished,
            evse_id: EVSE_ID.into(),
        }),
        D::AuthorizationSetupReq(_) => D::AuthorizationSetupRes(cm::AuthorizationSetupRes {
            header: header(),
            response_code: ok,
            authorization_services: vec![cm::Authorization::EIM],
            certificate_installation_service: false,
            choice: cm::AuthorizationSetupResChoice::EIMASResAuthorizationMode(
                cm::EIMASResAuthorizationMode,
            ),
        }),
        D::AuthorizationReq(_) => D::AuthorizationRes(cm::AuthorizationRes {
            header: header(),
            response_code: ok,
            evse_processing: Processing::Finished,
        }),
        D::ServiceDiscoveryReq(_) => D::ServiceDiscoveryRes(cm::ServiceDiscoveryRes {
            header: header(),
            response_code: ok,
            service_renegotiation_supported: false,
            energy_transfer_service_list: cm::ServiceList {
                service: vec![
                    cm::Service { service_id: 2, free_service: false },
                    cm::Service { service_id: 1, free_service: false },
                ],
            },
            vas_list: None,
        }),
        // One parameter set per service: connector, Dynamic control mode,
        // mobility needs from the vehicle, no pricing.
        D::ServiceDetailReq(req) => {
            let mut parameter = vec![
                // Extended (DC) and three-phase (AC) are both 2.
                int("Connector", 2),
                int("ControlMode", 2),
                int("MobilityNeedsMode", 1),
                int("Pricing", 0),
            ];
            if req.service_id == 1 {
                parameter.insert(2, int("EVSENominalVoltage", 230));
            }
            D::ServiceDetailRes(cm::ServiceDetailRes {
                header: header(),
                response_code: ok,
                service_id: req.service_id,
                service_parameter_list: cm::ServiceParameterList {
                    parameter_set: vec![cm::ParameterSet { parameter_set_id: 1, parameter }],
                },
            })
        }
        D::ServiceSelectionReq(_) => {
            D::ServiceSelectionRes(cm::ServiceSelectionRes { header: header(), response_code: ok })
        }
        D::ScheduleExchangeReq(_) => D::ScheduleExchangeRes(cm::ScheduleExchangeRes {
            header: header(),
            response_code: ok,
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
            response_code: ok,
            evse_status: None,
        }),
        D::SessionStopReq(_) => {
            D::SessionStopRes(cm::SessionStopRes { header: header(), response_code: ok })
        }
        other => {
            return failed(&Message::Iso20(Box::new(other.clone())));
        }
    };
    Message::Iso20(Box::new(body))
}

fn dc_answer(doc: &dc::Document) -> Message {
    use dc::Document as D;
    let ok = c20::ResponseCode::OK;
    let body = match doc {
        D::DCChargeParameterDiscoveryReq(_) => {
            D::DCChargeParameterDiscoveryRes(dc::DCChargeParameterDiscoveryRes {
                header: header(),
                response_code: ok,
                choice: dc::DCChargeParameterDiscoveryResChoice::DCCPDResEnergyTransferMode(
                    dc::DCCPDResEnergyTransferMode {
                        evse_maximum_charge_power: number(5, 4),
                        evse_minimum_charge_power: number(1, 3),
                        evse_maximum_charge_current: number(200, 0),
                        evse_minimum_charge_current: number(1, 0),
                        evse_maximum_voltage: number(900, 0),
                        evse_minimum_voltage: number(150, 0),
                        evse_power_ramp_limitation: None,
                    },
                ),
            })
        }
        D::DCCableCheckReq(_) => D::DCCableCheckRes(dc::DCCableCheckRes {
            header: header(),
            response_code: ok,
            evse_processing: Processing::Finished,
        }),
        D::DCPreChargeReq(req) => D::DCPreChargeRes(dc::DCPreChargeRes {
            header: header(),
            response_code: ok,
            evse_present_voltage: req.ev_target_voltage.clone(),
        }),
        D::DCChargeLoopReq(req) => D::DCChargeLoopRes(dc::DCChargeLoopRes {
            header: header(),
            response_code: ok,
            evse_status: None,
            meter_info: None,
            receipt: None,
            evse_present_current: number(100, 0),
            evse_present_voltage: req.ev_present_voltage.clone(),
            evse_power_limit_achieved: false,
            evse_current_limit_achieved: false,
            evse_voltage_limit_achieved: false,
            choice: dc::DCChargeLoopResChoice::DynamicDCCLResControlMode(
                dc::DynamicDCCLResControlMode {
                    departure_time: None,
                    minimum_soc: None,
                    target_soc: None,
                    ack_max_delay: None,
                    evse_maximum_charge_power: number(5, 4),
                    evse_minimum_charge_power: number(1, 3),
                    evse_maximum_charge_current: number(200, 0),
                    evse_maximum_voltage: number(900, 0),
                },
            ),
        }),
        D::DCWeldingDetectionReq(_) => D::DCWeldingDetectionRes(dc::DCWeldingDetectionRes {
            header: header(),
            response_code: ok,
            evse_present_voltage: number(0, 0),
        }),
        other => {
            return failed(&Message::Iso20Dc(Box::new(other.clone())));
        }
    };
    Message::Iso20Dc(Box::new(body))
}

fn ac_answer(doc: &ac::Document) -> Message {
    use ac::Document as D;
    let ok = c20::ResponseCode::OK;
    let body = match doc {
        D::ACChargeParameterDiscoveryReq(_) => {
            D::ACChargeParameterDiscoveryRes(ac::ACChargeParameterDiscoveryRes {
                header: header(),
                response_code: ok,
                choice: ac::ACChargeParameterDiscoveryResChoice::ACCPDResEnergyTransferMode(
                    ac::ACCPDResEnergyTransferMode {
                        evse_maximum_charge_power: number(11, 3),
                        evse_minimum_charge_power: number(1, 3),
                        evse_nominal_frequency: number(50, 0),
                        ..ac::ACCPDResEnergyTransferMode::minimal()
                    },
                ),
            })
        }
        D::ACChargeLoopReq(_) => D::ACChargeLoopRes(ac::ACChargeLoopRes {
            header: header(),
            response_code: ok,
            evse_status: None,
            meter_info: None,
            receipt: None,
            evse_target_frequency: None,
            choice: ac::ACChargeLoopResChoice::DynamicACCLResControlMode(
                ac::DynamicACCLResControlMode {
                    evse_target_active_power: number(11, 3),
                    ..ac::DynamicACCLResControlMode::minimal()
                },
            ),
        }),
        other => {
            return failed(&Message::Iso20Ac(Box::new(other.clone())));
        }
    };
    Message::Iso20Ac(Box::new(body))
}
