//! A scripted vehicle: the requests a real EV would send, chosen from the
//! station's last answer.
//!
//! It follows the station rather than a fixed list — repeats a phase answered
//! `Ongoing`, takes the schedule id the station offered, stops pre-charge when
//! the station's voltage matches — because a live peer answers the way it
//! answers, not the way a test expects. Every decision here is the vehicle's,
//! which is why none of it is in the crate.

use std::time::Duration;

use iso15118::Protocol;
use iso15118::iso2::{self, BodyChoice, ChargeProgress, EnergyTransferMode, PaymentOption};
use iso15118::iso20::common::{MessageHeader, Processing, RationalNumber};
use iso15118::iso20::{ac, dc, messages as cm};
use iso15118::message::Message;
use iso15118::pnc::{GenChallenge, PncError};

use crate::drive::{Generation, Next, Service, VehicleScript};

/// How long between repeats of a phase the station answered `Ongoing`.
const REPEAT: Duration = Duration::from_millis(250);
/// How many charge-loop exchanges before the vehicle stops.
const LOOPS: u32 = 5;
/// Repeats of one `Ongoing` phase before the vehicle gives up and stops.
const MAX_REPEATS: u32 = 120;
/// The voltage the vehicle asks pre-charge to reach.
const TARGET_V: f64 = 400.0;

const DC_SERVICE: u16 = 2;
const AC_SERVICE: u16 = 1;

/// What signs for the contract: the key lives with whoever built the vehicle.
pub(crate) trait ContractKey {
    fn sign_authorization(
        &self,
        request: &mut iso2::AuthorizationReq,
        challenge: &GenChallenge,
    ) -> Result<iso2::Signature, PncError>;
    fn sign_receipt(
        &self,
        receipt: &mut iso2::MeteringReceiptReq,
    ) -> Result<iso2::Signature, PncError>;
}

/// A Plug & Charge contract: the eMAID, the chain issuer-first, the key.
pub(crate) struct Contract {
    pub(crate) emaid: String,
    pub(crate) leaf: Vec<u8>,
    pub(crate) sub_certificates: Vec<Vec<u8>>,
    pub(crate) key: Box<dyn ContractKey>,
}

pub(crate) struct Vehicle {
    generation: Generation,
    service: Service,
    loops: u32,
    repeats: u32,
    stopping: bool,
    /// `PowerDeliveryRes(Start)` has arrived: power is flowing.
    powered: bool,
    sa_tuple: u8,
    service_id: u16,
    parameter_set: u16,
    contract: Option<Contract>,
    /// The signed `AuthorizationReq`, sent again while the station is busy.
    authorization: Option<Message>,
    abandoned: Option<String>,
}

impl Vehicle {
    #[must_use]
    pub(crate) fn new(generation: Generation, service: Service) -> Self {
        Self {
            generation,
            service,
            loops: 0,
            repeats: 0,
            stopping: false,
            sa_tuple: 1,
            service_id: match service {
                Service::Dc => DC_SERVICE,
                Service::Ac => AC_SERVICE,
            },
            parameter_set: 1,
            contract: None,
            authorization: None,
            abandoned: None,
            powered: false,
        }
    }

    /// Pays with this contract (Plug & Charge) rather than externally.
    pub(crate) fn with_contract(mut self, contract: Contract) -> Self {
        self.contract = Some(contract);
        self
    }

    /// Gives the session up: `SessionStopReq`, and a row that does not pass.
    fn abandon(&mut self, why: impl Into<String>) -> Next {
        let why = why.into();
        eprintln!("  !! {why}");
        self.abandoned = Some(why);
        Next::Send(self.stop(), Duration::ZERO)
    }

    fn again(&mut self, request: Message) -> Next {
        self.repeats += 1;
        if self.repeats > MAX_REPEATS {
            eprintln!("  !! the station stayed Ongoing; stopping");
            return Next::Send(self.stop(), Duration::ZERO);
        }
        Next::Send(request, REPEAT)
    }

    fn then(&mut self, request: Message) -> Next {
        self.repeats = 0;
        Next::Send(request, Duration::ZERO)
    }
}

impl VehicleScript for Vehicle {
    fn first(&mut self, protocol: Protocol) -> Message {
        eprintln!("  vehicle: {protocol}, {:?}", self.service);
        match self.generation {
            Generation::Iso2 => {
                v2(BodyChoice::SessionSetupReq(iso2::SessionSetupReq { evcc_id: EVCC_ID.to_vec() }))
            }
            Generation::Iso20 => common(cm::Document::SessionSetupReq(cm::SessionSetupReq {
                header: header(),
                evcc_id: "WMIVIN1234567890".into(),
            })),
        }
    }

    fn next(&mut self, response: &Message) -> Next {
        match self.generation {
            Generation::Iso2 => self.next_iso2(response),
            Generation::Iso20 => self.next_iso20(response),
        }
    }

    fn abandoned(&self) -> Option<&str> {
        self.abandoned.as_deref()
    }

    fn stop(&self) -> Message {
        match self.generation {
            Generation::Iso2 => v2(BodyChoice::SessionStopReq(iso2::SessionStopReq {
                charging_session: iso2::ChargingSession::Terminate,
            })),
            Generation::Iso20 => common(cm::Document::SessionStopReq(cm::SessionStopReq {
                header: header(),
                charging_session: cm::ChargingSession::Terminate,
                ev_termination_code: None,
                ev_termination_explanation: None,
            })),
        }
    }
}

// ---------------------------------------------------------------------------
// ISO 15118-2
// ---------------------------------------------------------------------------

const EVCC_ID: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];

impl Vehicle {
    #[allow(clippy::too_many_lines, reason = "one arm per response reads as the flow it is")]
    fn next_iso2(&mut self, response: &Message) -> Next {
        use BodyChoice as B;
        let Some(body) = iso2_body(response) else { return Next::Done };
        let dc = self.service == Service::Dc;
        if stop_charging(body) && !self.stopping {
            if !self.powered {
                return self.abandon("the station signalled StopCharging before power flowed");
            }
            // A station ending the charge is an ordinary stop.
            self.stopping = true;
            return self.then(power_delivery_iso2(ChargeProgress::Stop, self.sa_tuple, dc));
        }
        match body {
            B::SessionSetupRes(_) => {
                self.then(v2(B::ServiceDiscoveryReq(iso2::ServiceDiscoveryReq {
                    service_scope: None,
                    service_category: None,
                })))
            }
            B::ServiceDiscoveryRes(res) => {
                self.service_id = res.charge_service.service_id;
                let option = if self.contract.is_some() {
                    if !res.payment_option_list.payment_option.contains(&PaymentOption::Contract) {
                        return self.abandon("the station offers no Plug & Charge");
                    }
                    PaymentOption::Contract
                } else {
                    PaymentOption::ExternalPayment
                };
                self.then(v2(B::PaymentServiceSelectionReq(iso2::PaymentServiceSelectionReq {
                    selected_payment_option: option,
                    selected_service_list: iso2::SelectedServiceList {
                        selected_service: vec![iso2::SelectedService {
                            service_id: self.service_id,
                            parameter_set_id: None,
                        }],
                    },
                })))
            }
            B::PaymentServiceSelectionRes(_) => match &self.contract {
                Some(contract) => self.then(payment_details(contract)),
                None => self.then(authorization_iso2()),
            },
            B::PaymentDetailsRes(res) => {
                let signed = GenChallenge::from_slice(&res.gen_challenge)
                    .map_err(|e| e.to_string())
                    .and_then(|challenge| self.signed_authorization(&challenge));
                match signed {
                    Ok(request) => {
                        self.authorization = Some(request.clone());
                        self.then(request)
                    }
                    Err(e) => self.abandon(format!("could not sign the authorization: {e}")),
                }
            }
            B::AuthorizationRes(res) => {
                if res.evse_processing == iso2::EVSEProcessing::Finished {
                    let cpd = if dc { cpd_dc_iso2() } else { cpd_ac_iso2() };
                    self.then(cpd)
                } else {
                    let again = self.authorization.clone().unwrap_or_else(authorization_iso2);
                    self.again(again)
                }
            }
            B::ChargeParameterDiscoveryRes(res) => {
                if res.evse_processing != iso2::EVSEProcessing::Finished {
                    let cpd = if dc { cpd_dc_iso2() } else { cpd_ac_iso2() };
                    return self.again(cpd);
                }
                if let Some(iso2::ChargeParameterDiscoveryResChoice2::SAScheduleList(list)) =
                    &res.choice_2
                    && let Some(tuple) = list.sa_schedule_tuple.first()
                {
                    self.sa_tuple = tuple.sa_schedule_tuple_id;
                }
                if dc {
                    self.then(cable_check_iso2())
                } else {
                    self.then(power_delivery_iso2(ChargeProgress::Start, self.sa_tuple, false))
                }
            }
            B::CableCheckRes(res) => {
                if res.evse_processing == iso2::EVSEProcessing::Finished {
                    self.then(pre_charge_iso2())
                } else {
                    self.again(cable_check_iso2())
                }
            }
            B::PreChargeRes(res) => {
                if (volts(&res.evse_present_voltage) - TARGET_V).abs() <= 10.0 {
                    self.then(power_delivery_iso2(ChargeProgress::Start, self.sa_tuple, true))
                } else {
                    self.again(pre_charge_iso2())
                }
            }
            B::PowerDeliveryRes(_) => {
                if self.stopping {
                    if dc { self.then(welding_iso2()) } else { self.then(self.stop()) }
                } else {
                    self.powered = true;
                    self.charge_loop_iso2(dc)
                }
            }
            B::CurrentDemandRes(iso2::CurrentDemandRes {
                receipt_required: Some(true),
                meter_info: Some(meter),
                ..
            })
            | B::ChargingStatusRes(iso2::ChargingStatusRes {
                receipt_required: Some(true),
                meter_info: Some(meter),
                ..
            }) if self.contract.is_some() => {
                let session = response.session_id().map(|id| id.as_bytes().to_vec());
                match self.signed_receipt(session.unwrap_or_default(), meter.clone()) {
                    Ok(receipt) => self.then(receipt),
                    Err(e) => self.abandon(format!("could not sign the metering receipt: {e}")),
                }
            }
            B::CurrentDemandRes(_) | B::ChargingStatusRes(_) | B::MeteringReceiptRes(_) => {
                self.loops += 1;
                if self.loops >= LOOPS {
                    self.stopping = true;
                    self.then(power_delivery_iso2(ChargeProgress::Stop, self.sa_tuple, dc))
                } else {
                    self.charge_loop_iso2(dc)
                }
            }
            B::WeldingDetectionRes(_) => self.then(self.stop()),
            _ => Next::Done,
        }
    }

    fn charge_loop_iso2(&mut self, dc: bool) -> Next {
        let request = if dc {
            current_demand_iso2()
        } else {
            v2(BodyChoice::ChargingStatusReq(iso2::ChargingStatusReq))
        };
        Next::Send(request, if self.loops == 0 { Duration::ZERO } else { REPEAT })
    }

    fn signed_authorization(&self, challenge: &GenChallenge) -> Result<Message, String> {
        let contract = self.contract.as_ref().ok_or("no contract")?;
        let mut request = iso2::AuthorizationReq { id: None, gen_challenge: None };
        let signature =
            contract.key.sign_authorization(&mut request, challenge).map_err(|e| e.to_string())?;
        Ok(v2_signed(BodyChoice::AuthorizationReq(request), signature))
    }

    fn signed_receipt(
        &self,
        session_id: Vec<u8>,
        meter_info: iso2::MeterInfo,
    ) -> Result<Message, String> {
        let contract = self.contract.as_ref().ok_or("no contract")?;
        let mut receipt = iso2::MeteringReceiptReq {
            id: None,
            session_id,
            sa_schedule_tuple_id: Some(self.sa_tuple),
            meter_info,
        };
        let signature = contract.key.sign_receipt(&mut receipt).map_err(|e| e.to_string())?;
        Ok(v2_signed(BodyChoice::MeteringReceiptReq(receipt), signature))
    }
}

/// Whether a -2 response carries `EVSENotification = StopCharging`.
fn stop_charging(body: &BodyChoice) -> bool {
    use BodyChoice as B;
    use iso2::EVSENotification::StopCharging;
    let dc = |s: &iso2::DCEVSEStatus| s.evse_notification == StopCharging;
    let ac = |s: &iso2::ACEVSEStatus| s.evse_notification == StopCharging;
    match body {
        B::ChargeParameterDiscoveryRes(res) => match &res.choice_3 {
            iso2::ChargeParameterDiscoveryResChoice3::DCEVSEChargeParameter(p) => {
                dc(&p.dc_evse_status)
            }
            iso2::ChargeParameterDiscoveryResChoice3::ACEVSEChargeParameter(p) => {
                ac(&p.ac_evse_status)
            }
            iso2::ChargeParameterDiscoveryResChoice3::EVSEChargeParameter(_) => false,
        },
        B::CableCheckRes(res) => dc(&res.dc_evse_status),
        B::PreChargeRes(res) => dc(&res.dc_evse_status),
        B::CurrentDemandRes(res) => dc(&res.dc_evse_status),
        B::ChargingStatusRes(res) => ac(&res.ac_evse_status),
        _ => false,
    }
}

fn payment_details(contract: &Contract) -> Message {
    v2(BodyChoice::PaymentDetailsReq(iso2::PaymentDetailsReq {
        e_maid: contract.emaid.clone(),
        contract_signature_cert_chain: iso2::CertificateChain {
            id: Some("id1".into()),
            certificate: contract.leaf.clone(),
            sub_certificates: (!contract.sub_certificates.is_empty())
                .then(|| iso2::SubCertificates { certificate: contract.sub_certificates.clone() }),
        },
    }))
}

fn v2_signed(choice: BodyChoice, signature: iso2::Signature) -> Message {
    let Message::Iso2(mut doc) = v2(choice) else { unreachable!("v2 builds a -2 message") };
    if let iso2::Document::V2GMessage(m) = &mut *doc {
        m.header.signature = Some(signature);
    }
    Message::Iso2(doc)
}

fn v2(choice: BodyChoice) -> Message {
    Message::Iso2(Box::new(iso2::Document::V2GMessage(iso2::V2GMessage {
        // The driver stamps the session id the station assigned.
        header: iso2::MessageHeader { session_id: Vec::new(), notification: None, signature: None },
        body: iso2::Body { choice: Some(choice) },
    })))
}

/// The `BodyChoice` of a -2 message.
#[must_use]
pub(crate) fn iso2_body(message: &Message) -> Option<&BodyChoice> {
    match message {
        Message::Iso2(doc) => match &**doc {
            iso2::Document::V2GMessage(m) => m.body.choice.as_ref(),
            _ => None,
        },
        _ => None,
    }
}

/// A -2 physical value in its base unit.
#[must_use]
pub(crate) fn volts(value: &iso2::PhysicalValue) -> f64 {
    f64::from(value.value) * 10f64.powi(i32::from(value.multiplier))
}

#[must_use]
pub(crate) fn physical(value: i16, unit: iso2::UnitSymbol) -> iso2::PhysicalValue {
    iso2::PhysicalValue { multiplier: 0, unit, value }
}

fn dc_status() -> iso2::DCEVStatus {
    iso2::DCEVStatus {
        ev_ready: true,
        ev_error_code: iso2::DCEVErrorCode::NOERROR,
        ev_ress_soc: 42,
    }
}

fn authorization_iso2() -> Message {
    v2(BodyChoice::AuthorizationReq(iso2::AuthorizationReq { id: None, gen_challenge: None }))
}

fn cpd_dc_iso2() -> Message {
    use iso2::UnitSymbol as U;
    v2(BodyChoice::ChargeParameterDiscoveryReq(iso2::ChargeParameterDiscoveryReq {
        max_entries_sa_schedule_tuple: None,
        requested_energy_transfer_mode: EnergyTransferMode::DCExtended,
        choice: iso2::ChargeParameterDiscoveryReqChoice::DCEVChargeParameter(
            iso2::DCEVChargeParameter {
                departure_time: None,
                dc_ev_status: dc_status(),
                ev_maximum_current_limit: physical(200, U::A),
                ev_maximum_power_limit: Some(iso2::PhysicalValue {
                    multiplier: 3,
                    unit: U::W,
                    value: 100,
                }),
                ev_maximum_voltage_limit: physical(500, U::V),
                ev_energy_capacity: None,
                ev_energy_request: None,
                full_soc: None,
                bulk_soc: None,
            },
        ),
    }))
}

fn cpd_ac_iso2() -> Message {
    use iso2::UnitSymbol as U;
    v2(BodyChoice::ChargeParameterDiscoveryReq(iso2::ChargeParameterDiscoveryReq {
        max_entries_sa_schedule_tuple: None,
        requested_energy_transfer_mode: EnergyTransferMode::ACThreePhaseCore,
        choice: iso2::ChargeParameterDiscoveryReqChoice::ACEVChargeParameter(
            iso2::ACEVChargeParameter {
                departure_time: None,
                e_amount: iso2::PhysicalValue { multiplier: 3, unit: U::Wh, value: 20 },
                ev_max_voltage: physical(400, U::V),
                ev_max_current: physical(32, U::A),
                ev_min_current: physical(6, U::A),
            },
        ),
    }))
}

fn cable_check_iso2() -> Message {
    v2(BodyChoice::CableCheckReq(iso2::CableCheckReq { dc_ev_status: dc_status() }))
}

fn pre_charge_iso2() -> Message {
    use iso2::UnitSymbol as U;
    v2(BodyChoice::PreChargeReq(iso2::PreChargeReq {
        dc_ev_status: dc_status(),
        ev_target_voltage: physical(400, U::V),
        ev_target_current: physical(2, U::A),
    }))
}

fn power_delivery_iso2(progress: ChargeProgress, tuple: u8, dc: bool) -> Message {
    v2(BodyChoice::PowerDeliveryReq(iso2::PowerDeliveryReq {
        charge_progress: progress,
        sa_schedule_tuple_id: tuple,
        charging_profile: None,
        choice: dc.then(|| {
            iso2::PowerDeliveryReqChoice::DCEVPowerDeliveryParameter(
                iso2::DCEVPowerDeliveryParameter {
                    dc_ev_status: dc_status(),
                    bulk_charging_complete: None,
                    charging_complete: progress == ChargeProgress::Stop,
                },
            )
        }),
    }))
}

fn current_demand_iso2() -> Message {
    use iso2::UnitSymbol as U;
    v2(BodyChoice::CurrentDemandReq(iso2::CurrentDemandReq {
        dc_ev_status: dc_status(),
        ev_target_current: physical(100, U::A),
        ev_maximum_voltage_limit: None,
        ev_maximum_current_limit: None,
        ev_maximum_power_limit: None,
        bulk_charging_complete: None,
        charging_complete: false,
        remaining_time_to_full_soc: None,
        remaining_time_to_bulk_soc: None,
        ev_target_voltage: physical(400, U::V),
    }))
}

fn welding_iso2() -> Message {
    v2(BodyChoice::WeldingDetectionReq(iso2::WeldingDetectionReq { dc_ev_status: dc_status() }))
}

// ---------------------------------------------------------------------------
// ISO 15118-20
// ---------------------------------------------------------------------------

impl Vehicle {
    #[allow(clippy::too_many_lines, reason = "one arm per response reads as the flow it is")]
    fn next_iso20(&mut self, response: &Message) -> Next {
        use cm::Document as D;
        let dc_set = self.service == Service::Dc;
        match response {
            Message::Iso20(doc) => match &**doc {
                D::SessionSetupRes(_) => {
                    self.then(common(D::AuthorizationSetupReq(cm::AuthorizationSetupReq {
                        header: header(),
                    })))
                }
                D::AuthorizationSetupRes(_) => self.then(authorization_iso20()),
                D::AuthorizationRes(res) => {
                    if res.evse_processing == Processing::Finished {
                        self.then(common(D::ServiceDiscoveryReq(cm::ServiceDiscoveryReq {
                            header: header(),
                            supported_service_i_ds: None,
                        })))
                    } else {
                        self.again(authorization_iso20())
                    }
                }
                D::ServiceDiscoveryRes(res) => {
                    let wanted = if dc_set { DC_SERVICE } else { AC_SERVICE };
                    let offered = &res.energy_transfer_service_list.service;
                    self.service_id = offered
                        .iter()
                        .map(|s| s.service_id)
                        .find(|&id| id == wanted)
                        .unwrap_or(wanted);
                    self.then(common(D::ServiceDetailReq(cm::ServiceDetailReq {
                        header: header(),
                        service_id: self.service_id,
                    })))
                }
                D::ServiceDetailRes(res) => {
                    // This vehicle runs Dynamic control mode with its own
                    // mobility needs, so it selects the set that says so — a
                    // station's first set is often Scheduled, and selecting it
                    // then sending a Dynamic schedule exchange contradicts
                    // the selection.
                    let sets = &res.service_parameter_list.parameter_set;
                    let value = |set: &cm::ParameterSet, name: &str| {
                        set.parameter.iter().find(|p| p.name == name).and_then(|p| match p.choice {
                            cm::ParameterChoice::IntValue(v) => Some(v),
                            _ => None,
                        })
                    };
                    let dynamic = |set: &&cm::ParameterSet| value(set, "ControlMode") == Some(2);
                    if let Some(set) = sets
                        .iter()
                        .filter(dynamic)
                        .find(|s| value(s, "MobilityNeedsMode") == Some(1))
                        .or_else(|| sets.iter().find(dynamic))
                        .or_else(|| sets.first())
                    {
                        self.parameter_set = set.parameter_set_id;
                    }
                    self.then(common(D::ServiceSelectionReq(cm::ServiceSelectionReq {
                        header: header(),
                        selected_energy_transfer_service: cm::SelectedService {
                            service_id: self.service_id,
                            parameter_set_id: self.parameter_set,
                        },
                        selected_vas_list: None,
                    })))
                }
                D::ServiceSelectionRes(_) => {
                    if dc_set {
                        self.then(cpd_dc_iso20())
                    } else {
                        self.then(cpd_ac_iso20())
                    }
                }
                D::ScheduleExchangeRes(res) => {
                    if res.evse_processing != Processing::Finished {
                        self.again(schedule_exchange())
                    } else if dc_set {
                        self.then(dc_msg(dc::Document::DCCableCheckReq(dc::DCCableCheckReq {
                            header: header(),
                        })))
                    } else {
                        self.then(power_delivery_iso20(cm::ChargeProgress::Start))
                    }
                }
                D::PowerDeliveryRes(_) => {
                    if self.stopping {
                        if dc_set {
                            self.then(dc_msg(dc::Document::DCWeldingDetectionReq(
                                dc::DCWeldingDetectionReq {
                                    header: header(),
                                    ev_processing: Processing::Finished,
                                },
                            )))
                        } else {
                            self.then(self.stop())
                        }
                    } else if dc_set {
                        self.then(dc_charge_loop())
                    } else {
                        self.then(ac_charge_loop())
                    }
                }
                _ => Next::Done,
            },
            Message::Iso20Dc(doc) => match &**doc {
                dc::Document::DCChargeParameterDiscoveryRes(_) => self.then(schedule_exchange()),
                dc::Document::DCCableCheckRes(res) => {
                    if res.evse_processing == Processing::Finished {
                        self.then(pre_charge_iso20(Processing::Ongoing))
                    } else {
                        self.again(dc_msg(dc::Document::DCCableCheckReq(dc::DCCableCheckReq {
                            header: header(),
                        })))
                    }
                }
                dc::Document::DCPreChargeRes(res) => {
                    let present = rational(&res.evse_present_voltage);
                    if (present - TARGET_V).abs() <= 10.0 {
                        self.then(power_delivery_iso20(cm::ChargeProgress::Start))
                    } else {
                        self.again(pre_charge_iso20(Processing::Ongoing))
                    }
                }
                dc::Document::DCChargeLoopRes(_) => self.looped(dc_charge_loop()),
                dc::Document::DCWeldingDetectionRes(_) => self.then(self.stop()),
                _ => Next::Done,
            },
            Message::Iso20Ac(doc) => match &**doc {
                ac::Document::ACChargeParameterDiscoveryRes(_) => self.then(schedule_exchange()),
                ac::Document::ACChargeLoopRes(_) => self.looped(ac_charge_loop()),
                _ => Next::Done,
            },
            _ => Next::Done,
        }
    }

    fn looped(&mut self, again: Message) -> Next {
        self.loops += 1;
        if self.loops >= LOOPS {
            self.stopping = true;
            self.then(power_delivery_iso20(cm::ChargeProgress::Stop))
        } else {
            Next::Send(again, REPEAT)
        }
    }
}

fn now_s() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// A header with no session id: the driver stamps the station's in.
fn header() -> MessageHeader {
    MessageHeader { session_id: Vec::new(), time_stamp: now_s(), signature: None }
}

#[must_use]
pub(crate) fn number(value: i16, exponent: i8) -> RationalNumber {
    RationalNumber { exponent, value }
}

#[must_use]
pub(crate) fn rational(n: &RationalNumber) -> f64 {
    f64::from(n.value) * 10f64.powi(i32::from(n.exponent))
}

fn common(body: cm::Document) -> Message {
    Message::Iso20(Box::new(body))
}

fn dc_msg(body: dc::Document) -> Message {
    Message::Iso20Dc(Box::new(body))
}

fn ac_msg(body: ac::Document) -> Message {
    Message::Iso20Ac(Box::new(body))
}

fn authorization_iso20() -> Message {
    common(cm::Document::AuthorizationReq(cm::AuthorizationReq {
        header: header(),
        selected_authorization_service: cm::Authorization::EIM,
        choice: cm::AuthorizationReqChoice::EIMAReqAuthorizationMode(cm::EIMAReqAuthorizationMode),
    }))
}

fn cpd_dc_iso20() -> Message {
    dc_msg(dc::Document::DCChargeParameterDiscoveryReq(dc::DCChargeParameterDiscoveryReq {
        header: header(),
        choice: dc::DCChargeParameterDiscoveryReqChoice::DCCPDReqEnergyTransferMode(
            dc::DCCPDReqEnergyTransferMode {
                ev_maximum_charge_power: number(10, 4),
                ev_minimum_charge_power: number(1, 3),
                ev_maximum_charge_current: number(200, 0),
                ev_minimum_charge_current: number(1, 0),
                ev_maximum_voltage: number(500, 0),
                ev_minimum_voltage: number(200, 0),
                target_soc: Some(80),
            },
        ),
    }))
}

fn cpd_ac_iso20() -> Message {
    ac_msg(ac::Document::ACChargeParameterDiscoveryReq(ac::ACChargeParameterDiscoveryReq {
        header: header(),
        choice: ac::ACChargeParameterDiscoveryReqChoice::ACCPDReqEnergyTransferMode(
            ac::ACCPDReqEnergyTransferMode {
                ev_maximum_charge_power: number(11, 3),
                ev_maximum_charge_power_l2: None,
                ev_maximum_charge_power_l3: None,
                ev_minimum_charge_power: number(1, 3),
                ev_minimum_charge_power_l2: None,
                ev_minimum_charge_power_l3: None,
            },
        ),
    }))
}

fn schedule_exchange() -> Message {
    common(cm::Document::ScheduleExchangeReq(cm::ScheduleExchangeReq {
        header: header(),
        maximum_supporting_points: 12,
        choice: cm::ScheduleExchangeReqChoice::DynamicSEReqControlMode(
            cm::DynamicSEReqControlMode {
                departure_time: 3600,
                minimum_soc: Some(20),
                target_soc: Some(80),
                ev_target_energy_request: number(20, 3),
                ev_maximum_energy_request: number(40, 3),
                ev_minimum_energy_request: number(1, 3),
                ev_maximum_v2_x_energy_request: None,
                ev_minimum_v2_x_energy_request: None,
            },
        ),
    }))
}

fn pre_charge_iso20(processing: Processing) -> Message {
    dc_msg(dc::Document::DCPreChargeReq(dc::DCPreChargeReq {
        header: header(),
        ev_processing: processing,
        ev_present_voltage: number(380, 0),
        ev_target_voltage: number(400, 0),
    }))
}

fn power_delivery_iso20(progress: cm::ChargeProgress) -> Message {
    common(cm::Document::PowerDeliveryReq(cm::PowerDeliveryReq {
        header: header(),
        ev_processing: Processing::Finished,
        charge_progress: progress,
        // A `Start` carries the vehicle's power profile; both Josev's and
        // Donar's stations refuse one without it.
        ev_power_profile: (progress == cm::ChargeProgress::Start).then(|| cm::EVPowerProfile {
            time_anchor: 0,
            choice: cm::EVPowerProfileChoice::DynamicEVPPTControlMode(cm::DynamicEVPPTControlMode),
            ev_power_profile_entries: cm::EVPowerProfileEntryList {
                ev_power_profile_entry: vec![cm::PowerScheduleEntry {
                    duration: 3600,
                    power: number(11, 3),
                    power_l2: None,
                    power_l3: None,
                }],
            },
        }),
        bpt_channel_selection: None,
    }))
}

fn dc_charge_loop() -> Message {
    dc_msg(dc::Document::DCChargeLoopReq(dc::DCChargeLoopReq {
        header: header(),
        display_parameters: None,
        meter_info_requested: false,
        ev_present_voltage: number(400, 0),
        choice: dc::DCChargeLoopReqChoice::DynamicDCCLReqControlMode(
            dc::DynamicDCCLReqControlMode {
                departure_time: None,
                ev_target_energy_request: number(20, 3),
                ev_maximum_energy_request: number(40, 3),
                ev_minimum_energy_request: number(1, 3),
                ev_maximum_charge_power: number(10, 4),
                ev_minimum_charge_power: number(1, 3),
                ev_maximum_charge_current: number(200, 0),
                ev_maximum_voltage: number(500, 0),
                ev_minimum_voltage: number(200, 0),
            },
        ),
    }))
}

fn ac_charge_loop() -> Message {
    ac_msg(ac::Document::ACChargeLoopReq(ac::ACChargeLoopReq {
        header: header(),
        display_parameters: None,
        meter_info_requested: false,
        choice: ac::ACChargeLoopReqChoice::DynamicACCLReqControlMode(
            ac::DynamicACCLReqControlMode {
                departure_time: None,
                ev_target_energy_request: number(20, 3),
                ev_maximum_energy_request: number(40, 3),
                ev_minimum_energy_request: number(1, 3),
                ev_maximum_charge_power: number(11, 3),
                ev_maximum_charge_power_l2: None,
                ev_maximum_charge_power_l3: None,
                ev_minimum_charge_power: number(1, 3),
                ev_minimum_charge_power_l2: None,
                ev_minimum_charge_power_l3: None,
                ev_present_active_power: number(11, 3),
                ev_present_active_power_l2: None,
                ev_present_active_power_l3: None,
                ev_present_reactive_power: number(0, 0),
                ev_present_reactive_power_l2: None,
                ev_present_reactive_power_l3: None,
            },
        ),
    }))
}
