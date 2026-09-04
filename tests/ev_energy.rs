//! The one question a consumer above the protocol actually asks.
//!
//! `hems` drives an EVSE/EV pair for vehicle-to-home days and needs the
//! vehicle's state of charge, its battery capacity and what it is asking for —
//! without naming an EXI type. The two generations carry those in different
//! messages, different structures and different numeric encodings, so the test
//! that matters is the one asserting **the same battery reads the same both
//! ways**.

#![cfg(all(feature = "iso2", feature = "iso20"))]

use iso15118::message::{EvEnergyStatus, Message};
use iso15118::{iso2, iso20};

fn wrap(choice: iso2::BodyChoice) -> Message {
    Message::Iso2(Box::new(iso2::Document::V2GMessage(iso2::V2GMessage {
        header: iso2::MessageHeader {
            session_id: vec![0x11; 8],
            notification: None,
            signature: None,
        },
        body: iso2::Body { choice: Some(choice) },
    })))
}

fn header() -> iso20::common::MessageHeader {
    iso20::common::MessageHeader { session_id: vec![0x11; 8], time_stamp: 0, signature: None }
}

fn dc_status(soc: u8) -> iso2::DCEVStatus {
    iso2::DCEVStatus {
        ev_ready: true,
        ev_error_code: iso2::DCEVErrorCode::NOERROR,
        ev_ress_soc: soc,
    }
}

/// `PhysicalValue` is `value * 10^multiplier`, so 40 kWh is `4000 * 10^1`.
fn wh(value: i16, multiplier: i8) -> iso2::PhysicalValue {
    iso2::PhysicalValue { multiplier, unit: iso2::UnitSymbol::Wh, value }
}

fn rational(value: i16, exponent: i8) -> iso20::common::RationalNumber {
    iso20::common::RationalNumber { exponent, value }
}

/// 40 kWh, stated by an ISO 15118-2 vehicle and by an ISO 15118-20 one, has to
/// come out as the same integer. It is the whole point of the type.
#[test]
fn one_battery_reads_the_same_through_both_generations() {
    const FORTY_KWH: i64 = 40_000_000; // milliwatt-hours

    let first_generation =
        wrap(iso2::BodyChoice::ChargeParameterDiscoveryReq(iso2::ChargeParameterDiscoveryReq {
            max_entries_sa_schedule_tuple: None,
            requested_energy_transfer_mode: iso2::EnergyTransferMode::DCExtended,
            choice: iso2::ChargeParameterDiscoveryReqChoice::DCEVChargeParameter(
                iso2::DCEVChargeParameter {
                    departure_time: Some(7200),
                    dc_ev_status: dc_status(42),
                    ev_maximum_current_limit: wh(200, 0),
                    ev_maximum_power_limit: None,
                    ev_maximum_voltage_limit: wh(400, 0),
                    // 40 kWh as 4000 * 10^1 Wh.
                    ev_energy_capacity: Some(wh(4000, 1)),
                    ev_energy_request: Some(wh(2200, 1)),
                    full_soc: Some(97),
                    bulk_soc: Some(80),
                },
            ),
        }));

    let from_iso2 =
        first_generation.ev_energy_status().expect("a DC parameter discovery states plenty");
    assert_eq!(from_iso2.present_soc, Some(42));
    assert_eq!(from_iso2.full_soc, Some(97));
    assert_eq!(from_iso2.bulk_soc, Some(80));
    assert_eq!(from_iso2.energy_capacity, Some(FORTY_KWH));
    assert_eq!(from_iso2.target_energy_request, Some(22_000_000));
    assert_eq!(from_iso2.departure_in, Some(7200));

    // ...and the same battery under -20, where the capacity rides on the charge
    // loop as a `RationalNumber` with no unit at all: 4000 * 10^1 Wh.
    let second_generation = Message::Iso20Dc(Box::new(iso20::dc::Document::DCChargeLoopReq(
        iso20::dc::DCChargeLoopReq {
            header: header(),
            display_parameters: Some(iso20::common::DisplayParameters {
                present_soc: Some(42),
                minimum_soc: Some(20),
                target_soc: Some(80),
                maximum_soc: Some(97),
                remaining_time_to_minimum_soc: None,
                remaining_time_to_target_soc: None,
                remaining_time_to_maximum_soc: None,
                charging_complete: Some(false),
                battery_energy_capacity: Some(rational(4000, 1)),
                inlet_hot: Some(false),
            }),
            meter_info_requested: false,
            ev_present_voltage: rational(400, 0),
            choice: iso20::dc::DCChargeLoopReqChoice::DynamicDCCLReqControlMode(
                iso20::dc::DynamicDCCLReqControlMode {
                    departure_time: Some(7200),
                    ev_target_energy_request: rational(2200, 1),
                    ev_maximum_energy_request: rational(3000, 1),
                    ev_minimum_energy_request: rational(500, 1),
                    ev_maximum_charge_power: rational(150, 3),
                    ev_minimum_charge_power: rational(1, 3),
                    ev_maximum_charge_current: rational(200, 0),
                    ev_maximum_voltage: rational(900, 0),
                    ev_minimum_voltage: rational(200, 0),
                },
            ),
        },
    )));

    let from_iso20 = second_generation.ev_energy_status().expect("a charge loop states a battery");
    assert_eq!(from_iso20.present_soc, from_iso2.present_soc);
    assert_eq!(from_iso20.energy_capacity, Some(FORTY_KWH), "one battery, one integer");
    assert_eq!(from_iso20.full_soc, Some(97), "-20 calls the ceiling MaximumSOC");
    assert_eq!(from_iso20.charging_complete, Some(false));
    // ...and the dynamic control mode restates the request every turn of the
    // loop, so the two generations agree on that too.
    assert_eq!(from_iso20.target_energy_request, from_iso2.target_energy_request);
    assert_eq!(from_iso20.departure_in, from_iso2.departure_in);
}

/// The state of charge rides on six different -2 requests, and a consumer must
/// not have to know which. Each of them is the same field.
#[test]
fn the_state_of_charge_is_found_wherever_iso2_hides_it() {
    let cases: Vec<(&str, Message)> = vec![
        (
            "CableCheckReq",
            wrap(iso2::BodyChoice::CableCheckReq(iso2::CableCheckReq {
                dc_ev_status: dc_status(55),
            })),
        ),
        (
            "PreChargeReq",
            wrap(iso2::BodyChoice::PreChargeReq(iso2::PreChargeReq {
                dc_ev_status: dc_status(55),
                ev_target_voltage: wh(400, 0),
                ev_target_current: wh(2, 0),
            })),
        ),
        (
            "WeldingDetectionReq",
            wrap(iso2::BodyChoice::WeldingDetectionReq(iso2::WeldingDetectionReq {
                dc_ev_status: dc_status(55),
            })),
        ),
    ];
    for (name, message) in cases {
        let energy = message.ev_energy_status().unwrap_or_else(|| panic!("{name}"));
        assert_eq!(energy.present_soc, Some(55), "{name}");
        assert_eq!(energy.energy_capacity, None, "{name} says nothing about capacity");
    }
}

/// An AC -2 session states an energy amount and no state of charge at all, and
/// the view must say so rather than inventing a zero.
#[test]
fn absent_is_not_zero() {
    let ac =
        wrap(iso2::BodyChoice::ChargeParameterDiscoveryReq(iso2::ChargeParameterDiscoveryReq {
            max_entries_sa_schedule_tuple: None,
            requested_energy_transfer_mode: iso2::EnergyTransferMode::ACThreePhaseCore,
            choice: iso2::ChargeParameterDiscoveryReqChoice::ACEVChargeParameter(
                iso2::ACEVChargeParameter {
                    departure_time: None,
                    e_amount: wh(1500, 1),
                    ev_max_voltage: wh(400, 0),
                    ev_max_current: wh(32, 0),
                    ev_min_current: wh(6, 0),
                },
            ),
        }));
    let energy = ac.ev_energy_status().expect("AC states an amount");
    assert_eq!(energy.target_energy_request, Some(15_000_000));
    assert_eq!(energy.present_soc, None, "AC has no state of charge to state");
    assert_eq!(energy.energy_capacity, None);
}

/// A response carries no battery information, and neither does a request that is
/// pure protocol. `None` rather than an empty status, so a caller cannot mistake
/// "nothing was said" for "everything was zero".
#[test]
fn a_message_with_nothing_to_say_says_nothing() {
    let response = wrap(iso2::BodyChoice::SessionSetupRes(iso2::SessionSetupRes {
        response_code: iso2::ResponseCode::OK,
        evse_id: "DE*ABC*E1".into(),
        evse_time_stamp: None,
    }));
    assert_eq!(response.ev_energy_status(), None);

    let setup = wrap(iso2::BodyChoice::SessionSetupReq(iso2::SessionSetupReq {
        evcc_id: vec![1, 2, 3, 4, 5, 6],
    }));
    assert_eq!(setup.ev_energy_status(), None);

    // A -20 charge loop with no `DisplayParameters` is legal and says nothing.
    let bare = Message::Iso20Ac(Box::new(iso20::ac::Document::ACChargeLoopReq(
        iso20::ac::ACChargeLoopReq {
            header: header(),
            display_parameters: None,
            meter_info_requested: false,
            choice: iso20::ac::ACChargeLoopReqChoice::CLReqControlMode(
                iso20::common::CLReqControlMode,
            ),
        },
    )));
    assert_eq!(bare.ev_energy_status(), None);

    assert!(EvEnergyStatus::default().is_empty());
}

/// -20's dynamic control mode is where the energy request lives, and all three
/// figures are mandatory there — which is what "dynamic" means.
#[test]
fn the_from_iso20_request_comes_from_schedule_exchange() {
    let msg = Message::Iso20(Box::new(iso20::messages::Document::ScheduleExchangeReq(
        iso20::messages::ScheduleExchangeReq {
            header: header(),
            maximum_supporting_points: 12,
            choice: iso20::messages::ScheduleExchangeReqChoice::DynamicSEReqControlMode(
                iso20::messages::DynamicSEReqControlMode {
                    departure_time: 14_400,
                    minimum_soc: Some(20),
                    target_soc: Some(80),
                    ev_target_energy_request: rational(2200, 1),
                    ev_maximum_energy_request: rational(3000, 1),
                    ev_minimum_energy_request: rational(500, 1),
                    ev_maximum_v2_x_energy_request: None,
                    ev_minimum_v2_x_energy_request: None,
                },
            ),
        },
    )));

    let energy = msg.ev_energy_status().expect("dynamic mode states all three");
    assert_eq!(energy.departure_in, Some(14_400));
    assert_eq!(energy.minimum_soc, Some(20));
    assert_eq!(energy.target_soc, Some(80));
    assert_eq!(energy.target_energy_request, Some(22_000_000));
    assert_eq!(energy.maximum_energy_request, Some(30_000_000));
    assert_eq!(energy.minimum_energy_request, Some(5_000_000));
    assert_eq!(energy.present_soc, None, "a schedule exchange states no present charge");
}

/// Reading a voltage as an energy because both happen to be integers is the
/// kind of agreement nobody notices until it is on an invoice.
#[test]
fn an_energy_that_is_not_in_watt_hours_is_dropped_rather_than_converted() {
    let mistaken =
        wrap(iso2::BodyChoice::ChargeParameterDiscoveryReq(iso2::ChargeParameterDiscoveryReq {
            max_entries_sa_schedule_tuple: None,
            requested_energy_transfer_mode: iso2::EnergyTransferMode::DCExtended,
            choice: iso2::ChargeParameterDiscoveryReqChoice::DCEVChargeParameter(
                iso2::DCEVChargeParameter {
                    departure_time: None,
                    dc_ev_status: dc_status(10),
                    ev_maximum_current_limit: wh(200, 0),
                    ev_maximum_power_limit: None,
                    ev_maximum_voltage_limit: wh(400, 0),
                    // Volts where watt-hours belong.
                    ev_energy_capacity: Some(iso2::PhysicalValue {
                        multiplier: 1,
                        unit: iso2::UnitSymbol::V,
                        value: 4000,
                    }),
                    ev_energy_request: None,
                    full_soc: None,
                    bulk_soc: None,
                },
            ),
        }));
    let energy = mistaken.ev_energy_status().expect("the state of charge is still readable");
    assert_eq!(energy.present_soc, Some(10));
    assert_eq!(energy.energy_capacity, None, "a wrong number is worse than no number");
}
