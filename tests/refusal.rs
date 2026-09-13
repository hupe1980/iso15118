//! Every request can be refused, and every refusal encodes.
//!
//! A station that detects a sequence error has to *answer* it with the matching
//! response type and the code the standard prescribes. At that moment it
//! usually has nothing to put in the response, because the refusal is why the
//! exchange stopped — and a response built with an empty required list does not
//! encode. The station then goes silent exactly where the standard told it to
//! explain, and the vehicle waits out its timeout instead of learning what it
//! did wrong. That is the shape of `EVerest`'s CVE-2026-54170.
//!
//! So the assertion here is on the **bytes**: not that a refusal can be built,
//! but that it can be sent.

#![cfg(all(feature = "iso2", feature = "iso20"))]

use iso15118::exi::ExiDocument;
use iso15118::iso2;
use iso15118::iso20::{ac, acdp, dc, messages as cm, wpt};

#[test]
fn every_iso2_request_has_a_refusal_that_encodes() {
    let code = iso2::ResponseCode::FAILEDSequenceError;
    let mut checked = 0;
    for request in iso2_requests() {
        let refusal =
            request.refusal(code).unwrap_or_else(|| panic!("{} has no refusal", request.name()));
        assert_eq!(refusal.response_code(), Some(code), "{}", request.name());

        let message = iso2::Document::V2GMessage(iso2::V2GMessage {
            header: iso2::MessageHeader {
                session_id: vec![1, 2, 3, 4, 5, 6, 7, 8],
                notification: None,
                signature: None,
            },
            body: iso2::Body { choice: Some(refusal.clone()) },
        });
        message
            .to_vec()
            .unwrap_or_else(|e| panic!("{} refusal does not encode: {e:?}", request.name()));
        checked += 1;
    }
    assert_eq!(checked, 17, "every ISO 15118-2 request");
}

/// One of each ISO 15118-2 request, minimally built.
fn iso2_requests() -> Vec<iso2::BodyChoice> {
    use iso2::BodyChoice as B;
    vec![
        B::SessionSetupReq(iso2::SessionSetupReq::minimal()),
        B::ServiceDiscoveryReq(iso2::ServiceDiscoveryReq::minimal()),
        B::ServiceDetailReq(iso2::ServiceDetailReq::minimal()),
        B::PaymentServiceSelectionReq(iso2::PaymentServiceSelectionReq::minimal()),
        B::PaymentDetailsReq(iso2::PaymentDetailsReq::minimal()),
        B::AuthorizationReq(iso2::AuthorizationReq::minimal()),
        B::CertificateInstallationReq(iso2::CertificateInstallationReq::minimal()),
        B::CertificateUpdateReq(iso2::CertificateUpdateReq::minimal()),
        B::ChargeParameterDiscoveryReq(iso2::ChargeParameterDiscoveryReq::minimal()),
        B::PowerDeliveryReq(iso2::PowerDeliveryReq::minimal()),
        B::ChargingStatusReq(iso2::ChargingStatusReq::minimal()),
        B::MeteringReceiptReq(iso2::MeteringReceiptReq::minimal()),
        B::CableCheckReq(iso2::CableCheckReq::minimal()),
        B::PreChargeReq(iso2::PreChargeReq::minimal()),
        B::CurrentDemandReq(iso2::CurrentDemandReq::minimal()),
        B::WeldingDetectionReq(iso2::WeldingDetectionReq::minimal()),
        B::SessionStopReq(iso2::SessionStopReq::minimal()),
    ]
}

macro_rules! iso20_set {
    ($name:literal, $module:ident, $expected:expr, [$($variant:ident),* $(,)?]) => {
        let code = iso15118::iso20::common::ResponseCode::FAILEDSequenceError;
        let mut checked = 0;
        $(
            {
                let request = $module::Document::$variant($module::$variant::minimal());
                let refusal = request
                    .refusal(code)
                    .unwrap_or_else(|| panic!("{} has no refusal", stringify!($variant)));
                refusal.to_vec().unwrap_or_else(|e| {
                    panic!("{} refusal does not encode: {e:?}", stringify!($variant))
                });
                assert_eq!(refusal.response_code(), Some(code));
                checked += 1;
            }
        )*
        assert_eq!(checked, $expected, "every {} request", $name);
    };
}

#[test]
fn every_iso20_common_request_has_a_refusal_that_encodes() {
    iso20_set!(
        "ISO 15118-20 CommonMessages",
        cm,
        10,
        [
            SessionSetupReq,
            AuthorizationSetupReq,
            AuthorizationReq,
            ServiceDiscoveryReq,
            ServiceDetailReq,
            ServiceSelectionReq,
            ScheduleExchangeReq,
            PowerDeliveryReq,
            SessionStopReq,
            MeteringConfirmationReq,
        ]
    );
}

#[test]
fn every_iso20_energy_transfer_request_has_a_refusal_that_encodes() {
    iso20_set!("AC", ac, 2, [ACChargeParameterDiscoveryReq, ACChargeLoopReq]);
    iso20_set!(
        "DC",
        dc,
        5,
        [
            DCChargeParameterDiscoveryReq,
            DCCableCheckReq,
            DCPreChargeReq,
            DCChargeLoopReq,
            DCWeldingDetectionReq,
        ]
    );
    iso20_set!(
        "WPT",
        wpt,
        6,
        [
            WPTChargeParameterDiscoveryReq,
            WPTPairingReq,
            WPTAlignmentCheckReq,
            WPTChargeLoopReq,
            WPTFinePositioningSetupReq,
            WPTFinePositioningReq,
        ]
    );
    iso20_set!("ACDP", acdp, 3, [ACDPVehiclePositioningReq, ACDPConnectReq, ACDPSystemStatusReq,]);
}

/// The ten response types that cannot be built from nothing — a required list
/// with `minOccurs >= 1`, a string with a `minLength`, an exact-length binary.
/// `minimal()` is what makes them buildable, so this pins the ones that would
/// otherwise be silently empty.
#[test]
fn the_responses_with_mandatory_content_are_filled_not_empty() {
    let r = cm::AuthorizationSetupRes::minimal();
    assert!(!r.authorization_services.is_empty(), "AuthorizationSetupRes needs a service");

    let r = cm::ServiceDetailRes::minimal();
    assert!(
        !r.service_parameter_list.parameter_set.is_empty(),
        "ServiceDetailRes needs a ParameterSet — this is CVE-2026-54170's field"
    );

    let r = iso2::ServiceDiscoveryRes::minimal();
    assert!(!r.payment_option_list.payment_option.is_empty());
    assert!(!r.charge_service.supported_energy_transfer_mode.energy_transfer_mode.is_empty());

    let r = iso2::PaymentDetailsRes::minimal();
    assert_eq!(r.gen_challenge.len(), 16, "GenChallenge is an exact length, not a maximum");
}
