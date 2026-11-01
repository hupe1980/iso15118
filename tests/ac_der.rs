//! ISO 15118-20 Amd 1's `AC_DER` schema sets through the message layer and the
//! session flow.
//!
//! The grammars themselves are checked against `exificient` by
//! `scripts/verify-grammars.sh`; this checks the wiring around them — the
//! payload types they travel under, that a session admits them only when it
//! selected them, and that a refusal for each of their requests encodes.

#![cfg(all(feature = "iso20-ac-der-iec", feature = "iso20-ac-der-sae", feature = "iso20-ac"))]

use iso15118::Protocol;
use iso15118::exi::ExiDocument;
use iso15118::iso20::{ac, ac_der_iec, ac_der_sae};
use iso15118::message::Message;
use iso15118::session::{Flow, FlowError, Security, iso20};
use iso15118::v2gtp::PayloadType;

#[test]
fn each_variant_travels_under_its_own_payload_type_and_round_trips() {
    let iec = Message::Iso20AcDerIec(Box::new(ac_der_iec::Document::ACChargeLoopReq(
        ac_der_iec::ACChargeLoopReq::minimal(),
    )));
    let sae = Message::Iso20AcDerSae(Box::new(ac_der_sae::Document::ACChargeLoopReq(
        ac_der_sae::ACChargeLoopReq::minimal(),
    )));
    for (message, payload_type) in
        [(iec, PayloadType::Part20AcDerIec), (sae, PayloadType::Part20AcDerSae)]
    {
        let (pt, bytes) = message.encode().expect("encodes");
        assert_eq!(pt, payload_type);
        assert_eq!(pt.as_u16(), if pt == PayloadType::Part20AcDerIec { 0x8010 } else { 0x8011 });
        let back = Message::decode(Some(Protocol::Iso20), pt, &bytes).expect("decodes");
        assert_eq!(back, message);
        assert_eq!(back.name(), "AC_ChargeLoopReq");
    }
}

#[test]
fn every_ac_der_request_has_a_refusal_that_encodes() {
    let code = iso15118::iso20::common::ResponseCode::FAILEDSequenceError;
    let requests = [
        ac_der_iec::Document::ACChargeParameterDiscoveryReq(
            ac_der_iec::ACChargeParameterDiscoveryReq::minimal(),
        ),
        ac_der_iec::Document::ACChargeLoopReq(ac_der_iec::ACChargeLoopReq::minimal()),
    ];
    for request in requests {
        let refusal = request.refusal(code).expect("has a refusal");
        refusal.to_vec().expect("refusal encodes");
    }
    let requests = [
        ac_der_sae::Document::ACChargeParameterDiscoveryReq(
            ac_der_sae::ACChargeParameterDiscoveryReq::minimal(),
        ),
        ac_der_sae::Document::ACChargeLoopReq(ac_der_sae::ACChargeLoopReq::minimal()),
    ];
    for request in requests {
        let refusal = request.refusal(code).expect("has a refusal");
        refusal.to_vec().expect("refusal encodes");
    }
}

/// A peer that selected one service and then speaks another's message set is
/// out of sequence, however legal the same request would be in the right set.
#[test]
fn a_charge_loop_from_the_wrong_message_set_is_refused() {
    let mut flow = Flow::new(Protocol::Iso20, Security::Tls).expect("-20 is compiled in");
    flow.resume(iso20::EnergyTransfer::from_service_id(10).expect("AC_DER_IEC"))
        .expect("a -20 flow resumes");
    let plain_ac = Message::Iso20Ac(Box::new(ac::Document::ACChargeParameterDiscoveryReq(
        ac::ACChargeParameterDiscoveryReq::minimal(),
    )));
    assert!(matches!(flow.permits(&plain_ac), Err(FlowError::Sequence(_))));
    assert!(matches!(flow.accept(&plain_ac), Err(FlowError::Sequence(_))));

    let der =
        Message::Iso20AcDerIec(Box::new(ac_der_iec::Document::ACChargeParameterDiscoveryReq(
            ac_der_iec::ACChargeParameterDiscoveryReq::minimal(),
        )));
    flow.accept(&der).expect("the selected service's set is admitted");
}

/// A pantograph session speaks two message sets: ACDP to position and connect,
/// DC for everything that moves energy. Driven with real messages rather than
/// abstract requests, because the abstract graph cannot see which set a
/// message came from.
#[cfg(all(feature = "iso20-dc", feature = "iso20-acdp"))]
#[test]
fn a_pantograph_session_admits_the_dc_and_acdp_sets_and_nothing_else() {
    use iso15118::iso20::{acdp, dc};
    let mut flow = Flow::new(Protocol::Iso20, Security::Tls).expect("-20 is compiled in");
    flow.resume(iso20::EnergyTransfer::from_service_id(4).expect("DC_ACDP"))
        .expect("a -20 flow resumes");

    let positioning = Message::Iso20Acdp(Box::new(acdp::Document::ACDPVehiclePositioningReq(
        acdp::ACDPVehiclePositioningReq::minimal(),
    )));
    flow.accept(&positioning).expect("ACDP positioning belongs to a pantograph session");

    let discovery = Message::Iso20Dc(Box::new(dc::Document::DCChargeParameterDiscoveryReq(
        dc::DCChargeParameterDiscoveryReq::minimal(),
    )));
    flow.accept(&discovery).expect("parameter discovery runs in the DC set");

    let ac = Message::Iso20Ac(Box::new(ac::Document::ACChargeParameterDiscoveryReq(
        ac::ACChargeParameterDiscoveryReq::minimal(),
    )));
    assert!(matches!(flow.permits(&ac), Err(FlowError::Sequence(_))), "AC is not this session's");
}
