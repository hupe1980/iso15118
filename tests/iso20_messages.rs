//! End-to-end tests of the generated ISO 15118-20 message set.
//!
//! The vectors are the `SessionStop` pair from `EVerest`'s independent C++
//! implementation, the same ones `tests/golden.rs` walks event by event. Here
//! they go through the generated structs instead.

#![cfg(feature = "iso20-common")]

use iso15118::exi::{ExiDocument, ExiError};
use iso15118::iso20::common::{MessageHeader, ResponseCode};
use iso15118::iso20::messages::{ChargingSession, SessionStopReq, SessionStopRes};

const SESSION_STOP_REQ: &[u8] = &[
    0x80, 0x94, 0x04, 0x1e, 0xa6, 0x5f, 0xc9, 0x9b, 0xa7, 0x6c, 0x4d, 0x8d, 0x7b, 0xfe, 0x1b, 0x60,
    0x62, 0x28,
];

const SESSION_STOP_RES: &[u8] = &[
    0x80, 0x98, 0x04, 0x1e, 0xa6, 0x5f, 0xc9, 0x9b, 0xa7, 0x6c, 0x4d, 0x8d, 0x7b, 0xfe, 0x1b, 0x60,
    0x62, 0x00, 0x00,
];

const SESSION_ID: [u8; 8] = [0x3D, 0x4C, 0xBF, 0x93, 0x37, 0x4E, 0xD8, 0x9B];

fn header() -> MessageHeader {
    MessageHeader { session_id: SESSION_ID.to_vec(), time_stamp: 1_725_456_343, signature: None }
}

#[test]
fn session_stop_req_decodes_into_typed_fields() {
    let msg = SessionStopReq::from_bytes(SESSION_STOP_REQ).expect("golden vector should decode");
    assert_eq!(msg.header.session_id, SESSION_ID);
    assert_eq!(msg.header.time_stamp, 1_725_456_343);
    assert_eq!(msg.charging_session, ChargingSession::Terminate);
    assert!(msg.ev_termination_code.is_none());
    assert!(msg.ev_termination_explanation.is_none());
}

#[test]
fn session_stop_req_encodes_to_the_golden_bytes() {
    let msg = SessionStopReq {
        header: header(),
        charging_session: ChargingSession::Terminate,
        ev_termination_code: None,
        ev_termination_explanation: None,
    };
    assert_eq!(msg.to_vec().unwrap(), SESSION_STOP_REQ);
}

#[test]
fn session_stop_res_round_trips() {
    let msg = SessionStopRes::from_bytes(SESSION_STOP_RES).expect("golden vector should decode");
    assert_eq!(msg.response_code, ResponseCode::OK);
    assert_eq!(msg.to_vec().unwrap(), SESSION_STOP_RES);
}

#[test]
fn document_codes_are_the_ones_the_grammar_derives() {
    // 37 and 38 of the 54 global elements the schema set declares, sorted by
    // local name then namespace. `tests/golden.rs` pins the same numbers from
    // the wire.
    assert_eq!(SessionStopReq::DOCUMENT_CODE, 37);
    assert_eq!(SessionStopRes::DOCUMENT_CODE, 38);
    assert_eq!(iso15118::iso20::messages::DOCUMENT_WIDTH, 6);
}

#[test]
fn a_request_does_not_decode_as_a_response() {
    assert_eq!(SessionStopRes::from_bytes(SESSION_STOP_REQ), Err(ExiError::UnknownEventCode));
    assert_eq!(SessionStopReq::from_bytes(SESSION_STOP_RES), Err(ExiError::UnknownEventCode));
}

#[test]
fn the_charging_session_enumeration_follows_document_order() {
    assert_eq!(ChargingSession::Pause.as_index(), 0);
    assert_eq!(ChargingSession::Terminate.as_index(), 1);
    assert_eq!(ChargingSession::ServiceRenegotiation.as_index(), 2);
    assert_eq!(ChargingSession::WIDTH, 2);
}

#[test]
fn optional_trailing_fields_round_trip() {
    // Exercises the positions the golden vectors leave empty: the two optional
    // children after `ChargingSession`, whose presence changes every following
    // event code.
    for (code, explanation) in [
        (None, None),
        (Some("EV_STOP".to_owned()), None),
        (Some("EV_STOP".to_owned()), Some("driver pressed stop".to_owned())),
        (None, Some("driver pressed stop".to_owned())),
    ] {
        let msg = SessionStopReq {
            header: header(),
            charging_session: ChargingSession::Pause,
            ev_termination_code: code,
            ev_termination_explanation: explanation,
        };
        let bytes = msg.to_vec().unwrap();
        assert_eq!(SessionStopReq::from_bytes(&bytes).unwrap(), msg);
    }
}

/// The ISO 15118 profile of `ds:Signature` is a real, typed part of the message
/// set — the wire format Plug & Charge rides on.
///
/// `xmldsig` as published allows arbitrary foreign content (`xs:any`, mixed
/// text, `KeyInfo`, `Object`); ISO 15118 uses none of it. Those productions
/// keep their event codes here so every other code stays where the reference
/// implementation puts it, but they have no Rust form and decoding one is a
/// rejection rather than a silent drop.
#[test]
fn a_signed_header_round_trips() {
    use iso15118::iso20::common::{
        CanonicalizationMethod, DigestMethod, Reference, Signature, SignatureMethod,
        SignatureValue, SignedInfo, Transform, Transforms,
    };

    let signature = Signature {
        id: None,
        signed_info: SignedInfo {
            id: None,
            canonicalization_method: CanonicalizationMethod {
                algorithm: "http://www.w3.org/TR/canonical-exi/".into(),
            },
            signature_method: SignatureMethod {
                algorithm: "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256".into(),
                hmac_output_length: None,
            },
            reference: vec![Reference {
                id: None,
                r#type: None,
                uri: Some("#id1".into()),
                transforms: Some(Transforms {
                    transform: vec![Transform {
                        algorithm: "http://www.w3.org/TR/canonical-exi/".into(),
                    }],
                }),
                digest_method: DigestMethod {
                    algorithm: "http://www.w3.org/2001/04/xmlenc#sha256".into(),
                },
                digest_value: vec![0xAB; 32],
            }],
        },
        signature_value: SignatureValue { id: None, value: vec![0xCD; 64] },
    };

    let msg = SessionStopReq {
        header: MessageHeader { signature: Some(signature), ..header() },
        charging_session: ChargingSession::Terminate,
        ev_termination_code: None,
        ev_termination_explanation: None,
    };
    let bytes = msg.to_vec().unwrap();
    assert_eq!(SessionStopReq::from_bytes(&bytes).unwrap(), msg);
    assert!(bytes.len() > SESSION_STOP_REQ.len(), "the signature is really on the wire");
}

#[test]
fn foreign_content_inside_a_signature_is_refused_not_ignored() {
    // `ds:CanonicalizationMethodType` is `mixed` and carries an
    // `xs:any`, neither of which ISO 15118 ever sends and neither of which has
    // a Rust form here. Both still occupy their event codes, so that every
    // other code in the type lands where the reference implementation puts it —
    // and a peer that does send one gets an error rather than a signature
    // silently missing part of what it signed.
    use iso15118::exi::{Encoder, Header, Lengths, ValueCtx};
    use iso15118::iso20::common::{DOCUMENT_WIDTH, Signature};

    let mut buf = [0u8; 128];
    let mut e = Encoder::new(&mut buf);
    e.write_header(Header::ISO15118).unwrap();
    e.event(Signature::DOCUMENT_CODE, DOCUMENT_WIDTH).unwrap();
    e.event(1, 2).unwrap(); // Signature: skip the optional Id, SE(SignedInfo)
    e.event(1, 2).unwrap(); // SignedInfo: skip Id, SE(CanonicalizationMethod)
    e.event(0, 1).unwrap(); // AT(Algorithm)
    e.string(ValueCtx(0), "http://www.w3.org/TR/canonical-exi/", Lengths::max(128)).unwrap();
    // Codes here are: 0 = SE(*), 1 = EE, 2 = untyped CH from `mixed`.
    e.event(0, 2).unwrap();
    let len = e.finish().unwrap();

    assert_eq!(
        Signature::from_bytes(&buf[..len]),
        Err(ExiError::UnsupportedOption),
        "content the ISO 15118 profile excludes must be refused, not stripped"
    );
}

#[test]
fn truncating_a_vector_never_panics() {
    for n in 0..SESSION_STOP_REQ.len() {
        let _ = SessionStopReq::from_bytes(&SESSION_STOP_REQ[..n]);
    }
}

/// ISO 15118-20 types `SessionID` as `length = 8` — exactly eight bytes, not at
/// most eight, unlike ISO 15118-2. A short one is a message a conforming
/// charger must reject, so this crate will neither write nor read one.
#[test]
fn a_dash_20_session_id_is_exactly_eight_bytes() {
    use iso15118::exi::ExiError;
    use iso15118::iso20::common::MessageHeader;
    use iso15118::iso20::messages::{ChargingSession, SessionStopReq};

    let stop = |session_id: Vec<u8>| SessionStopReq {
        header: MessageHeader { session_id, time_stamp: 1_725_456_343, signature: None },
        charging_session: ChargingSession::Terminate,
        ev_termination_code: None,
        ev_termination_explanation: None,
    };

    stop(SESSION_ID.to_vec()).to_vec().expect("eight bytes is the length");
    assert_eq!(stop(vec![0x3D, 0x4C, 0xBF, 0x93]).to_vec(), Err(ExiError::ValueTooShort));
    assert_eq!(stop(Vec::new()).to_vec(), Err(ExiError::ValueTooShort));
    assert_eq!(stop(vec![0u8; 9]).to_vec(), Err(ExiError::ValueTooLong));
}
