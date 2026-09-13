//! End-to-end tests of the generated ISO 15118-2 message set.
//!
//! These are the same golden vectors `tests/golden.rs` walks event by event,
//! but decoded into typed messages and re-encoded from them. Where that file
//! proves the *grammar* arithmetic, this proves the generated structs, fields,
//! enumerations and bounds sit on top of it correctly.
//!
//! The vectors come from the EXI reference implementation; see
//! `tests/golden.rs` for how they were produced.

#![cfg(feature = "iso2")]

use iso15118::exi::{ExiDocument, ExiError, ValueCoding};
use iso15118::iso2::{
    Body, BodyChoice, MessageHeader, ResponseCode, SessionSetupReq, SessionSetupRes, V2GMessage,
};

/// `V2G_Message` carrying `SessionSetupReq` with `EVCCID = 0011223344AA`.
const SESSION_SETUP_REQ: &[u8] = &[
    0x80, 0x98, 0x02, 0x0f, 0x53, 0x2f, 0xe4, 0xcd, 0xd3, 0xb6, 0x26, 0xd1, 0xd0, 0x18, 0x00, 0x44,
    0x88, 0xcd, 0x12, 0xa8, 0x00,
];

/// `V2G_Message` carrying `SessionSetupRes`.
const SESSION_SETUP_RES: &[u8] = &[
    0x80, 0x98, 0x02, 0x0f, 0x53, 0x2f, 0xe4, 0xcd, 0xd3, 0xb6, 0x26, 0xd1, 0xe0, 0x20, 0x3d, 0x11,
    0x14, 0xa9, 0x05, 0x09, 0x0c, 0xa9, 0x14, 0xc0, 0xc0, 0xc0, 0xc0, 0xc4, 0x1a, 0xf7, 0xfc, 0x36,
    0xc0, 0xc0,
];

const SESSION_ID: [u8; 8] = [0x3D, 0x4C, 0xBF, 0x93, 0x37, 0x4E, 0xD8, 0x9B];

fn header() -> MessageHeader {
    MessageHeader { session_id: SESSION_ID.to_vec(), notification: None, signature: None }
}

#[test]
fn session_setup_req_decodes_into_typed_fields() {
    let msg = V2GMessage::from_bytes(SESSION_SETUP_REQ).expect("the golden vector should decode");
    assert_eq!(msg.header.session_id, SESSION_ID);
    assert!(msg.header.notification.is_none());
    match msg.body.choice {
        Some(BodyChoice::SessionSetupReq(req)) => {
            assert_eq!(req.evcc_id, [0x00, 0x11, 0x22, 0x33, 0x44, 0xAA]);
        }
        other => panic!("expected a SessionSetupReq, got {other:?}"),
    }
}

#[test]
fn session_setup_req_encodes_to_the_golden_bytes() {
    let msg = V2GMessage {
        header: header(),
        body: Body {
            choice: Some(BodyChoice::SessionSetupReq(SessionSetupReq {
                evcc_id: vec![0x00, 0x11, 0x22, 0x33, 0x44, 0xAA],
            })),
        },
    };
    assert_eq!(msg.to_vec().unwrap(), SESSION_SETUP_REQ);
}

#[test]
fn session_setup_res_decodes_into_typed_fields() {
    let msg = V2GMessage::from_bytes(SESSION_SETUP_RES).expect("the golden vector should decode");
    match msg.body.choice {
        Some(BodyChoice::SessionSetupRes(res)) => {
            // Enumeration indices follow schema document order.
            assert_eq!(res.response_code, ResponseCode::OKNewSessionEstablished);
            assert_eq!(res.evse_id, "DE*ABC*E00001");
            assert_eq!(res.evse_time_stamp, Some(1_725_456_343));
        }
        other => panic!("expected a SessionSetupRes, got {other:?}"),
    }
}

#[test]
fn session_setup_res_encodes_to_the_golden_bytes() {
    let msg = V2GMessage {
        header: header(),
        body: Body {
            choice: Some(BodyChoice::SessionSetupRes(SessionSetupRes {
                response_code: ResponseCode::OKNewSessionEstablished,
                evse_id: "DE*ABC*E00001".into(),
                evse_time_stamp: Some(1_725_456_343),
            })),
        },
    };
    assert_eq!(msg.to_vec().unwrap(), SESSION_SETUP_RES);
}

#[test]
fn both_vectors_round_trip() {
    for vector in [SESSION_SETUP_REQ, SESSION_SETUP_RES] {
        let msg = V2GMessage::from_bytes(vector).unwrap();
        assert_eq!(msg.to_vec().unwrap(), vector, "re-encoding must be byte-identical");
        assert_eq!(V2GMessage::from_bytes(&msg.to_vec().unwrap()).unwrap(), msg);
    }
}

#[test]
fn the_response_code_enumeration_matches_the_schema() {
    // Document order, not lexicographic: `OK` is 0 even though `FAILED` sorts
    // before it.
    assert_eq!(ResponseCode::OK.as_index(), 0);
    assert_eq!(ResponseCode::OKNewSessionEstablished.as_index(), 1);
    assert_eq!(ResponseCode::OK.as_str(), "OK");
    assert_eq!(ResponseCode::ALL.len(), 26);
    assert_eq!(ResponseCode::WIDTH, 5, "26 values need five bits");
    for value in ResponseCode::ALL {
        assert_eq!(ResponseCode::from_index(value.as_index()), Ok(value));
    }
    assert_eq!(ResponseCode::from_index(26), Err(ExiError::UnknownEnumValue));
}

#[test]
fn truncating_a_vector_never_panics() {
    for vector in [SESSION_SETUP_REQ, SESSION_SETUP_RES] {
        for n in 0..vector.len() {
            let _ = V2GMessage::from_bytes(&vector[..n]);
        }
    }
}

#[test]
fn every_single_bit_flip_is_rejected_or_decodes_cleanly() {
    for vector in [SESSION_SETUP_REQ, SESSION_SETUP_RES] {
        for byte in 0..vector.len() {
            for bit in 0..8 {
                let mut mutated = vector.to_vec();
                mutated[byte] ^= 1 << bit;
                if let Ok(msg) = V2GMessage::from_bytes(&mutated) {
                    // Anything that decodes must survive a re-encode.
                    let bytes = msg.to_vec().expect("a decoded message must re-encode");
                    assert_eq!(V2GMessage::from_bytes(&bytes).unwrap(), msg);
                }
            }
        }
    }
}

/// ISO 15118-2 Annex J: the `SignedInfo` element an XML signature actually
/// signs is EXI-encoded against the **xmldsig schema on its own**, not against
/// the V2G schema set that imports it.
///
/// Both are well-formed EXI and both decode; they simply are not the same
/// bytes, so an implementation that picks the other table produces signatures
/// nobody else can verify. `OpenV2G` shipped the V2G-set reading and changed to
/// this one for interoperability.
///
///
/// Two vectors, because `SignedInfo` names the canonical-EXI URI **twice** and
/// the two ways of writing the second occurrence are the whole of this crate's
/// Plug & Charge interoperability story:
///
/// * `FIELD` is what this crate signs and what the field signs — the URI spelled
///   out both times. `RiseV2G` produces it, and `libcbv2g` (`EVerest`'s codec) can
///   read nothing else: it implements no string table and answers
///   `EXI_ERROR__STRINGVALUES_NOT_SUPPORTED` for a reference.
/// * `REFERENCE` is `exificient`'s, and what Canonical EXI actually requires —
///   *"a string value MUST be represented using a compact identifier"*.
///
/// Both decode to the same `SignedInfo`. Only the first is verifiable by a real
/// peer, which is why it is the default and why the specification is the one
/// that gives way here. See [`ValueCoding`].
#[test]
fn signed_info_is_a_fragment_of_the_xmldsig_schema_alone() {
    use iso15118::iso2::{
        CanonicalizationMethod, DigestMethod, Reference, SignatureMethod, SignedInfo, Transform,
        Transforms,
    };

    // exificient's: the second canonical-EXI URI is a string-table reference.
    const REFERENCE: &str = "808112b43a3a381d1797bbbbbb973b999737b93397aa2917b1b0b737b734b1b0b\
616b2bc3497a1ab43a3a381d1797bbbbbb973b999737b933979918181897981a17bc36b63239b4b396b6b7b93291b2b1b2\
39b096b9b430991a9b2206234944310002429687474703a2f2f7777772e77332e6f72672f323030312f30342f786d6c656\
e6323736861323536406aabbccddeeff1b8";

    // What this crate signs: the URI written out in full both times.
    const FIELD: &str = "808112b43a3a381d1797bbbbbb973b999737b93397aa2917b1b0b737b734b1b0b\
616b2bc3497a1ab43a3a381d1797bbbbbb973b999737b933979918181897981a17bc36b63239b4b396b6b7b93291b2b1b2\
39b096b9b4309 91a9b220623494431025687474703a2f2f7777772e77332e6f72672f54522f63616e6f6e6963616c2d65\
78692f4852d0e8e8e0745e5eeeeeee5cee665cdee4ce5e646060625e60685ef0dad8cadcc646e6d0c2646a6c80d557799b\
bddfe370";

    let signed_info = SignedInfo {
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
            uri: Some("#ID1".into()),
            transforms: Some(Transforms {
                transform: vec![Transform {
                    algorithm: "http://www.w3.org/TR/canonical-exi/".into(),
                }],
            }),
            digest_method: DigestMethod {
                algorithm: "http://www.w3.org/2001/04/xmlenc#sha256".into(),
            },
            digest_value: vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        }],
    };

    let unhex = |s: &str| -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    };
    let field = unhex(FIELD);
    let referenced = unhex(REFERENCE);

    // The default is the field's.
    assert_eq!(signed_info.to_xmldsig_fragment().unwrap(), field);
    assert_eq!(
        signed_info.to_xmldsig_fragment_with(ValueCoding::Referenced).unwrap(),
        referenced,
        "this codec must still be able to produce exificient's bytes exactly"
    );

    // And both read back to the same structure, which is why verifying under
    // either is not leniency about content.
    assert_eq!(SignedInfo::from_xmldsig_fragment(&field).unwrap(), signed_info);
    assert_eq!(SignedInfo::from_xmldsig_fragment(&referenced).unwrap(), signed_info);
    assert!(field.len() > referenced.len(), "spelling it out costs bytes; that is the trade");
}
