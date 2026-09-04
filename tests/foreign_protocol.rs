//! Speaking a message set this crate does not have.
//!
//! DIN SPEC 70121 is the reason this file exists. Its schemas are not freely
//! available, so its codec is not here and hand-transcribing it would produce
//! exactly the thing this project exists to avoid — a wire format with no
//! reference to check against. But a charge-point operator with a German DC
//! estate still has to talk to it, and everything *below* the message set is
//! identical for every generation.
//!
//! So the claim the documentation makes is that a consumer can bring its own
//! message set and keep the rest: V2GTP framing with its bounds, the
//! `supportedAppProtocol` handshake, the spec timers. This test is that claim,
//! executed. It stands in a two-byte pretend codec for DIN, because the point
//! is the seam and not the schema.

#![cfg(feature = "std")]

use iso15118::app_protocol::{SupportedAppProtocolReq, SupportedAppProtocolRes};
use iso15118::exi::ExiDocument;
use iso15118::message::Message;
use iso15118::session::{Connection, ConnectionError, Instant, Millis, Timer, Timers};
use iso15118::v2gtp::PayloadType;
use iso15118::{Protocol, Protocols};

/// The station's set: it speaks DIN, through a codec of its own.
const STATION: Protocols = Protocols::new().with(Protocol::Din70121);

/// A message of the foreign set. Two bytes, and entirely the caller's business.
const FOREIGN_REQ: &[u8] = &[0x80, 0x01];
const FOREIGN_RES: &[u8] = &[0x80, 0x02];

#[test]
fn a_foreign_message_set_rides_the_crate_s_handshake_framing_and_timers() {
    let mut vehicle = Connection::new();
    let mut station = Connection::new();
    let mut timers = Timers::new();
    let now = Instant::ZERO;

    // --- the handshake is the crate's, whichever generation wins -------------
    let offer = SupportedAppProtocolReq::advertising([Protocol::Din70121, Protocol::Iso2]);
    vehicle.send(&Message::AppProtocolReq(Box::new(offer))).unwrap();
    timers.arm(Timer::CommunicationSetup, now, Millis::from_secs(18));

    station.receive(&vehicle.take_transmit()).unwrap();
    let Some(Message::AppProtocolReq(req)) = station.next_message().unwrap() else {
        panic!("the handshake is decodable before any generation is chosen");
    };

    // The station's own codec decides what it can speak; `Flow::supports` is
    // the crate's answer and deliberately not the only one allowed.
    let agreed = req.negotiate(STATION).expect("DIN is on offer and this station speaks it");
    assert_eq!(agreed.protocol, Protocol::Din70121, "the vehicle's first choice");
    assert!(!agreed.minor_deviation);

    station
        .send(&Message::AppProtocolRes(Box::new(SupportedAppProtocolRes::accept(agreed))))
        .unwrap();
    station.set_protocol(agreed.protocol);

    vehicle.receive(&station.take_transmit()).unwrap();
    let Some(Message::AppProtocolRes(res)) = vehicle.next_message().unwrap() else {
        panic!("expected the handshake answer");
    };
    assert!(res.response_code.is_ok());
    // The schema id is what comes back, so the vehicle asks its own request
    // which protocol it meant by that id — no index arithmetic at the call site.
    let chosen = req.protocol_for_schema_id(res.schema_id.unwrap()).unwrap();
    assert_eq!(chosen, Protocol::Din70121);
    vehicle.set_protocol(chosen);
    timers.disarm(Timer::CommunicationSetup);

    // --- from here the message set is the caller's, the framing is not ------
    vehicle.send_frame(PayloadType::ExiEncodedV2gMessage, FOREIGN_REQ).unwrap();
    let wire = vehicle.take_transmit();

    // Byte at a time: the reassembly is the same one every generation gets.
    for byte in &wire {
        station.receive(&[*byte]).unwrap();
    }
    assert_eq!(
        station.next_frame(),
        Some((PayloadType::ExiEncodedV2gMessage, FOREIGN_REQ.to_vec()))
    );
    assert_eq!(station.next_frame(), None);

    station.send_frame(PayloadType::ExiEncodedV2gMessage, FOREIGN_RES).unwrap();
    vehicle.receive(&station.take_transmit()).unwrap();
    assert_eq!(
        vehicle.next_frame(),
        Some((PayloadType::ExiEncodedV2gMessage, FOREIGN_RES.to_vec()))
    );
}

/// The seam does not open a hole in the bounds.
///
/// A caller supplying its own message set supplies its own bugs with it; what
/// it does not get to do is hand a frame past the ceiling that protects the
/// peer's allocator.
#[test]
fn a_foreign_payload_is_bounded_like_any_other() {
    let mut conn = Connection::with_limit(64);
    let too_big = vec![0u8; 65];
    assert!(matches!(
        conn.send_frame(PayloadType::ExiEncodedV2gMessage, &too_big),
        Err(ConnectionError::Overflow { limit: 64 })
    ));
    assert!(conn.transmit_is_empty(), "nothing is queued for a frame that was refused");

    // And on the way in: the declared length is checked before a single byte
    // of the payload is buffered for it.
    let mut framed = vec![0u8; iso15118::v2gtp::HEADER_LEN + 65];
    iso15118::v2gtp::write_frame(PayloadType::ExiEncodedV2gMessage, &too_big, &mut framed).unwrap();
    assert!(matches!(
        conn.receive(&framed[..iso15118::v2gtp::HEADER_LEN]),
        Err(ConnectionError::Framing(iso15118::v2gtp::V2gtpError::PayloadTooLarge {
            declared: 65,
            limit: 64,
        }))
    ));
    assert_eq!(conn.pending_input(), 0);
    assert_eq!(conn.pending_frames(), 0);
}

/// A generation the crate has no codec for is **reported** by `next_message` and
/// handed over by `next_frame` — which is the whole of the difference.
///
/// This is the case \[V2G2-800\] does *not* cover, and telling the two apart is
/// the point. A payload type that does not belong to this session at all is
/// ignored, because ignoring is what the requirement asks for and the frame is
/// skippable. But `0x8001` under a DIN session **is** this session's own type:
/// the message is part of the conversation, so dropping it silently would look
/// like a peer that had gone quiet, and the operator would be debugging a
/// timeout instead of a missing codec.
#[test]
fn the_typed_path_reports_a_message_it_has_no_codec_for() {
    let mut conn = Connection::new();
    conn.set_protocol(Protocol::Din70121);
    conn.send_frame(PayloadType::ExiEncodedV2gMessage, FOREIGN_REQ).unwrap();
    let wire = conn.take_transmit();

    let mut typed = Connection::new();
    typed.set_protocol(Protocol::Din70121);
    typed.receive(&wire).unwrap();
    assert!(
        matches!(
            typed.next_message(),
            Err(ConnectionError::Message(iso15118::message::MessageError::NoCodec { .. }))
        ),
        "no DIN codec, and the crate says so rather than guessing or going quiet"
    );
    assert_eq!(typed.ignored_frames(), 0, "this one is reported, not skipped");

    let mut raw = Connection::new();
    raw.set_protocol(Protocol::Din70121);
    raw.receive(&wire).unwrap();
    assert_eq!(raw.next_frame(), Some((PayloadType::ExiEncodedV2gMessage, FOREIGN_REQ.to_vec())));
}

/// The handshake's own encoding does not depend on any generation being
/// compiled in — it is the one schema all three share.
#[test]
fn the_handshake_round_trips_for_a_generation_with_no_message_set() {
    let req = SupportedAppProtocolReq::advertising(Protocol::Din70121);
    let bytes = req.to_vec().unwrap();
    assert_eq!(SupportedAppProtocolReq::from_bytes(&bytes).unwrap(), req);
    assert_eq!(req.app_protocols[0].protocol(), Some(Protocol::Din70121));
    assert_eq!(req.app_protocols[0].version_number_major, 2);
}

/// The complement, and the reason the two cannot be one rule: a frame for a
/// session this is not is stepped over, and the foreign message behind it still
/// arrives.
#[test]
fn a_frame_for_somebody_else_does_not_disturb_the_foreign_set() {
    let mut out = Connection::new();
    out.send_frame(PayloadType::ManufacturerSpecific(0xB00B), b"another vendor").unwrap();
    out.send_frame(PayloadType::ExiEncodedV2gMessage, FOREIGN_REQ).unwrap();
    let wire = out.take_transmit();

    let mut station = Connection::new();
    station.set_protocol(Protocol::Din70121);
    station.receive(&wire).unwrap();

    // The raw seam sees everything, in order — it is the caller's stream.
    assert_eq!(
        station.next_frame(),
        Some((PayloadType::ManufacturerSpecific(0xB00B), b"another vendor".to_vec()))
    );
    assert_eq!(
        station.next_frame(),
        Some((PayloadType::ExiEncodedV2gMessage, FOREIGN_REQ.to_vec()))
    );
}
