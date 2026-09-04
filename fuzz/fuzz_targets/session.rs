//! The charging station's front door.
//!
//! Every other target starts partway in: this one starts where a charging
//! station actually starts, with a TCP byte stream from a vehicle that has
//! authenticated nothing. The bytes go through V2GTP reassembly, the EXI
//! decoder, session-id checking and the message-ordering rules, which is the
//! whole path an attacker with a cable controls.
//!
//! The input is chopped into arbitrary chunks, because frame boundaries and
//! read boundaries are unrelated and the reassembler is where that goes wrong.
//!
//! Every request is answered, because V2G is half-duplex and the station reads
//! nothing further until it is. The *content* of the answer does not matter
//! here — the ordering rules constrain requests, not responses — so one canned
//! `SessionStopRes` per generation stands in for the thirty-odd real ones and
//! keeps the fuzzer walking the whole flow rather than stopping at the first
//! message.
//!
//! Properties:
//!   * no input panics;
//!   * a session that has closed stays closed and stops producing events;
//!   * the transmit queue never grows without an event to explain it.
#![no_main]

use iso15118::message::Message;
use iso15118::secc::{Event, Secc, SeccConfig};
use iso15118::session::{Instant, Millis, SessionId};
use iso15118::{Protocol, Protocols, iso2, iso20};
use libfuzzer_sys::fuzz_target;

/// A response the station can always send, whatever was asked.
fn canned(protocol: Option<Protocol>) -> Option<Message> {
    match protocol? {
        Protocol::Iso2 => Some(Message::Iso2(Box::new(iso2::Document::V2GMessage(
            iso2::V2GMessage {
                header: iso2::MessageHeader {
                    session_id: alloc_id(),
                    notification: None,
                    signature: None,
                },
                body: iso2::Body {
                    choice: Some(iso2::BodyChoice::SessionStopRes(iso2::SessionStopRes {
                        response_code: iso2::ResponseCode::OK,
                    })),
                },
            },
        )))),
        Protocol::Iso20 => Some(Message::Iso20(Box::new(
            iso20::messages::Document::SessionStopRes(iso20::messages::SessionStopRes {
                header: iso20::common::MessageHeader {
                    session_id: alloc_id(),
                    time_stamp: 0,
                    signature: None,
                },
                response_code: iso20::common::ResponseCode::OK,
            }),
        ))),
        // DIN SPEC 70121 has no message set here, so there is nothing to send.
        _ => None,
    }
}

fn alloc_id() -> Vec<u8> {
    vec![1, 2, 3, 4, 5, 6, 7, 8]
}

fuzz_target!(|data: &[u8]| {
    let mut secc = Secc::new(SeccConfig {
        protocols: Protocols::ISO,
        session_id: SessionId::new([1, 2, 3, 4, 5, 6, 7, 8]),
        // A small limit so the fuzzer reaches the refusal paths rather than
        // spending its budget allocating.
        max_payload_len: 8192,
        ..SeccConfig::default()
    });
    let mut now = Instant::ZERO;
    secc.opened(now);

    // The first byte picks a chunk size, so one input covers both "one frame
    // per read" and "one byte per read".
    let (chunk, body) = data.split_first().map_or((1usize, data), |(n, rest)| {
        (usize::from(*n).max(1), rest)
    });

    for piece in body.chunks(chunk) {
        if secc.handle_input(now, piece).is_err() {
            // An error from `handle_input` is fatal *by construction*: the
            // stream cannot be resynchronised, so the engine closes rather than
            // leaving that to a caller who might log it and call again. This
            // target is the only place that assertion is made against
            // arbitrary bytes split at arbitrary boundaries, which is where a
            // path that reports a fault without shutting would hide.
            assert!(secc.is_closed(), "a reported stream fault must close the session");
            secc.handle_input(now, body).ok();
            assert!(secc.is_closed(), "and it must stay shut");
            return;
        }
        let mut closed = false;
        while let Some(event) = secc.poll_event() {
            match event {
                Event::Closed(_) => closed = true,
                Event::Request(_) | Event::Refused { .. } | Event::Overdue { .. } => {
                    if let Some(res) = canned(secc.protocol()) {
                        let _ = secc.respond(now, res);
                    }
                }
                _ => {}
            }
        }
        let _ = secc.take_transmit();
        if closed {
            assert!(secc.is_closed());
            // A closed session must stay shut whatever else arrives.
            secc.handle_input(now, body).ok();
            assert!(secc.poll_event().is_none() || secc.is_closed());
            return;
        }
        now = now + Millis::from_millis(1);
    }

    // Whatever state it reached, running the clock past every deadline must end
    // the session rather than leave it waiting forever.
    if let Some(deadline) = secc.poll_timeout() {
        secc.handle_timeout(deadline + Millis::from_secs(1));
        assert!(secc.is_closed(), "an expired deadline must end the session");
    }
});
