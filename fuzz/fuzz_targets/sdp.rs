//! SECC discovery datagrams — the first bytes a charger accepts from anyone on
//! the link-local multicast group.
#![no_main]

use iso15118::sdp::{Discovery, Event, Request, Response};
use iso15118::session::{Instant, Millis};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(req) = Request::from_frame(data) {
        assert_eq!(Request::from_payload(&req.to_payload()), Ok(req));
    }
    if let Ok(res) = Response::from_frame(data) {
        assert_eq!(Response::from_payload(&res.to_payload()), Ok(res));
        // The downgrade check must never panic, whatever the peer sent.
        let _ = res.satisfies(&Request::TLS);
    }

    // The discovery engine reads datagrams from a multicast group, so anything
    // on the link can send it anything. A bad datagram must leave it running.
    let mut discovery = Discovery::new(Request::TLS).with_max_attempts(3);
    let mut now = Instant::ZERO;
    discovery.start(now);
    let _ = discovery.poll_transmit();

    let accepted = discovery.handle_datagram(now, data).is_ok();
    assert_eq!(accepted, discovery.is_finished(), "only a good answer ends the run");

    // Whatever it was given, running the clock out must reach an outcome rather
    // than leave the vehicle waiting on a charger that never answered.
    for _ in 0..8 {
        let Some(deadline) = discovery.poll_timeout() else { break };
        now = deadline + Millis::from_millis(1);
        discovery.handle_timeout(now);
        let _ = discovery.poll_transmit();
    }
    assert!(discovery.is_finished(), "discovery must terminate");
    match discovery.poll_event() {
        Some(Event::Found(res) | Event::Refused(res)) => assert!(res.port != 0),
        Some(Event::GaveUp { attempts }) => assert!(attempts <= 3),
        _ => panic!("a finished discovery has an outcome"),
    }
});
