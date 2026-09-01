//! SECC discovery datagrams — the first bytes a charger accepts from anyone on
//! the link-local multicast group.
#![no_main]

use iso15118::sdp::{Discovery, Event, Refusal, Request, Response};
use iso15118::session::{Instant, Millis};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(req) = Request::from_frame(data) {
        assert_eq!(Request::from_payload(&req.to_payload()), Ok(req));
    }
    if let Ok(res) = Response::from_frame(data) {
        assert_eq!(Response::from_payload(&res.to_payload()), Ok(res));
        // Whatever the peer sent, a decoded response names an endpoint that
        // could be connected to: not port zero, not the unspecified address,
        // not a multicast group.
        assert!(res.port != 0);
        assert!(res.address != [0u8; 16]);
        assert!(res.address[0] != 0xff);
        // The downgrade check must never panic.
        let _ = res.satisfies(&Request::TLS);
    }

    // The discovery engine reads datagrams from a multicast group, so anything
    // on the link can send it anything. Only a *usable* answer ends the run: a
    // malformed one and a refused one both leave it retrying, because if either
    // ended it, one spoofed datagram would stop the vehicle ever hearing the
    // station it is plugged into.
    let mut discovery = Discovery::new(Request::TLS).with_max_attempts(3);
    let mut now = Instant::ZERO;
    discovery.start(now);
    let _ = discovery.poll_transmit();

    discovery.handle_datagram(now, data).ok();

    // One event slot, so events are drained as they appear rather than looked
    // for once at the end. A refusal is reported *and* the run carries on; only
    // a terminal event is the outcome.
    let mut outcome = None;
    while let Some(event) = discovery.poll_event() {
        match event {
            Event::Refused { response, reason } => {
                assert!(!discovery.is_finished(), "a refusal must not end the run");
                // Every refusal names a reason that is actually true of it.
                match reason {
                    Refusal::SecurityDowngrade | Refusal::TransportMismatch => {
                        assert!(!response.satisfies(&Request::TLS));
                    }
                    Refusal::OffLink => assert!(!response.is_link_local()),
                    _ => {}
                }
            }
            terminal => outcome = Some(terminal),
        }
    }

    // Whatever it was given, running the clock out must reach an outcome rather
    // than leave the vehicle waiting on a charger that never answered.
    for _ in 0..8 {
        let Some(deadline) = discovery.poll_timeout() else { break };
        now = deadline + Millis::from_millis(1);
        discovery.handle_timeout(now);
        let _ = discovery.poll_transmit();
        while let Some(event) = discovery.poll_event() {
            if !matches!(event, Event::Refused { .. }) {
                outcome = Some(event);
            }
        }
    }
    assert!(discovery.is_finished(), "discovery must terminate");
    match outcome {
        Some(Event::Found(res)) => {
            // A find is an endpoint the caller is being told to connect to, so
            // it has to be everything that was asked for.
            assert!(res.satisfies(&Request::TLS));
            assert!(res.is_link_local(), "off-link answers are refused, not found");
        }
        Some(Event::GaveUp { attempts }) => assert!(attempts <= 3),
        _ => panic!("a finished discovery has an outcome"),
    }
});
