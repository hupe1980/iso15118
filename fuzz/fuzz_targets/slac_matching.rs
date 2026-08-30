//! The SLAC matching engines, on frames from a shared medium.
//!
//! SLAC runs before there is an IP link, let alone TLS, so every frame here is
//! from an unauthenticated stranger — and one of the engines' jobs is deciding
//! which stranger to hand a network key to. The properties checked are the ones
//! that decision rests on.
#![no_main]

use iso15118::session::{Instant, Millis};
use iso15118::slac::matching::{Ev, EvConfig, Evse, EvseConfig};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut evse = Evse::new(EvseConfig {
        mac: [2, 0, 0, 0, 0, 1],
        id: [b'E'; 17],
        nmk: [0xAB; 16],
        nid: [0xCD; 7],
        attenuation_limit: None,
    });
    let mut ev = Ev::new(EvConfig {
        mac: [2, 0, 0, 0, 0, 2],
        id: [b'V'; 17],
        run_id: [0xA5; 8],
        sounding_payload: [0x5A; 16],
        attenuation_limit: Some(60),
    });
    ev.start(Instant::ZERO);

    let mut now = Instant::ZERO;
    for piece in data.chunks(64) {
        evse.handle_frame(now, piece);
        ev.handle_frame(now, piece);
        while evse.poll_transmit().is_some() {}
        while ev.poll_transmit().is_some() {}
        while evse.poll_event().is_some() {}
        while ev.poll_event().is_some() {}
        now = now + Millis::from_millis(10);
        evse.handle_timeout(now);
        ev.handle_timeout(now);

        // The station must not hand over its key to a peer that never sounded.
        // Reaching `is_matched` requires a measurement, and the fuzzer has no
        // way to supply one.
        assert!(!evse.is_matched(), "matched without a measurement");
    }
});
