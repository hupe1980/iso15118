//! A whole SLAC matching run, vehicle to charging station, with no raw socket.
//!
//! The interesting case is the one the protocol exists for: two stations share
//! the powerline medium and both hear the vehicle, so both answer and both
//! report a measurement. Only the one this cable is actually plugged into hears
//! it loudly, and that is the one that gets to hand over the network key.

#![cfg(all(feature = "slac", feature = "std"))]

use iso15118::session::{Instant, Millis};
use iso15118::slac::AttenProfile;
use iso15118::slac::matching::{Ev, EvConfig, EvEvent, Evse, EvseConfig, EvseEvent, Reason};
use iso15118::slac::{AAG_LEN, MacAddr};

const EV_MAC: MacAddr = [0x02, 0, 0, 0, 0, 0x01];
const NEAR_MAC: MacAddr = [0x02, 0, 0, 0, 0, 0x10];
const FAR_MAC: MacAddr = [0x02, 0, 0, 0, 0, 0x20];
const RUN_ID: [u8; 8] = [0xA5; 8];

fn station_id(tag: u8) -> [u8; 17] {
    let mut id = [0u8; 17];
    id[0] = tag;
    id
}

fn ev() -> Ev {
    Ev::new(EvConfig {
        mac: EV_MAC,
        id: station_id(b'V'),
        run_id: RUN_ID,
        sounding_payload: [0x5A; 16],
        // A station heard at 60 dB is not at the other end of this cable.
        attenuation_limit: Some(60),
    })
}

fn evse(mac: MacAddr, tag: u8) -> Evse {
    Evse::new(EvseConfig {
        mac,
        id: station_id(tag),
        nmk: [tag; 16],
        nid: [tag; 7],
        attenuation_limit: None,
    })
}

/// An attenuation profile that is `db` decibels flat across every group.
fn flat(db: u8) -> AttenProfile {
    AttenProfile { num_groups: u8::try_from(AAG_LEN).unwrap(), aag: [db; AAG_LEN] }
}

/// The medium: everything anyone transmits is heard by everyone else.
struct Medium {
    ev: Ev,
    stations: Vec<Evse>,
    now: Instant,
}

impl Medium {
    /// Moves every queued frame to every other party, until nothing is queued.
    fn settle(&mut self) {
        for _ in 0..64 {
            let mut frames: Vec<Vec<u8>> = Vec::new();
            while let Some(out) = self.ev.poll_transmit() {
                frames.push(out.frame);
            }
            let mut from_stations: Vec<Vec<u8>> = Vec::new();
            for station in &mut self.stations {
                while let Some(out) = station.poll_transmit() {
                    from_stations.push(out.frame);
                }
            }
            if frames.is_empty() && from_stations.is_empty() {
                return;
            }
            for f in &frames {
                for station in &mut self.stations {
                    station.handle_frame(self.now, f);
                }
            }
            for f in &from_stations {
                self.ev.handle_frame(self.now, f);
            }
        }
        panic!("the medium never went quiet");
    }

    /// Runs the clock forward to the next deadline anyone is waiting on.
    fn tick(&mut self) -> bool {
        let mut next = self.ev.poll_timeout();
        for station in &self.stations {
            next = match (next, station.poll_timeout()) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
        }
        let Some(next) = next else { return false };
        self.now = next.max(self.now + Millis::from_millis(1));
        self.ev.handle_timeout(self.now);
        for station in &mut self.stations {
            station.handle_timeout(self.now);
        }
        self.settle();
        true
    }

    fn run(&mut self) {
        self.ev.start(self.now);
        self.settle();
        for _ in 0..200 {
            if self.ev.is_matched() || !self.tick() {
                return;
            }
        }
        panic!("the run never finished");
    }

    fn ev_events(&mut self) -> Vec<EvEvent> {
        core::iter::from_fn(|| self.ev.poll_event()).collect()
    }
}

#[test]
fn the_nearest_station_wins_and_hands_over_its_key() {
    let mut near = evse(NEAR_MAC, 0x11);
    let mut far = evse(FAR_MAC, 0x22);
    // What each station's modem measured: the one this cable is plugged into
    // hears the sounding burst loudly, the neighbour barely.
    near.observe(&flat(10));
    far.observe(&flat(55));

    let mut medium = Medium { ev: ev(), stations: vec![near, far], now: Instant::ZERO };
    medium.run();

    assert!(medium.ev.is_matched(), "the vehicle should have matched");
    assert_eq!(medium.ev.stations().len(), 2, "both stations answered the broadcast");

    let matched = medium
        .ev_events()
        .into_iter()
        .find_map(|e| match e {
            EvEvent::Matched { evse_mac, nmk, .. } => Some((evse_mac, nmk)),
            _ => None,
        })
        .expect("a match");
    assert_eq!(matched.0, NEAR_MAC, "the quietest link loses; the loudest wins");
    assert_eq!(matched.1, [0x11; 16], "and its key is the one that arrived");

    assert!(medium.stations[0].is_matched());
    assert!(!medium.stations[1].is_matched(), "the neighbour must not think it won");
}

#[test]
fn a_station_that_is_too_far_away_is_not_matched() {
    let mut far = evse(FAR_MAC, 0x22);
    far.observe(&flat(90));

    let mut medium = Medium { ev: ev(), stations: vec![far], now: Instant::ZERO };
    medium.run();

    assert!(!medium.ev.is_matched());
    let failed = medium.ev_events().into_iter().find_map(|e| match e {
        EvEvent::Failed(r) => Some(r),
        _ => None,
    });
    assert_eq!(failed, Some(Reason::TooFarAway));
}

#[test]
fn a_vehicle_with_nobody_to_talk_to_gives_up() {
    let mut medium = Medium { ev: ev(), stations: Vec::new(), now: Instant::ZERO };
    medium.run();
    assert_eq!(
        medium.ev_events().into_iter().find_map(|e| match e {
            EvEvent::Failed(r) => Some(r),
            _ => None,
        }),
        Some(Reason::NoStation)
    );
}

/// The network key travels in the clear, and the only thing that makes that
/// acceptable is the measurement that preceded it. A station must not hand the
/// key to a peer that skipped straight to asking for it.
#[test]
fn the_key_is_not_given_before_the_measurement() {
    use iso15118::slac::{Mmtype, Mmv, write_frame};
    use iso15118::slac::{SlacMatchReq, SlacParmReq};

    let mut station = evse(NEAR_MAC, 0x11);
    let now = Instant::ZERO;

    let mut payload = [0u8; 128];
    let mut wire = [0u8; 128];

    // Open a run, so the station is listening...
    let n = SlacParmReq { run_id: RUN_ID }.encode(&mut payload).unwrap();
    let len =
        write_frame(&mut wire, NEAR_MAC, EV_MAC, Mmv::Av1_1, Mmtype::SlacParmReq, &payload[..n])
            .unwrap();
    station.handle_frame(now, &wire[..len]);

    // ...then ask for the key without ever sounding.
    let req = SlacMatchReq {
        pev_id: station_id(b'V'),
        pev_mac: EV_MAC,
        evse_id: station_id(0x11),
        evse_mac: NEAR_MAC,
        run_id: RUN_ID,
    };
    let n = req.encode(&mut payload).unwrap();
    let len =
        write_frame(&mut wire, NEAR_MAC, EV_MAC, Mmv::Av1_1, Mmtype::SlacMatchReq, &payload[..n])
            .unwrap();
    station.handle_frame(now, &wire[..len]);

    assert!(!station.is_matched(), "no measurement, no key");
    let events: Vec<EvseEvent> = core::iter::from_fn(|| station.poll_event()).collect();
    assert!(events.contains(&EvseEvent::Failed(Reason::OutOfSequence)));
}

/// On a shared medium every station hears every frame. A station that answers
/// a match request addressed to its neighbour gives its network key to a
/// vehicle that chose someone else.
#[test]
fn a_station_ignores_a_match_request_addressed_to_another() {
    use iso15118::slac::{Mmtype, Mmv, write_frame};
    use iso15118::slac::{SlacMatchReq, SlacParmReq};

    let mut bystander = evse(FAR_MAC, 0x22);
    bystander.observe(&flat(20));
    let now = Instant::ZERO;
    let mut payload = [0u8; 192];
    let mut wire = [0u8; 192];

    let n = SlacParmReq { run_id: RUN_ID }.encode(&mut payload).unwrap();
    let len =
        write_frame(&mut wire, FAR_MAC, EV_MAC, Mmv::Av1_1, Mmtype::SlacParmReq, &payload[..n])
            .unwrap();
    bystander.handle_frame(now, &wire[..len]);
    // Drain the `CM_SLAC_PARM.CNF` it correctly answered the broadcast with.
    while bystander.poll_transmit().is_some() {}

    // A match request that names the *other* station.
    let req = SlacMatchReq {
        pev_id: station_id(b'V'),
        pev_mac: EV_MAC,
        evse_id: station_id(0x11),
        evse_mac: NEAR_MAC,
        run_id: RUN_ID,
    };
    let n = req.encode(&mut payload).unwrap();
    let len =
        write_frame(&mut wire, FAR_MAC, EV_MAC, Mmv::Av1_1, Mmtype::SlacMatchReq, &payload[..n])
            .unwrap();
    bystander.handle_frame(now, &wire[..len]);

    assert!(!bystander.is_matched(), "it was not the station the vehicle chose");
    assert!(bystander.poll_transmit().is_none(), "and it must not answer");
}

#[test]
fn a_frame_from_another_protocol_is_ignored_not_an_error() {
    let mut station = evse(NEAR_MAC, 0x11);
    // An ordinary IPv4 frame sharing the medium.
    let mut frame = [0u8; 64];
    frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    station.handle_frame(Instant::ZERO, &frame);
    assert!(station.poll_event().is_none());
}

/// The frame that hands over the network key is unauthenticated and travels in
/// the clear. Its run id was broadcast in the clear too, so quoting it proves
/// nothing: anything on the powerline segment can forge a `CM_SLAC_MATCH.CNF`
/// and race the real station. A vehicle that took the first one to arrive would
/// join an attacker's logical network, which is exactly what the attenuation
/// measurement is there to prevent.
#[test]
fn the_vehicle_takes_the_key_only_from_the_station_it_chose() {
    use iso15118::slac::matching::MAX_FRAME_LEN;
    use iso15118::slac::{AttenCharInd, Mmtype, Mmv, SlacMatchCnf, SlacParmCnf, write_frame};

    let mut vehicle = ev();
    let mut now = Instant::ZERO;
    let mut payload = [0u8; MAX_FRAME_LEN];
    let mut wire = [0u8; MAX_FRAME_LEN];

    let deliver = |vehicle: &mut Ev,
                   now: Instant,
                   from: MacAddr,
                   mmtype: Mmtype,
                   n: usize,
                   payload: &[u8],
                   wire: &mut [u8]| {
        let len =
            write_frame(wire, EV_MAC, from, Mmv::Av1_1, mmtype, &payload[..n]).expect("frame");
        vehicle.handle_frame(now, &wire[..len]);
    };

    // The real station answers the broadcast.
    vehicle.start(now);
    while vehicle.poll_transmit().is_some() {}
    let cnf = SlacParmCnf {
        m_sound_target: [0xFF; 6],
        num_sounds: 10,
        timeout: 6,
        resp_type: 0x01,
        forwarding_sta: EV_MAC,
        run_id: RUN_ID,
    };
    let n = cnf.encode(&mut payload).unwrap();
    deliver(&mut vehicle, now, NEAR_MAC, Mmtype::SlacParmCnf, n, &payload, &mut wire);

    // Let the sounding burst run to completion.
    for _ in 0..64 {
        let Some(next) = vehicle.poll_timeout() else { break };
        now = next;
        vehicle.handle_timeout(now);
        while vehicle.poll_transmit().is_some() {}
        // Once the burst is over the vehicle waits for measurements; report one.
        if vehicle.stations().len() == 1 {
            let ind = AttenCharInd {
                source_address: EV_MAC,
                run_id: RUN_ID,
                source_id: station_id(b'V'),
                resp_id: station_id(0x11),
                num_sounds: 10,
                profile: flat(10),
            };
            let n = ind.encode(&mut payload).unwrap();
            deliver(&mut vehicle, now, NEAR_MAC, Mmtype::AttenCharInd, n, &payload, &mut wire);
        }
        // The vehicle has chosen once it has a match request queued.
        if vehicle.poll_timeout() == Some(now + Millis::from_millis(12_000)) {
            break;
        }
    }
    while vehicle.poll_transmit().is_some() {}
    while vehicle.poll_event().is_some() {}

    // An impostor answers with its own key, quoting the run id it overheard.
    let forged = SlacMatchCnf {
        pev_id: station_id(b'V'),
        pev_mac: EV_MAC,
        evse_id: station_id(0xEE),
        evse_mac: FAR_MAC,
        run_id: RUN_ID,
        nid: [0xEE; 7],
        nmk: [0xEE; 16],
    };
    let n = forged.encode(&mut payload).unwrap();
    deliver(&mut vehicle, now, FAR_MAC, Mmtype::SlacMatchCnf, n, &payload, &mut wire);
    assert!(!vehicle.is_matched(), "a key from a station this vehicle did not choose");

    // ...and the station it did choose is still able to finish the run.
    let genuine = SlacMatchCnf {
        pev_id: station_id(b'V'),
        pev_mac: EV_MAC,
        evse_id: station_id(0x11),
        evse_mac: NEAR_MAC,
        run_id: RUN_ID,
        nid: [0x11; 7],
        nmk: [0x11; 16],
    };
    let n = genuine.encode(&mut payload).unwrap();
    deliver(&mut vehicle, now, NEAR_MAC, Mmtype::SlacMatchCnf, n, &payload, &mut wire);
    assert!(vehicle.is_matched(), "the real station's key is still accepted");
    assert!(
        core::iter::from_fn(|| vehicle.poll_event())
            .any(|e| matches!(e, EvEvent::Matched { nmk, .. } if nmk == [0x11; 16])),
        "and it is the real key that comes out"
    );
}

/// Sounding packets are what the winning station is chosen by, and their count
/// is what closes the sounding window. A station that counted a bystander's
/// sounds would measure a burst that was not the vehicle's.
#[test]
fn a_station_counts_only_the_sounds_of_the_vehicle_that_opened_the_run() {
    use iso15118::slac::{Mmtype, Mmv, MnbcSoundInd, SlacParmReq, write_frame};

    let mut station = evse(NEAR_MAC, 0x11);
    station.observe(&flat(10));
    let now = Instant::ZERO;
    let mut payload = [0u8; 192];
    let mut wire = [0u8; 256];

    let n = SlacParmReq { run_id: RUN_ID }.encode(&mut payload).unwrap();
    let len =
        write_frame(&mut wire, NEAR_MAC, EV_MAC, Mmv::Av1_1, Mmtype::SlacParmReq, &payload[..n])
            .unwrap();
    station.handle_frame(now, &wire[..len]);
    while station.poll_transmit().is_some() {}
    while station.poll_event().is_some() {}

    // Ten sounds from an impostor, quoting the run id it overheard: enough to
    // close the window if they were counted.
    let sound = MnbcSoundInd {
        sender_id: station_id(b'X'),
        remaining_sound_count: 0,
        run_id: RUN_ID,
        random: [0x11; 16],
    };
    let n = sound.encode(&mut payload).unwrap();
    let len =
        write_frame(&mut wire, NEAR_MAC, FAR_MAC, Mmv::Av1_1, Mmtype::MnbcSoundInd, &payload[..n])
            .unwrap();
    for _ in 0..10 {
        station.handle_frame(now, &wire[..len]);
    }

    let events: Vec<EvseEvent> = core::iter::from_fn(|| station.poll_event()).collect();
    assert!(
        !events.iter().any(|e| matches!(e, EvseEvent::Measured { .. })),
        "a bystander's sounds must not close the vehicle's sounding window: {events:?}"
    );
    assert!(station.poll_transmit().is_none(), "and nothing must be reported for them");
}

/// A station that has handed over its key has formed a network. Reopening it
/// with a stray `CM_SLAC_PARM.REQ` would undo the measurement that justified
/// the handover; the application says when the station is free again.
#[test]
fn a_matched_station_is_not_reopened_by_a_stray_request() {
    use iso15118::slac::{Mmtype, Mmv, SlacParmReq, write_frame};

    let mut near = evse(NEAR_MAC, 0x11);
    near.observe(&flat(10));
    let mut medium = Medium { ev: ev(), stations: vec![near], now: Instant::ZERO };
    medium.run();
    assert!(medium.stations[0].is_matched());

    let mut payload = [0u8; 192];
    let mut wire = [0u8; 256];
    let n = SlacParmReq { run_id: [0x5A; 8] }.encode(&mut payload).unwrap();
    let len =
        write_frame(&mut wire, NEAR_MAC, FAR_MAC, Mmv::Av1_1, Mmtype::SlacParmReq, &payload[..n])
            .unwrap();
    medium.stations[0].handle_frame(medium.now, &wire[..len]);
    assert!(medium.stations[0].is_matched(), "still matched to the vehicle that won");

    medium.stations[0].reset();
    medium.stations[0].handle_frame(medium.now, &wire[..len]);
    assert!(!medium.stations[0].is_matched(), "...and available again once reset");
}

/// `CM_SLAC_PARM.REQ` is broadcast and unauthenticated, so anything on the
/// segment can send one. A run already under way belongs to the vehicle that
/// opened it: a bystander that could restart it could abort every matching run
/// within earshot, one frame at a time.
#[test]
fn a_run_in_progress_is_not_restarted_by_a_bystander() {
    use iso15118::slac::{Mmtype, Mmv, SlacParmReq, write_frame};

    let mut station = evse(NEAR_MAC, 0x11);
    station.observe(&flat(10));
    let now = Instant::ZERO;
    let mut payload = [0u8; 192];
    let mut wire = [0u8; 256];

    let mut parm = |from: MacAddr, run_id: [u8; 8], wire: &mut [u8]| {
        let n = SlacParmReq { run_id }.encode(&mut payload).unwrap();
        write_frame(wire, NEAR_MAC, from, Mmv::Av1_1, Mmtype::SlacParmReq, &payload[..n]).unwrap()
    };

    // The real vehicle opens a run.
    let len = parm(EV_MAC, RUN_ID, &mut wire);
    station.handle_frame(now, &wire[..len]);
    let started: Vec<EvseEvent> = core::iter::from_fn(|| station.poll_event()).collect();
    assert_eq!(started, vec![EvseEvent::RunStarted(RUN_ID)]);
    while station.poll_transmit().is_some() {}

    // A bystander tries to take the station over with a run of its own.
    let other = [0x5A; 8];
    let len = parm(FAR_MAC, other, &mut wire);
    station.handle_frame(now, &wire[..len]);
    assert!(
        core::iter::from_fn(|| station.poll_event()).next().is_none(),
        "the intruder's run must not open"
    );
    assert!(station.poll_transmit().is_none(), "and it must not be answered");

    // The real vehicle's own retry — same MAC, same run id — still gets through,
    // because that is what ISO 15118-3 has it do when the confirmation is lost.
    let len = parm(EV_MAC, RUN_ID, &mut wire);
    station.handle_frame(now, &wire[..len]);
    assert_eq!(
        core::iter::from_fn(|| station.poll_event()).collect::<Vec<_>>(),
        vec![EvseEvent::RunStarted(RUN_ID)],
        "a retry re-opens the same run"
    );
    assert!(station.poll_transmit().is_some(), "and is answered again");
}

/// A SLAC engine is a promiscuous listener on a shared medium: everything on
/// the segment arrives, and none of it is authenticated. A frame that does not
/// parse is ordinary weather, not an exception — reporting one would hand any
/// station within earshot a one-frame kill switch for somebody else's run.
#[test]
fn nothing_a_bystander_can_send_disturbs_a_run() {
    use iso15118::slac::{Mmtype, Mmv, SlacParmReq, write_frame};

    let mut station = evse(NEAR_MAC, 0x11);
    station.observe(&flat(10));
    let now = Instant::ZERO;
    let mut payload = [0u8; 192];
    let mut wire = [0u8; 256];

    // The real vehicle opens a run.
    let n = SlacParmReq { run_id: RUN_ID }.encode(&mut payload).unwrap();
    let len =
        write_frame(&mut wire, NEAR_MAC, EV_MAC, Mmv::Av1_1, Mmtype::SlacParmReq, &payload[..n])
            .unwrap();
    station.handle_frame(now, &wire[..len]);
    while station.poll_transmit().is_some() {}
    while station.poll_event().is_some() {}

    // Every way a frame can be wrong, all of them from a bystander. Each is
    // otherwise a well-formed `CM_SLAC_PARM.REQ`, so what is under test is the
    // one thing that differs.
    let bystander =
        write_frame(&mut wire, NEAR_MAC, FAR_MAC, Mmv::Av1_1, Mmtype::SlacParmReq, &payload[..n])
            .unwrap();
    let base = &wire[..bystander];

    let mut wrong_ether = [0u8; 256];
    wrong_ether[..bystander].copy_from_slice(base);
    wrong_ether[12..14].copy_from_slice(&0x0800u16.to_be_bytes()); // IPv4, not HomePlug

    let mut wrong_mmv = [0u8; 256];
    wrong_mmv[..bystander].copy_from_slice(base);
    wrong_mmv[14] = 0x7F; // a HomePlug version nobody defines

    let mut wrong_profile = [0u8; 256];
    wrong_profile[..bystander].copy_from_slice(base);
    wrong_profile[19] = 0xFF; // application_type outside PEV-EVSE

    let mut truncated = [0u8; 256];
    truncated[..bystander].copy_from_slice(base);

    for bad in [
        &wrong_ether[..bystander],
        &wrong_mmv[..bystander],
        &wrong_profile[..bystander],
        &truncated[..20], // framed, but the body stops mid-field
        &[0xABu8; 60][..],
        &[][..],
        &[0x00, 0x01, 0x02][..],
    ] {
        station.handle_frame(now, bad);
        assert!(
            core::iter::from_fn(|| station.poll_event()).next().is_none(),
            "a malformed bystander frame became an event"
        );
        assert!(station.poll_transmit().is_none(), "...or a frame on the wire");
    }

    // ...and a matching run still completes end to end afterwards.
    let mut medium = Medium { ev: ev(), stations: vec![evse(NEAR_MAC, 0x11)], now };
    medium.stations[0].observe(&flat(10));
    medium.run();
    assert!(medium.stations[0].is_matched());
}
