//! The live-peer node's scripted vehicle and station, against each other over
//! a real TCP socket on `::1`.
//!
//! Not interoperability — both ends are this crate — but the precondition for
//! reading a live-peer row: a row that fails against Josev has to be the
//! peer's disagreement or ours, never a script that cannot finish a session
//! with anybody. So every (generation, service) the node plays completes here
//! first, on every `cargo test`, with no Docker and no SDP.

#![cfg(all(
    feature = "std",
    feature = "iso2",
    feature = "iso20-ac",
    feature = "iso20-dc",
    feature = "sdp",
    feature = "evcc",
    feature = "secc",
    feature = "pnc"
))]
#![allow(dead_code, unreachable_pub, reason = "the node's modules, compiled into a test")]

#[path = "../examples/v2g_node/drive.rs"]
mod drive;
#[path = "../examples/v2g_node/net.rs"]
mod net;
#[path = "../examples/v2g_node/station.rs"]
mod station;
#[path = "../examples/v2g_node/vehicle.rs"]
mod vehicle;

use std::net::{Ipv6Addr, SocketAddrV6, TcpListener, TcpStream};
use std::thread;

use iso15118::evcc::EvccConfig;
use iso15118::secc::SeccConfig;
use iso15118::session::SessionId;
use iso15118::{Iso20Set, Protocol, Protocols};

use drive::{Generation, Service};
use net::Deadline;

fn session(generation: Generation, service: Service) {
    let protocol = match generation {
        Generation::Iso2 => Protocol::Iso2,
        Generation::Iso20 => Protocol::Iso20,
    };
    let set = match service {
        Service::Dc => Iso20Set::Dc,
        Service::Ac => Iso20Set::Ac,
    };
    let listener = TcpListener::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0)).unwrap();
    let addr = listener.local_addr().unwrap();

    let station = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let config = SeccConfig {
            protocols: Protocols::only(protocol),
            session_id: SessionId::new([0x8A, 1, 2, 3, 4, 5, 6, 7]),
            iso20_sets: vec![Iso20Set::Dc, Iso20Set::Ac],
            ..SeccConfig::default()
        };
        drive::secc(&mut stream, config, &mut station::Station, Deadline::after(30_000))
    });

    let mut stream = TcpStream::connect(addr).unwrap();
    let config = EvccConfig {
        protocols: Protocols::only(protocol),
        iso20_sets: vec![set],
        ..EvccConfig::default()
    };
    let mut script = vehicle::Vehicle::new(generation, service);
    let ours = drive::evcc(&mut stream, config, &mut script, Deadline::after(30_000));
    drop(stream);
    let theirs = station.join().unwrap();

    assert!(ours.normal, "{generation:?} {service:?} vehicle: {ours:?}");
    assert!(theirs.normal, "{generation:?} {service:?} station: {theirs:?}");
    assert_eq!(ours.last_request.as_deref().map(|r| r.ends_with("SessionStopReq")), Some(true));
}

#[test]
fn an_iso2_dc_session_completes_between_the_scripts() {
    session(Generation::Iso2, Service::Dc);
}

#[test]
fn an_iso2_ac_session_completes_between_the_scripts() {
    session(Generation::Iso2, Service::Ac);
}

#[test]
fn an_iso20_dc_session_completes_between_the_scripts() {
    session(Generation::Iso20, Service::Dc);
}

#[test]
fn an_iso20_ac_session_completes_between_the_scripts() {
    session(Generation::Iso20, Service::Ac);
}
