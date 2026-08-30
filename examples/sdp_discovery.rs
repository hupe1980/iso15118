//! Find a charging station on the link, over a real UDP socket.
//!
//! This is the smallest complete example of the sans-I/O shape: the engine
//! decides *what* to send and *when*, the twenty lines around it move bytes and
//! read the clock. Nothing in [`iso15118::sdp::Discovery`] knows what a socket
//! is, which is why the same code runs on `smoltcp` on an ECU.
//!
//! ```sh
//! cargo run --example sdp_discovery -- eth0
//! ```
//!
//! It will not find anything unless a charging station is actually on that
//! interface, which is the point: the give-up path is the one worth seeing.

use std::env;
use std::io;
use std::net::{Ipv6Addr, SocketAddrV6, UdpSocket};
use std::time::{Duration, Instant as StdInstant};

use iso15118::sdp::{Discovery, Event, MULTICAST_ADDR, Request};
use iso15118::session::Instant;
use iso15118::v2gtp::SDP_PORT;

fn main() -> io::Result<()> {
    // The scope id is the interface index: a link-local multicast has to say
    // which link, because `ff02::1` means something different on each.
    let scope_id: u32 = env::args()
        .nth(1)
        .and_then(|arg| arg.parse().ok().or_else(|| if_nametoindex(&arg)))
        .unwrap_or(0);

    let socket = UdpSocket::bind(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, scope_id))?;
    socket.set_read_timeout(Some(Duration::from_millis(50)))?;
    let group = SocketAddrV6::new(Ipv6Addr::from(MULTICAST_ADDR), SDP_PORT, 0, scope_id);

    // ISO 15118-20 mandates TLS; under -2 a vehicle doing Plug & Charge must
    // ask for it too. Asking for less and accepting less is the downgrade the
    // engine reports as `Refused`.
    let mut discovery = Discovery::new(Request::TLS);
    let started = StdInstant::now();
    let now = |started: &StdInstant| {
        // A monotonic millisecond count is all the crate wants; the origin is
        // arbitrary and only differences are ever read.
        Instant::from_millis(u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX))
    };

    discovery.start(now(&started));

    while !discovery.is_finished() {
        // 1. Whatever the engine wants on the wire, goes on the wire.
        if let Some(datagram) = discovery.poll_transmit() {
            socket.send_to(&datagram, group)?;
        }

        // 2. Whatever comes back, goes in. A datagram that is not a
        //    `SECCDiscoveryRes` is not fatal: the request went to a multicast
        //    group, so anything on the link may answer.
        let mut buf = [0u8; 64];
        match socket.recv_from(&mut buf) {
            Ok((n, from)) => {
                if let Err(e) = discovery.handle_datagram(now(&started), &buf[..n]) {
                    eprintln!("ignoring {n} bytes from {from}: {e}");
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) if e.kind() == io::ErrorKind::TimedOut => {}
            Err(e) => return Err(e),
        }

        // 3. The engine says when it next needs the clock; nothing polls.
        if let Some(deadline) = discovery.poll_timeout() {
            let elapsed = now(&started);
            if deadline <= elapsed {
                discovery.handle_timeout(elapsed);
            }
        }
    }

    match discovery.poll_event() {
        Some(Event::Found(res)) => {
            println!("charger at [{}]:{} ({:?})", res.ipv6(), res.port, res.security);
            println!("connect a TCP (or TLS) stream there and hand it to `Evcc`.");
        }
        Some(Event::Refused(res)) => {
            println!("[{}]:{} answered without TLS — refusing to charge", res.ipv6(), res.port);
        }
        Some(Event::GaveUp { attempts }) => {
            println!("no charger answered {attempts} requests on scope {scope_id}");
        }
        None | Some(_) => unreachable!("a finished discovery has exactly one outcome"),
    }
    Ok(())
}

/// Resolves an interface name to its index, so `eth0` works as well as `2`.
fn if_nametoindex(name: &str) -> Option<u32> {
    // Reading the index out of sysfs keeps this example free of `unsafe` and of
    // a `libc` dependency; on a non-Linux host, pass the number instead.
    std::fs::read_to_string(format!("/sys/class/net/{name}/ifindex")).ok()?.trim().parse().ok()
}
