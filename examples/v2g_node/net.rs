//! The I/O the crate leaves to its caller: an interface, its link-local
//! address, SDP over UDP multicast, TCP, and a clock.
//!
//! Linux only where it reads `/sys` and `/proc` — the peers run in Linux
//! containers, joined by a veth pair, because SDP is link-local multicast and
//! does not cross a Docker Desktop VM.

use std::fs;
use std::io;
use std::net::{Ipv6Addr, SocketAddrV6, UdpSocket};
use std::time::{Duration, Instant as StdInstant};

use iso15118::session::Instant;

/// The index of an interface, which is the scope id of every link-local
/// address on it.
///
/// # Errors
///
/// When the interface does not exist.
pub(crate) fn ifindex(name: &str) -> io::Result<u32> {
    let raw = fs::read_to_string(format!("/sys/class/net/{name}/ifindex"))?;
    raw.trim().parse().map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// The `fe80::/10` address of an interface, read from `/proc/net/if_inet6`.
///
/// # Errors
///
/// When the interface has none — IPv6 disabled, or the link not up yet.
pub(crate) fn link_local(name: &str) -> io::Result<Ipv6Addr> {
    let table = fs::read_to_string("/proc/net/if_inet6")?;
    for line in table.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() == 6 && fields[5] == name && fields[0].starts_with("fe8") {
            let bits = u128::from_str_radix(fields[0], 16)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            return Ok(Ipv6Addr::from(bits));
        }
    }
    Err(io::Error::new(io::ErrorKind::NotFound, format!("no link-local address on {name}")))
}

/// A UDP socket on the SDP port, joined to `ff02::1` on one interface.
///
/// # Errors
///
/// When the bind or the join fails.
pub(crate) fn sdp_server_socket(scope: u32) -> io::Result<UdpSocket> {
    let socket =
        UdpSocket::bind(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, iso15118::v2gtp::SDP_PORT, 0, 0))?;
    socket.join_multicast_v6(&Ipv6Addr::from(iso15118::sdp::MULTICAST_ADDR), scope)?;
    socket.set_read_timeout(Some(Duration::from_millis(50)))?;
    Ok(socket)
}

/// Monotonic milliseconds since the harness started, which is all the
/// engines want from a clock.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Clock(StdInstant);

impl Clock {
    #[must_use]
    pub(crate) fn start() -> Self {
        Self(StdInstant::now())
    }

    #[must_use]
    pub(crate) fn now(&self) -> Instant {
        Instant::from_millis(u64::try_from(self.0.elapsed().as_millis()).unwrap_or(u64::MAX))
    }

    #[must_use]
    pub(crate) fn elapsed_ms(&self) -> u64 {
        u64::try_from(self.0.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

/// The hard bound on one session: a peer that hangs fails its row.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Deadline(StdInstant);

impl Deadline {
    #[must_use]
    pub(crate) fn after(ms: u64) -> Self {
        Self(StdInstant::now() + Duration::from_millis(ms))
    }

    #[must_use]
    pub(crate) fn passed(&self) -> bool {
        StdInstant::now() >= self.0
    }
}
