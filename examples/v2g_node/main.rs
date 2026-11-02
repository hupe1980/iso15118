//! This crate's engines on a real link: SDP over UDP multicast, then a whole
//! session over TCP, as the vehicle or as the station.
//!
//! It is the node `tests/josev.rs` runs inside a Linux container, opposite a
//! peer implementation nobody here wrote, joined by a veth pair — SDP is
//! link-local multicast, and that is the only way to give it a real link. It
//! prints one JSON object as its last line, the row the test reports.
//!
//! ```sh
//! v2g_node evcc --iface v1 --generation iso2 --service dc
//! v2g_node secc --iface v0 --generation iso20 --service ac
//! v2g_node evcc --iface v1 --generation iso2 --service dc \
//!          --tls ca.pem --tls-name SECCCert --contract contract/
//! ```
//!
//! `--tls` asks SDP for TLS and reaches the station through `socat`, which
//! speaks ISO 15118-2's TLS 1.2 suite with OpenSSL — no TLS code is linked
//! into this binary. `--contract` pays by Plug & Charge with the directory's
//! `leaf.der`, `sub1.der` (the leaf's issuer), `sub2.der`, `key.hex` (the
//! P-256 scalar) and `emaid.txt`.
//!
//! Exit code: 0 the session closed normally after `SessionStop`, 1 it did not,
//! 2 usage. The process never outlives `--deadline-ms`.

mod drive;
mod net;
mod station;
mod vehicle;

use std::net::{Ipv6Addr, SocketAddrV6, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode};
use std::time::Duration;

use iso15118::evcc::EvccConfig;
use iso15118::iso2;
use iso15118::pnc::rustcrypto::{Sha2, SigningKey};
use iso15118::pnc::{self, GenChallenge, PncError};
use iso15118::sdp::{self, Discovery, Request, Response, TlsPolicy};
use iso15118::secc::SeccConfig;
use iso15118::session::{Security, SessionId};
use iso15118::{Iso20Set, Protocol, Protocols};

use drive::{Generation, Ran, Service};
use net::{Clock, Deadline};

struct Args {
    role: String,
    iface: String,
    generation: Generation,
    service: Service,
    deadline_ms: u64,
    tls: Option<PathBuf>,
    tls_name: String,
    contract: Option<PathBuf>,
}

fn parse() -> Result<Args, String> {
    let mut args = std::env::args().skip(1);
    let role = args.next().ok_or("expected evcc or secc")?;
    if role != "evcc" && role != "secc" {
        return Err(format!("unknown role {role}"));
    }
    let (mut iface, mut generation, mut service, mut deadline_ms) = (None, None, None, 60_000);
    let (mut tls, mut tls_name, mut contract) = (None, String::from("SECCCert"), None);
    while let Some(flag) = args.next() {
        let value = args.next().ok_or_else(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--iface" => iface = Some(value),
            "--generation" => generation = Some(value.parse()?),
            "--service" => service = Some(value.parse()?),
            "--deadline-ms" => deadline_ms = value.parse().map_err(|e| format!("{e}"))?,
            "--tls" => tls = Some(PathBuf::from(value)),
            "--tls-name" => tls_name = value,
            "--contract" => contract = Some(PathBuf::from(value)),
            other => return Err(format!("unknown flag {other}")),
        }
    }
    Ok(Args {
        role,
        iface: iface.ok_or("--iface is required")?,
        generation: generation.ok_or("--generation is required")?,
        service: service.ok_or("--service is required")?,
        deadline_ms,
        tls,
        tls_name,
        contract,
    })
}

fn main() -> ExitCode {
    let args = match parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!(
                "usage: v2g_node evcc|secc --iface <if> --generation iso2|iso20 --service ac|dc [--deadline-ms <n>]\n{e}"
            );
            return ExitCode::from(2);
        }
    };
    let clock = Clock::start();
    let deadline = Deadline::after(args.deadline_ms);
    let ran = if args.role == "evcc" { vehicle(&args, deadline) } else { station(&args, deadline) };

    let pass = ran.normal;
    let reason = (!pass).then(|| {
        ran.error.clone().or_else(|| ran.close.clone()).unwrap_or_else(|| "no close".into())
    });
    let row = serde_json::json!({
        "role": args.role,
        "generation": args.generation.as_str(),
        "service": args.service.as_str(),
        "auth": if args.contract.is_some() { "pnc" } else { "eim" },
        "tls": args.tls.is_some(),
        "outcome": if pass { "pass" } else { "fail" },
        "reason": reason,
        "messages": ran.messages,
        "elapsed_ms": clock.elapsed_ms(),
        "last_request": ran.last_request,
        "close": ran.close,
    });
    println!("{row}");
    if pass { ExitCode::SUCCESS } else { ExitCode::from(1) }
}

fn protocols(generation: Generation) -> Protocols {
    Protocols::only(match generation {
        Generation::Iso2 => Protocol::Iso2,
        Generation::Iso20 => Protocol::Iso20,
    })
}

fn sets(service: Service) -> Vec<Iso20Set> {
    vec![match service {
        Service::Dc => Iso20Set::Dc,
        Service::Ac => Iso20Set::Ac,
    }]
}

fn failed(error: String) -> Ran {
    eprintln!("  !! {error}");
    Ran { error: Some(error), ..Ran::default() }
}

/// SDP, then a session, as the vehicle.
fn vehicle(args: &Args, deadline: Deadline) -> Ran {
    let scope = match net::ifindex(&args.iface) {
        Ok(s) => s,
        Err(e) => return failed(format!("{}: {e}", args.iface)),
    };
    let request = if args.tls.is_some() { Request::TLS } else { Request::PLAIN };
    let found = match discover(scope, request, deadline) {
        Ok(r) => r,
        Err(e) => return failed(e),
    };
    eprintln!("  station at [{}%{}]:{}", found.ipv6(), args.iface, found.port);
    let mut proxy = None;
    let connected = match &args.tls {
        Some(ca) => tls_proxy(&found, &args.iface, ca, &args.tls_name).and_then(|(child, port)| {
            proxy = Some(child);
            connect(&SocketAddrV6::new(Ipv6Addr::LOCALHOST, port, 0, 0))
        }),
        None => connect(&SocketAddrV6::new(found.ipv6(), found.port, 0, scope)),
    };
    let mut stream = match connected {
        Ok(s) => s,
        Err(e) => return failed(e),
    };
    let config = EvccConfig {
        protocols: protocols(args.generation),
        iso20_sets: sets(args.service),
        security: if args.tls.is_some() { Security::Tls } else { Security::None },
        ..EvccConfig::default()
    };
    let mut script = vehicle::Vehicle::new(args.generation, args.service);
    if let Some(dir) = &args.contract {
        match load_contract(dir) {
            Ok(contract) => script = script.with_contract(contract),
            Err(e) => return failed(format!("contract {}: {e}", dir.display())),
        }
    }
    let ran = drive::evcc(&mut stream, config, &mut script, deadline);
    // Closing our side lets `socat` end the TLS session properly
    // (`close_notify`); it is killed only if it does not exit by itself.
    drop(stream);
    if let Some(mut child) = proxy {
        for _ in 0..30 {
            if child.try_wait().is_ok_and(|s| s.is_some()) {
                return ran;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = child.kill();
        let _ = child.wait();
    }
    ran
}

/// Connects, retrying briefly: a proxy just spawned may not be listening yet.
fn connect(to: &SocketAddrV6) -> Result<TcpStream, String> {
    let mut last = String::new();
    for _ in 0..30 {
        match TcpStream::connect_timeout(&(*to).into(), Duration::from_secs(5)) {
            Ok(s) => return Ok(s),
            Err(e) => last = e.to_string(),
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(format!("connect {to}: {last}"))
}

/// `socat` listening on loopback and speaking ISO 15118-2's TLS to the station:
/// TLS 1.2, `ECDHE-ECDSA-AES128-SHA256`, the chain checked against `ca`.
fn tls_proxy(
    station: &Response,
    iface: &str,
    ca: &Path,
    name: &str,
) -> Result<(Child, u16), String> {
    let port = TcpListener::bind((Ipv6Addr::LOCALHOST, 0))
        .and_then(|l| l.local_addr())
        .map_err(|e| format!("no local port: {e}"))?
        .port();
    let child = Command::new("socat")
        .arg(format!("TCP6-LISTEN:{port},bind=[::1],reuseaddr"))
        .arg(format!(
            "OPENSSL:[{}%{iface}]:{},cafile={},commonname={name},cipher=ECDHE-ECDSA-AES128-SHA256,\
             openssl-min-proto-version=TLS1.2,openssl-max-proto-version=TLS1.2",
            station.ipv6(),
            station.port,
            ca.display()
        ))
        .spawn()
        .map_err(|e| format!("socat: {e}"))?;
    Ok((child, port))
}

/// A contract directory: `leaf.der`, `sub1.der`, `sub2.der`, `key.hex`, `emaid.txt`.
fn load_contract(dir: &Path) -> Result<vehicle::Contract, String> {
    let read = |name: &str| std::fs::read(dir.join(name)).map_err(|e| format!("{name}: {e}"));
    let text = |name: &str| {
        std::fs::read_to_string(dir.join(name))
            .map(|s| s.trim().to_owned())
            .map_err(|e| format!("{name}: {e}"))
    };
    let hex = text("key.hex")?;
    let scalar = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(hex.get(i..i + 2).unwrap_or(""), 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|e| format!("key.hex: {e}"))?;
    let key = SigningKey::p256(&scalar).map_err(|e| format!("key.hex: {e}"))?;
    let sub_certificates = ["sub1.der", "sub2.der"]
        .iter()
        .filter(|name| dir.join(name).exists())
        .map(|name| read(name))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(vehicle::Contract {
        emaid: text("emaid.txt")?,
        leaf: read("leaf.der")?,
        sub_certificates,
        key: Box::new(RustCryptoKey(key)),
    })
}

/// The contract key, with `pnc-rustcrypto`'s P-256 and SHA-256.
struct RustCryptoKey(SigningKey);

impl vehicle::ContractKey for RustCryptoKey {
    fn sign_authorization(
        &self,
        request: &mut iso2::AuthorizationReq,
        challenge: &GenChallenge,
    ) -> Result<iso2::Signature, PncError> {
        pnc::iso2::sign_authorization(request, challenge, &Sha2, &self.0)
    }

    fn sign_receipt(
        &self,
        receipt: &mut iso2::MeteringReceiptReq,
    ) -> Result<iso2::Signature, PncError> {
        pnc::iso2::sign_metering_receipt(receipt, &Sha2, &self.0)
    }
}

fn discover(scope: u32, request: Request, deadline: Deadline) -> Result<Response, String> {
    let socket = std::net::UdpSocket::bind(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, scope))
        .map_err(|e| format!("bind: {e}"))?;
    socket.set_read_timeout(Some(Duration::from_millis(50))).map_err(|e| e.to_string())?;
    let group =
        SocketAddrV6::new(Ipv6Addr::from(sdp::MULTICAST_ADDR), iso15118::v2gtp::SDP_PORT, 0, scope);
    let clock = Clock::start();
    // Enough attempts to outlast a station still starting; the deadline bounds it.
    let mut discovery = Discovery::new(request).with_max_attempts(400);
    discovery.start(clock.now());
    let mut buf = [0u8; 64];
    loop {
        if deadline.passed() {
            return Err("deadline passed during SDP".into());
        }
        if let Some(datagram) = discovery.poll_transmit() {
            socket.send_to(&datagram, group).map_err(|e| format!("send SDP: {e}"))?;
        }
        if let Ok((n, _)) = socket.recv_from(&mut buf) {
            let _ = discovery.handle_datagram(clock.now(), &buf[..n]);
        }
        if discovery.poll_timeout().is_some_and(|t| t <= clock.now()) {
            discovery.handle_timeout(clock.now());
        }
        match discovery.poll_event() {
            Some(sdp::Event::Found(r)) => return Ok(r),
            Some(sdp::Event::GaveUp { attempts }) => {
                return Err(format!("no SDP answer after {attempts} attempts"));
            }
            Some(other) => eprintln!("  sdp: {other:?}"),
            None => {}
        }
    }
}

/// An SDP responder and one session, as the station.
fn station(args: &Args, deadline: Deadline) -> Ran {
    let (scope, address) =
        match net::ifindex(&args.iface).and_then(|s| Ok((s, net::link_local(&args.iface)?))) {
            Ok(v) => v,
            Err(e) => return failed(format!("{}: {e}", args.iface)),
        };
    // A station's TCP port is a dynamic port, 49152–65535, and a vehicle may
    // refuse an SDP answer naming any other — Josev does. The operating
    // system's ephemeral range starts lower on Linux, so the port is chosen
    // here rather than left to `bind(0)`.
    let Some(listener) = (49_152..=65_535)
        .find_map(|port| TcpListener::bind(SocketAddrV6::new(address, port, 0, scope)).ok())
    else {
        return failed(format!("no dynamic port free on {address}%{scope}"));
    };
    let port = listener.local_addr().map_or(0, |a| a.port());
    let sdp = match net::sdp_server_socket(scope) {
        Ok(s) => s,
        Err(e) => return failed(format!("SDP socket: {e}")),
    };
    let _ = listener.set_nonblocking(true);
    eprintln!("  listening on [{address}%{scope}]:{port}");

    // Answer SDP until the vehicle connects.
    let mut buf = [0u8; 64];
    let mut stream = loop {
        if deadline.passed() {
            return failed("no vehicle connected before the deadline".into());
        }
        if let Ok((n, from)) = sdp.recv_from(&mut buf)
            && let Ok(request) = Request::from_frame(&buf[..n])
        {
            let answer =
                Response::answering(request, address.octets(), port, TlsPolicy::Unsupported);
            let mut frame = [0u8; 28];
            if let Ok(len) = answer.write_frame(&mut frame, false) {
                let _ = sdp.send_to(&frame[..len], from);
                eprintln!("  sdp: answered {from}");
            }
        }
        match listener.accept() {
            Ok((s, from)) => {
                eprintln!("  vehicle at {from}");
                let _ = s.set_nonblocking(false);
                break s;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => return failed(format!("accept: {e}")),
        }
    };

    let config = SeccConfig {
        protocols: protocols(args.generation),
        session_id: session_id(),
        iso20_sets: vec![Iso20Set::Dc, Iso20Set::Ac],
        ..SeccConfig::default()
    };
    drive::secc(&mut stream, config, &mut station::Station, deadline)
}

/// Not random, and need not be on a veth pair; a real station draws these
/// bytes from an RNG.
fn session_id() -> SessionId {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(1, |d| d.subsec_nanos() ^ u32::try_from(d.as_secs() & 0xFFFF_FFFF).unwrap_or(0));
    let mut bytes = (u64::from(nanos) << 32 | 1).to_be_bytes();
    bytes[0] |= 0x80;
    SessionId::new(bytes)
}
