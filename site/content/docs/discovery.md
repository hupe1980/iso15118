+++
title = "Discovery and framing"
description = "V2GTP framing and the SECC Discovery Protocol in iso15118: bounded framing of an attacker-controlled length, ignored versus fatal frames, and an SDP engine that refuses a downgrade without stopping the run."
weight = 50

[extra]
nav_title = "Discovery & framing"
+++

Between the IP link coming up and the first EXI message sit two small non-EXI
pieces: the frame header around everything, and the exchange that tells the
vehicle which port to connect to.

## V2GTP framing

```text
0        1        2        3        4        5        6        7        8
+--------+--------+--------+--------+--------+--------+--------+--------+
|  0x01  |  0xFE  |   payload type  |            payload length         |
+--------+--------+--------+--------+--------+--------+--------+--------+
 version  ~version     big-endian              big-endian, in bytes
```

The payload length is unauthenticated, so `Header::decode` never allocates on it:
it returns the declared length and the caller checks it against its own limit.

| Code | Payload |
|---|---|
| `0x8001` | `supportedAppProtocol`, DIN/TS 70121, or ISO 15118-2 — session state decides which |
| `0x8002` | ISO 15118-20 `CommonMessages` |
| `0x8003` – `0x8006` | ISO 15118-20 AC, DC, ACDP, WPT |
| `0x8010` / `0x8011` | ISO 15118-20 Amd 1 `AC_DER_IEC` / `AC_DER_SAE` (the values EVerest uses; Amd 1's table is not public) |
| `0x9000` / `0x9001` | SDP request / response |
| `0x9002` / `0x9003` | SDP request / response over a wireless link |
| `0xA000` – `0xFFFF` | Manufacturer-specific |

Everything else is reserved.

### Ignored, fatal, or reported

| Frame | Outcome |
|---|---|
| Bad sync pattern, or a length over the limit | **Fatal**: no frame boundary left to trust. |
| Manufacturer-specific or reserved payload type | **Ignored** \[V2G2-800\], counted in `ignored_frames()`. |
| A payload type of a generation this session did not negotiate | **Ignored**: a `0x8002` cannot reach a -2 session, nor end it. |
| This session's payload type with no message set compiled in | `MessageError::NoCodec`; `Connection::next_frame` lets a caller supply the codec. |

### Stream reassembly

`session::Connection` turns a TCP byte stream into whole frames and back, with two
bounds:

- **`max_payload_len`** bounds one frame. Set it to what the target can hold — an
  ECU with 64 KiB of RAM, not the 1 MiB server default.
- **`max_pending_frames`** bounds whole frames a peer pushes ahead of the reader.
  V2G is half-duplex, so a pipelining peer is already outside the protocol.

## SECC Discovery Protocol

The vehicle multicasts a two-byte request to `ff02::1` port 15118 naming the
security and transport it wants; the station answers with an address and a port.

### The vehicle checks the answer

`Response::satisfies` makes the check explicit: more security than requested is
allowed (the vehicle then uses TLS); **less** is refused. Less is not by itself an
attack — \[V2G2-627\] obliges a station without TLS to answer in plain — so it is
the decision \[V2G2-628\] puts to the vehicle: ISO 15118-20 mandates TLS, a -2
Plug & Charge vehicle must stop, and an external-identification vehicle may start
a new run with `Request::PLAIN`.

```rust
use iso15118::sdp::{Discovery, Event, Refusal, Request};
use iso15118::session::Instant;

let mut d = Discovery::new(Request::TLS);
d.start(Instant::ZERO);

// ...feed datagrams with `handle_datagram`, polling events each time round:
match d.poll_event() {
    Some(Event::Found(res)) => { /* connect to res.ipv6():res.port */ }
    Some(Event::Refused { response, reason }) => { /* logged; the run continues */ }
    Some(Event::GaveUp { attempts }) => { /* nothing usable answered */ }
    None => {}
}
```

| `Refusal` | The answer offered |
|---|---|
| `SecurityDowngrade` | less transport security than requested |
| `TransportMismatch` | a different transport protocol |
| `OffLink` | an address outside `fe80::/10` — no station on the charging cable has one; `allow_off_link(true)` for a test rig |

The codec itself refuses `::`, multicast addresses and port `0`.

### The station's answer is a table

| The vehicle asked for | `Unsupported` | `Supported` | `Required` |
|---|---|---|---|
| TLS | plaintext \[V2G2-627\] | TLS \[V2G2-626\] | TLS |
| plaintext | plaintext | plaintext | TLS |

```rust
use iso15118::sdp::{Request, Response, TlsPolicy};

# let my_address = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
# let request = Request::TLS;
// Whatever the vehicle asked for, this is the answer the standard obliges.
let answer = Response::answering(request, my_address, 15118, TlsPolicy::Required);
let mut frame = [0u8; 64];
let n = answer.write_frame(&mut frame, false)?;
# Ok::<_, iso15118::sdp::SdpError>(())
```

The transport is echoed \[V2G2-625\]. A station answers every request \[V2G2-144\]
from the port it arrived on \[V2G2-151\], statelessly, so there is no station-side
engine.

### The retry engine

`sdp::Discovery` is ISO 15118-2's retry policy — how often to repeat the
unacknowledged multicast and when to give up — as a sans-I/O state machine. Only a
*usable* answer ends the run: a malformed datagram is an error, a refused one an
event, and both leave the deadline and the attempt counter untouched. One spoofed
datagram cannot stop the vehicle hearing its station.

### Two usable answers

A well-formed, link-local answer offering the requested security cannot be told
from the real station's, and the first to arrive wins
([arXiv 2404.06635](https://arxiv.org/abs/2404.06635);
[arXiv 2601.15515](https://arxiv.org/abs/2601.15515)). The engine keeps listening
after the run and reports a second usable answer naming another endpoint:

```rust,ignore
Some(Event::Conflict { accepted, other }) => {
    // `accepted` is what Event::Found already reported, and what your TCP
    // connection is open to.
}
```

It reports rather than acts: a spoofer and a misconfigured second station look the
same, and the decision is the caller's.
