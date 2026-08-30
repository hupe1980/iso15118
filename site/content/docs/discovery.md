+++
title = "Discovery and framing"
description = "V2GTP framing and the SECC Discovery Protocol in iso15118: the first hostile number a charging station reads, and the TLS downgrade a vehicle must refuse."
weight = 50

[extra]
nav_title = "Discovery & framing"
+++

Between the IP link coming up and the first EXI message there are two small,
entirely non-EXI pieces: the frame header that wraps everything, and the exchange
that tells the vehicle which port to connect to.

## V2GTP framing

Every byte that crosses the charging cable above TCP or UDP is wrapped in the same
eight-byte header:

```text
0        1        2        3        4        5        6        7        8
+--------+--------+--------+--------+--------+--------+--------+--------+
|  0x01  |  0xFE  |   payload type  |            payload length         |
+--------+--------+--------+--------+--------+--------+--------+--------+
 version  ~version     big-endian              big-endian, in bytes
```

The payload length arrives before, and is not covered by, any authentication. It
is the first hostile number a charging station reads, so `Header::decode` never
allocates on the strength of it: it returns the declared length, and the caller
compares it against its own limit and decides.

The payload type is what says which schema set the bytes belong to — with one
important exception. `0x8001` means the `supportedAppProtocol` handshake before
negotiation, a DIN SPEC 70121 message if DIN won, and an ISO 15118-2 message if
-2 won. Nothing in the frame distinguishes them, which is one of the reasons the
handshake has to be tracked rather than sniffed.

| Code | Payload |
|---|---|
| `0x8001` | `supportedAppProtocol`, DIN SPEC 70121, or ISO 15118-2 |
| `0x8002` | ISO 15118-20 `CommonMessages` |
| `0x8003` – `0x8006` | ISO 15118-20 AC, DC, ACDP, WPT |
| `0x9000` / `0x9001` | SDP request / response |
| `0x9002` / `0x9003` | SDP request / response over a wireless link |
| `0xA000` – `0xFFFF` | Manufacturer-specific |

Everything else is a reserved range and is rejected.

### Stream reassembly

Above the header sits `session::Connection`, which does one job and only that job:
turn a TCP byte stream into whole frames and back. Frames arrive split across
reads and coalesced with their neighbours, and the length field that says where
one ends is attacker-controlled.

Two bounds, answering two different questions:

- **`max_payload_len`** bounds one frame. An embedded vehicle controller with
  64 KiB of RAM should set this to what it can actually hold, not to the crate
  default — the limit is what stops a peer from making the receiver buffer more
  than it has.
- **A cap on undrained frames** bounds how many whole frames a peer may push ahead
  of the reader. V2G is half-duplex, so a peer that pipelines is already outside
  the protocol; without this second bound, bounding only the byte buffer would
  move the problem rather than solve it.

A framing error is fatal to the connection rather than something to resynchronise
from — there is no frame delimiter to scan for, so nothing after a malformed
header can be trusted.

## SECC Discovery Protocol

Once the data link is up, the vehicle still has to find the charger's TCP
endpoint. It multicasts a two-byte request to `ff02::1` port 15118 saying which
security and transport it wants; the charger answers with an address and a port.

Both datagrams are fixed-layout payloads inside a V2GTP frame, so this is pure
byte shuffling — no EXI involved.

### The negotiation is a request, not a command

A charger that requires TLS answers a `NoTransportSecurity` request **with a TLS
response**, and it is the vehicle's job to notice. `Response::satisfies` makes
that check explicit rather than leaving it to be forgotten:

- more security than was asked for is allowed, and the vehicle must then use TLS;
- **less** is a downgrade, and is refused.

ISO 15118-20 mandates TLS outright. Under -2, a vehicle doing Plug & Charge must
refuse a downgrade; one doing external identification may choose not to. The
crate surfaces the two outcomes as different events so the decision cannot be
made by accident:

```rust
use iso15118::sdp::{Discovery, Event, Request};
use iso15118::session::Instant;

let mut d = Discovery::new(Request::TLS);
d.start(Instant::ZERO);

// ...feed datagrams with `handle_datagram`, then:
match d.poll_event() {
    Some(Event::Found(res)) => { /* connect to res.ipv6():res.port */ }
    Some(Event::Refused(_)) => { /* the charger offered less security */ }
    Some(Event::GaveUp { attempts }) => { /* nothing answered */ }
    None => {}
}
```

### The retry engine

The codec is the easy half. The part that is actually specified, and that every
implementation has to get right the same way, is the retry policy: the request is
an unacknowledged UDP multicast, and ISO 15118-2 bounds both how often it may be
repeated and how many times before the vehicle gives up.

Those two numbers are the difference between a vehicle that finds a charger
through one dropped packet and a vehicle that floods the link. `sdp::Discovery` is
that policy as a sans-I/O state machine — the same shape as every other engine
here, so you own the socket and the clock.

A datagram that is not a well-formed response is an error but **not** the end of
discovery: the request went to a multicast group, so anything on the link can
answer, and one bad answer must not stop the vehicle waiting for a good one.
