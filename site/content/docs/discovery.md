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

Everything else is a reserved range.

### An unsupported payload type is *ignored*, not fatal

\[V2G2-800\] is explicit: if the V2GTP header contains wrong data — "not
supported payload type, wrong payload length, or not supported V2GTP version" —
the entity **shall ignore this message**. Not refuse it, not drop the connection.

That is only possible because the three cases are not alike. A bad synchronisation
pattern or an over-long declared length leaves you not knowing where the next
frame starts, so there is nothing to resynchronise to and the connection is over.
But an unsupported *payload type* arrives in a header that is otherwise intact:
the sync pattern matched, the length field is where it belongs, and the next frame
begins exactly where the peer said it would. The frame is skippable, so it is
skipped.

`Connection::next_message` therefore steps over three things a conforming peer
may legitimately send, counting them in `ignored_frames()`:

- a **manufacturer-specific** frame (`0xA000` – `0xFFFF`, which Table 10 reserves
  for exactly that purpose);
- a **reserved** code, which is not legitimate but is still well-framed;
- a payload type belonging to a **generation this session did not negotiate** — a
  `0x8002` in an ISO 15118-2 session.

Ignoring costs nothing in security: a peer still cannot get an ISO 15118-20
message processed in a session that agreed to -2. What it cannot do either is
end the session by trying — and a station that dropped a charge because a vehicle
sent one vendor extension frame would be a station nobody could extend.

**One case is deliberately not ignored:** a payload type that *does* belong to
this session and has no message set compiled in — `0x8001` under DIN SPEC 70121,
or a -20 schema set behind a feature that is off. That message is part of this
session, so silently dropping it would look like a peer that had gone quiet.
`MessageError::NoCodec` says so, and `Connection::next_frame` is where a caller
supplies the codec.

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

A framing error — a bad synchronisation pattern, or a declared length past the
limit — is fatal to the connection rather than something to resynchronise from:
there is no frame delimiter to scan for, so nothing after a malformed header can
be trusted. An unsupported payload type is not a framing error, for the reason
above.

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
- **less** is refused.

The second is worth being precise about, because the obvious reading is wrong.
Less security is **not**, by itself, an attack: \[V2G2-627\] *obliges* a station
that does not support TLS to answer a TLS request with "No transport layer
security". A conforming station downgrades. What `satisfies` returns is therefore
not "somebody is attacking you" but the question \[V2G2-628\] puts to the
vehicle — use what was offered, or stop — and the answer depends on the vehicle:
ISO 15118-20 mandates TLS outright, a -2 vehicle doing Plug & Charge must stop,
and one doing external identification may choose to carry on by starting a new
run with `Request::PLAIN`.

Which is exactly why it is a check rather than a silent acceptance. The failure
it prevents is a vehicle that asked for TLS, was answered plaintext, and never
noticed — and on an unauthenticated multicast segment that answer may equally
have come from something that is not a charger at all.

The crate surfaces the two outcomes as different events so the decision cannot be
made by accident:

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

### The station's side is a table, not a decision

A station has nothing to decide here beyond its own TLS policy — ISO 15118-2
determines the rest in three requirements — so `Response::answering` is that
table rather than three paragraphs each station re-derives:

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

The transport is echoed \[V2G2-625\]. `TlsPolicy::Required` is the one row the
-2 text does not spell out and it is not an invention either: -20 mandates TLS
and -2 requires it for Plug & Charge, so a station in either position has nothing
to offer a plaintext request *but* an upgrade — and upgrading is the one
direction a vehicle will act on.

There is no station-side discovery *engine*, and there does not need to be: a
station answers every request it receives \[V2G2-144\], from the port it arrived
on \[V2G2-151\], with no state between them. The retry policy — the part that
is a state machine — is entirely the vehicle's.

### Three ways an answer can be unusable

`Refusal` names which, because the three call for different things:

| Reason | What happened |
|---|---|
| `SecurityDowngrade` | Less transport security than the request asked for. |
| `TransportMismatch` | A different transport protocol than the request asked for. |
| `OffLink` | An address that is not link-local. |

`OffLink` is the one that needs a word. ISO 15118 runs over an IPv6 link-local
segment brought up by SLAAC on the charging cable, with no router on it, so a
station's own address is in `fe80::/10`. An answer naming anything else names
somewhere this vehicle has no protocol reason to connect to — and SDP is an
unauthenticated multicast, so *anything on the segment can send one*. Refused by
default; a test rig on an ordinary LAN says `allow_off_link(true)`, deliberately
and visibly.

Two addresses never get that far: the codec refuses the unspecified address (`::`)
and any multicast group outright, for the same reason it refuses port `0` — those
are not endpoints, and no caller could act on one.

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

**Neither is a well-formed answer the vehicle must not act on.** Only a *usable*
answer ends the run. This is the whole of the difference between reporting a bad
answer and obeying one: if the first answer to arrive were the last, a single
spoofed datagram — a TLS downgrade, or an address pointing off the link — would
stop the vehicle from ever hearing the station it is plugged into. One packet,
and the charge does not happen.

So a refusal leaves the deadline armed and the attempt counter untouched, exactly
as if the datagram had never arrived, and the caller polls for events *inside*
its loop rather than only after it. The engine holds two unread events — the
run's outcome, and the latest refusal or conflict — so a flood costs nothing and
neither half is lost to the other.

### The answer that cannot be refused

Every refusal above is a *judgement* about one datagram: this one offers less
security than I asked for, this one points off the link. The attack that works
makes no such datagram.

A well-formed answer, from a link-local address, offering exactly the security
requested, is **indistinguishable** from the real station's. Whichever arrives
first wins, and an attacker on the segment needs no forged measurement and no
key — only to be quicker (Löw et al.,
[arXiv 2512.15966](https://arxiv.org/abs/2512.15966) §3.2).

One datagram cannot be checked; two can be checked against each other. So the
engine keeps listening after the run has finished — which costs nothing, since
the caller is feeding datagrams either way — and reports a second usable answer
that names somewhere else:

```rust,ignore
Some(Event::Conflict { accepted, other }) => {
    // `accepted` is what Event::Found already reported, and what your TCP
    // connection is open to.
}
```

It stops there rather than tearing the session down: the crate cannot tell a
spoofer from a second station somebody misconfigured, and a refused charge costs
a real driver. Protocol, not policy — the evidence is yours, and so is the
decision.
