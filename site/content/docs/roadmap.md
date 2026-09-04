+++
title = "What is not here"
description = "The honest edges of the iso15118 crate: certificate revocation, transport bindings, DIN SPEC 70121, conformance testing — named rather than implied."
weight = 120

[extra]
nav_title = "What is not here"
+++

A library that is vague about its edges is one you find the edges of in the field.
These are named rather than implied.

## Certificate revocation

**The remaining gap in the PKI, and the one worth naming loudest.**

`pnc::pki` validates a chain: every signature, every validity window,
`BasicConstraints`, `pathLenConstraint`, `keyCertSign`, the depth limit
\[V2G2-009\], and the Annex F profile of whichever leaf you say it is. What it
does **not** do is check whether a certificate was withdrawn this morning. There
is no OCSP and no CRL.

That is a limitation to plan around, and the standard is unusually candid about
why it is hard rather than merely undone. Annex F's own note: "as access to OCSP
services can not be guaranteed during charging, the usage of OCSP can only be
recommended but not be mandatory" — and \[V2G2-868\] removes it from private
environments entirely. A vehicle in a basement has no path to a responder.

Which is where the answer belongs, and it is not in a protocol crate. A station's
back end is already asking a clearing house whether to authorize this contract at
all; `Validated::subject_common_name` is the `EMAID` to ask about, and that answer
covers revocation along with everything else the operator knows. An OCSP client
inside a sans-I/O crate would put a network round trip inside a charge loop with
a 25 ms budget.

## A chain from a published test pool

The certificates `pnc::pki` is tested against are minted by **OpenSSL**, and the
envelope `pnc::envelope` opens is sealed by OpenSSL too. That is differential
evidence — a third implementation's bytes, from the requirement text — and it is
not interoperability. Hubject's and OPNC's test pools need registration, and a
chain from one of those is worth more than any number of further self-built
cases.

## Anything that would defeat a relay

ISO 15118's Plug & Charge authenticates the contract, not the cable. What the
vehicle signs is the station's random challenge and nothing else — no timestamp,
no station identity.

The challenge is worth exactly what it is worth, and the two should not be
confused. Checking it — which this crate
[does](@/docs/plug-and-charge.md), in the same call as the signature — defeats
**replay**: a signature captured from one session does not authorize another,
because the nonce inside it is somebody else's. It does nothing about **relay**,
where an attacker forwards a *live* exchange between a victim's vehicle and a
distant charger. The challenge that comes back is genuinely this session's; it
just travelled further than anyone thinks. The victim gets the bill
([arXiv 2512.15966](https://arxiv.org/abs/2512.15966) — Löw, Vasu, Hutzelmann and
Hof, *Charge It to My Neighbor*, with a working proof of concept).

That is a gap in the standard, not in an implementation. The paper's
countermeasures are a *protocol change* (bind the `EVSEID` into the signed data),
mandatory OCSP, or distance bounding, and none of them is something this crate can
add unilaterally without talking to something that would not understand it.

Correct verification here means "this contract made this signature, for this
session" — not "the car is plugged in here", and not "this station is the one it
is plugged into".

## Transport bindings

No TCP, no TLS, no raw-socket code, by design. There is no `tokio` and no `rustls`
in the dependency tree and there will not be.

Bringing your own is what lets `rustls` run on a server and `embedded-tls` on a
vehicle controller without this crate choosing for either. The examples show the
twenty lines of glue for each. The protocol requirements are still enforced where
they *are* protocol: `Protocol::Iso20::requires_tls()` is `true`, and SDP refuses a
security downgrade.

## DIN SPEC 70121

**Recognised in the handshake, so a charger can decline it explicitly rather than
by silence. Its message set is not implemented, and will not be transcribed by
hand.**

DIN SPEC 70121:2014-12 — since superseded by DIN/TS 70121:2024-11 — is a
pre-standard whose XSDs are behind a paywall. Hand-transcribing them would
produce a codec with no reference to check against, which is precisely the
failure mode this project exists to avoid. Third-party copies circulate; a
licence to generate from them does not.

That is uncomfortable, because of who is on the other end: DIN SPEC 70121 is what
most European DC chargers commissioned before roughly 2020 speak, and a charge
point platform that cannot talk to them cannot talk to its own estate. So the
position is precise rather than blanket.

**The message set is out of scope until the schemas are obtainable under a
licence that permits generating from them.** The generator, the session layer and
the timers are ready for it that day.

**Everything below the message set is yours to use, deliberately** — and tested
against a foreign message set on purpose, in `tests/foreign_protocol.rs`:

| You keep | Crate |
|---|---|
| The `supportedAppProtocol` handshake | `app_protocol` — one schema shared by all three generations, and `negotiate` takes whatever set *you* say you speak |
| V2GTP framing, reassembly, the hostile length field, both ceilings | `session::Connection::next_frame` / `send_frame` |
| The spec timers and loop budgets | `session::Timers` |
| A schema-informed EXI codec to build on | `exi` |
| Which id the charger echoed | `SupportedAppProtocolReq::protocol_for_schema_id` |

You supply the message set and its ordering. `Connection::next_message` is the
typed path and refuses a generation it has no codec for; `next_frame` is the same
reassembly with the decode left to you.

<div class="note">
<span class="note-title">Why not a plug-in trait for the message set</span>
A <code>dyn</code> trait letting <code>Secc</code> and <code>Evcc</code> drive a
foreign message set would mean trait objects threaded through
<code>Message</code> and <code>Flow</code>, a decoder registry on both
configurations, and hand-written <code>Clone</code>/<code>PartialEq</code>
forwarding — a few hundred lines of API with no in-tree implementor to check it
against. That is the same argument that keeps the DIN codec itself out, one layer
up: an extension point nothing exercises is not an extension point. The seam
above is smaller, a test exercises it, and it is drawn where the generations
actually differ.
</div>

## A conformance suite

ISO 15118-4:2018 test-case IDs mapped onto the sans-I/O cores, and
ISO 15118-21:2025 for the second generation — the two application-layer test
plans, one per generation. (Not -9: that is the *wireless* physical-layer plan
and belongs to -8.) The cores make this cheap — no I/O means conformance tests
are fast unit tests — but the test texts are paid documents.

## Interop CI

Cross-testing against Josev and EVerest in containers, on every change. The
differential scripts already check the *wire format* against a third
implementation; this would check the *flow*.

## Out of scope, permanently

- Reimplementing TLS, TCP, IPv6, or an async runtime.
- **Writing** cryptography. The optional backend binds to `sha2`, `p256` and
  `p521`; it does not implement a hash or a curve, and it never will.
- OCPP, EEBUS or OpenADR bridges — separate crates can build on the event API.
- Charging-station hardware abstraction (power modules, contactors, insulation
  monitoring) — the events are the boundary.
- ISO 15118-8 (the WLAN physical layer). Below the abstraction: an IP link is
  consumed, however it was established.
- Redistributing the ISO schemas or spec texts.
