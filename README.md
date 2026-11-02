<h1 align="center">⚡ iso15118</h1>

<p align="center">
  <strong>ISO 15118 vehicle-to-grid communication in pure Rust.</strong><br>
  Sans-I/O, <code>no_std</code>-capable, both sides of the plug.
</p>

<p align="center">
  <a href="https://github.com/hupe1980/iso15118/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/hupe1980/iso15118/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://crates.io/crates/iso15118"><img alt="crates.io" src="https://img.shields.io/crates/v/iso15118.svg"></a>
  <a href="https://docs.rs/iso15118"><img alt="docs.rs" src="https://img.shields.io/docsrs/iso15118"></a>
  <a href="#-license"><img alt="License" src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue"></a>
</p>

<p align="center">
  <a href="https://hupe1980.github.io/iso15118/"><strong>Documentation</strong></a> ·
  <a href="https://hupe1980.github.io/iso15118/docs/getting-started/">Getting started</a> ·
  <a href="https://docs.rs/iso15118">API reference</a>
</p>

---

The protocol an electric vehicle and a charging station speak over the CCS
cable, in one crate: a schema-informed EXI codec generated from the official
schemas, the ISO 15118-2 and -20 message sets, HomePlug link setup (SLAC), SECC
discovery, V2GTP framing, the ordering rules and timers of both generations,
session engines for both roles, and the Plug & Charge signature profile and PKI.

No sockets, no clock, no async runtime, no cryptography in the core — those are
the caller's.

> 🚧 **Pre-1.0.** All 166 message types — both generations and ISO 15118-20
> Amd 1's AC_DER sets — round-trip byte for byte against the EXI reference
> implementation, as documents and as signature fragments, and
> 3 760 messages from captured charging sessions do the same against real equipment.

## 💡 Why

- **Sans-I/O.** Bytes and a timestamp in; bytes, events and deadlines out. A
  whole DC charging session runs as a unit test in microseconds.
- **`no_std` + `alloc`.** The core builds for `thumbv7em-none-eabihf`; every
  feature flag gates real code, grammar tables included.
- **Both roles, both generations.** The vehicle and the station share one
  ordering graph, one timer table and one codec.
- **Hostile input is the normal case.** Every length is bounded by its schema
  facets before anything is allocated; `#![forbid(unsafe_code)]` and ten fuzz targets.
- **Evidence from outside.** Differential against `exificient`, replayed against
  captured sessions, run live against two other stacks, PKI checked
  against a published test pool, citations checked against the standard's text.

## 📦 Install

```sh
cargo add iso15118
```

A DC-only embedded vehicle controller, with nothing else compiled in:

```sh
cargo add iso15118 --no-default-features --features evcc,iso20-dc,pnc
```

Rust 1.88 or newer.

## 🔌 A charging station, without a socket

The engine owns framing, decoding, the handshake, session ids, ordering and
every spec timer. Your code owns the charging decisions.

```rust,no_run
use iso15118::message::Message;
use iso15118::secc::{Event, Secc, SeccConfig, SeccError};
use iso15118::session::{Instant, SessionId};
use iso15118::Protocols;
# use std::io::{Read, Write};
# fn now() -> Instant { Instant::ZERO }
# fn random_session_id() -> [u8; 8] { [0; 8] }
# fn my_logic(_: &Message) -> Result<Message, SeccError> { unimplemented!() }
# fn run(stream: &mut std::net::TcpStream) -> Result<(), Box<dyn std::error::Error>> {
# let mut buf = [0u8; 4096];
let mut secc = Secc::new(SeccConfig {
    protocols: Protocols::ISO,                         // -20 and -2, whichever wins
    session_id: SessionId::new(random_session_id()),   // must be unpredictable
    ..SeccConfig::default()
});
secc.opened(now());

loop {
    let n = stream.read(&mut buf)?;
    secc.handle_input(now(), &buf[..n])?;

    while let Some(event) = secc.poll_event() {
        match event {
            Event::ProtocolAgreed(p) => println!("speaking {p}"),   // "iso15118-20"
            Event::Request(req) => secc.respond(now(), my_logic(&req)?)?,
            // Out of sequence: `refusal` builds the answer, and it always encodes.
            Event::Refused { message, response_code, .. } => {
                if let Some(no) = message.refusal(response_code) {
                    secc.respond(now(), no)?;
                }
            }
            Event::Closed(why) => return Ok(println!("session over: {why}")),
            _ => {}
        }
    }
    stream.write_all(&secc.take_transmit())?;
}
# }
```

Arm a timer for `secc.poll_timeout()` and call `secc.handle_timeout(now)` when
it fires. `evcc::Evcc` is driven the same way from the vehicle's side, with
`request` instead of `respond`.

```sh
cargo run --example secc_tcp     # a minimal charging station
cargo run --example evcc_tcp     # ...and a car that charges from it
```

## 🏷️ Which generation

"ISO 15118" names two incompatible protocols. Every name this crate emits says
which, and it refuses to parse one that does not.

```rust
use iso15118::{Protocol, Protocols};

assert_eq!(Protocol::Iso20.as_str(), "iso15118-20");
assert_eq!(Protocol::Iso20.title(), "ISO 15118-20:2022");
assert_eq!("iso15118-2".parse(), Ok(Protocol::Iso2));

let speaks: Protocols = "iso15118-20,iso15118-2".parse()?;
assert_eq!(speaks, Protocols::ISO);
assert_eq!(speaks.best(), Some(Protocol::Iso20));

// A bare "iso15118" is refused rather than guessed at.
assert!("iso15118".parse::<Protocol>().unwrap_err().generation_omitted());
# Ok::<_, iso15118::ParseProtocolError>(())
```

## 📨 Messages

```rust
use iso15118::exi::ExiDocument;
use iso15118::iso20::common::MessageHeader;
use iso15118::iso20::messages::{ChargingSession, SessionStopReq};

let req = SessionStopReq {
    header: MessageHeader {
        // ISO 15118-20 SessionID is exactly eight bytes; a shorter one is refused.
        session_id: vec![0x3D, 0x4C, 0xBF, 0x93, 0x37, 0x4E, 0xD8, 0x9B],
        time_stamp: 1_725_456_343,
        signature: None,
    },
    charging_session: ChargingSession::Terminate,
    ev_termination_code: None,
    ev_termination_explanation: None,
};
let bytes = req.to_vec()?;
assert_eq!(SessionStopReq::from_bytes(&bytes)?, req);
# Ok::<_, iso15118::exi::ExiError>(())
```

## ✅ What works

| Layer | |
|---|---|
| **EXI** | Schema-informed, bit-packed: primitives, value string table, grammars, documents **and fragments**, every length facet enforced both ways. Writes the coding deployed decoders read and accepts both ([`ValueCoding`](https://docs.rs/iso15118/latest/iso15118/exi/enum.ValueCoding.html)) |
| **V2GTP** · **SDP** | All payload types, hostile-length handling, bounded reassembly; discovery for both sides, with TLS-downgrade and off-link rejection |
| **SLAC** (ISO 15118-3) | Frame codec with every layout pinned, timers, the matching state machine for both roles |
| **ISO 15118-2** | All 34 body messages, `ds:Signature` included |
| **ISO 15118-20** | `CommonMessages`, AC, DC, WPT, ACDP, and Amd 1's `AC_DER_IEC` / `AC_DER_SAE`; MCS runs the DC set. The handshake uses the per-set namespaces deployed peers use ([`Iso20Set`](https://docs.rs/iso15118/latest/iso15118/enum.Iso20Set.html)) |
| **Sessions** | Ordering graphs and spec timers for both generations and both roles; a -20 session admits only the message set of the service it selected; Plug & Charge refused without TLS; loop budgets a deployment can set (`LoopBudgets`), the DC safety phases excepted |
| **EVCC / SECC drivers** | Handshake, sequencing, session-id stamping and checking, half-duplex both ways, pause and resume |
| **Refusals** | `Message::refusal()` builds the response that refuses a request, and it always encodes. All 51 requests across the eight schema sets are covered |
| **Battery view** | `Message::ev_energy_status()` — state of charge, capacity, energy request and departure from either generation, in exact milliwatt-hours |
| **Plug & Charge** | XMLDSig over EXI fragments, build and verify, the algorithm profile enforced, bound to the session's `GenChallenge` and to the metered reading |
| **V2G PKI** | `pnc::pki` — allocation-free X.509 reader and RFC 5280 path validation under the Annex F profiles, plus the Amd 1 rules (1 600-byte bound, validity nested in the issuer's, trust anchors with provenance, cross-certificates) |
| **Contract key delivery** | `pnc::envelope` — ECDH, the concatenation KDF, AES-128-CBC, and the check that the key belongs to its certificate |

**Not included:** certificate revocation (no OCSP or CRL; the station's back end
answers it), transport and TLS, and the DIN/TS 70121 message set —
`session::Connection` carries a caller's own DIN codec over the same framing.

## 🔬 Verification

```text
scripts/verify-grammars.sh   all 2 / 80 / 54 / 42 / 48 / 38 / 34 / 48 / 49 element
                             grammars agree with the reference  (395 total)
scripts/verify-messages.sh   all 166 documents round-trip against the reference
                             all 166 fragments round-trip against the reference
scripts/verify-captures.sh   3760 messages decoded, 3760 re-encoded byte-identical,
                             198 DIN frames declined by name,
                             4/4 Plug & Charge authorizations verify
```

- **Differential, against `exificient`** — every grammar and every message, as
  document and as fragment. Certificate chains and the contract-key envelope are
  checked against **OpenSSL**, and all ten OEM provisioning leaves of Hubject's
  public test PKI validate to its real V2G Root.
- **Replayed against real hardware** — 3 760 messages from sixteen captured
  charging sessions (dSPACE DS5366 against Josev and RiseV2G), ISO 15118-2 and
  -20 over TLS 1.3 included, decode and re-encode byte for byte.
- **Live against other stacks** — whole sessions in containers: Josev in both
  roles (-2 and -20, AC and DC), and EVerest's station for our vehicle (-2 and
  -20 DC, TLS, Plug & Charge, where EVerest verifies our signature).
- **Citations checked against the text** — `scripts/verify-citations.sh`
  confirms that each of the 101 requirement numbers cited here exists among the
  852 ISO 15118-2:2014 defines.
- **Fuzzed** — ten targets, run in CI on every push.

```sh
cargo test --workspace --all-features
scripts/generate.sh && git diff --exit-code src/generated   # codegen has not drifted
scripts/verify-grammars.sh && scripts/verify-messages.sh    # need a JDK and the schemas
scripts/verify-captures.sh                                  # needs tshark
cargo test --test josev --test everest                      # need Docker
```

The schemas are fetched by `scripts/fetch-schemas.sh` and pinned by SHA-256.
Building or using the crate needs none of this — `src/generated/` is committed.
[The full account →](https://hupe1980.github.io/iso15118/docs/verification/)

## 🔐 Security

Report vulnerabilities privately — see [SECURITY.md](SECURITY.md). Each release
carries a CycloneDX SBOM and a build-provenance attestation for the published
`.crate`:

```sh
gh attestation verify iso15118-X.Y.Z.crate --repo hupe1980/iso15118
```

## 📚 Documentation

| | |
|---|---|
| [Getting started](https://hupe1980.github.io/iso15118/docs/getting-started/) | Install, and a session end to end |
| [Architecture](https://hupe1980.github.io/iso15118/docs/architecture/) | The layers, and why each is separate |
| [Sessions and ordering](https://hupe1980.github.io/iso15118/docs/sessions/) | Which request is legal when |
| [The EXI profile](https://hupe1980.github.io/iso15118/docs/exi/) | Every coding option ISO 15118 pins |
| [Plug & Charge](https://hupe1980.github.io/iso15118/docs/plug-and-charge/) | What gets signed, and what a signature does not prove |
| [SLAC](https://hupe1980.github.io/iso15118/docs/slac/) | Which station this cable is plugged into |
| [Embedded and `no_std`](https://hupe1980.github.io/iso15118/docs/embedded/) | Running it on a microcontroller |
| [FAQ](https://hupe1980.github.io/iso15118/docs/faq/) | Short answers |

API reference on [docs.rs](https://docs.rs/iso15118); release history in
[CHANGELOG.md](CHANGELOG.md).

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). A change to any wire format needs a
golden vector or a spec citation — "it round-trips with itself" is not evidence.

## ⚖️ License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your
option.

ISO 15118 is a standard published by the International Organization for
Standardization. This is an independent implementation, not affiliated with or
endorsed by ISO; no part of the standard is redistributed here.
