+++
title = "FAQ"
description = "Common questions about the iso15118 Rust crate — sans-I/O, coverage of ISO 15118, TLS, no_std, DIN/TS 70121, how it compares — and what it deliberately does not do."
weight = 130

[extra]
faq = [
  { q = "What is ISO 15118?", a = "The digital protocol between an electric vehicle and a charging station over the CCS cable: authentication, the charging schedule and the control loop. Part 2 (2014) is the first-generation application layer, part 20 (2022) the second, and part 3 brings up the powerline link. It is what makes Plug & Charge and bidirectional power transfer possible." },
  { q = "What does sans-I/O mean here?", a = "No type opens a socket, reads a clock or spawns a task. You call `handle_input(now, &bytes)`, `poll_event()`, `take_transmit()` and `poll_timeout()`; transport, clock, randomness and cryptography are yours. The same logic runs under Tokio and on a bare-metal controller, and a whole DC session runs as a unit test with time as a variable." },
  { q = "Which parts of ISO 15118 are implemented?", a = "ISO 15118-2:2014 (all 34 body messages); ISO 15118-20:2022 (`CommonMessages`, AC, DC, WPT, ACDP) with Amd 1:2026's `AC_DER_IEC` and `AC_DER_SAE` sets and the megawatt charging system on the DC flow; ISO 15118-3 (SLAC frames and matching for both roles); SECC discovery; V2GTP framing; the Plug & Charge signature profile and V2G PKI. DIN/TS 70121 is recognised in the handshake, but its message set is not included — see [Limitations](@/docs/faq.md#limitations)." },
  { q = "How do I record which generation a session spoke?", a = "`Protocol::as_str()` — `\"din70121\"`, `\"iso15118-2\"`, `\"iso15118-20\"`. `Display`, `FromStr` and `serde` use the same names, so a record written today parses tomorrow. `Protocols` is the set form, one comma-separated token. A bare `\"iso15118\"` does not parse: DATEX II's AFIR profile uses that literal for ISO 15118-20 and has none for -2." },
  { q = "What is the difference between `Protocol` and `Protocols`?", a = "`Protocol` is what one session negotiated. `Protocols` is an ordered set — what a vehicle offers, a station accepts, or a device implements. It is `Copy`, allocation-free and `const`-constructible." },
  { q = "Does it do TLS?", a = "No: a sans-I/O engine consumes bytes, so you bring `rustls` on a server or `embedded-tls` on a controller. What is protocol is enforced: `Protocol::Iso20.requires_tls()` is `true`, SDP refuses a security downgrade, and ISO 15118-2 Plug & Charge is refused on a session the caller has not marked as TLS." },
  { q = "Can I run it on a microcontroller?", a = "Yes. The core builds for `thumbv7em-none-eabihf` without `std`, checked in CI. You need an allocator — decoded EXI strings cannot borrow from the input. Set `max_payload_len` to what you can hold and enable only the message sets you speak; see [Embedded and `no_std`](@/docs/embedded.md)." },
  { q = "How is the EXI codec verified?", a = "Against other implementations, not itself. All 395 derived grammars are diffed against `exificient`, the EXI reference implementation, and all 166 message types are re-encoded byte for byte from its output, as documents and as signature fragments. 3760 messages from captured charging sessions — dSPACE hardware against Josev and RiseV2G, ISO 15118-20 over TLS 1.3 included — also re-encode byte for byte. See [Verification](@/docs/verification.md)." },
  { q = "Why does strict mode matter so much?", a = "ISO 15118 sends no EXI options document, and its default is `strict = false`. Non-strict grammars add second-level productions that cost no bits themselves but widen every first-level event code, so every element of every message is shifted if you get it wrong." },
  { q = "How does it compare to EVerest, Josev and OpenV2G?", a = "EVerest runs DIN, -2 and -20 on one C++ station stack with a generated C codec, coupled to its runtime. Josev is Python, readable and reference-quality, but not for a vehicle controller. OpenV2G is C, ISO 15118-2 and DIN only. This crate is one sans-I/O, `no_std` Rust codebase for both roles and both generations, with its wire format checked against third implementations and captured sessions." },
  { q = "Is Plug & Charge complete?", a = "Signatures (build, verify, the algorithm restrictions, the challenge and metering bindings), X.509 chain validation under Annex F and the Amd 1 rules, and the contract-key envelope are implemented. Certificate revocation is the caller's — see [Limitations](@/docs/faq.md#limitations)." },
  { q = "Do I need the ISO schemas to build it?", a = "No. The generated message sets are committed. You need the schemas only to regenerate; `scripts/fetch-schemas.sh` downloads them, pinned by SHA-256." },
  { q = "Is it production ready?", a = "It is pre-1.0: the minor version is the breaking one. The message sets are generated from the official schemas and verified against third implementations, the session layer implements both generations' ordering rules, and there is no `unsafe`. Read the limitations below before deciding — revocation above all." },
  { q = "What licence is it under?", a = "MIT or Apache-2.0, at your option. No part of the ISO standard is redistributed." },
]
+++

Short answers to common questions. Start with
[Getting started](@/docs/getting-started.md) or the
[architecture](@/docs/architecture.md) for depth.

## Limitations

What the crate does not do, as of this release.

| | |
|---|---|
| **Certificate revocation** | No OCSP, no CRL: a revoked certificate validates like a live one. Annex F makes OCSP a recommendation because a charging vehicle cannot be assumed to reach a responder. Ask your back end; `Validated::subject_common_name` is the `EMAID`. |
| **Transport** | No TCP, TLS, UDP or raw sockets. The examples show the glue. |
| **DIN/TS 70121 message set** | Not included: no schema licence that permits generating from them. The handshake recognises DIN so a station can decline it by name, and the framing, timers and `Connection::next_frame` let your own DIN codec ride the same layers (`tests/foreign_protocol.rs`). |
| **Relay attacks** | Plug & Charge authenticates the contract, not the cable: the vehicle signs the station's challenge and nothing else, so a live relay passes every check the protocol defines ([arXiv 2512.15966](https://arxiv.org/abs/2512.15966)). Checking the challenge stops replay, not relay. |
| **Real certificates for two profiles** | Hubject's public test PKI has real leaves only for OEM provisioning; `SeccCertificate` and `ContractCertificate` are tested on OpenSSL-minted chains. |
| **ISO 15118-20 timing values** | The -20 timing table is not freely available; loop budgets for -20 are this crate's labelled policy, overridable with `LoopBudgets`. |
| **MCS rules** | MCS runs the DC flow; Amd 1's no-fallback rule (configure the station for ISO 15118-20 only) and the data-link pause are the caller's. |
| **Conformance** | Not conformance-tested against the ISO test plans; verified against third implementations and captured sessions. |
| **Out of scope** | Writing cryptography (the optional backend binds `sha2`, `p256`, `p521`, `aes`, `cbc`); control pilot, PWM and modem drivers; OCPP, EEBUS or OpenADR bridges; station hardware abstraction; the ISO 15118-8 WLAN layer; redistributing ISO material. |
