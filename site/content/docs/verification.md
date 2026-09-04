+++
title = "Verification"
description = "How iso15118 is verified: 298 grammars and 121 messages differed against the EXI reference implementation, layouts pinned byte for byte, ten fuzz targets, and every spec citation checked against the text."
weight = 100
+++

Round-tripping your own encoder through your own decoder proves that they agree
with each other. It proves nothing about whether a charger will understand you.

This crate is checked in layers, in increasing strength. Only the differential
ones say anything about other implementations.

| Layer | What it proves |
|---|---|
| **Property tests** | `decode(encode(m)) == m`, and bit reader/writer duality. Self-consistency, and nothing more. |
| **Layout pins** | Every SLAC message encoded with a distinct byte per field and asserted verbatim, because SLAC has no reference implementation to differ against. Pins field order, offsets, widths and reserved gaps — the things a round trip cannot see. |
| **Golden vectors** | Real ISO 15118-20 frames from an independent C++ implementation, walked event by event and re-encoded byte for byte — including a negative test showing strict-mode widths *cannot* decode the same bytes. |
| **Differential grammars** | Every derived state and production compared against `exificient`, the EXI reference implementation, for all **298** element grammars. Golden vectors cover the paths they take; this covers the whole grammar. |
| **Differential messages** | A schema-valid instance of **every** message type, encoded by the reference implementation as a document **and** as a fragment, decoded and re-encoded byte for byte by the generated codec. **121 × 2.** |
| **Requirement register** | Every `[V2G2-nnn]` cited anywhere in the repository checked against the text of ISO 15118-2:2014 itself — **101** cited, against the standard's **852**. |
| **Differential certificates** | The V2G chains `pnc::pki` validates are minted by **OpenSSL** (`scripts/make-test-pki.sh`) — a third implementation's DER, to the same ASN.1, with the Annex F fields where Annex F puts them, and a `ContractSignatureEncryptedPrivateKey` OpenSSL sealed. |

```text
scripts/verify-grammars.sh   all 2 / 80 / 54 / 42 / 48 / 38 / 34 element
                             grammars agree with the reference  (298 total)
scripts/verify-messages.sh   all 121 documents round-trip against the reference
                             all 121 fragments round-trip against the reference
```

The fragment half is a separate claim, not a restatement: a fragment is indexed by
every element qname the schema *declares* rather than by its global elements, so
the same message encodes differently from its very first event code. Those are the
bytes Plug & Charge signs.

Both scripts need a JDK and the ISO schemas, so they are scripts rather than CI
jobs — the schemas are licensed and are not redistributed. `scripts/generate.sh`
followed by `git diff` is the third check: that the committed codec still matches
its generator.

## What the grammar layers catch

Six things a round trip cannot see, because encoder and decoder agree on all of
them and the reference implementation does not:

- **substitution groups** — ISO 15118-2 routes all 34 body messages through one
  choice, and the *abstract* head occupies an event code of its own. Dropping it
  shifts every later message down by one;
- **mixed content** — contributes an untyped character-data production that sorts
  **after** `EE`, and only inside the content region;
- **wildcard ordering** — declared elements precede `xs:any` regardless of schema
  order;
- **bounded repetition** — `maxOccurs="2048"` must be unrolled exactly, not
  approximated by a loop;
- **repeated choices** — after one occurrence the grammar re-offers *every* branch,
  not one event code;
- **string-table partitions** — a value found in the *global* partition must not be
  added to the local one. Getting this wrong desynchronises the moment one string
  appears under two element names, which is most real messages.

Facets are the other half, and they are enforced in both directions: `xs:length`
is not `xs:maxLength`, and six V2G types have an exact length that is precisely
the security-relevant one — both `GenChallenge`s, ISO 15118-20's `SessionID`, the
ECDH public key, the three encrypted-contract-key envelopes. A truncated one must
not decode. See [Bounded everything](@/docs/exi.md#bounded-everything-in-both-directions).

## What the scripts cannot check

They prove the encoding. They say nothing about whether the flow above it is the
one ISO wrote. That is checked by reading the layers against the standards and
against both live open-source implementations, and every rule is a test:

- **the ordering graph, including its exits.** A DC renegotiation arrives with the
  contactors closed and no cable check coming, so demanding the isolation test
  before every `PowerDeliveryReq(Start)` deadlocks it — and a *service*
  renegotiation is the opposite case, which must not inherit that exemption;
- **half-duplex, in both directions.** Several requests are legal repeatedly, so
  the ordering graph cannot catch a peer that pipelines — it constrains *which*
  request, not *when*. The vehicle enforces it on what it sends and the station on
  what it reads;
- **identity, not just presence.** A session id is checked against the one that
  was assigned, not against zero; ISO 15118-20 service ids map to the flows the
  standard assigns them, which is where EVerest's `ServiceCategory` and Josev's
  `ServiceV20` agree;
- **the loop budgets are armed**, not merely declared. A cable-check loop that
  repeats promptly for ever is never late by a per-message timeout.

Two checks are about binding rather than validity, and are the ones most often
left out: a Plug & Charge signature must name the session it arrived in, and a
metering receipt must be checked against the reading the station actually metered.
See [Plug & Charge](@/docs/plug-and-charge.md).

## What an unauthenticated peer can make an engine do

SDP and SLAC run on a shared powerline segment where anything can transmit and
nothing is authenticated. So the question is not "is this frame well-formed" but
"what can a frame nobody can authenticate make this engine *do*" — and dropping a
bad frame is only half of not being steered by one. The other half is that such a
frame must set neither a deadline nor a queue length:

- **a well-formed answer the vehicle must not act on does not end discovery.** If
  any answer were terminal, one spoofed datagram would stop a vehicle ever hearing
  the station it is plugged into;
- **an SDP answer cannot redirect the vehicle off the link.** The address it names
  is where the vehicle opens its connection, and the V2G link is link-local with no
  router on it;
- **a forged attenuation report cannot postpone a SLAC choice.** Everything a
  forgery needs is broadcast in the clear during sounding, so a report may move the
  choice earlier and never later;
- **every collection an unauthenticated peer can reach is bounded** — the station
  list keyed by an Ethernet source MAC, both event queues, the outgoing frame
  queue. Terminal events are never dropped;
- **a malformed frame is weather, not an exception.** `handle_frame` returns no
  `Result` at all: a caller that acted on one would let anything within earshot end
  somebody else's matching run with a single packet. See [SLAC](@/docs/slac.md).

## SLAC has no reference implementation

Its thirteen message layouts are hand-transcribed from ISO 15118-3 and HomePlug
GreenPHY, and there is nothing to differ them against. A round trip is not
evidence here for the reason this page opens with: swap two fields of the same
width in both the encoder and the decoder and every test still passes, while the
frame is wrong on the wire and fails against every real modem.

So `tests/slac_layout.rs` is the next strongest thing — every message encoded with
a distinct byte per field and asserted verbatim, pinning field order, offsets,
widths, the reserved gaps and both `MVFLength` constants, checked field for field
against [EVerest's `libslac`](https://github.com/EVerest/libslac). A mutation test
records the gap it closes: a same-width field swap applied to encoder *and*
decoder passes a round trip and fails this.

Message writers derive their length from what they wrote rather than from the
caller's buffer, so a field list that does not add up fails instead of spilling
into whatever follows.

## Citations, checked against the text

Every `[V2G2-nnn]` in the source names the requirement that states the rule it is
attached to, and every timing constant matches Table 109 and Table 111 of
ISO 15118-2 — *both halves* of Table 109, the timeouts each side enforces and the
performance times each side owes. Where a value is *not* quoted — the ISO 15118-20
loop budgets — the constant says it is this crate's judgement and why. A constant
that cites a requirement it does not come from cannot be questioned, which is
worse than one that admits it is a guess.

Half of that is mechanical now:

```text
scripts/verify-citations.sh  every [V2G2-nnn] cited in this repository names a
                             requirement ISO 15118-2:2014 defines  (101 of 852)
```

ISO 15118-2:2014(E) is a paid document that a US Federal Highway Administration
rulemaking docket nonetheless publishes in full, with ANSI's permission, for the
NEVI programme. So the script fetches the text, extracts the 852 requirement
labels it defines, and fails on any citation here that names none of them. It
writes nothing into the repository: the copyright notice on every page is
explicit.

What that catches is the citation that names *something else* — a number one
digit out is still a real requirement, about a different rule, and reads
perfectly. What it cannot catch is whether the requirement says what the comment
beside it claims; that is a person reading, and it is how the ordering graph came
to match §8.8.4's "allowed next request" clauses line for line.

Two citations are excluded by name, which is the honest kind of exclusion:
`[V2G2-ED2-1664]` and `[V2G2-ED2-1667]` belong to the standard's second edition,
which is neither this document nor freely readable. They are the only unverified
protocol citations in the crate, and what rests on them is one behaviour — that a
`FAILED` response leaves the session alive for a `SessionStopReq` rather than
dropping the socket at once, which is what EVerest and Josev also do.

The generator's `--why` report is part of the same claim: the only types it
declines to express are the seven xmldsig ones ISO 15118 never uses, and every
field it declines is refused at decode rather than skipped — including the
`KeyInfo` a `ds:Signature` must never be allowed to smuggle in.

## Beyond the wire format

| Concern | Approach |
|---|---|
| **Fuzzing** | Ten `cargo-fuzz` targets: EXI primitives, every message decoder, fragment decoders, V2GTP, SDP, SLAC frames, SLAC matching, X.509 certificates, and the whole charging-station front door from raw TCP bytes with arbitrary read boundaries. Committed seed corpora get past the format gates random input never guesses. The certificate target is the one with the most to prove — it is the only hand-written parser in the crate — and it asserts that every borrowed field lies inside the input, not merely that nothing panicked. |
| **Session tests** | A whole DC charging session **per generation**, vehicle to station through byte vectors, with a mock clock — the ISO 15118-20 one crossing two V2GTP payload types and two schema sets in a single session. Sequence violations, failure responses, pauses, timer expiry and protocol mismatch each have a test. |
| **Hostile-peer tests** | A pipelined burst, a response to a question nobody asked, a forged SLAC key handover, a bystander's sounding packets, a bystander restarting somebody else's matching run, a Plug & Charge signature replayed from another session. Each is a peer inside the framing and outside the protocol, which is where a fuzzer's random bytes rarely land. |
| **Examples that run** | Two examples complete an AC session over a real socket, so the integration story cannot rot into prose. |
| **Signature tests** | Every refusal in the Plug & Charge profile has a test, including both directions of the coverage check, the suite-downgrade attempt, the truncation request, a signature replayed from another session, and a meter reading the vehicle made up. |
| **Timing** | Mock-clock tests for the spec timers, with each constant saying where it comes from — a requirement number where there is one, and "this crate's policy" where the value is derived — including the loop budgets, where the test is that the repeats do *not* extend them. |
| **Unsafe** | `#![forbid(unsafe_code)]` crate-wide, no exceptions. |
| **Feature matrix** | `cargo hack check --feature-powerset --depth 2`, 129 combinations. |
| **Terminal faults** | The session fuzz target asserts that any error `handle_input` reports has *already* closed the session — not that it could be closed, that it is. A detected fault the caller is free to ignore is not enforcement, and arbitrary bytes at arbitrary read boundaries is where the next path that reports without shutting would hide. |
| **`no_std`** | CI builds for `thumbv7em-none-eabihf` with `std` off and everything else on. |
| **MSRV** | Declared and CI-enforced over the whole workspace — library, tests, doctests and examples — because an MSRV only the library meets is not one a reader can build against. |

## Running it yourself

```sh
cargo test --workspace --all-features
cargo hack check -p iso15118 --feature-powerset --depth 2 --no-dev-deps
cargo +nightly fuzz run session fuzz/corpus/session fuzz/seeds/session

scripts/generate.sh && git diff --exit-code src/generated   # codegen has not drifted
scripts/verify-grammars.sh              # every grammar vs. the reference
scripts/verify-messages.sh              # every message, as document and fragment
scripts/verify-citations.sh             # every [V2G2-nnn] vs. the standard's text
```

Three of those need a JDK and the fetched schemas; `scripts/fetch-schemas.sh`
downloads the XSDs, which ISO publishes freely. The last needs `pdftotext` and
network access, and fetches ISO 15118-2's own text from the FHWA docket into a
scratch directory. Nothing here depends on having any of them to build or use the
crate — `src/generated/` is committed.
